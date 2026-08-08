"""Daemon lifecycle: framing I/O, error paths, and socket bind/reclaim races."""

import json
import os
import socket
import struct
import threading
import time
from pathlib import Path

import pytest

from agent_sanitizer.secrets import daemon as S
from tests.secrets.redactor_helpers import wait_for_listener


def _drain(sock: socket.socket) -> object:
    header = b""
    while len(header) < 4:
        header += sock.recv(4 - len(header))
    (length,) = struct.unpack(">I", header)
    buf = b""
    while len(buf) < length:
        buf += sock.recv(length - len(buf))
    return json.loads(buf.decode("utf-8"))


# ─── _write_frame / _serve_one over a socketpair ─────────────────────────────


def test_write_frame_round_trips():
    a, b = socket.socketpair()
    try:
        S._write_frame(a, {"hello": "world"})
        assert _drain(b) == {"hello": "world"}
    finally:
        a.close()
        b.close()


def test_serve_one_non_dict_request_closes_silently():
    a, b = socket.socketpair()
    try:
        body = json.dumps([1, 2, 3]).encode("utf-8")  # a list, not a dict
        a.sendall(struct.pack(">I", len(body)) + body)
        S._serve_one(b)  # must return without writing a response
        a.settimeout(1)
        assert a.recv(4) == b""  # peer closed, no frame written
    finally:
        a.close()


def test_serve_one_engine_failure_writes_error(monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("detection blew up")

    monkeypatch.setattr(S, "handle_request", _boom)
    a, b = socket.socketpair()
    try:
        body = json.dumps({"text": "key: AKIAIOSFODNN7EXAMPLE"}).encode("utf-8")
        a.sendall(struct.pack(">I", len(body)) + body)
        S._serve_one(b)
        assert _drain(a) == {"error": "redaction failed"}
    finally:
        a.close()


def test_serve_one_engine_failure_logs_type_and_frames_not_input_or_message(
    monkeypatch, capsys
):
    # A detection failure logs the exception TYPE and its stack FRAMES for the
    # operator, but NEVER the exception message or the request text: either can
    # embed bytes of the secret-bearing input line, which must not reach the logs.
    secret_input = "AKIAIOSFODNN7EXAMPLE"
    secret_message = "leaky-exception-message-9f3a2b"

    def _boom(*a, **k):
        raise RuntimeError(secret_message)

    monkeypatch.setattr(S, "handle_request", _boom)
    a, b = socket.socketpair()
    try:
        body = json.dumps({"text": f"key: {secret_input}"}).encode("utf-8")
        a.sendall(struct.pack(">I", len(body)) + body)
        S._serve_one(b)
        _drain(a)  # the client-facing response is asserted separately above
    finally:
        a.close()
    err = capsys.readouterr().err
    # Positive markers proving the log path ran and is useful to the operator.
    assert "RuntimeError" in err  # exception type is logged
    assert "_serve_one" in err  # a stack frame is logged
    # The two leak vectors are absent.
    assert secret_message not in err  # exception message withheld
    assert secret_input not in err  # request text withheld


def test_serve_one_malformed_json_body_closes():
    a, b = socket.socketpair()
    try:
        body = b"{not valid json"
        a.sendall(struct.pack(">I", len(body)) + body)
        S._serve_one(b)  # ValueError swallowed, connection closed
        a.settimeout(1)
        assert a.recv(4) == b""
    finally:
        a.close()


# ─── the wait helper itself ──────────────────────────────────────────────────


def test_wait_for_listener_rejects_a_socket_file_with_no_listener(sock_dir):
    # Non-vacuity for every `wait_for_listener` call below: the helper replaced
    # a loop that waited only for the socket FILE, which is created by bind()
    # and therefore exists in the window before listen() runs. Prove the helper
    # tells the two apart by handing it exactly that shape — a bound-then-closed
    # path, file present, nobody accepting — and asserting it does NOT return.
    socket_path = str(sock_dir / "s.sock")
    dead = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    dead.bind(socket_path)
    dead.close()
    assert Path(socket_path).exists()
    with pytest.raises(AssertionError, match="no daemon accepting"):
        wait_for_listener(socket_path, timeout=0.2)


# ─── _bind_or_exit / _reclaim_stale_socket ───────────────────────────────────


def test_reclaim_stale_socket_removes_dead_file(sock_dir):
    socket_path = str(sock_dir / "s.sock")
    # A stale socket FILE with nobody listening: a leftover bind, then closed.
    dead = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    dead.bind(socket_path)
    dead.close()  # file remains on disk, but no listener
    assert Path(socket_path).exists()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        assert S._bind_or_exit(sock, socket_path) is True
    finally:
        sock.close()


def test_bind_or_exit_returns_false_when_live_daemon_owns_path(sock_dir):
    socket_path = str(sock_dir / "s.sock")
    stop = threading.Event()
    thread = threading.Thread(target=S.serve, args=(socket_path, stop), daemon=True)
    thread.start()
    wait_for_listener(socket_path)
    try:
        # A second daemon trying the same live path must exit quietly (False).
        second = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            assert S._bind_or_exit(second, socket_path) is False
        finally:
            second.close()
        # And a full second serve() likewise returns without taking over. Run it
        # in a helper thread with a bounded join so a regression that blocks
        # (e.g. taking over the live socket instead of bailing) surfaces as a
        # failed assertion, not a silent hang that wedges the whole suite.
        second_serve = threading.Thread(
            target=S.serve, args=(socket_path, threading.Event()), daemon=True
        )
        second_serve.start()
        # Bound generously: a cold serve() re-runs configure_plugins + a warm-up
        # scan before it can bail on the live path (the sibling daemon-start
        # tests allow 10s just for the socket to appear), so a short join could
        # flake on slow CI while still not being an unbounded hang.
        second_serve.join(timeout=30)
        assert not second_serve.is_alive(), (
            "second serve() must return because the path is live, not block"
        )
        # Non-vacuous positive marker: the ORIGINAL daemon still owns the socket
        # and answers — proving the second serve() bailed without disturbing it,
        # rather than the assertion passing because nothing was ever serving.
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(socket_path)
            body = json.dumps({"text": "key: AKIAIOSFODNN7EXAMPLE"}).encode("utf-8")
            client.sendall(struct.pack(">I", len(body)) + body)
            client.settimeout(5)
            assert "AWS Access Key" in _drain(client)["found"]
        finally:
            client.close()
    finally:
        stop.set()
        thread.join(timeout=5)


def test_bind_or_exit_reraises_non_addrinuse(sock_dir):
    # A bind error that is NOT EADDRINUSE (here ENOENT: the parent directory does
    # not exist) must propagate, not be swallowed as a stale-socket case.
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    missing = str(sock_dir / "no_such_dir" / "s.sock")
    try:
        with pytest.raises(OSError):
            S._bind_or_exit(sock, missing)
    finally:
        sock.close()


# ─── main() ──────────────────────────────────────────────────────────────────


def test_main_usage_error_on_wrong_argc():
    with pytest.raises(SystemExit):
        S.main([])
    with pytest.raises(SystemExit):
        S.main(["a", "b"])


def test_main_serves_until_stopped(sock_dir, monkeypatch):
    socket_path = str(sock_dir / "s.sock")
    called = {}

    def _fake_serve(path):
        called["path"] = path

    monkeypatch.setattr(S, "serve", _fake_serve)
    S.main([socket_path])
    assert called["path"] == socket_path


def test_serve_creates_socket_dir_with_mode(sock_dir):
    nested = sock_dir / "sub" / "dir"
    socket_path = str(nested / "s.sock")
    stop = threading.Event()
    thread = threading.Thread(target=S.serve, args=(socket_path, stop), daemon=True)
    thread.start()
    wait_for_listener(socket_path)
    try:
        assert oct(os.stat(nested).st_mode)[-3:] == "700"
    finally:
        stop.set()
        thread.join(timeout=5)


def test_serve_tightens_preexisting_loose_socket_dir(sock_dir):
    # `os.makedirs(..., mode=0o700, exist_ok=True)` only applies `mode` to a
    # directory it actually CREATES — a dir another (possibly untrusted) local
    # process pre-created at a looser mode is accepted as-is. Simulate that by
    # loosening the already-existing sock_dir before the daemon starts, then
    # assert serve() unconditionally tightens it back to 0o700.
    os.chmod(sock_dir, 0o777)
    assert oct(os.stat(sock_dir).st_mode)[-3:] == "777"
    socket_path = str(sock_dir / "s.sock")
    stop = threading.Event()
    thread = threading.Thread(target=S.serve, args=(socket_path, stop), daemon=True)
    thread.start()
    wait_for_listener(socket_path)
    try:
        assert oct(os.stat(sock_dir).st_mode)[-3:] == "700"
    finally:
        stop.set()
        thread.join(timeout=5)


# ─── Per-connection timeout (DoS on a stalled peer) ──────────────────────────


def test_stalled_connection_does_not_block_the_daemon(sock_dir, monkeypatch):
    # A client that connects and sends only PART of the 4-byte length header
    # must not wedge `_serve_one` — and thus the whole single-threaded accept
    # loop — forever. Shrink the per-connection timeout so the test is fast
    # while still exercising the real bound (unbounded before the fix).
    monkeypatch.setattr(S, "CONN_TIMEOUT_SECONDS", 0.5)
    socket_path = str(sock_dir / "s.sock")
    stop = threading.Event()
    thread = threading.Thread(target=S.serve, args=(socket_path, stop), daemon=True)
    thread.start()
    wait_for_listener(socket_path)
    stalled = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    fresh = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        stalled.connect(socket_path)
        stalled.sendall(b"\x00\x00")  # 2 of 4 header bytes; never sends the rest

        fresh.connect(socket_path)
        body = json.dumps({"text": "key: AKIAIOSFODNN7EXAMPLE", "map": False}).encode(
            "utf-8"
        )
        fresh.sendall(struct.pack(">I", len(body)) + body)
        fresh.settimeout(5)
        start = time.time()
        result = _drain(fresh)
        elapsed = time.time() - start
        assert "AWS Access Key" in result["found"]
        # Bounded by roughly CONN_TIMEOUT_SECONDS (the stalled connection ahead
        # of it in accept order), never by an unbounded hang.
        assert elapsed < 3, (
            f"a stalled peer must not block a fresh request ({elapsed}s)"
        )
    finally:
        stalled.close()
        fresh.close()
        stop.set()
        thread.join(timeout=5)
