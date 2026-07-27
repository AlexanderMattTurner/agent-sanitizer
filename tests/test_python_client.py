"""Tests for the Python client (`python/agent_sanitizer`).

The client is a thin bridge to the Node CLI, so these assert the bridge holds:
Layer 1 strips, the html flag reaches Layers 2/3, the persistent worker agrees
with the one-shot path, and a missing Node fails loudly. The sanitization
verdicts themselves are owned by the JS suite — here the CLI is the source of
truth and the client must faithfully relay it.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT

sys.path.insert(0, str(REPO_ROOT / "python"))

import agent_sanitizer as ais  # noqa: E402
from agent_sanitizer import (  # noqa: E402
    PromptVerdict,
    Sanitizer,
    SanitizeResult,
    TextResult,
    classify_prompt,
    clean_file,
    sanitize,
    sanitize_text,
    scan_instruction_files,
    shutdown_worker,
)

ESC = "\x1b"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None, reason="Node.js required for the CLI bridge"
)

ZERO_WIDTH_SPACE = "​"
HIDDEN_HTML = '<div style="display:none">leak</div>'


@pytest.fixture(autouse=True)
def _no_shared_worker_leak() -> Iterator[None]:
    """Each test starts and ends with no shared worker, so persistence state
    can't bleed across tests."""
    shutdown_worker()
    assert ais._worker is None
    yield
    shutdown_worker()


@pytest.fixture(autouse=True)
def _no_bundled_cli_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """A repo checkout has no bundled CLI — it is a build artifact written into
    the wheel, not committed. But a developer who ran `scripts/bundle-python-cli.mjs`
    leaves one on disk, and it takes precedence over the source sibling. Neutralize
    it by default so the suite resolves the source-tree CLI deterministically
    regardless; the tests that exercise the bundled path re-point it explicitly.
    """
    monkeypatch.setattr(
        ais,
        "_BUNDLED_CLI",
        REPO_ROOT / "python" / "agent_sanitizer" / "_bundled" / "absent.mjs",
    )


def test_strips_invisible_layer1() -> None:
    result = sanitize(f"a{ZERO_WIDTH_SPACE}b")
    assert result.cleaned == "ab"
    assert result.found == ["cf-format"]
    assert result.warnings  # any change carries a warning


def test_clean_text_passes_through_unchanged() -> None:
    result = sanitize("hello world")
    assert result == SanitizeResult(cleaned="hello world", found=[], warnings=[])


def test_empty_input() -> None:
    assert sanitize("") == SanitizeResult(cleaned="", found=[], warnings=[])


def test_html_flag_reaches_layer2() -> None:
    assert "leak" in sanitize(HIDDEN_HTML, html=False).cleaned  # Layer 1 only
    assert "leak" not in sanitize(HIDDEN_HTML, html=True).cleaned  # hidden removed


def test_html_amortizes_load_via_shared_worker() -> None:
    # Default persist=None ⇒ html calls reuse one warm worker: the ~200 ms
    # module-load is paid once, not per call.
    first = sanitize(HIDDEN_HTML, html=True)
    worker = ais._worker
    assert worker is not None and worker.is_alive()
    second = sanitize(f"a{ZERO_WIDTH_SPACE}b", html=True)
    assert ais._worker is worker  # same process reused, not respawned
    assert "leak" not in first.cleaned
    assert second.cleaned == "ab"


def test_shared_worker_self_heals_after_death() -> None:
    # The riskiest path: a dead shared worker must be reaped and respawned, not
    # left wedging every later persistent call on a corpse.
    sanitize(HIDDEN_HTML, html=True)
    dead = ais._worker
    assert dead is not None
    dead._proc.kill()
    dead._proc.wait()
    assert not dead.is_alive()

    result = sanitize(f"a{ZERO_WIDTH_SPACE}b", html=True, persist=True)
    assert ais._worker is not None and ais._worker.is_alive()
    assert ais._worker is not dead  # a fresh process, not the corpse
    assert result.cleaned == "ab"


def test_layer1_default_stays_oneshot() -> None:
    # A caller that never touches HTML must not leave a process running.
    sanitize(f"a{ZERO_WIDTH_SPACE}b")
    assert ais._worker is None


def test_persist_true_forces_worker_for_layer1() -> None:
    sanitize("plain", persist=True)
    assert ais._worker is not None and ais._worker.is_alive()


def test_persist_false_forces_oneshot_for_html() -> None:
    result = sanitize(HIDDEN_HTML, html=True, persist=False)
    assert ais._worker is None
    assert "leak" not in result.cleaned


def test_shutdown_worker_is_idempotent() -> None:
    sanitize("x", persist=True)
    assert ais._worker is not None
    shutdown_worker()
    assert ais._worker is None
    shutdown_worker()  # second call is a no-op, not an error
    assert ais._worker is None


def test_worker_matches_oneshot() -> None:
    texts = [f"a{ZERO_WIDTH_SPACE}b", "plain", HIDDEN_HTML]
    with Sanitizer() as worker:
        for text in texts:
            assert worker.sanitize(text, html=True) == sanitize(text, html=True)


def test_worker_preserves_embedded_newlines() -> None:
    text = f"line1\nline2{ZERO_WIDTH_SPACE}"
    with Sanitizer() as worker:
        assert worker.sanitize(text) == sanitize(text)


def test_missing_node_fails_loudly() -> None:
    with pytest.raises(RuntimeError, match="Node.js"):
        sanitize("x", node="definitely-not-a-real-node-binary")


def test_worker_missing_node_fails_loudly() -> None:
    with pytest.raises(RuntimeError, match="Node.js"):
        with Sanitizer(node="definitely-not-a-real-node-binary"):
            pass


def test_missing_cli_fails_with_clear_message(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ais, "_CLI", REPO_ROOT / "bin" / "does-not-exist.mjs")
    with pytest.raises(RuntimeError, match="sanitize CLI not found"):
        sanitize("x")


def test_worker_error_response_becomes_runtime_error() -> None:
    # A CLI `{error}` response (here: a non-string text) must surface as a clear
    # exception, not a malformed SanitizeResult.
    with Sanitizer() as worker:
        with pytest.raises(RuntimeError, match="text must be a string"):
            worker.sanitize(123)  # type: ignore[arg-type]


def test_oneshot_error_becomes_runtime_error() -> None:
    with pytest.raises(RuntimeError, match="sanitize CLI failed"):
        sanitize(123, persist=False)  # type: ignore[arg-type]


def test_drain_stderr_reads_back_worker_stderr() -> None:
    # The death-diagnostic path: a child process writes to the worker's stderr
    # temp file via its fd; _drain_stderr must read it back across that fd.
    worker = Sanitizer()
    worker._stderr = tempfile.SpooledTemporaryFile(mode="w+", encoding="utf-8")
    node = shutil.which("node")
    assert node is not None
    subprocess.run(
        [node, "-e", "process.stderr.write('diag-from-child')"],
        stderr=worker._stderr,
        check=True,
    )
    assert worker._drain_stderr() == "diag-from-child"
    worker._stderr.close()


def test_killed_worker_raises_loudly_on_next_use() -> None:
    # A worker that WAS started then died mid-use must not claim it was never
    # used as a context manager — it reports the unexpected exit (bug #2).
    with Sanitizer() as worker:
        worker._proc.kill()
        worker._proc.wait()
        with pytest.raises(RuntimeError, match="worker exited unexpectedly"):
            worker.sanitize("x")


def test_never_started_worker_says_use_as_context_manager() -> None:
    # The original message is still correct for a worker that genuinely never
    # ran: distinguish "not started" from "started then died".
    worker = Sanitizer()
    with pytest.raises(RuntimeError, match="use it as a context manager"):
        worker.request({"text": "x"})


def test_shared_worker_not_shared_across_fork() -> None:
    # Simulate inheriting a worker across os.fork: a pid mismatch must force a
    # fresh process, never reuse the parent's pipe.
    sanitize("x", persist=True)
    inherited = ais._worker
    assert inherited is not None
    inherited._pid = -1  # pretend this worker was spawned by another process

    sanitize("y", persist=True)
    assert ais._worker is not None and ais._worker is not inherited
    assert ais._worker._pid == os.getpid()
    # The "inherited" worker was abandoned, not reaped — still running.
    assert inherited.is_alive()
    inherited.close()


# ─── Additional self-contained entry points (op dispatch) ────────────────────


def test_classify_prompt_pass() -> None:
    assert classify_prompt("hello world") == PromptVerdict(action="pass")


def test_classify_prompt_note_on_sgr_only() -> None:
    # A purely cosmetic color sequence is usable: note, not block.
    assert classify_prompt(f"{ESC}[31mred{ESC}[0m") == PromptVerdict(action="note")


def test_classify_prompt_block_carries_reason() -> None:
    verdict = classify_prompt(f"{ESC}[2Jwipe")  # non-SGR escape → block
    assert verdict.action == "block"
    assert verdict.reason


def test_sanitize_text_layer1() -> None:
    result = sanitize_text(f"a{ZERO_WIDTH_SPACE}b")
    assert result == TextResult(
        cleaned="ab",
        warnings=result.warnings,  # exact text owned by JS suite
        modified=True,
        sgr_note=False,
    )
    assert result.warnings


def test_sanitize_text_clean_passthrough() -> None:
    assert sanitize_text("hello") == TextResult(
        cleaned="hello", warnings=[], modified=False, sgr_note=False
    )


def test_sanitize_text_html_layer() -> None:
    assert "leak" not in sanitize_text(HIDDEN_HTML, html=True).cleaned


def test_scan_and_clean_instruction_files(tmp_path: Path) -> None:
    payload = f"intro {ZERO_WIDTH_SPACE * 100} outro\n"
    (tmp_path / "NOTES.md").write_text(payload, encoding="utf-8")
    (tmp_path / "CLEAN.md").write_text("nothing hidden here\n", encoding="utf-8")

    findings = scan_instruction_files(["*.md"], cwd=str(tmp_path))
    assert [f.file for f in findings] == ["NOTES.md"]
    assert findings[0].findings  # non-empty hidden-Unicode hits

    assert clean_file(str(tmp_path / "NOTES.md")) is True
    assert clean_file(str(tmp_path / "NOTES.md")) is False  # already clean now
    assert clean_file(str(tmp_path / "CLEAN.md")) is False
    assert scan_instruction_files(["*.md"], cwd=str(tmp_path)) == []


def test_sanitize_text_uses_shared_worker_for_html() -> None:
    sanitize_text(HIDDEN_HTML, html=True)
    assert ais._worker is not None and ais._worker.is_alive()


# ─── Robustness: framing, concurrency, death, DoS, error surfaces ─────────────


def test_blank_request_does_not_hang_and_framing_survives() -> None:
    # A blank request line must come back as a single structured error, never a
    # silent skip that leaves the client's readline waiting forever. We bound the
    # read so the unfixed worker (which skips the blank line, emitting nothing)
    # fails fast as a timeout instead of hanging the whole suite.
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(Sanitizer, "_READ_TIMEOUT_S", 8.0)
        with Sanitizer() as worker:
            # A literally blank request line: the worker must answer it (with a
            # structured error), not skip it and leave the read hanging.
            worker._proc.stdin.write("\n")
            worker._proc.stdin.flush()
            line = worker._read_response_line()
            assert line != ""
            assert "error" in json.loads(line)
            # Framing intact: a normal request right after still answers.
            assert worker.sanitize(f"a{ZERO_WIDTH_SPACE}b").cleaned == "ab"


def test_concurrent_threads_get_uncorrupted_responses() -> None:
    # Drive the SHARED persistent worker from many threads at once: the
    # per-request lock must serialize each write+read so no response is
    # interleaved with another's, and every thread gets exactly its own answer.
    inputs = [f"thread-{i}{ZERO_WIDTH_SPACE}" for i in range(40)]
    results: dict[int, str] = {}
    errors: list[Exception] = []
    barrier = threading.Barrier(len(inputs))

    def worker(i: int) -> None:
        try:
            barrier.wait()  # maximize contention: all fire together
            results[i] = sanitize(inputs[i], persist=True).cleaned
        except Exception as exc:  # noqa: BLE001 — collect for assertion
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(len(inputs))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    # Each thread's cleaned text must be exactly its own input minus the ZWS — a
    # corrupted/interleaved response would mismatch.
    assert results == {i: f"thread-{i}" for i in range(len(inputs))}


def test_killed_worker_includes_stderr_not_raw_ioerror() -> None:
    # A worker killed mid-use must raise a clear sanitizer error carrying its
    # stderr — never a bare ValueError/BrokenPipeError leaking I/O internals.
    with Sanitizer() as worker:
        worker._proc.kill()
        worker._proc.wait()
        with pytest.raises(RuntimeError, match="worker exited unexpectedly"):
            worker.sanitize("x")


def test_oversized_input_oneshot_raises_clear_error() -> None:
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("AGENT_SANITIZER_MAX_INPUT_BYTES", "100")
        with pytest.raises(RuntimeError, match="request too large"):
            sanitize("A" * 500, persist=False)


def test_oversized_input_worker_raises_clear_error() -> None:
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("AGENT_SANITIZER_MAX_INPUT_BYTES", "100")
        with Sanitizer() as worker:
            with pytest.raises(RuntimeError, match="request too large"):
                worker.sanitize("A" * 500)
            # Worker survives the oversized request and still serves.
            assert worker.sanitize("ok").cleaned == "ok"


def test_non_json_stdout_raises_wrapped_error() -> None:
    # A CLI (or fake) that prints non-JSON must surface as a clear sanitizer
    # error naming the offending output, not a bare json.JSONDecodeError.
    node = shutil.which("node")
    assert node is not None
    fake_cli = Path(tempfile.mkdtemp()) / "fake-cli.mjs"
    fake_cli.write_text(
        "process.stdin.resume();\nconsole.log('not json at all');\n",
        encoding="utf-8",
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(ais, "_CLI", fake_cli)
        with pytest.raises(RuntimeError, match="non-JSON output"):
            sanitize("x", persist=False)


# ─── CLI resolution: bundled wheel CLI, env-var override, source sibling ──────

REAL_CLI = REPO_ROOT / "bin" / "sanitize-cli.mjs"


def test_bundled_cli_used_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    # A pip-installed wheel has no source sibling but ships a bundled CLI. With
    # the env override unset, the bundled CLI is resolved and drives sanitization.
    # (The real source bin stands in for the bundle — this tests the resolution
    # precedence, which is what ships, not the bundling itself.)
    monkeypatch.setattr(ais, "_CLI", REPO_ROOT / "bin" / "does-not-exist.mjs")
    monkeypatch.setattr(ais, "_BUNDLED_CLI", REAL_CLI)
    monkeypatch.delenv("AGENT_SANITIZER_CLI", raising=False)
    assert ais._resolve_cli() == REAL_CLI
    assert sanitize(f"a{ZERO_WIDTH_SPACE}b").cleaned == "ab"


def test_bundled_cli_takes_precedence_over_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # When both a bundle and a source sibling exist, the bundle wins — an
    # installed wheel must not accidentally reach for an unrelated source tree.
    monkeypatch.setattr(ais, "_BUNDLED_CLI", REAL_CLI)
    monkeypatch.setattr(ais, "_CLI", REPO_ROOT / "bin" / "other-cli.mjs")
    monkeypatch.delenv("AGENT_SANITIZER_CLI", raising=False)
    assert ais._resolve_cli() == REAL_CLI


def test_env_var_overrides_bundled_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    # AGENT_SANITIZER_CLI is the top-priority escape hatch: it must win even over
    # a present bundled CLI (e.g. to run against unreleased src/ changes).
    monkeypatch.setattr(ais, "_BUNDLED_CLI", REPO_ROOT / "bin" / "does-not-exist.mjs")
    monkeypatch.setenv("AGENT_SANITIZER_CLI", str(REAL_CLI))
    assert ais._resolve_cli() == REAL_CLI
    assert sanitize(f"a{ZERO_WIDTH_SPACE}b").cleaned == "ab"


def test_cli_env_var_overrides_source_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    # A pip-installed package has no source sibling; AGENT_SANITIZER_CLI must
    # point the client at a JS checkout's CLI and take priority over _CLI.
    monkeypatch.setattr(ais, "_CLI", REPO_ROOT / "bin" / "does-not-exist.mjs")
    monkeypatch.setenv(
        "AGENT_SANITIZER_CLI", str(REPO_ROOT / "bin" / "sanitize-cli.mjs")
    )
    assert sanitize(f"a{ZERO_WIDTH_SPACE}b").cleaned == "ab"


def test_cli_env_var_missing_file_fails_with_both_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An env var pointing at a non-existent CLI fails loudly, and the message
    # names both ways to locate the CLI (env var + source checkout).
    monkeypatch.setenv("AGENT_SANITIZER_CLI", "/no/such/sanitize-cli.mjs")
    with pytest.raises(RuntimeError, match="sanitize CLI not found") as exc:
        sanitize("x")
    assert "AGENT_SANITIZER_CLI" in str(exc.value)
    assert "repo checkout" in str(exc.value)


# ─── Process lifecycle: fork, read-timeout, group-kill, atexit teardown ──────


def _write_fake_cli(body: str) -> Path:
    """Write a fake worker-mode CLI (a Node script) and return its path. Each
    gets its own temp dir so concurrent fakes never collide."""
    fake = Path(tempfile.mkdtemp()) / "fake-cli.mjs"
    fake.write_text(body, encoding="utf-8")
    return fake


def _pid_alive(pid: int) -> bool:
    """True iff `pid` names a live process (signal 0 probes without killing)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but not ours to signal
    return True


def test_fork_child_spawns_own_worker_parent_pipe_intact() -> None:
    # A real os.fork: the child inherits the parent's shared worker reference but
    # MUST NOT drive the parent's pipe. _shared_worker detects the pid mismatch
    # and spawns a worker the child owns; the parent's worker stays untouched.
    sanitize("warm-up", persist=True)
    parent_worker = ais._worker
    assert parent_worker is not None and parent_worker.is_alive()
    parent_node_pid = parent_worker._proc.pid

    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # child
        os.close(read_fd)
        code = 0
        try:
            result = sanitize(f"a{ZERO_WIDTH_SPACE}b", persist=True)
            child_worker = ais._worker
            # The child must have its OWN worker (a different Node process) and a
            # correct result; reusing the parent's pipe would desync or hang.
            own = (
                child_worker is not None
                and child_worker is not parent_worker
                and child_worker._proc.pid != parent_node_pid
                and child_worker._pid == os.getpid()
                and result.cleaned == "ab"
            )
            os.write(write_fd, str(child_worker._proc.pid).encode())
            code = 0 if own else 1
        except BaseException:  # noqa: BLE001 — child must never raise into pytest
            code = 2
        finally:
            os.close(write_fd)
            os._exit(code)

    # parent
    os.close(write_fd)
    child_worker_pid = int(os.read(read_fd, 32).decode() or "0")
    os.close(read_fd)
    _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    # The child's worker is a genuinely different Node process.
    assert child_worker_pid not in (0, parent_node_pid)
    # The parent's worker survived the fork untouched and still serves.
    assert ais._worker is parent_worker and parent_worker.is_alive()
    assert sanitize("still-here", persist=True).cleaned == "still-here"


def test_worker_read_timeout_terminates_and_raises() -> None:
    # A worker that reads a request but never replies must surface as a clear
    # "did not respond" timeout (not an unbounded hang), and be dead afterward.
    fake = _write_fake_cli(
        # Consume stdin line-by-line and deliberately never write a response.
        "import readline from 'node:readline';\n"
        "const rl = readline.createInterface({ input: process.stdin });\n"
        "rl.on('line', () => {});\n"
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(ais, "_CLI", fake)
        mp.setattr(Sanitizer, "_READ_TIMEOUT_S", 1.0)
        worker = Sanitizer().start()
        node_pid = worker._proc.pid
        with pytest.raises(RuntimeError, match="did not respond"):
            worker.sanitize("x")
        assert not worker.is_alive()
        # The real OS process was reaped by the timeout's _terminate_proc.
        worker._proc.wait()
        assert not _pid_alive(node_pid)
        worker.close()


def test_close_kills_grandchild_via_process_group() -> None:
    # close() must group-kill: a long-lived grandchild the worker spawned shares
    # the worker's process group (start_new_session) and must die with it.
    fake = _write_fake_cli(
        # Spawn a detached-but-same-group child that sleeps long and prints its
        # PID to stderr, then idle reading stdin so close()'s EOF doesn't race.
        "import { spawn } from 'node:child_process';\n"
        "import readline from 'node:readline';\n"
        "const child = spawn(process.execPath, "
        "['-e', 'setTimeout(() => {}, 600000)']);\n"
        "process.stderr.write('grandchild:' + child.pid + '\\n');\n"
        "readline.createInterface({ input: process.stdin }).on('line', () => {});\n"
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(ais, "_CLI", fake)
        worker = Sanitizer().start()
        node_pid = worker._proc.pid
        # Wait for the grandchild PID to appear on the worker's stderr temp file.
        deadline = time.monotonic() + 10
        grandchild_pid = None
        while time.monotonic() < deadline:
            text = worker._drain_stderr()
            match = re.search(r"grandchild:(?P<pid>\d+)", text)
            if match:
                grandchild_pid = int(match.group("pid"))
                break
            time.sleep(0.05)
        assert grandchild_pid is not None, "fake worker never reported a grandchild"
        assert _pid_alive(grandchild_pid)

        worker.close()
        # After close(), both the worker and its grandchild are gone.
        deadline = time.monotonic() + 10
        while _pid_alive(grandchild_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _pid_alive(grandchild_pid), "grandchild outlived close() group-kill"
        assert not _pid_alive(node_pid)


def test_atexit_teardown_reaps_real_node_process() -> None:
    # A process that starts the shared persistent worker and exits WITHOUT
    # calling shutdown_worker must still leave no Node process behind: the
    # atexit hook tears it down. We capture the real Node PID and assert it dies.
    node = shutil.which("node")
    assert node is not None
    script = (
        "import sys\n"
        f"sys.path.insert(0, {str(REPO_ROOT / 'python')!r})\n"
        "import agent_sanitizer as ais\n"
        "ais.sanitize('x', persist=True)\n"
        "print(ais._worker._proc.pid, flush=True)\n"
        # Exit without shutdown_worker(): only the atexit hook can reap it.
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )
    node_pid = int(proc.stdout.strip())
    # The child Python has exited; its atexit hook should have torn the worker
    # down. Give the OS a moment to reap, then assert the Node process is gone.
    deadline = time.monotonic() + 10
    while _pid_alive(node_pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _pid_alive(node_pid), "atexit hook left the Node worker running"


# ─── Cross-language golden: Python client byte-identical to the JS recording ──


def _from_units(units: list[int]) -> str:
    """Reconstruct a Python string from an array of UTF-16 code units, mirroring
    the JS generator's String.fromCharCode. Decoding the units as UTF-16-LE with
    ``surrogatepass`` combines surrogate pairs into the astral scalar while
    leaving a lone surrogate intact — so the input is byte-identical to the JS
    side (which a JSON string couldn't carry losslessly)."""
    raw = b"".join(u.to_bytes(2, "little") for u in units)
    return raw.decode("utf-16-le", "surrogatepass")


def _to_units(text: str) -> list[int]:
    """A Python string back to its UTF-16 code units (astral chars split into
    surrogate pairs), the same representation the JS generator recorded. Compared
    as units so an encoding mismatch can't hide behind a code-point compare."""
    raw = text.encode("utf-16-le", "surrogatepass")
    return [int.from_bytes(raw[i : i + 2], "little") for i in range(0, len(raw), 2)]


def _golden_cases() -> list[dict]:
    corpus = json.loads((REPO_ROOT / "tests" / "golden-corpus.json").read_text("utf-8"))
    golden = json.loads((REPO_ROOT / "tests" / "golden.json").read_text("utf-8"))
    # The JS golden test pins name-order equality of corpus⇄golden; rely on it
    # and zip so each Python case carries both the input and its recorded output.
    assert [c["name"] for c in corpus["cases"]] == [c["name"] for c in golden["cases"]]
    return [
        {"name": g["name"], "input": _from_units(c["units"]), "golden": g}
        for c, g in zip(corpus["cases"], golden["cases"])
    ]


_GOLDEN = _golden_cases()


@pytest.mark.parametrize("html", [False, True], ids=["plain", "html"])
@pytest.mark.parametrize("case", _GOLDEN, ids=[c["name"] for c in _GOLDEN])
def test_python_client_matches_js_golden(case: dict, html: bool) -> None:
    # The Python client and the JS `sanitize` share one source of truth (`src/`
    # via the CLI), so the client's output must equal the recorded JS output
    # byte-for-byte — including lone surrogates and astral chars, compared as
    # code units so an encoding mismatch can't hide behind a string compare.
    recorded = case["golden"]["html" if html else "plain"]
    result = sanitize(case["input"], html=html)
    assert _to_units(result.cleaned) == recorded["cleaned"], case["name"]
    assert result.found == recorded["found"], case["name"]
    assert result.warnings == recorded["warnings"], case["name"]
