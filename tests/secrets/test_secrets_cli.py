"""Tests for the one-shot CLI (agent_sanitizer.secrets.cli)."""

import io
import json

from agent_sanitizer.secrets import cli


def _run(argv, text, monkeypatch):
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(text))
    out = io.StringIO()
    monkeypatch.setattr(cli.sys, "stdout", out)
    cli.main(argv)
    raw = out.getvalue()
    return json.loads(raw) if raw.strip() else None


def test_cli_plain_redaction(monkeypatch):
    result = _run([], "key: AKIAIOSFODNN7EXAMPLE", monkeypatch)
    assert result["text"] == "key: [REDACTED: AWS Access Key]"
    assert "AWS Access Key" in result["found"]


def test_cli_clean_input_emits_nothing(monkeypatch):
    assert _run([], "just prose here", monkeypatch) is None


def test_cli_map_mode(monkeypatch):
    result = _run(["--map"], "password: SuperSecretP4ssword123456", monkeypatch)
    assert result["pairs"][0]["original"] == "SuperSecretP4ssword123456"
    assert result["pairs"][0]["placeholder"] == "[REDACTED]"


def test_cli_web_ingress_flag(monkeypatch):
    result = _run(["--web-ingress"], "next_token: abcdefghij1234567890XYZ", monkeypatch)
    assert result is not None and "[REDACTED" in result["text"]
    assert "abcdefghij1234567890XYZ" not in result["text"]


def test_cli_high_confidence_drops_keyword(monkeypatch):
    assert (
        _run(["--high-confidence"], "password: hunter2longplaintextvalue", monkeypatch)
        is None
    )


def test_cli_env_secret_reads_process_env(monkeypatch):
    value = "qZ7vK2mNp9rT4wX1cY6bA8dF3gH5jL0e"
    monkeypatch.setenv("MY_SECRET_VAR", value)
    result = _run(["--env-secret", "MY_SECRET_VAR"], f"leaked {value}", monkeypatch)
    assert value not in result["text"]
    assert "MY_SECRET_VAR" in result["found"]


def test_cli_env_secret_absent_var_ignored(monkeypatch):
    monkeypatch.delenv("NOPE_VAR", raising=False)
    assert _run(["--env-secret", "NOPE_VAR"], "just prose", monkeypatch) is None
