"""Tests for .github/scripts/check-token-scope.sh scope validation logic.

The required-env smoke test (test_required_env.py) only checks that the script
exits non-zero when TOKEN is unset. This module covers the actual scope-check
behaviour by injecting a fake `curl` that returns controlled header output.
"""

import os
import subprocess
from pathlib import Path

from tests._helpers import REPO_ROOT

SCRIPT = REPO_ROOT / ".github" / "scripts" / "check-token-scope.sh"


def run_scope_check(
    tmp_path: Path, headers: list[str], curl_exit: int = 0
) -> subprocess.CompletedProcess:
    """Run check-token-scope.sh with a fake curl that emits the given headers."""
    echo_lines = "\n".join(f"echo {h!r}" for h in headers)
    fake_curl = tmp_path / "curl"
    fake_curl.write_text(
        f"#!/usr/bin/env bash\n{echo_lines}\nexit {curl_exit}\n", encoding="utf-8"
    )
    fake_curl.chmod(0o755)
    env = {
        **os.environ,
        "TOKEN": "fake-token",
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
    }
    return subprocess.run(
        ["bash", str(SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
    )


def test_passes_for_fine_grained_pat(tmp_path: Path) -> None:
    """Fine-grained PATs expose no x-oauth-scopes header → skip check, exit 0."""
    result = run_scope_check(tmp_path, ["HTTP/2 200", "content-type: application/json"])
    assert result.returncode == 0
    assert "skipping" in result.stdout.lower()


def test_passes_for_classic_pat_with_workflow_scope(tmp_path: Path) -> None:
    """Classic PAT with 'workflow' in x-oauth-scopes → exit 0."""
    result = run_scope_check(
        tmp_path,
        ["HTTP/2 200", "x-oauth-scopes: repo, workflow, read:org"],
    )
    assert result.returncode == 0
    assert "workflow" in result.stdout.lower()


def test_fails_for_classic_pat_missing_workflow_scope(tmp_path: Path) -> None:
    """Classic PAT without 'workflow' scope → exit non-zero with clear error."""
    result = run_scope_check(
        tmp_path,
        ["HTTP/2 200", "x-oauth-scopes: repo, read:org"],
    )
    assert result.returncode != 0
    assert "workflow" in result.stdout + result.stderr


def test_fails_when_curl_errors(tmp_path: Path) -> None:
    """Network failure from curl → exit non-zero (must not silently pass)."""
    result = run_scope_check(
        tmp_path,
        ["curl: (6) Could not resolve host: api.github.com"],
        curl_exit=6,
    )
    assert result.returncode != 0
