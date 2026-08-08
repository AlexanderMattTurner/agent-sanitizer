"""Smoke tests: every new GitHub-glue script must exit non-zero (with a clear
message) when a required env var is unset. This catches the regression where
a workflow change silently drops an env var, leaving the script to misbehave
on an empty value."""

import subprocess
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT

SCRIPTS = REPO_ROOT / ".github" / "scripts"

# (script, required env vars, vars to scrub from inherited environment)
CASES = [
    # check-token-scope.sh requires TOKEN
    ("check-token-scope.sh", ["TOKEN"]),
    # template-sync.sh requires GITHUB_OUTPUT
    ("template-sync.sh", ["GITHUB_OUTPUT"]),
]


@pytest.mark.parametrize("script, required_vars", CASES, ids=[c[0] for c in CASES])
def test_script_exits_when_required_var_missing(
    tmp_path: Path, script: str, required_vars: list[str]
) -> None:
    # Run with all required vars scrubbed so the script's `${VAR:?…}` guard fires.
    env = {"PATH": "/usr/bin:/bin"}
    result = subprocess.run(
        ["bash", str(SCRIPTS / script)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, (
        f"{script} should exit non-zero with no env vars set, got 0"
    )
    # The unset variable should appear in stderr (bash's `${VAR:?msg}` syntax
    # prints "VAR: msg" — at minimum one of the required names must be cited).
    err = result.stderr
    assert any(var in err for var in required_vars), (
        f"{script} stderr should mention one of {required_vars}: {err}"
    )
