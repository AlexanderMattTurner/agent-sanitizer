"""`tests._helpers.REPO_ROOT` must survive a git hook's exported environment.

A git hook exports `GIT_DIR` into every process it spawns. With `GIT_DIR` set
and no `GIT_WORK_TREE`, git treats the *current directory* as the work tree, so
`git rev-parse --show-toplevel` run from `tests/` answers `<repo>/tests` — one
directory too deep.

That is not hypothetical: `.hooks/run-guard-pairs.mjs` runs a paired pytest
guard from inside the `pre-commit` hook, and every guard that reads a repo file
through `REPO_ROOT` died there on `FileNotFoundError: <repo>/tests/<file>` while
passing in ordinary CI. A guard that cannot run in the hook is a guard that only
catches the drift it was written to block *after* the commit lands — which is
the whole failure mode the guard-pair map exists to close.

This pins the fix behaviorally (resolve with the hook's variables set), not by
grepping `_helpers.py` for an env-stripping idiom that a refactor could rename.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT

pytestmark = pytest.mark.drift_guard

# Resolve REPO_ROOT in a fresh interpreter, so the module-level constant is
# computed under the environment this test sets rather than reused from import.
_RESOLVE = "from tests._helpers import REPO_ROOT; print(REPO_ROOT)"


def _resolve_with(env: dict[str, str], cwd: Path) -> str:
    return subprocess.run(
        [sys.executable, "-c", _RESOLVE],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def test_repo_root_is_the_repo_not_the_tests_directory() -> None:
    """Sanity: the constant every guard reads points at the repo itself."""
    assert (REPO_ROOT / "package.json").is_file(), (
        f"REPO_ROOT={REPO_ROOT} does not contain package.json, so every guard "
        f"reading a repo file through it is resolving against the wrong root"
    )


@pytest.mark.parametrize("run_from", ["repo root", "tests dir"])
def test_repo_root_survives_a_hooks_git_dir(run_from: str) -> None:
    """The regression: GIT_DIR exported, resolved from both plausible cwds."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT)
    env["GIT_DIR"] = str(REPO_ROOT / ".git")
    cwd = REPO_ROOT if run_from == "repo root" else REPO_ROOT / "tests"

    resolved = _resolve_with(env, cwd)
    assert Path(resolved) == REPO_ROOT, (
        f"with GIT_DIR set and cwd={cwd}, REPO_ROOT resolved to {resolved!r} "
        f"instead of {REPO_ROOT} — this is exactly what breaks every pytest "
        f"guard run from the pre-commit hook"
    )


def test_the_hazard_is_real_without_the_fix() -> None:
    """Non-vacuity: prove the environment above actually misleads raw git.

    Without this, the test could keep passing after the fix was removed and the
    hazard silently stopped applying (a future git that ignores GIT_DIR here) —
    a guard asserting a property nothing threatens.
    """
    env = dict(os.environ)
    env["GIT_DIR"] = str(REPO_ROOT / ".git")
    misled = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=REPO_ROOT / "tests",
        env=env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert Path(misled) == REPO_ROOT / "tests", (
        "a bare `git rev-parse --show-toplevel` under an exported GIT_DIR no "
        "longer reports the cwd as the work tree, so the env-stripping in "
        "tests/_helpers.py may now be guarding nothing — re-check before "
        "deleting it"
    )
