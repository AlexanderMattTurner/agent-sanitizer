"""Shared helpers used by multiple test modules.

Lives in a regular module (not `conftest.py`) so it can be imported directly
without manipulating `sys.path` or relying on the conftest plugin loader.
"""

import os
import shutil
import subprocess
from pathlib import Path

#: Git's own repository-location overrides. A git hook exports GIT_DIR (and
#: friends) into every child process, and with GIT_DIR set but no GIT_WORK_TREE
#: git treats the CURRENT DIRECTORY as the work tree — so `rev-parse
#: --show-toplevel` run from `tests/` answers `<repo>/tests`, not `<repo>`.
#: Under the pre-commit guard-pair runner that made REPO_ROOT wrong by one
#: directory for every pytest guard, and each one died on a FileNotFoundError
#: for a repo file it was reading. Stripping the overrides makes the lookup mean
#: "the repo this file lives in", which is what every caller wants.
_GIT_LOCATION_VARS = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_PREFIX",
)


def _repo_root() -> Path:
    env = {k: v for k, v in os.environ.items() if k not in _GIT_LOCATION_VARS}
    return Path(
        subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            check=True,
            env=env,
        ).stdout.strip()
    )


REPO_ROOT = _repo_root()

GIT_IDENTITY_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@t",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@t",
}


def git_env() -> dict[str, str]:
    """Environment for running git in test sandboxes."""
    return {**os.environ, **GIT_IDENTITY_ENV}


def init_test_repo(path: Path) -> None:
    """Init a throwaway repo with signing/hooks disabled so fixtures can commit
    in any environment (including CI runners with enforced commit signing)."""
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True)
    for k, v in [
        ("commit.gpgsign", "false"),
        ("tag.gpgsign", "false"),
        ("user.name", "t"),
        ("user.email", "t@t"),
        ("core.hooksPath", "/dev/null"),
    ]:
        subprocess.run(["git", "config", "--local", k, v], cwd=path, check=True)


def commit_all(repo: Path, message: str = "fixture") -> str:
    """Stage everything and create a commit; returns the resulting SHA."""
    env = git_env()
    subprocess.run(["git", "add", "-A"], cwd=repo, env=env, check=True)
    subprocess.run(
        ["git", "commit", "-q", "--allow-empty", "-m", message],
        cwd=repo,
        env=env,
        check=True,
    )
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return sha.stdout.strip()


_SCRIPT_DIRS = [
    REPO_ROOT / ".github" / "scripts",
    REPO_ROOT / ".claude" / "hooks",
    REPO_ROOT / ".hooks",
]


def copy_script_to(script_name: str, dest_dir: Path) -> Path:
    """Copy a repo script into `dest_dir`, preserving the executable bit."""
    for src_dir in _SCRIPT_DIRS:
        src = src_dir / script_name
        if src.exists():
            dest = dest_dir / script_name
            shutil.copy2(src, dest)
            dest.chmod(0o755)
            return dest
    raise FileNotFoundError(f"Could not find {script_name} in any known location")
