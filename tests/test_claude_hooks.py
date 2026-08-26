"""Smoke tests for .claude/hooks/ scripts."""

import os
import subprocess
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT

SESSION_SETUP = REPO_ROOT / ".claude" / "hooks" / "session-setup.sh"


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    """Throwaway git repo containing a copy of session-setup.sh under
    .claude/hooks/. The script computes its project dir from $(dirname $0)/../..
    rather than $CLAUDE_PROJECT_DIR, so the script must live inside the
    sandbox for tests to operate on it."""
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    hooks_dir = tmp_path / ".claude" / "hooks"
    hooks_dir.mkdir(parents=True)
    script = hooks_dir / "session-setup.sh"
    script.write_bytes(SESSION_SETUP.read_bytes())
    script.chmod(0o755)
    return tmp_path


def set_remote(sandbox: Path, url: str) -> None:
    subprocess.run(["git", "remote", "add", "origin", url], cwd=sandbox, check=True)


# The install section of session-setup.sh installs tools via `go install` (shfmt)
# and apt-get (gh/jq/shellcheck), then shells out to uv/pnpm for deps. Left
# unstubbed, the smoke test would reach the network (non-hermetic, flaky, slow).
# Prepending a directory of these stubs to PATH neutralizes the whole section:
# the tool stubs (shfmt/gh/jq/shellcheck) make `command -v` succeed so their
# install branch is skipped, and the installer stubs (go/apt-get/uv/pnpm/npm) are
# local no-ops if anything still invokes them. The script then runs its
# git/GH_REPO logic — what these tests actually exercise — without a single
# outbound call. (This stands alone and does not depend on any script-side skip
# flag.)
_INERT_COMMANDS = (
    "go",
    "apt-get",
    "uv",
    "pnpm",
    "npm",
    "shfmt",
    "gh",
    "jq",
    "shellcheck",
)


def _write_installer_stubs(stub_dir: Path) -> Path:
    """Write exit-0 stubs for every network/installer command onto a dir that
    callers prepend to PATH; return the dir."""
    stub_dir.mkdir(parents=True, exist_ok=True)
    for name in _INERT_COMMANDS:
        stub = stub_dir / name
        stub.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        stub.chmod(0o755)
    return stub_dir


def run_session_setup(
    sandbox: Path,
    *,
    extra_env: dict[str, str] | None = None,
    scrub: tuple[str, ...] = (),
) -> tuple[Path, subprocess.CompletedProcess]:
    """Invoke session-setup.sh in the sandbox; return (env_file, result)."""
    env = {k: v for k, v in os.environ.items() if k not in scrub}
    env_file = sandbox / "claude.env"
    env_file.touch()
    env.update(
        {
            "CLAUDE_PROJECT_DIR": str(sandbox),
            "CLAUDE_ENV_FILE": str(env_file),
            "GH_TOKEN": "fake",
            # Isolate the script's `git remote get-url` from ambient git config.
            # Proxy environments (incl. this one's CI) register a global
            # `url.<proxy>.insteadOf = https://github.com/`, which rewrites the
            # github-https/ssh fixtures to the proxy form before the script sees
            # them — making GH_REPO extraction look like it fired on a plain
            # GitHub URL. Pinning config to /dev/null lets each fixture exercise
            # the regex against the literal URL it sets.
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
        }
    )
    if extra_env:
        env.update(extra_env)
    # Neutralize the install section: no outbound curl / apt-get / uv / pnpm.
    stub_dir = _write_installer_stubs(sandbox / "_installer_stubs")
    env["PATH"] = f"{stub_dir}{os.pathsep}{env.get('PATH', os.environ['PATH'])}"
    result = subprocess.run(
        ["bash", str(sandbox / ".claude" / "hooks" / "session-setup.sh")],
        env=env,
        capture_output=True,
        text=True,
    )
    return env_file, result


@pytest.mark.parametrize(
    "remote_url, expected",
    [
        (
            "http://local_proxy@127.0.0.1:18393/git/test-owner/test-repo",
            "test-owner/test-repo",
        ),
        (
            "http://local_proxy@127.0.0.1:18393/git/owner/repo.git",
            "owner/repo",
        ),
        ("https://github.com/owner/repo.git", None),
        ("https://evil.com/notgit/owner/repo", None),
        ("git@github.com:owner/repo.git", None),
    ],
    ids=["proxy", "proxy-with-.git", "github-https", "hostile-substring", "ssh"],
)
def test_gh_repo_extraction(
    sandbox: Path, remote_url: str, expected: str | None
) -> None:
    set_remote(sandbox, remote_url)
    env_file, result = run_session_setup(
        sandbox, scrub=("GH_REPO", "CLAUDE_CODE_BASE_REF")
    )
    assert result.returncode == 0, (
        f"session-setup.sh exited {result.returncode}\nstderr: {result.stderr}"
    )
    exports = [
        line
        for line in env_file.read_text(encoding="utf-8").splitlines()
        if line.startswith("export GH_REPO=")
    ]
    if expected is None:
        assert exports == [], f"expected no GH_REPO export, got: {exports}"
    else:
        assert exports == [f'export GH_REPO="{expected}"']


def test_preserves_pre_set_gh_repo(sandbox: Path) -> None:
    """Pre-existing $GH_REPO must not be overwritten by extraction."""
    set_remote(sandbox, "http://local_proxy@127.0.0.1:18393/git/other-owner/other-repo")
    env_file, result = run_session_setup(
        sandbox,
        extra_env={"GH_REPO": "preset/value"},
        scrub=("CLAUDE_CODE_BASE_REF",),
    )
    assert result.returncode == 0, result.stderr
    exports = [
        line
        for line in env_file.read_text(encoding="utf-8").splitlines()
        if line.startswith("export GH_REPO=")
    ]
    assert exports == []
