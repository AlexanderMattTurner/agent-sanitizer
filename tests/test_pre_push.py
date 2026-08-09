"""Tests for .hooks/pre-push.

The hook shells out to pre-commit, so every test replaces `uvx` with a stub that
records its argv and exits with a caller-chosen code. The stub also proves the
hook never spawns pre-commit at all on the paths that should short-circuit.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT, commit_all, init_test_repo

ZERO = "0" * 40
WORKFLOW = Path(".github/workflows/pre-commit.yaml")

FAKE_UVX = """#!/bin/bash
printf '%s\\n' "$*" >>"$UVX_LOG"
printf 'stub pre-commit output\\n'
exit "${UVX_RC:-0}"
"""


def live_pin_and_python() -> tuple[str, str]:
    """The pre-commit pin and Python version CI actually runs, read
    independently of the hook's own parser."""
    text = (REPO_ROOT / WORKFLOW).read_text()
    line = next(ln for ln in text.splitlines() if "pre-commit==" in ln)
    pin = re.search(r"pre-commit==(?P<pin>[0-9][0-9.]*)", line)
    python_version = re.search(r"--python (?P<version>[0-9][0-9.]*)", line)
    assert pin and python_version, f"no pin/--python in {WORKFLOW}: {line!r}"
    return pin.group(1), python_version.group(1)


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    """Repo with two commits, the real hook, the real workflow, and a uvx stub."""
    repo = tmp_path / "repo"
    init_test_repo(repo)
    commit_all(repo, "base")
    commit_all(repo, "head")

    hooks = repo / ".hooks"
    hooks.mkdir()
    # The hook and the library it sources ship together: pre-push resolves
    # lib-gate.sh by its OWN path, so a sandbox holding only pre-push makes it
    # die at the `source` line before running anything it is being tested for.
    for name in ("pre-push", "lib-gate.sh"):
        shutil.copy2(REPO_ROOT / ".hooks" / name, hooks / name)
    (hooks / "pre-push").chmod(0o755)

    workflow = repo / WORKFLOW
    workflow.parent.mkdir(parents=True)
    shutil.copy2(REPO_ROOT / WORKFLOW, workflow)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "uvx").write_text(FAKE_UVX)
    (fake_bin / "uvx").chmod(0o755)
    (tmp_path / "home").mkdir()
    return repo


def run_hook(sandbox: Path, refs: str, uvx_rc: int = 0) -> subprocess.CompletedProcess:
    tmp_path = sandbox.parent
    env = {
        **os.environ,
        "HOME": str(tmp_path / "home"),
        "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}",
        "UVX_LOG": str(tmp_path / "uvx.log"),
        "UVX_RC": str(uvx_rc),
    }
    return subprocess.run(
        ["bash", str(sandbox / ".hooks" / "pre-push")],
        cwd=sandbox,
        input=refs,
        env=env,
        capture_output=True,
        text=True,
    )


def uvx_calls(sandbox: Path) -> list[str]:
    log = sandbox.parent / "uvx.log"
    return log.read_text().splitlines() if log.exists() else []


def rev(repo: Path, ref: str) -> str:
    return subprocess.run(
        ["git", "rev-parse", ref], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()


def test_branch_push_runs_precommit_with_cis_pin(sandbox: Path) -> None:
    pin, python_version = live_pin_and_python()
    base, head = rev(sandbox, "HEAD~1"), rev(sandbox, "HEAD")
    result = run_hook(sandbox, f"refs/heads/topic {head} refs/heads/topic {base}\n")
    assert result.returncode == 0, result.stderr
    assert uvx_calls(sandbox) == [
        f"--python {python_version} --from pre-commit=={pin} pre-commit run "
        f"--from-ref {base} --to-ref {head} --show-diff-on-failure"
    ]


def test_tag_push_skips_precommit(sandbox: Path) -> None:
    """A tag adds no commits; running the suite would rebuild every hook env to
    re-lint history that already passed on its branch."""
    head = rev(sandbox, "HEAD")
    # uvx_rc=1 so an accidental invocation fails the test loudly.
    result = run_hook(sandbox, f"refs/tags/v2.0.0 {head} refs/tags/v2.0.0 {ZERO}\n", 1)
    assert result.returncode == 0, result.stderr
    assert uvx_calls(sandbox) == []


def test_branch_deletion_skips_precommit(sandbox: Path) -> None:
    result = run_hook(
        sandbox, f"(delete) {ZERO} refs/heads/topic {rev(sandbox, 'HEAD')}\n", 1
    )
    assert result.returncode == 0, result.stderr
    assert uvx_calls(sandbox) == []


def test_every_pushed_ref_is_checked(sandbox: Path) -> None:
    """pre-commit must not swallow the ref list git feeds the loop on stdin."""
    base, head = rev(sandbox, "HEAD~1"), rev(sandbox, "HEAD")
    result = run_hook(
        sandbox,
        f"refs/heads/a {head} refs/heads/a {base}\n"
        f"refs/heads/b {head} refs/heads/b {base}\n",
    )
    assert result.returncode == 0, result.stderr
    assert len(uvx_calls(sandbox)) == 2


def test_provisioning_failure_skips_instead_of_blocking(sandbox: Path) -> None:
    """pre-commit exits 3 when it cannot build a hook environment — a blocked
    network, not a lint failure, so it must not strand the push."""
    base, head = rev(sandbox, "HEAD~1"), rev(sandbox, "HEAD")
    result = run_hook(sandbox, f"refs/heads/topic {head} refs/heads/topic {base}\n", 3)
    assert result.returncode == 0, result.stderr
    assert "PROVISION" in result.stderr
    assert len(uvx_calls(sandbox)) == 1


def test_missing_precommit_skips_loudly_instead_of_blocking(sandbox: Path) -> None:
    """Neither uvx nor pre-commit on PATH is a machine that CANNOT run the suite,
    not a machine hiding a failure — and this repo's own format/dist autofix jobs
    push from exactly such runners, so refusing here strands every autofix."""
    tmp_path = sandbox.parent
    bare_bin = tmp_path / "bare-bin"
    bare_bin.mkdir()
    for name in ("bash", "git", "grep", "sed", "cat", "printf"):
        real = shutil.which(name)
        if real:
            (bare_bin / name).symlink_to(real)
    base, head = rev(sandbox, "HEAD~1"), rev(sandbox, "HEAD")
    result = subprocess.run(
        ["bash", str(sandbox / ".hooks" / "pre-push")],
        cwd=sandbox,
        input=f"refs/heads/topic {head} refs/heads/topic {base}\n",
        env={"HOME": str(tmp_path / "home"), "PATH": str(bare_bin)},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "SKIPPING" in result.stderr
    assert "CI still enforces the suite" in result.stderr


def test_lint_failure_aborts_the_push(sandbox: Path) -> None:
    base, head = rev(sandbox, "HEAD~1"), rev(sandbox, "HEAD")
    result = run_hook(sandbox, f"refs/heads/topic {head} refs/heads/topic {base}\n", 1)
    assert result.returncode == 1
    assert "stub pre-commit output" in result.stdout


def test_unparseable_workflow_is_fatal(sandbox: Path) -> None:
    """A silent fallback to an unpinned pre-commit is the drift the parser
    exists to prevent, so an unrecognised run line must fail loudly."""
    (sandbox / WORKFLOW).write_text("jobs:\n  pre-commit:\n    run: pre-commit run\n")
    base, head = rev(sandbox, "HEAD~1"), rev(sandbox, "HEAD")
    result = run_hook(sandbox, f"refs/heads/topic {head} refs/heads/topic {base}\n")
    assert result.returncode == 1
    assert "changed shape" in result.stderr
    assert uvx_calls(sandbox) == []
