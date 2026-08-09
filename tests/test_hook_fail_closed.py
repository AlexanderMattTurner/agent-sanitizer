"""Invariant: git/Claude hooks fail CLOSED when a required tool is off PATH.

A hook that silently skips its check (exits 0) when jq/Node/a package manager is
missing turns a broken environment into a green light — the exact fail-open flaw
these tests guard against. Each test curates PATH down to a whitelist so a
specific dependency is genuinely absent, then asserts the hook refuses rather
than skips. Positive controls (the escape hatch works; the command gate skips
non-push commands) keep the suite from passing vacuously.
"""

import shutil
import subprocess
from pathlib import Path

from tests._helpers import REPO_ROOT

# Coreutils the hooks legitimately need; everything else is "absent" unless a
# test opts it back in. printf/pwd/cd/command/[[ are bash builtins (always
# available), so they are intentionally not listed here.
BASE_TOOLS = [
    "bash", "sh", "git", "cat", "grep", "sed", "awk", "tr", "head", "cut",
    "dirname", "basename", "env", "mktemp", "rm", "xargs", "find", "id",
]  # fmt: skip


def curated_path(tmp_path: Path, allow: list[str]) -> str:
    """A PATH containing symlinks to only the allowed real tools."""
    bindir = tmp_path / "curated-bin"
    bindir.mkdir(exist_ok=True)
    for name in allow:
        real = shutil.which(name)
        if real and not (bindir / name).exists():
            (bindir / name).symlink_to(real)
    return str(bindir)


def base_env(path: str) -> dict[str, str]:
    return {
        "PATH": path,
        "HOME": "/nonexistent",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }


def init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    # Every .hooks/ hook sources lib-gate.sh relative to the sandbox's own git
    # root, not to the hook's own path, so the helper has to exist here even
    # when the hook under test is invoked from REPO_ROOT.
    hooks = repo / ".hooks"
    hooks.mkdir()
    shutil.copy(REPO_ROOT / ".hooks" / "lib-gate.sh", hooks)
    return repo


# --------------------------------------------------------------------------- #
# commit-msg: no Node → refuse (K5), unless the explicit escape hatch is set.
# --------------------------------------------------------------------------- #


def test_commit_msg_fails_closed_without_node(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    msg = repo / "msg.txt"
    msg.write_text("feat(scope): a perfectly valid conventional subject\n")
    path = curated_path(tmp_path, BASE_TOOLS)  # no node/pnpm/npm/npx
    result = subprocess.run(
        ["bash", str(REPO_ROOT / ".hooks" / "commit-msg"), str(msg)],
        cwd=repo,
        env=base_env(path),
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, "commit-msg must refuse when it cannot validate"
    assert "refusing" in result.stderr.lower()


def test_commit_msg_escape_hatch_allows_skip(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    msg = repo / "msg.txt"
    msg.write_text("anything at all\n")
    path = curated_path(tmp_path, BASE_TOOLS)
    result = subprocess.run(
        ["bash", str(REPO_ROOT / ".hooks" / "commit-msg"), str(msg)],
        cwd=repo,
        env={**base_env(path), "ALLOW_UNLINTED_COMMITS": "1"},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


# --------------------------------------------------------------------------- #
# pre-push-check: Node project without jq → refuse (K3); non-push command is
# skipped by the stdin gate (K4).
# --------------------------------------------------------------------------- #


def _sandbox_pre_push_check(tmp_path: Path) -> Path:
    repo = init_repo(tmp_path)
    (repo / "package.json").write_text('{"scripts":{"build":"echo build"}}\n')
    hooks = repo / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    for name in ("pre-push-check.sh", "lib-checks.sh"):
        dst = hooks / name
        dst.write_bytes((REPO_ROOT / ".claude" / "hooks" / name).read_bytes())
        dst.chmod(0o755)
    return repo


def _run_pre_push_check(
    repo: Path, path: str, stdin: str
) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(repo / ".claude" / "hooks" / "pre-push-check.sh")],
        cwd=repo,
        env={**base_env(path), "CLAUDE_PROJECT_DIR": str(repo)},
        input=stdin,
        capture_output=True,
        text=True,
    )


def test_pre_push_check_fails_closed_without_jq(tmp_path: Path) -> None:
    repo = _sandbox_pre_push_check(tmp_path)
    # python3 present so the gate recognizes "git push"; jq absent so the
    # package.json script lookup has no parser and must fail closed.
    path = curated_path(tmp_path, BASE_TOOLS + ["python3"])
    result = _run_pre_push_check(
        repo, path, '{"tool_input":{"command":"git push origin HEAD"}}'
    )
    assert result.returncode != 0, "must refuse when jq is missing on a Node project"
    assert "jq is required" in result.stderr


def test_pre_push_check_gate_skips_non_push(tmp_path: Path) -> None:
    repo = _sandbox_pre_push_check(tmp_path)
    path = curated_path(tmp_path, BASE_TOOLS + ["python3"])  # jq still absent
    result = _run_pre_push_check(repo, path, '{"tool_input":{"command":"ls -la"}}')
    # A non-push command exits 0 without ever reaching the (jq-guarded) checks —
    # proves the gate fires and that fail-closed only applies to gated commands.
    assert result.returncode == 0, result.stderr


# --------------------------------------------------------------------------- #
# pre-commit: neither pnpm nor npm on PATH → run the lint-staged binary directly
# rather than skipping (K6).
# --------------------------------------------------------------------------- #


def test_pre_commit_runs_lint_staged_directly_without_package_manager(
    tmp_path: Path,
) -> None:
    repo = init_repo(tmp_path)
    (repo / "package.json").write_text("{}\n")
    binp = repo / "node_modules" / ".bin"
    binp.mkdir(parents=True)
    marker = tmp_path / "lint-staged-ran"
    fake = binp / "lint-staged"
    fake.write_text(f'#!/bin/bash\necho ran > "{marker}"\nexit 0\n')
    fake.chmod(0o755)
    (repo / "a.txt").write_text("hello\n")
    subprocess.run(["git", "add", "a.txt"], cwd=repo, check=True)
    path = curated_path(tmp_path, BASE_TOOLS)  # no pnpm/npm
    result = subprocess.run(
        ["bash", str(REPO_ROOT / ".hooks" / "pre-commit")],
        cwd=repo,
        env=base_env(path),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert marker.exists() and marker.read_text().strip() == "ran", (
        "pre-commit must invoke the lint-staged binary directly, not skip"
    )


# --------------------------------------------------------------------------- #
# pre-commit: lint-staged absent in a NODE project → refuse the commit (K7); a
# repo with no package.json has no lint-staged gate to run and passes.
# --------------------------------------------------------------------------- #


def test_pre_commit_fails_closed_when_lint_staged_missing(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    (repo / "package.json").write_text("{}\n")
    (repo / "a.txt").write_text("hello\n")
    subprocess.run(["git", "add", "a.txt"], cwd=repo, check=True)
    path = curated_path(tmp_path, BASE_TOOLS)  # no node_modules in repo at all
    result = subprocess.run(
        ["bash", str(REPO_ROOT / ".hooks" / "pre-commit")],
        cwd=repo,
        env=base_env(path),
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, (
        "a Node project whose lint/format gate cannot run must refuse the commit"
    )
    assert "lint-staged" in result.stderr
    assert "pnpm install" in result.stderr


def test_pre_commit_passes_without_package_json(tmp_path: Path) -> None:
    # Positive control for the test above: the refusal comes from "Node project
    # with a broken gate", not from "no lint-staged binary" on its own.
    repo = init_repo(tmp_path)
    (repo / "a.txt").write_text("hello\n")
    subprocess.run(["git", "add", "a.txt"], cwd=repo, check=True)
    path = curated_path(tmp_path, BASE_TOOLS)
    result = subprocess.run(
        ["bash", str(REPO_ROOT / ".hooks" / "pre-commit")],
        cwd=repo,
        env=base_env(path),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


# --------------------------------------------------------------------------- #
# pre-commit: staged SSOT source runs its paired guard test and blocks the
# commit when the guard fails (map: .hooks/guard-pairs.json).
# --------------------------------------------------------------------------- #


def _sandbox_ssot_repo(tmp_path: Path, guard_body: str) -> Path:
    repo = init_repo(tmp_path)
    binp = repo / "node_modules" / ".bin"
    binp.mkdir(parents=True)
    fake = binp / "lint-staged"
    fake.write_text("#!/bin/bash\nexit 0\n")
    fake.chmod(0o755)
    hooks = repo / ".hooks"
    shutil.copy(REPO_ROOT / ".hooks" / "run-guard-pairs.mjs", hooks)
    (hooks / "guard-pairs.json").write_text(
        '{"pairs": {"data.json": ["guard.test.mjs"]}}'
    )
    (repo / "guard.test.mjs").write_text(guard_body)
    (repo / "data.json").write_text("{}\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    return repo


def _run_pre_commit_ssot(repo: Path, tmp_path: Path) -> subprocess.CompletedProcess:
    # node for the guard runner; no pnpm/npm so lint-staged (a stub) runs via
    # the direct-binary branch, keeping the test about the SSOT guard wiring.
    path = curated_path(tmp_path, BASE_TOOLS + ["node"])
    return subprocess.run(
        ["bash", str(REPO_ROOT / ".hooks" / "pre-commit")],
        cwd=repo,
        env=base_env(path),
        capture_output=True,
        text=True,
    )


def test_pre_commit_blocks_when_paired_ssot_guard_fails(tmp_path: Path) -> None:
    repo = _sandbox_ssot_repo(
        tmp_path,
        'import { test } from "node:test";\n'
        'import assert from "node:assert";\n'
        'test("guard", () => assert.fail("contract broken"));\n',
    )
    result = _run_pre_commit_ssot(repo, tmp_path)
    assert result.returncode != 0, (
        "a failing paired guard test must block the commit\n" + result.stderr
    )
    assert "SSOT guard test failed" in result.stderr


def test_pre_commit_passes_when_paired_ssot_guard_passes(tmp_path: Path) -> None:
    # Positive control: same wiring, green guard — proves the block above comes
    # from the guard's verdict, not from broken plumbing.
    repo = _sandbox_ssot_repo(
        tmp_path,
        'import { test } from "node:test";\ntest("guard", () => {});\n',
    )
    result = _run_pre_commit_ssot(repo, tmp_path)
    assert result.returncode == 0, result.stderr
    assert "running paired guard test" in result.stderr
