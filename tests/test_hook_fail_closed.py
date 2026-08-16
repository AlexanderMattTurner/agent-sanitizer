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

from tests._helpers import REPO_ROOT, env_without_git_location

# Coreutils the hooks legitimately need; everything else is "absent" unless a
# test opts it back in. printf/pwd/cd/command/[[ are bash builtins (always
# available), so they are intentionally not listed here.
BASE_TOOLS = [
    "bash", "sh", "git", "cat", "grep", "sed", "awk", "tr", "head", "cut",
    "dirname", "basename", "env", "mktemp", "rm", "xargs", "find", "id",
]  # fmt: skip


def git(repo: Path, *args: str) -> None:
    """Run git against the SANDBOX repo, never the one this suite runs inside.

    The repo-location overrides have to be stripped: the pre-commit hook exports
    GIT_DIR into every child, and with GIT_DIR set `cwd=` stops deciding which
    repository git answers for. These sandboxes commit and stage, so an inherited
    GIT_DIR writes those commits into the developer's own checkout.
    """
    subprocess.run(["git", *args], cwd=repo, check=True, env=env_without_git_location())


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


def init_repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir(parents=True)
    git(repo, "init", "-q")
    # A CI runner has no global git identity, so a sandbox that commits (the
    # staged-deletion cases seed a commit first) dies with "empty ident name"
    # there while passing on any developer machine.
    for key, value in (("user.email", "test@example.com"), ("user.name", "Test")):
        git(repo, "config", key, value)
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
    git(repo, "add", "a.txt")
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
    git(repo, "add", "a.txt")
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
    git(repo, "add", "a.txt")
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
# pre-commit: a staged guarded source runs its paired guard test and blocks the
# commit when the guard fails (map: .hooks/guard-pairs.json).
# --------------------------------------------------------------------------- #


def _sandbox_guarded_repo(
    tmp_path: Path,
    guard_body: str,
    *,
    pairs: str = '{"data.json": ["guard.test.mjs"]}',
    too_slow: str = "{}",
    stage: tuple[str, ...] = ("data.json",),
    with_acorn: bool = True,
) -> Path:
    repo = init_repo(tmp_path)
    binp = repo / "node_modules" / ".bin"
    binp.mkdir(parents=True)
    fake = binp / "lint-staged"
    fake.write_text("#!/bin/bash\nexit 0\n")
    fake.chmod(0o755)
    hooks = repo / ".hooks"
    shutil.copy(REPO_ROOT / ".hooks" / "run-guard-pairs.mjs", hooks)
    # The runner DERIVES its pairs by parsing the repo's suites, so the scan and
    # the acorn it parses with have to come along. Without them the hook would
    # refuse every commit here for a missing dependency and these tests would
    # pass for the wrong reason — which is why the sandbox mirrors the real
    # dependency instead of stubbing the scan out.
    shutil.copytree(REPO_ROOT / ".hooks" / "lib", hooks / "lib")
    if with_acorn:
        (repo / "node_modules" / "acorn").symlink_to(
            REPO_ROOT / "node_modules" / "acorn"
        )
    (hooks / "guard-pairs.json").write_text(
        f'{{"pairs": {pairs}, "tooSlowForCommit": {too_slow}}}'
    )
    (repo / "guard.test.mjs").write_text(guard_body)
    (repo / "data.json").write_text("{}\n")
    # Stage ONLY the guarded source by default, never `git add -A`. Staging the
    # suite too would schedule it through the runner's "a staged suite is its
    # own guard" rule before `pairs` is consulted at all, and both the failing
    # case and its positive control would pass with `pairs` emptied — the
    # pairing path, which is the only thing these two tests cover, would be
    # asserting nothing. The suite does not need to be tracked: the runner
    # executes it by path.
    git(repo, "add", "--", *stage)
    return repo


def _run_pre_commit_guarded(repo: Path, tmp_path: Path) -> subprocess.CompletedProcess:
    # node for the guard runner; no pnpm/npm so lint-staged (a stub) runs via
    # the direct-binary branch, keeping the test about the guard-pair wiring.
    path = curated_path(tmp_path, BASE_TOOLS + ["node"])
    return subprocess.run(
        ["bash", str(REPO_ROOT / ".hooks" / "pre-commit")],
        cwd=repo,
        env=base_env(path),
        capture_output=True,
        text=True,
    )


def test_pre_commit_blocks_when_paired_guard_fails(tmp_path: Path) -> None:
    repo = _sandbox_guarded_repo(
        tmp_path,
        'import { test } from "node:test";\n'
        'import assert from "node:assert";\n'
        'test("guard", () => assert.fail("contract broken"));\n',
    )
    result = _run_pre_commit_guarded(repo, tmp_path)
    assert result.returncode != 0, (
        "a failing paired guard test must block the commit\n" + result.stderr
    )
    assert "paired guard test failed" in result.stderr


def test_pre_commit_passes_when_paired_guard_passes(tmp_path: Path) -> None:
    # Positive control: same wiring, green guard — proves the block above comes
    # from the guard's verdict, not from broken plumbing.
    repo = _sandbox_guarded_repo(
        tmp_path,
        'import { test } from "node:test";\ntest("guard", () => {});\n',
    )
    result = _run_pre_commit_guarded(repo, tmp_path)
    assert result.returncode == 0, result.stderr
    # Both operator-facing strings are pinned, not just the one this rename left
    # alone: matching only "running paired guard test" would stay green through a
    # revert of "staged guarded source(s)". ASCII-only on purpose — `text=True`
    # decodes stderr with the locale codec, so matching the em dash is fragile.
    assert "staged guarded source(s)" in result.stderr
    assert "running paired guard test" in result.stderr


FAILING_GUARD = (
    'import { test } from "node:test";\n'
    'import assert from "node:assert";\n'
    'test("guard", () => assert.fail("contract broken"));\n'
)
PASSING_GUARD = 'import { test } from "node:test";\ntest("guard", () => {});\n'

# A failing guard that NAMES data.json in a form the scan resolves, so it is
# paired by derivation rather than by the map. The path is only bound, never
# read: the case that uses this deletes the file.
DERIVED_FAILING_GUARD = (
    'import { test } from "node:test";\n'
    'import assert from "node:assert";\n'
    'import { join } from "node:path";\n'
    'const DATA = join(import.meta.dirname, "data.json");\n'
    'test("guard", () => assert.fail(`contract broken: ${DATA}`));\n'
)


def test_pre_commit_runs_a_staged_suite_as_its_own_guard(tmp_path: Path) -> None:
    """A staged test file is scheduled even when nothing pairs it.

    Nothing else covers an edit to a suite, so the runner treats one as its own
    guard. `pairs` is emptied here so the schedule can only have come from that
    rule — with the map consulted, this would pass either way.
    """
    repo = _sandbox_guarded_repo(
        tmp_path, FAILING_GUARD, pairs="{}", stage=("guard.test.mjs",)
    )
    result = _run_pre_commit_guarded(repo, tmp_path)
    assert result.returncode != 0, (
        "a staged suite must run itself\n" + result.stderr + result.stdout
    )
    assert "paired guard test failed" in result.stderr


def test_pre_commit_does_not_schedule_a_deleted_suite(tmp_path: Path) -> None:
    """Removing a test must not be un-committable.

    `git rm` stages a path that is gone from the working tree; scheduling it
    would run `node --test` on a missing file and fail the very commit that
    removes it. Positive control above proves the staged-suite rule is live, so
    this cannot pass by the rule being dead.
    """
    repo = _sandbox_guarded_repo(
        tmp_path, PASSING_GUARD, pairs="{}", stage=("guard.test.mjs",)
    )
    git(repo, "commit", "-q", "-m", "seed", "--no-verify")
    git(repo, "rm", "-q", "--", "guard.test.mjs")
    result = _run_pre_commit_guarded(repo, tmp_path)
    assert result.returncode == 0, (
        "deleting a suite must not block the commit\n" + result.stderr
    )
    assert "guard.test.mjs" not in result.stderr


def test_pre_commit_guards_a_staged_deletion_of_a_guarded_source(
    tmp_path: Path,
) -> None:
    """Deleting guarded data still runs its guard.

    The derivation reads the working tree, where a staged deletion no longer
    exists — so without the runner seeding the staged paths back into the scan,
    `git rm data.json` would resolve to no suites and pass having run nothing.
    That is the silent no-op the mechanism exists to close, and the map this
    replaced did not have it. The guard fails here, so a scheduled run is
    visible as a blocked commit.

    `pairs` is emptied and the guard NAMES the file, so the only route to a
    scheduled run is the derivation seeing the seeded path — with a curated
    pair present this would pass without the scan running at all.
    """
    repo = _sandbox_guarded_repo(tmp_path, DERIVED_FAILING_GUARD, pairs="{}")
    git(repo, "commit", "-q", "-m", "seed", "--no-verify")
    git(repo, "rm", "-q", "--", "data.json")
    result = _run_pre_commit_guarded(repo, tmp_path)
    assert result.returncode != 0, (
        "deleting a guarded source must still run its guard\n" + result.stderr
    )
    assert "paired guard test failed" in result.stderr


def test_pre_commit_refuses_when_the_scan_cannot_be_derived(tmp_path: Path) -> None:
    """No acorn, no derivation, no commit.

    The pairs are computed by parsing the suites, so an absent parser means the
    runner cannot know what to schedule. Passing would be a fail-OPEN on a gate:
    it must refuse, and say which install fixes it.
    """
    repo = _sandbox_guarded_repo(tmp_path, PASSING_GUARD, with_acorn=False)
    result = _run_pre_commit_guarded(repo, tmp_path)
    assert result.returncode != 0, (
        "an underivable map must block the commit\n" + result.stderr
    )
    assert "cannot derive the guard-pair map" in result.stderr
    assert "pnpm install" in result.stderr


def test_pre_commit_skips_a_guard_excluded_as_too_slow(tmp_path: Path) -> None:
    """`tooSlowForCommit` drops a suite from the schedule, loudly.

    The guard would FAIL if it ran, so a passing commit proves the exclusion is
    what took it out of the schedule and not something else — and the operator
    is told, since a silent skip is indistinguishable from a broken map.
    """
    repo = _sandbox_guarded_repo(
        tmp_path,
        FAILING_GUARD,
        too_slow='{"guard.test.mjs": "excluded so this case can observe the skip"}',
    )
    result = _run_pre_commit_guarded(repo, tmp_path)
    assert result.returncode == 0, (
        "an excluded guard must not run\n" + result.stderr + result.stdout
    )
    assert "not running guard.test.mjs at commit time" in result.stderr


def test_pre_commit_refuses_a_pair_naming_a_missing_guard(tmp_path: Path) -> None:
    """A curated pair pointing at a file that is not there is a broken map.

    Running it would fail with a path error that blames the test rather than the
    map, so the runner names the pair instead.
    """
    repo = _sandbox_guarded_repo(
        tmp_path, PASSING_GUARD, pairs='{"data.json": ["gone.test.mjs"]}'
    )
    result = _run_pre_commit_guarded(repo, tmp_path)
    assert result.returncode != 0, result.stderr
    assert "gone.test.mjs, which does not exist" in result.stderr


def _head(repo: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        env=env_without_git_location(),
    ).stdout


def test_the_sandbox_git_helper_ignores_an_inherited_git_dir(
    tmp_path: Path, monkeypatch
) -> None:
    """A sandbox commit lands in the sandbox, whatever GIT_DIR the caller exports.

    This is the incident, not a hypothetical: run under the pre-commit hook —
    which exports GIT_DIR — the helpers above committed each sandbox's fixture
    files onto the developer's own branch, because with GIT_DIR set `cwd=` no
    longer decides which repository git answers for.
    """
    sandbox = init_repo(tmp_path, "sandbox")
    decoy = init_repo(tmp_path, "decoy")
    (decoy / "kept.txt").write_text("do not touch\n")
    git(decoy, "add", "kept.txt")
    git(decoy, "commit", "-q", "-m", "decoy", "--no-verify")
    decoy_head = _head(decoy)

    monkeypatch.setenv("GIT_DIR", str(decoy / ".git"))
    (sandbox / "fixture.txt").write_text("sandbox only\n")
    git(sandbox, "add", "fixture.txt")
    git(sandbox, "commit", "-q", "-m", "seed", "--no-verify")

    assert _head(decoy) == decoy_head, (
        "the sandbox commit landed in the decoy repository"
    )
    # Positive marker: the commit really happened, so the assertion above is not
    # satisfied by a helper that quietly did nothing at all.
    listed = subprocess.run(
        ["git", "show", "--name-only", "--format=", "HEAD"],
        cwd=sandbox,
        check=True,
        capture_output=True,
        text=True,
        env=env_without_git_location(),
    ).stdout
    assert listed.split() == ["fixture.txt"]
