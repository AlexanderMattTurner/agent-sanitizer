"""The push gate checks the tree a push publishes, not the session's checkout.

Each fixture repository's `build` script passes only when a committed `ok`
file exists, so the real `pre-push-check.sh` (driven through `judgePush`, the
hook's entry point) reports which tree it ran on. The session checkout and the
pushed repository disagree in every case, and so do a commit and the
uncommitted edits on top of it, so a gate checking the wrong one is red here.
"""

import contextlib
import json
import os
import signal
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT, commit_all, git_env, init_test_repo

_JUDGE = f"""
import {{ judgePush }} from {json.dumps(str(REPO_ROOT / ".claude/hooks/push-gate.mjs"))};
const [command, cwd] = process.argv.slice(1);
const verdict = await judgePush(
  {{ tool_name: "Bash", tool_input: {{ command }}, cwd }},
  {{ now: () => 0 }},
);
process.stdout.write(JSON.stringify(verdict));
"""


def _repo(path: Path, *, committed_ok: bool, worktree_ok: bool) -> Path:
    """A repo whose `build` passes on a tree holding `ok`, committed or not."""
    init_test_repo(path)
    (path / "package.json").write_text(
        '{"scripts":{"build":"test -f ok"}}\n', encoding="utf-8"
    )
    if committed_ok:
        (path / "ok").write_text("", encoding="utf-8")
    commit_all(path)
    if worktree_ok != committed_ok:
        if worktree_ok:
            (path / "ok").write_text("", encoding="utf-8")
        else:
            (path / "ok").unlink()
    return path


def _judge_argv(command: str, cwd: Path) -> list[str]:
    return ["node", "--input-type=module", "-e", _JUDGE, command, str(cwd)]


def _judge(command: str, cwd: Path, tmp: Path | None = None) -> dict | None:
    result = subprocess.run(
        _judge_argv(command, cwd),
        cwd=cwd,
        env=_judge_env(cwd, tmp),
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def _judge_env(cwd: Path, tmp: Path | None) -> dict[str, str]:
    env = {**git_env(), "CLAUDE_PROJECT_DIR": str(cwd)}
    return env if tmp is None else {**env, "TMPDIR": str(tmp)}


@pytest.mark.parametrize("pushed_ok", [True, False])
@pytest.mark.parametrize(
    "command",
    [
        "git -C {pushed} push origin HEAD",
        "cd {pushed} && git push",
        "cd {pushed} && echo pushing && git push -u origin HEAD",
        "echo pushing && cd {pushed} && git push",
        "cd {pushed} 2>/dev/null && git push",
        "if cd {pushed}; then git push; fi",
    ],
)
def test_checks_the_repository_the_push_runs_in(
    tmp_path: Path, command: str, pushed_ok: bool
) -> None:
    session = _repo(
        tmp_path / "session", committed_ok=not pushed_ok, worktree_ok=not pushed_ok
    )
    pushed = _repo(tmp_path / "pushed", committed_ok=pushed_ok, worktree_ok=pushed_ok)
    verdict = _judge(command.format(pushed=pushed), session)
    assert (verdict is None) == pushed_ok, verdict
    if not pushed_ok:
        assert str(pushed) in json.dumps(verdict)


@pytest.mark.parametrize("committed_ok", [True, False])
def test_checks_the_commit_not_the_uncommitted_working_tree(
    tmp_path: Path, committed_ok: bool
) -> None:
    repo = _repo(
        tmp_path / "repo", committed_ok=committed_ok, worktree_ok=not committed_ok
    )
    assert (_judge("git push origin HEAD", repo) is None) == committed_ok


def test_checks_the_branch_a_refspec_names_rather_than_head(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo", committed_ok=True, worktree_ok=True)
    env = git_env()
    subprocess.run(
        ["git", "checkout", "-q", "-b", "broken"], cwd=repo, env=env, check=True
    )
    (repo / "ok").unlink()
    commit_all(repo, "break the build")
    subprocess.run(["git", "checkout", "-q", "main"], cwd=repo, env=env, check=True)
    assert _judge("git push origin main", repo) is None
    verdict = _judge("git push origin broken:main", repo)
    assert verdict is not None
    assert "test -f ok" in json.dumps(verdict)


def test_a_cd_in_a_subshell_does_not_move_the_push(tmp_path: Path) -> None:
    session = _repo(tmp_path / "session", committed_ok=True, worktree_ok=True)
    broken = _repo(tmp_path / "broken", committed_ok=False, worktree_ok=False)
    assert _judge(f"(cd {broken}); git push", session) is None
    assert _judge(f"cd {broken}; git push", session) is not None


@pytest.mark.parametrize(
    "command",
    [
        "git -C {passing} push origin HEAD && git push origin HEAD",
        "git push origin HEAD; git -C {passing} push origin HEAD",
    ],
)
def test_checks_every_push_in_the_call(tmp_path: Path, command: str) -> None:
    session = _repo(tmp_path / "session", committed_ok=False, worktree_ok=False)
    passing = _repo(tmp_path / "passing", committed_ok=True, worktree_ok=True)
    verdict = _judge(command.format(passing=passing), session)
    assert verdict is not None
    assert str(session) in json.dumps(verdict)


def test_installs_dependencies_without_a_lockfile(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    init_test_repo(repo)
    (repo / "dep").mkdir()
    (repo / "dep" / "package.json").write_text(
        '{"name":"dep","version":"1.0.0","main":"index.js"}\n', encoding="utf-8"
    )
    (repo / "dep" / "index.js").write_text("", encoding="utf-8")
    (repo / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"dep": "file:./dep"},
                "scripts": {"build": "node -e \"require('dep')\""},
            }
        ),
        encoding="utf-8",
    )
    commit_all(repo)
    assert _judge("git push origin HEAD", repo) is None


def test_leaves_no_worktree_behind(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo", committed_ok=False, worktree_ok=False)
    assert _judge("git push", repo) is not None
    listed = subprocess.run(
        ["git", "worktree", "list", "--porcelain"],
        cwd=repo,
        env=git_env(),
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert listed.count("worktree ") == 1, listed


@pytest.mark.parametrize(
    "command, reason",
    [
        ('cd "$TARGET" && git push', "cannot tell which repository"),
        ("git push origin $(git branch --show-current)", "cannot tell which commits"),
        ("git push origin no-such-branch", "cannot resolve the pushed revision"),
        ("false && cd {other}; git push", "cannot tell which repository"),
        ("cd {other} || git push", "cannot tell which repository"),
        ("git push origin :", "cannot tell which commits"),
        ("git push origin +:", "cannot tell which commits"),
        ("git push --all origin", "cannot tell which commits"),
        ("pushd {other} && git push", "cannot tell which repository"),
        ("GIT_DIR={other}/.git git push", "cannot tell which repository"),
        ("env GIT_WORK_TREE={other} git push", "cannot tell which repository"),
        ("export GIT_DIR={other}/.git; git push", "cannot tell which repository"),
    ],
)
def test_denies_a_push_it_cannot_place(
    tmp_path: Path, command: str, reason: str
) -> None:
    repo = _repo(tmp_path / "repo", committed_ok=True, worktree_ok=True)
    other = _repo(tmp_path / "other", committed_ok=True, worktree_ok=True)
    verdict = _judge(command.format(other=other), repo)
    assert verdict is not None
    assert reason in json.dumps(verdict)


def test_a_deletion_only_push_runs_no_checks(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo", committed_ok=False, worktree_ok=False)
    assert _judge("git push origin --delete old-branch", repo) is None
    assert _judge("git push origin :old-branch", repo) is None


@contextlib.contextmanager
def _hung_gate(repo: Path, tmp: Path) -> Iterator[tuple[subprocess.Popen, Path]]:
    """A real gate run on `repo` whose build hangs, and the directory it checked
    the push out into, once the checkout exists. Killed on exit."""
    before = set(tmp.glob("push-gate-*"))
    (repo / "package.json").write_text(
        '{"scripts":{"build":"sleep 600"}}\n', encoding="utf-8"
    )
    commit_all(repo, "hang the build")
    gate = subprocess.Popen(
        _judge_argv("git push origin HEAD", repo),
        cwd=repo,
        env=_judge_env(repo, tmp),
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 60
        while not (
            started := {
                d
                for d in set(tmp.glob("push-gate-*")) - before
                if any(d.rglob("package.json"))
            }
        ):
            assert gate.poll() is None and time.monotonic() < deadline
            time.sleep(0.1)
        [base] = started
        yield gate, base
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(gate.pid, signal.SIGKILL)
        gate.wait()


def _registered_worktrees(repo: Path) -> set[str]:
    listed = subprocess.run(
        ["git", "worktree", "list", "--porcelain"],
        cwd=repo,
        env=git_env(),
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return {
        line.removeprefix("worktree ")
        for line in listed.splitlines()
        if line.startswith("worktree ")
    }


def test_a_killed_gate_leaves_nothing_registered_in_the_repository(
    tmp_path: Path,
) -> None:
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    repo = _repo(tmp_path / "repo", committed_ok=True, worktree_ok=True)
    with _hung_gate(repo, tmp) as (gate, _):
        os.killpg(gate.pid, signal.SIGKILL)
        gate.wait()
    assert _registered_worktrees(repo) == {str(repo)}


def test_a_checkout_a_check_made_unwritable_is_still_removed(tmp_path: Path) -> None:
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    repo = _repo(tmp_path / "repo", committed_ok=True, worktree_ok=True)
    (repo / "package.json").write_text(
        '{"scripts":{"build":"mkdir -p d && touch d/x && chmod 000 d && test -f ok"}}\n',
        encoding="utf-8",
    )
    commit_all(repo, "lock a directory")
    assert _judge("git push origin HEAD", repo, tmp) is None
    assert list(tmp.glob("push-gate-*")) == []
