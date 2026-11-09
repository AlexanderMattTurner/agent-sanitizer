"""The push gate checks the tree a push publishes, not the session's checkout.

Each fixture repository's `build` script passes only when a committed `ok`
file exists, so the real `pre-push-check.sh` (driven through `judgePush`, the
hook's entry point) reports which tree it ran on. The session checkout and the
pushed repository disagree in every case, and so do a commit and the
uncommitted edits on top of it, so a gate checking the wrong one is red here.
"""

import json
import subprocess
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


def _judge(command: str, cwd: Path) -> dict | None:
    result = subprocess.run(
        ["node", "--input-type=module", "-e", _JUDGE, command, str(cwd)],
        cwd=cwd,
        env={**git_env(), "CLAUDE_PROJECT_DIR": str(cwd)},
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


@pytest.mark.parametrize("pushed_ok", [True, False])
@pytest.mark.parametrize(
    "command",
    [
        "git -C {pushed} push origin HEAD",
        "cd {pushed} && git push",
        "cd {pushed} && echo pushing && git push -u origin HEAD",
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
    ],
)
def test_denies_a_push_it_cannot_place(
    tmp_path: Path, command: str, reason: str
) -> None:
    repo = _repo(tmp_path / "repo", committed_ok=True, worktree_ok=True)
    verdict = _judge(command, repo)
    assert verdict is not None
    assert reason in json.dumps(verdict)


def test_a_deletion_only_push_runs_no_checks(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo", committed_ok=False, worktree_ok=False)
    assert _judge("git push origin --delete old-branch", repo) is None
    assert _judge("git push origin :old-branch", repo) is None
