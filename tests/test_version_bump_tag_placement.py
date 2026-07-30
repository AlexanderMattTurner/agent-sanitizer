"""The release tag must mark the SHA that was PUBLISHED, not the local HEAD.

version-bump.sh decides "has HEAD already been released?" with
``git tag --contains HEAD``. That predicate is only sound if every tag sits on the
commit whose tree actually shipped.

It did not. The script committed release docs on top of the published SHA, pushed
with ``push_with_rebase``, and tagged the local HEAD. When a second merge landed
mid-run the docs commit was replayed onto it, so a tag certifying tree A came to
sit on a DESCENDANT of unrelated merge B. ``git tag --contains B`` then reported B
as released, and B never published — observed on 2026-07-30, when the agent-
sanitizer #192 merge (caa1fb1) was skipped with "HEAD is already released as
v2.7.1" while the shipped 2.7.1 tarball contained none of its changes.

These build the real topology with real git rather than asserting on the script's
source text, so they keep testing the property if the implementation moves.
"""

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(
    subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
)
SCRIPT = REPO_ROOT / ".github" / "scripts" / "version-bump.sh"


def _git(repo: Path, *args: str) -> str:
    """Run git in ``repo`` and return stdout, raising on a non-zero exit."""
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _commit(repo: Path, message: str) -> str:
    """Create an empty commit and return its SHA."""
    _git(repo, "commit", "--allow-empty", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def raced_release(tmp_path: Path) -> dict[str, str]:
    """The exact shape of the stranding: publish A, merge B, rebase A's docs onto B.

    Returns the published SHA of release A and the SHA of the racing merge B.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")

    _commit(repo, "chore: base")
    published_a = _commit(repo, "Merge pull request #194")
    # B lands on the branch while A's run is still publishing.
    merge_b = _commit(repo, "Merge pull request #192")
    # push_with_rebase replays A's release-docs commit onto the new tip, B.
    docs = _commit(repo, "docs: release 2.7.1 [skip ci]")

    return {
        "repo": str(repo),
        "published_a": published_a,
        "merge_b": merge_b,
        "docs": docs,
    }


def test_tagging_the_docs_commit_strands_the_racing_merge(raced_release):
    """The old placement: the guard reports B released, though B never shipped."""
    repo = Path(raced_release["repo"])
    _git(repo, "tag", "v2.7.1", raced_release["docs"])

    contains_b = _git(
        repo, "tag", "--contains", raced_release["merge_b"], "--list", "v*"
    )
    assert contains_b == "v2.7.1", (
        "fixture must reproduce the stranding: a tag on the rebased docs commit "
        "has to look like it contains the racing merge"
    )


def test_tagging_the_published_sha_lets_the_racing_merge_release(raced_release):
    """The fixed placement: B is not claimed by A's tag, so B publishes."""
    repo = Path(raced_release["repo"])
    _git(repo, "tag", "v2.7.1", raced_release["published_a"])

    contains_b = _git(
        repo, "tag", "--contains", raced_release["merge_b"], "--list", "v*"
    )
    assert contains_b == "", (
        f"merge B is claimed by {contains_b!r}; its release would be skipped"
    )

    # ...and the guard still fires for a genuine re-trigger against A, which is
    # the duplicate-publish the guard exists to prevent.
    contains_a = _git(
        repo, "tag", "--contains", raced_release["published_a"], "--list", "v*"
    )
    assert contains_a == "v2.7.1"


def test_script_tags_the_published_sha_not_local_head():
    """The tag command names the pre-docs-commit SHA.

    Paired with the topology tests above: those prove which placement is correct,
    this proves the script asks for that one. A bare source grep would pass
    vacuously if the tag step were deleted, so the captured variable and its use
    are both asserted.
    """
    source = SCRIPT.read_text(encoding="utf-8")
    assert "PUBLISHED_SHA=$(git rev-parse HEAD)" in source, (
        "the published SHA must be captured before the release-docs commit"
    )
    assert 'git tag "v$NEW_VERSION" "$PUBLISHED_SHA"' in source, (
        "the tag must be pinned to the published SHA, not to the local HEAD"
    )
