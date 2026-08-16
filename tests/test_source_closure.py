"""The source-closure walk is LOUD about a target it cannot read.

PROBLEM CLASS — a `source` edge the walk drops in silence. The closure states
what a job's sparse-checkout list has to fetch, so a dropped edge is a missing
requirement nothing reports: the checkout omits the library and the job dies at
the `source` line under `set -e`, leaving a required check that never posts.

Quoting used to decide loud versus silent. `source "$LIB"` carries no literal, so
the walk resolved it to nothing and moved on; the unquoted `source $LIB` fell out
of the argument filter and raised. These tests pin the contract the other way
round: an unreadable target raises whatever its quoting, a target named through a
variable this file assigns resolves, and the two runtime-named targets in
`_RUNTIME_NAMED_TARGETS` stay quiet because their reason is written down.
"""

import pytest

from tests import _source_closure
from tests._source_closure import (
    _RUNTIME_NAMED_TARGETS,
    REPO_ROOT,
    sourced_by,
    tracked_files,
    unresolved_sources,
)

TRACKED = tracked_files()

#: A real tracked library, so a resolving case below proves the walk found a file
#: rather than proving nothing.
LIBRARY = ".github/scripts/lib/reviewer-identity.bash"


@pytest.fixture
def script(tmp_path, monkeypatch):
    """Write a shell script into a throwaway repo root and return its rel path."""

    def write(body: str) -> str:
        (tmp_path / "s.sh").write_text(body, encoding="utf-8")
        monkeypatch.setattr(_source_closure, "REPO_ROOT", tmp_path)
        return "s.sh"

    return write


@pytest.mark.parametrize(
    "body",
    [
        'LIB=/somewhere/gen.sh\nsource "$LIB2"\n',
        "LIB=/somewhere/gen.sh\nsource $LIB2\n",
        'source "${LIB2}"\n',
        "source\n",
        'source "$(compute-it)"\n',
    ],
    ids=["quoted", "unquoted", "braced", "no-argument", "substitution"],
)
def test_a_target_the_grammar_cannot_read_raises(script, body: str) -> None:
    rel = script(body)
    with pytest.raises(AssertionError, match="cannot read the target"):
        sourced_by(rel, TRACKED)


def test_a_target_named_by_a_local_assignment_resolves(script) -> None:
    rel = script(f'lib="$dir/{LIBRARY}"\n. "$lib"\n')
    assert sourced_by(rel, TRACKED) == {LIBRARY}


def test_two_assignments_naming_different_files_raise(script) -> None:
    other = ".github/scripts/lib/review-threads.bash"
    rel = script(f'lib="$d/{LIBRARY}"\nlib="$d/{other}"\n. "$lib"\n')
    with pytest.raises(AssertionError, match="cannot say which is needed"):
        sourced_by(rel, TRACKED)


def test_a_source_written_into_a_message_string_is_not_a_source(script) -> None:
    # The grammar is what tells an executed `source` from text a command prints,
    # and a false raise here would be the same silent-failure trade in reverse.
    rel = script('echo "run source \\"$LIB\\" first"\n')
    assert sourced_by(rel, TRACKED) == set()


@pytest.mark.parametrize(
    ("rel", "written"), sorted(_RUNTIME_NAMED_TARGETS), ids=lambda v: v
)
def test_each_runtime_named_target_is_still_written_that_way(
    rel: str, written: str
) -> None:
    """An allowlist entry that no longer matches its script is dead cover.

    It would keep excusing a `source` nobody writes any more, and the next edit
    to that line would land unnoticed.
    """
    assert written in (REPO_ROOT / rel).read_text(encoding="utf-8")
    assert written in unresolved_sources(rel, TRACKED)
