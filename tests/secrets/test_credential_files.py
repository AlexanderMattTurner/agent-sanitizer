"""The published credential-FILE vocabulary and the path matcher built from it.

``data/credential-files.json`` is the single source. The matcher is a hand-written
twin of ``src/credential-files.mjs``, so both suites assert the SAME literal verdicts
from ``tests/data/credential-files.cases.json``. Fail-closed cases drive the pure
validator: an empty list matches nothing (every credential file passes) and a glob
of wildcards alone matches everything, so both must raise rather than build a matcher.

# covers: python/agent_sanitizer/secrets/credential_files.py
# covers: python/agent_sanitizer/secrets/data/credential-files.json
# covers: tests/data/credential-files.cases.json
"""

import json

import pytest
from hypothesis import given, settings, strategies as st

from tests._helpers import REPO_ROOT
from agent_sanitizer.secrets import (
    CREDENTIAL_FILES_FILE,
    credential_directories,
    credential_name_globs,
    credential_path_globs,
    credential_path_matcher,
    parse_credential_files,
)

SPEC = json.loads(CREDENTIAL_FILES_FILE.read_text(encoding="utf-8"))
CORPUS = json.loads(
    (REPO_ROOT / "tests" / "data" / "credential-files.cases.json").read_text(
        encoding="utf-8"
    )
)
CASES = CORPUS["cases"]
EXAMPLES = CORPUS["globExamples"]

# Lists that match nothing, so the one list under test is the only way in.
INERT = {
    "nameGlobs": ["inert.placeholder"],
    "pathGlobs": ["*/inert/placeholder"],
    "directories": ["inert-dir"],
}

_FIELDS = ("nameGlobs", "pathGlobs", "directories")
_PAIRS = [
    (field, entry, example)
    for field in _FIELDS
    for entry, example in EXAMPLES[field].items()
]


def test_the_accessors_return_the_packaged_lists() -> None:
    """Non-vacuity, and the accessors render the file unchanged."""
    assert credential_name_globs() == tuple(SPEC["nameGlobs"])
    assert credential_path_globs() == tuple(SPEC["pathGlobs"])
    assert credential_directories() == tuple(SPEC["directories"])
    assert parse_credential_files(SPEC).name_globs == credential_name_globs()


@pytest.mark.parametrize("field", _FIELDS)
def test_the_corpus_has_an_example_for_each_entry_and_no_stale_one(field) -> None:
    """Adding an entry to the vocabulary without an example here fails."""
    assert sorted(EXAMPLES[field]) == sorted(SPEC[field])


@pytest.mark.parametrize(
    ("field", "entry", "example"), _PAIRS, ids=[f"{f}:{e}" for f, e, _ in _PAIRS]
)
def test_every_entry_matches_a_real_example_alone(field, entry, example) -> None:
    """The entry is the only list item that can match, so a dead entry reds."""
    holds = credential_path_matcher(spec={**INERT, field: [entry]})
    assert holds(example) is True
    assert holds("/home/u/project/main.py") is False


def test_the_conformance_corpus_is_loaded_and_well_formed() -> None:
    """Non-vacuity: a corpus that failed to load would pass every case below."""
    assert len(CASES) >= 30, len(CASES)
    assert all(isinstance(c["path"], str) for c in CASES)
    assert all(isinstance(c["expected"], bool) for c in CASES)
    assert {c["expected"] for c in CASES} == {True, False}
    ids = [c["id"] for c in CASES]
    assert len(set(ids)) == len(ids)


# allow-unreset-state: a per-session coverage accumulator, consumed once by the
# non-vacuity assertion below and never read across a session boundary.
_CONSUMED: set[str] = set()


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_the_matcher_agrees_with_the_conformance_corpus(case) -> None:
    """This language's matcher returns the corpus's literal verdict. A failure is a
    divergence from the other implementation: diagnose it against ``why``."""
    assert credential_path_matcher()(case["path"]) is case["expected"], case["why"]
    _CONSUMED.add(case["id"])


def test_every_conformance_case_was_consumed() -> None:
    """A case silently dropped is a hole in the coverage the corpus exists for."""
    assert _CONSUMED == {c["id"] for c in CASES}


def test_the_leaf_not_an_inner_directory_meets_the_name_globs() -> None:
    holds = credential_path_matcher()
    assert holds("/home/u/.npmrc/readme.txt") is False
    assert holds("/home/u/.npmrc") is True


def test_a_long_path_does_not_stall_the_matcher() -> None:
    holds = credential_path_matcher()
    assert holds("/" + "a*" * 50_000 + "/credentialz") is True
    assert holds("/" + "secre" * 40_000 + "/x") is False


_GOOD = INERT
_BAD_SPECS = [
    ({}, "nameGlobs is empty or missing"),
    ({**_GOOD, "nameGlobs": []}, "nameGlobs is empty or missing"),
    ({**_GOOD, "nameGlobs": "env"}, "nameGlobs is empty or missing"),
    ({**_GOOD, "pathGlobs": []}, "pathGlobs is empty or missing"),
    ({**_GOOD, "directories": []}, "directories is empty or missing"),
    ({**_GOOD, "nameGlobs": [7]}, "bad entr"),
    ({**_GOOD, "nameGlobs": ["*"]}, "bad entr"),
    ({**_GOOD, "nameGlobs": ["**"]}, "bad entr"),
    ({**_GOOD, "nameGlobs": [".ENV"]}, "bad entr"),
    ({**_GOOD, "nameGlobs": ["a/b"]}, "bad entr"),
    ({**_GOOD, "nameGlobs": ["a[bc]"]}, "bad entr"),
    ({**_GOOD, "nameGlobs": ["a?"]}, "bad entr"),
    ({**_GOOD, "nameGlobs": ["env\n"]}, "bad entr"),
    ({**_GOOD, "nameGlobs": [""]}, "bad entr"),
    ({**_GOOD, "pathGlobs": [".docker/config.json"]}, "bad entr"),
    ({**_GOOD, "pathGlobs": ["*/*"]}, "bad entr"),
    ({**_GOOD, "directories": ["*"]}, "bad entr"),
    ({**_GOOD, "directories": ["a/b"]}, "bad entr"),
    ({**_GOOD, "directories": [".."]}, "bad entr"),
    ({**_GOOD, "directories": ["."]}, "bad entr"),
]


@pytest.mark.parametrize(("spec", "message"), _BAD_SPECS)
def test_a_malformed_spec_raises_rather_than_matching_nothing(spec, message) -> None:
    with pytest.raises(ValueError, match=message):
        parse_credential_files(spec)
    with pytest.raises(ValueError, match=message):
        credential_path_matcher(spec=spec)


def test_a_repeated_entry_is_dropped_keeping_first_occurrence_order() -> None:
    spec = {**_GOOD, "nameGlobs": [".b", ".a", ".b"]}
    assert parse_credential_files(spec).name_globs == (".b", ".a")


# ── properties over arbitrary paths ──────────────────────────────────────────

_PATH_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-/~"


@settings(max_examples=300, deadline=None)
@given(st.text())
def test_the_matcher_never_raises_and_answers_a_bool(path) -> None:
    assert isinstance(credential_path_matcher()(path), bool)


@settings(max_examples=300, deadline=None)
@given(st.text(alphabet=_PATH_ALPHABET, max_size=40))
def test_the_matcher_ignores_ascii_letter_case(path) -> None:
    holds = credential_path_matcher()
    assert holds(path.upper()) is holds(path.lower())


@settings(max_examples=200, deadline=None)
@given(
    st.sampled_from(credential_directories()),
    st.text(
        alphabet="abcdefghijklmnopqrstuvwxyz0123456789_.-", min_size=1, max_size=12
    ),
)
def test_every_path_under_a_credential_directory_matches(directory, leaf) -> None:
    assert credential_path_matcher()(f"/home/u/{directory}/{leaf}") is True
