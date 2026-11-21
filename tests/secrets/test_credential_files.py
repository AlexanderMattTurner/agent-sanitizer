"""Twin of test/credential-files.test.mjs: both assert the SAME literal verdicts
from tests/data/credential-files.cases.json.

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
    credential_path_matcher as matcher,
    parse_credential_files as parse,
)

SPEC = json.loads(CREDENTIAL_FILES_FILE.read_text(encoding="utf-8"))
SHARED = json.loads(
    (REPO_ROOT / "tests" / "data" / "credential-files.cases.json").read_text(
        encoding="utf-8"
    )
)
INERT, CASES = SHARED["inert"], SHARED["cases"]
BAD = [(f, [v], "bad entr") for f, vs in SHARED["badEntries"].items() for v in vs]
BAD += [(f, v, "is empty or missing") for f, v in SHARED["emptySpecs"]]
PAIRS = [(f, e) for f in ("nameGlobs", "pathGlobs", "directories") for e in SPEC[f]]
holds = matcher()


def test_the_accessors_return_the_packaged_lists() -> None:
    assert credential_name_globs() == tuple(SPEC["nameGlobs"])
    assert credential_path_globs() == tuple(SPEC["pathGlobs"])
    assert credential_directories() == tuple(SPEC["directories"])


@pytest.mark.parametrize(("field", "entry"), PAIRS, ids=lambda p: str(p)[:40])
def test_every_entry_alone_matches_its_own_instance(field, entry) -> None:
    """An entry alone, in an otherwise inert spec, must match; a dead one reds."""
    alone = matcher(spec={**INERT, field: [entry]})
    example = (
        f"/home/u/{entry}/x" if field == "directories" else entry.replace("*", "x")
    )
    assert alone(example) is True
    assert alone("/home/u/project/main.py") is False


def test_the_corpus_is_loaded() -> None:
    assert len(CASES) >= 30
    assert len({path for path, _, _ in CASES}) == len(CASES)
    assert {ok for _, ok, _ in CASES} == {True, False}


@pytest.mark.parametrize(("path", "expected", "why"), CASES, ids=[c[0] for c in CASES])
def test_the_matcher_agrees_with_the_conformance_corpus(path, expected, why) -> None:
    assert holds(path) is expected, why


def test_a_long_leaf_name_does_not_stall_the_matcher() -> None:
    assert holds("/home/u/" + "a*" * 50_000 + "credentialz") is True
    assert holds("/home/u/" + "secre" * 40_000) is False


@pytest.mark.parametrize(("field", "value", "message"), BAD, ids=lambda p: str(p)[:30])
def test_a_malformed_spec_raises_rather_than_matching_nothing(field, value, message):
    spec = {**INERT, field: value}
    if value is None:  # an absent key, not a null one
        del spec[field]
    with pytest.raises(ValueError, match=message):
        parse(spec)
    with pytest.raises(ValueError, match=message):
        matcher(spec=spec)


def test_a_repeated_entry_is_dropped_keeping_first_occurrence_order() -> None:
    assert parse({**INERT, "nameGlobs": [".b", ".a", ".b"]}).name_globs == (".b", ".a")


@settings(max_examples=300, deadline=None)
@given(st.text())
def test_the_matcher_never_raises_and_answers_a_bool(path) -> None:
    assert isinstance(holds(path), bool)


@settings(max_examples=300, deadline=None)
@given(st.text(alphabet="abcXYZ019_.-/~ABC", max_size=40))
def test_the_matcher_ignores_ascii_letter_case(path) -> None:
    assert holds(path.upper()) is holds(path.lower())


@settings(max_examples=200, deadline=None)
@given(
    st.sampled_from(credential_directories()),
    st.text(
        alphabet="abcdefghijklmnopqrstuvwxyz0123456789_.-", min_size=1, max_size=12
    ).filter(lambda leaf: leaf not in (".", "..")),  # `..` leaves the directory
)
def test_every_path_under_a_credential_directory_matches(directory, leaf) -> None:
    assert holds(f"/home/u/{directory}/{leaf}") is True
