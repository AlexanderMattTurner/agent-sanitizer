"""The published credential-noun vocabulary is one source, rendered two ways.

``data/credential-names.json`` feeds an env-var-NAME matcher (whole-name segments)
and the engine's ``field = value`` redactor (regex fragments). These tests
enumerate the JSON **member by member**, so a noun added there is covered with no
test edit, and pin the two properties a consumer depends on:

* **rendering** — every part interpolates into a pattern unescaped, and each
  rendered form is an instance of the noun it came from;
* **separation** — a noun marked ``env-name`` only never reaches ``_FIELD_NAMES``.
  That is not cosmetic: ``key = <20 chars>`` redacts a value in ordinary prose,
  which is why the name scrub may carry ``key`` and the redactor may not.

Both are asserted behaviourally where behaviour exists (through ``redact``), never
by grepping source text. Fail-closed cases drive the pure validator directly: an
empty list yields an alternation matching nothing (every credential forwarded) and
a metacharacter part yields one matching everything (all output blanked), so both
must raise rather than build a pattern.

# covers: python/agent_sanitizer/secrets/credential_names.py
# covers: python/agent_sanitizer/secrets/data/credential-names.json
"""

import json
import re

import pytest
from agent_sanitizer.secrets import (
    CREDENTIAL_NAMES_FILE,
    credential_field_name_patterns,
    credential_name_matcher,
    credential_name_segments,
    non_secret_name_segments,
    redact,
)
from agent_sanitizer.secrets import credential_names
from agent_sanitizer.secrets.credential_names import (
    ENV_NAME_USE,
    FIELD_VALUE_USE,
    parse_credential_names,
)

SPEC = json.loads(CREDENTIAL_NAMES_FILE.read_text(encoding="utf-8"))
NOUNS = SPEC["nouns"]
NON_SECRET_SUFFIXES = SPEC["nonSecretSuffixes"]

# Long enough to clear the engine's minimum-secret-length floor, and mixed-case
# with digits so no placeholder/metavariable value-shape skip claims it.
_NEEDLE = "A1b2C3d4E5f6G7h8I9j0"


def _segment_forms(parts: list[str]) -> list[str]:
    """The whole-name forms a consumer expects for ``parts`` — the same two
    spellings the module renders, restated here so the test states the contract
    rather than importing the implementation of it."""
    return list(dict.fromkeys(["_".join(parts).upper(), "".join(parts).upper()]))


# --------------------------------------------------------------------------
# The vocabulary itself: every member, from the JSON.
# --------------------------------------------------------------------------


def test_the_vocabulary_is_not_empty() -> None:
    """Non-vacuity for every enumeration below."""
    assert NOUNS and NON_SECRET_SUFFIXES
    assert credential_name_segments() and credential_field_name_patterns()
    assert non_secret_name_segments()


@pytest.mark.parametrize("noun", NOUNS, ids=lambda n: "_".join(n["parts"]))
def test_every_noun_carries_metacharacter_free_parts_and_a_known_use(noun) -> None:
    """A part must interpolate into a consumer's pattern unescaped, and a use must
    be one the renderings act on — an unrecognized use would silently drop the
    noun from both matchers."""
    assert noun["parts"], noun
    for part in noun["parts"]:
        assert re.fullmatch(r"[a-z0-9]+", part), part
    assert noun["uses"], noun
    assert set(noun["uses"]) <= {ENV_NAME_USE, FIELD_VALUE_USE}, noun


@pytest.mark.parametrize("noun", NOUNS, ids=lambda n: "_".join(n["parts"]))
def test_env_name_nouns_render_both_whole_name_forms(noun) -> None:
    """Both spellings of an env-name noun are segments (``API_KEY`` and
    ``APIKEY``); a consumer matching by trailing segment sees them as different
    tokens, so emitting only one leaves the other unscrubbed."""
    if ENV_NAME_USE not in noun["uses"]:
        pytest.skip(f"{noun['parts']} is not an env-name noun")
    segments = credential_name_segments()
    for form in _segment_forms(noun["parts"]):
        assert form in segments, f"{form} missing from the rendered segments"


@pytest.mark.parametrize("suffix", NON_SECRET_SUFFIXES, ids=lambda s: "_".join(s))
def test_every_non_secret_suffix_renders_both_whole_name_forms(suffix) -> None:
    """The non-secret markers render the same two spellings, so a consumer
    declines ``APP_KEY_ID`` and ``APP_KEYID`` alike."""
    for form in _segment_forms(suffix):
        assert form in non_secret_name_segments(), form


@pytest.mark.parametrize("noun", NOUNS, ids=lambda n: "_".join(n["parts"]))
def test_field_value_nouns_redact_a_following_value(noun) -> None:
    """Every ``field-value`` noun redacts the value after it, in all three
    separator spellings the fragment claims to tolerate."""
    if FIELD_VALUE_USE not in noun["uses"]:
        pytest.skip(f"{noun['parts']} is not a field-value noun")
    for separator in ("_", "-", ""):
        field = separator.join(noun["parts"])
        out, found = redact(f"{field} = {_NEEDLE}")
        assert _NEEDLE not in out, f"{field} value survived redaction"
        assert found, f"{field} reported no finding"


def test_env_name_only_nouns_stay_out_of_the_field_value_rendering() -> None:
    """A noun the JSON withholds from ``field-value`` must not appear in the
    field-name fragments. ``key``/``pat`` are broad enough for a name scrub and a
    false-positive flood for a value redactor, so the separation is the whole
    reason ``uses`` exists — a rendering that ignored it would redact whatever
    follows ``key = `` throughout ordinary text."""
    fragments = set(credential_field_name_patterns())
    env_only = [n for n in NOUNS if FIELD_VALUE_USE not in n["uses"]]
    assert env_only, "no env-name-only noun — this separation is untested"
    for noun in env_only:
        assert "[_-]?".join(noun["parts"]) not in fragments, noun


def test_uses_drives_the_rendering_not_the_noun_spelling() -> None:
    """Non-vacuity for the assertion above: the rendering is driven by ``uses``,
    not by the noun's spelling — the same parts render a fragment when marked
    ``field-value`` and none when not."""
    parts = ["token"]
    spec = {
        "nouns": [{"parts": parts, "uses": [ENV_NAME_USE]}],
        "nonSecretSuffixes": [["key", "id"]],
    }
    with pytest.raises(ValueError, match="no noun is marked field-value"):
        parse_credential_names(spec)
    both = parse_credential_names(
        {**spec, "nouns": [{"parts": parts, "uses": [ENV_NAME_USE, FIELD_VALUE_USE]}]}
    )
    assert both.field_name_patterns == ("token",)
    assert both.segments == ("TOKEN",)


# --------------------------------------------------------------------------
# The renderings are what the accessors promise.
# --------------------------------------------------------------------------


def test_segments_are_interpolation_safe_upper_case_tokens() -> None:
    """A consumer joins these into a regex alternation directly, so a segment must
    carry no metacharacter."""
    for segment in credential_name_segments() + non_secret_name_segments():
        assert re.fullmatch(r"[A-Z0-9_]+", segment), segment


def test_field_name_patterns_carry_no_unbounded_metacharacter() -> None:
    """The only metacharacter a fragment may carry is the separator class it needs;
    anything else would let one noun's fragment match beyond its own words."""
    for fragment in credential_field_name_patterns():
        assert re.fullmatch(r"[a-z0-9]+(?:\[_-\]\?[a-z0-9]+)*", fragment), fragment


def test_renderings_are_deduplicated() -> None:
    """A duplicate would inflate a consumer's alternation, and a generator
    materializing these into a committed file would emit it twice."""
    for rendered in (
        credential_name_segments(),
        credential_field_name_patterns(),
        non_secret_name_segments(),
    ):
        assert len(set(rendered)) == len(rendered), rendered


# --------------------------------------------------------------------------
# Fail closed on a bad spec.
# --------------------------------------------------------------------------

_GOOD = {
    "nouns": [{"parts": ["api", "key"], "uses": [ENV_NAME_USE, FIELD_VALUE_USE]}],
    "nonSecretSuffixes": [["key", "id"]],
}

_BAD_SPECS = [
    ("nouns_missing", {"nonSecretSuffixes": [["key", "id"]]}, "nouns"),
    ("nouns_empty", {**_GOOD, "nouns": []}, "nouns"),
    ("nouns_not_a_list", {**_GOOD, "nouns": "api_key"}, "nouns"),
    ("noun_not_an_object", {**_GOOD, "nouns": ["api_key"]}, "nouns[0]"),
    (
        "parts_missing",
        {**_GOOD, "nouns": [{"uses": [FIELD_VALUE_USE]}]},
        "nouns[0].parts",
    ),
    (
        "parts_empty",
        {**_GOOD, "nouns": [{"parts": [], "uses": [FIELD_VALUE_USE]}]},
        "nouns[0].parts",
    ),
    (
        "part_metacharacter",
        {**_GOOD, "nouns": [{"parts": ["key|.*"], "uses": [FIELD_VALUE_USE]}]},
        "nouns[0].parts",
    ),
    (
        "part_upper_case",
        {**_GOOD, "nouns": [{"parts": ["KEY"], "uses": [FIELD_VALUE_USE]}]},
        "nouns[0].parts",
    ),
    (
        "part_trailing_newline",
        {**_GOOD, "nouns": [{"parts": ["key\n"], "uses": [FIELD_VALUE_USE]}]},
        "nouns[0].parts",
    ),
    (
        "part_not_a_string",
        {**_GOOD, "nouns": [{"parts": [7], "uses": [FIELD_VALUE_USE]}]},
        "nouns[0].parts",
    ),
    (
        "uses_missing",
        {**_GOOD, "nouns": [{"parts": ["token"]}]},
        "nouns[0].uses",
    ),
    (
        "uses_empty",
        {**_GOOD, "nouns": [{"parts": ["token"], "uses": []}]},
        "nouns[0].uses",
    ),
    (
        "uses_unknown",
        {**_GOOD, "nouns": [{"parts": ["token"], "uses": ["everything"]}]},
        "nouns[0].uses",
    ),
    ("suffixes_missing", {"nouns": _GOOD["nouns"]}, "nonSecretSuffixes"),
    ("suffixes_empty", {**_GOOD, "nonSecretSuffixes": []}, "nonSecretSuffixes"),
    (
        "suffix_metacharacter",
        {**_GOOD, "nonSecretSuffixes": [["(?:.*)"]]},
        "nonSecretSuffixes[0]",
    ),
    (
        # The same anchoring case as ``part_trailing_newline``, on the other path
        # through the validator. ``re.fullmatch`` rejects it; a ``^…$`` pattern
        # would accept it here and be rejected by the JavaScript twin reading the
        # same file, which is the split that has to stay closed on BOTH paths.
        "suffix_trailing_newline",
        {**_GOOD, "nonSecretSuffixes": [["key", "id\n"]]},
        "nonSecretSuffixes[0]",
    ),
    (
        "no_env_name_noun",
        {**_GOOD, "nouns": [{"parts": ["token"], "uses": [FIELD_VALUE_USE]}]},
        "env-name",
    ),
]


@pytest.mark.parametrize(
    "spec,field", [(s, f) for _, s, f in _BAD_SPECS], ids=[c[0] for c in _BAD_SPECS]
)
def test_the_validator_rejects_a_bad_spec(spec, field) -> None:
    """Every field, every way of being wrong: the validator raises naming the file
    and the offending field, rather than building a pattern that matches
    everything or nothing."""
    with pytest.raises(ValueError) as excinfo:
        parse_credential_names(spec)
    message = str(excinfo.value)
    assert "credential-names.json" in message
    assert field in message


def test_the_validator_accepts_the_real_spec() -> None:
    """Non-vacuity for the rejections above: the live vocabulary parses and
    renders, so the raises refuse bad input and not all input."""
    rendered = parse_credential_names(SPEC)
    assert rendered.segments == credential_name_segments()
    assert rendered.field_name_patterns == credential_field_name_patterns()
    assert rendered.non_secret_segments == non_secret_name_segments()


def test_an_empty_alternation_would_be_permissive_or_blind() -> None:
    """Why the empty-list rejections above are security-relevant, not tidiness: an
    empty alternation matches nothing, so every credential is forwarded verbatim,
    and an interpolated metacharacter matches everything, so all output blanks."""
    assert re.search(r"(?:^|_)(?:)$", "MY_TOKEN") is None
    assert re.search(r"(?:^|_)(?:KEY|.*)$", "TOTALLY_INNOCENT") is not None


# ── the NAME matcher: the rule built from the vocabulary ─────────────────────
#
# The renderings above are the words. These cover the RULE, and every case here is
# one a consumer's hand-rolled matcher has got wrong in practice.

_MATCHER_SPEC = {
    "nouns": [
        {"parts": ["api", "key"], "uses": [ENV_NAME_USE, FIELD_VALUE_USE]},
        {"parts": ["access", "token"], "uses": [ENV_NAME_USE, FIELD_VALUE_USE]},
        {"parts": ["token"], "uses": [ENV_NAME_USE]},
    ],
    "nonSecretSuffixes": [["key", "id"]],
}


@pytest.mark.parametrize(
    "name",
    ["GITHUB_TOKEN", "DEPLOY_API_KEY", "npm_config__authToken", "deploy_apikey"],
)
def test_a_credential_name_matches_in_any_case(name: str) -> None:
    """Case is folded: npm renders its config into the environment as
    ``npm_config_<key>`` and reads the same names back, so a registry token arrives
    lower-case without anyone exporting a credential-looking variable."""
    assert credential_name_matcher()(name)


@pytest.mark.parametrize(
    "name", ["PATH", "TOKENIZERS_PARALLELISM", "UV_KEYRING_PROVIDER", "HOME"]
)
def test_a_name_that_merely_contains_a_noun_does_not_match(name: str) -> None:
    """Runs are compared whole. PATH matters most: a scrub that strips it leaves
    the command it was protecting unable to find its own executable."""
    assert not credential_name_matcher(scope="any-segment")(name)


@pytest.mark.parametrize(
    "name", ["TEMPLATE_SYNC_TOKEN_ORG", "OAUTH_ACCESS_TOKEN_FALLBACK_4"]
)
def test_scope_decides_whether_a_mid_name_noun_counts(name: str) -> None:
    """The two scopes must actually differ, or the argument is a lie. Both names
    hold a live credential and neither ENDS in a noun, so a trailing-only matcher
    reports "not a credential" — which is the leak this matcher exists to stop a
    consumer from re-inventing."""
    assert not credential_name_matcher(spec=_MATCHER_SPEC)(name)
    assert credential_name_matcher(spec=_MATCHER_SPEC, scope="any-segment")(name)


def test_a_multi_word_noun_is_compared_as_one_run() -> None:
    """ACCESS_TOKEN is a noun; ACCESS alone is not. Word-by-word matching would
    strip ACCESS_LOG_LEVEL."""
    holds = credential_name_matcher(spec=_MATCHER_SPEC, scope="any-segment")
    assert holds("SERVICE_ACCESS_TOKEN_V2")
    assert not holds("ACCESS_LOG_LEVEL")


def test_a_non_secret_suffix_is_declined_unless_the_caller_opts_out() -> None:
    """DEPLOY_API_KEY_ID carries a noun mid-name AND ends in a non-secret marker,
    so it is exactly where a redactor and a scrub want opposite answers: redacting
    an identifier out of output is a visible defect, forwarding a credential is a
    silent one."""
    assert not credential_name_matcher(spec=_MATCHER_SPEC, scope="any-segment")(
        "DEPLOY_API_KEY_ID"
    )
    assert credential_name_matcher(
        spec=_MATCHER_SPEC, scope="any-segment", decline_non_secret=False
    )("DEPLOY_API_KEY_ID")


def test_an_unknown_scope_is_refused_rather_than_defaulted() -> None:
    with pytest.raises(ValueError, match="unknown scope"):
        credential_name_matcher(spec=_MATCHER_SPEC, scope="suffix")


def test_an_unusable_vocabulary_reaches_no_matcher() -> None:
    """A matcher over an empty noun set answers "no credential here" for every name
    it is asked about — a scrub that forwards every secret while reporting success."""
    with pytest.raises(ValueError, match="nouns is empty or missing"):
        credential_name_matcher(spec={})


def test_a_hostile_variable_name_cannot_stall_the_matcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The caller does not choose these names — a scrub is handed whatever the
    surrounding process exported. One alternation of the renderings backtracks
    polynomially on this input, and an unbounded run walk is quadratic on it.

    The bound asserted is the COUNT of membership tests, not elapsed time. Both
    say the same thing about the algorithm, but a wall-clock threshold also
    reports on the machine that ran it: the ratio between linear and quadratic
    here is ~20000, so any threshold separating them passes locally and reds
    under load, which is the flake this suite already carries a scar from
    (``test/invisible.test.mjs`` names one). A count has no such term — it is
    identical on every machine and on every run.
    """
    counted = []

    class CountingFrozenset(frozenset):  # type: ignore[type-arg]
        def __contains__(self, item: object) -> bool:
            counted.append(item)
            return super().__contains__(item)

    # raising=False because `frozenset` is a builtin, not a module attribute: this
    # ADDS a module global, which the matcher's name lookup finds before builtins.
    monkeypatch.setattr(credential_names, "frozenset", CountingFrozenset, raising=False)
    segments = 20_000
    name = "A_" * segments + "TOKENISH"
    assert not credential_name_matcher(scope="any-segment")(name)

    # Linear: at most `max_run` runs per starting segment. The longest noun in the
    # packaged vocabulary is 3 words, so 4x the segment count is generous headroom
    # over the true bound while still an order of magnitude under the quadratic
    # walk's ~2e8 for this input.
    assert len(counted) <= 4 * segments


@pytest.mark.parametrize("segment", credential_name_segments())
def test_every_rendered_segment_drives_the_real_matcher(segment: str) -> None:
    """Member by member, from the vocabulary: a name ending in each rendered
    segment holds a credential, in every spelling an environment produces.

    The per-noun tests above assert that a segment is RENDERED. This asserts the
    matcher then acts on it, which is a different failure: a noun can reach the
    segment list and still be unreachable by the walk that consumes it.

    The trailing-newline case is asserted NEGATIVE, and that is the point of it.
    ``KEY\\n`` is not the noun ``KEY``, so the name does not hold a credential —
    but Python's ``$`` also matches just before a trailing newline, so a matcher
    rebuilt around ``re.search(r"KEY$", name)`` would answer True here while its
    JavaScript twin answered False, and a value would reach the transcript through
    whichever path ran second. ``test/credential-matcher-parity.test.mjs`` checks
    the two implementations against each other; this pins the Python side alone,
    so the suite still fails if the JavaScript side is renamed away.
    """
    holds = credential_name_matcher()
    assert holds(f"DEPLOY_{segment}")
    assert holds(f"deploy_{segment.lower()}")
    assert not holds(f"DEPLOY_{segment}\n")


@pytest.mark.parametrize("marker", non_secret_name_segments())
def test_every_non_secret_marker_declines_a_credential_name(marker: str) -> None:
    """Member by member: each marker turns a name that otherwise holds a
    credential into one the redactor declines, and ``decline_non_secret=False``
    turns it back on for a scrub that prefers over-stripping.

    Built from the vocabulary rather than named, so a marker added to the JSON is
    covered with no edit here. Asserting both directions is what stops this from
    passing on a matcher that simply never matched the name at all.
    """
    name = f"{credential_name_segments()[0]}_{marker}"
    assert not credential_name_matcher()(name)
    assert credential_name_matcher(scope="any-segment", decline_non_secret=False)(name)


def test_a_missing_data_file_raises_rather_than_rendering_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """The reader's own failure, which no ``spec`` case reaches: every bad-spec
    case above drives the pure validator, and a missing FILE never gets that far.

    It is worth pinning because the tempting repair — catching the read so
    start-up survives a packaging mistake — yields an empty vocabulary, and a
    matcher over an empty noun set answers "not a credential" for every name it is
    asked about. That forwards every credential with no error anywhere.
    """
    monkeypatch.setattr(
        credential_names, "CREDENTIAL_NAMES_FILE", tmp_path / "absent.json"
    )
    # The renderings are memoized, so the patched path is only read if the cache
    # is cleared first — and restored afterwards so no later test sees the gap.
    credential_names._rendered.cache_clear()
    try:
        with pytest.raises(FileNotFoundError):
            credential_name_matcher()
    finally:
        # Undo before the cache clear, not after: the accessor re-reads on the
        # next call, and monkeypatch's own teardown would otherwise run second and
        # leave the cache holding the failure for every later test in the session.
        monkeypatch.undo()
        credential_names._rendered.cache_clear()
    # Non-vacuity: the accessor works again with the real file back, so the raise
    # above was the missing file rather than a cache left poisoned by an earlier
    # test — which would make this pass without exercising anything.
    assert credential_name_segments()
