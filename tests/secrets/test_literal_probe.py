""":mod:`agent_sanitizer.secrets.prefilter` — the whole-text literal probes that
decide which lines and which whole-payload passes can be skipped.

A probe is a NECESSARY condition, so its failure mode is asymmetric: an
over-broad answer costs time, an under-broad one silently stops detecting. Every
test here is aimed at the second direction — the AST walk's per-opcode
soundness, the case fold's coverage of ``re.IGNORECASE``'s own equivalences, and
the end-to-end claim that redaction output is byte-identical with the probes in
play and with every one of them opened.
"""

import re

import pytest
from detect_secrets.settings import get_plugins

import agent_sanitizer.secrets.engine as E
from agent_sanitizer.secrets import prefilter as P
from redactor_helpers import SAMPLES, cfg, run_plain
from tests._helpers import REPO_ROOT

# Every active detector has a sample here (test_secrets_detectors.py's
# test_fixture_covers_every_active_detector derives the requirement from the live
# plugin set), so this is the corpus that exercises EVERY indexed literal.
SAMPLE_VALUES = ["".join(sample["parts"]) for sample in SAMPLES]


# ─── required_literals: the AST walk ─────────────────────────────────────────


@pytest.mark.parametrize(
    "pattern, expected",
    [
        # A plain run of literals is merged into one string, not split per char.
        (r"ghp_[0-9a-f]{36}", {"ghp_"}),
        # An alternation contributes the UNION of its arms — here the parser has
        # already factored the shared leading "A" out of the group, so the arms
        # are what is left of each.
        (r"(?:AKIA|ASIA)[0-9A-Z]{16}", {"KIA", "SIA"}),
        # An arm with no literal of its own poisons the whole alternation, so the
        # answer falls back to the most selective run outside it.
        (r"pre(?:AKIA|[0-9]{4})post", {"post"}),
        # A `?`/`*` body may not appear at all, so it is never required.
        (r"abcd(?:xyz)?", {"abcd"}),
        (r"(?:xyz)*abcd", {"abcd"}),
        # A `+`/`{1,}` body must appear at least once, so it is.
        (r"(?:xyzw)+", {"xyzw"}),
        # A negative lookahead asserts its content is ABSENT — reading it as
        # required would skip every line that legitimately matches.
        (r"abcd(?!never)", {"abcd"}),
        (r"(?<=never)abcd", {"abcd"}),
        # Character classes, `.` and anchors carry no fixed text.
        (r"^[a-z]+\d+.$", None),
        # Nested groups are walked through.
        (r"(?:(?:(?P<x>wxyz)))", {"wxyz"}),
        # The most selective run wins: a set is only as good as its shortest
        # member, so the long tail beats the two-char head.
        (r"ab[0-9]+cdefghij", {"cdefghij"}),
    ],
)
def test_required_literals_reads_the_ast(pattern, expected):
    """The walk must under-claim (None / a shorter run), never over-claim: a
    literal it reports as required but that a real match can omit is a line
    skipped with a secret on it."""
    found = P.required_literals(pattern, 0)
    assert found == (None if expected is None else frozenset(expected))


def test_required_literals_are_genuinely_required_of_the_live_denylists():
    """The property the probe rests on, checked against every real detector: a
    string that matches the pattern contains one of the literals the AST walk
    derived for it. Driven from the sample corpus, which covers every active
    detector, so this cannot pass by never finding a match."""
    with E.configure_plugins():
        matched = 0
        for pattern in P.denylist_patterns(get_plugins()):
            found = P.required_literals(pattern.pattern, pattern.flags)
            if found is None:
                continue
            for value in SAMPLE_VALUES:
                hit = pattern.search(value)
                if hit is None:
                    continue
                matched += 1
                folded = P.fold(hit.group(0))
                assert folded is not None
                assert any(P.fold(lit) in folded for lit in found), (
                    f"{pattern.pattern!r} matched {hit.group(0)!r}, which "
                    f"contains none of its required literals {sorted(found)}"
                )
        # Positive marker: the loop above really did compare real matches, so a
        # regression that stopped deriving literals cannot pass vacuously.
        assert matched >= len(SAMPLES) // 2, matched


# ─── the case fold ───────────────────────────────────────────────────────────


def _probe_literal_chars() -> set[str]:
    with E.configure_plugins():
        probes = [E._line_probe(), E._eligible_probe()]
    probes += [E._PEM_PROBE, E._FIELD_VALUE_PROBE]
    return {char for probe in probes for lit in probe.by_literal for char in lit}


def test_case_fold_covers_every_ignorecase_equivalent():
    """The derivation of ``_CASE_EQUIVALENT_FIXUPS``, run rather than trusted.

    A probe searches its folded literal in a folded haystack, so it must fold
    every code point ``re.IGNORECASE`` considers equal to a literal character
    onto that character. Two code points (U+0131, U+017F) are equivalent under
    ``re`` but not under ``str.lower``, and the fixup table exists for exactly
    them — this brute-forces the whole of Unicode against every character the
    LIVE probes actually index, so a detect-secrets upgrade that introduces a
    character with a new exception fails here rather than silently
    under-matching in production.
    """
    chars = _probe_literal_chars()
    assert chars, "no probe contributed a literal — nothing was checked"
    matchers = {char: re.compile(re.escape(char), re.IGNORECASE) for char in chars}
    equivalents: dict[str, int] = {char: 0 for char in chars}
    for code_point in range(0x110000):
        candidate = chr(code_point)
        # An UNCASED code point can only be IGNORECASE-matched by itself, and
        # `fold` is the identity on it (the fixup table holds only cased points,
        # and `str.lower` leaves it alone), so it cannot be a counterexample.
        if (
            candidate.lower() == candidate
            and candidate.upper() == candidate
            and candidate.casefold() == candidate
        ):
            continue
        folded = P.fold(candidate)
        for char, matcher in matchers.items():
            if matcher.match(candidate) is None:
                continue
            equivalents[char] += 1
            assert folded is not None and char in folded, (
                f"U+{code_point:04X} {candidate!r} is IGNORECASE-equal to "
                f"{char!r}, but folds to {folded!r} — a probe would miss it"
            )
    # Positive marker: every CASED literal character really was compared against
    # at least one other code point (its own opposite case, at minimum), so a
    # matcher that silently matched nothing cannot pass the assertion above. The
    # uncased characters (digits, `-`, `/`, `:`) have no equivalent by
    # construction and are excluded rather than asserted about.
    unchecked = {
        char
        for char, hits in equivalents.items()
        if not hits and char.lower() != char.upper()
    }
    assert unchecked == set(), unchecked


def test_fold_preserves_length_over_all_of_unicode():
    """The precondition `fold`'s length guard exists for: a folded offset must
    still name the character it came from, or every line index derived from it is
    wrong. U+0130 is the one code point `str.lower` expands to two characters,
    and the fixup table maps it one-to-one ahead of the lower — this is the
    statement that nothing else does, so the guard's `None` branch (fall back to
    scanning everything) stays unreachable in practice."""
    offenders = [
        f"U+{cp:04X} {chr(cp)!r}" for cp in range(0x110000) if P.fold(chr(cp)) is None
    ]
    assert offenders == []
    # Positive marker: folding really is doing case work, so a `fold` degraded to
    # the identity function could not pass the assertion above.
    assert P.fold("İIı\u017f") == "iiis"


def test_a_secret_beside_a_turkish_dotted_capital_still_redacts():
    """The end-to-end consequence of the fixup: the character that would
    otherwise desynchronize every offset costs neither a missed secret nor a
    fallback to unnarrowed scanning."""
    result = run_plain("İstanbul header\nAWS_KEY=AKIAIOSFODNN7EXAMPLE")
    assert result is not None
    assert result["found"] == ["AWS Access Key"]
    assert "AKIAIOSFODNN7EXAMPLE" not in result["text"]


# ─── LiteralProbe: the index and its verdicts ────────────────────────────────


def test_probe_indexes_each_literal_to_the_patterns_that_named_it():
    """The narrowing claim: a line's confirm set is the patterns that named one
    of its literals — not all of them, and never fewer than the patterns that
    could actually match."""
    key = re.compile(r"ghp_[0-9a-z]{36}")
    pem = re.compile(r"-----BEGIN RSA PRIVATE KEY-----")
    probe = P.LiteralProbe([key, pem])
    assert set(probe.by_literal) == {"ghp_", "-----begin rsa private key-----"}
    assert probe.by_literal["ghp_"] == (key,)
    candidates = probe.candidates("nothing\nghp_ here\n-----BEGIN RSA PRIVATE KEY-----")
    assert candidates == {1: (key,), 2: (pem,)}


def test_a_single_character_literal_keeps_its_pattern_as_a_regex():
    """`.` and `:` occur on nearly every line, so a pattern whose only required
    literal is one character narrows nothing by literal and must be run as
    itself instead — never dropped, which would skip its type entirely."""
    weak = re.compile(r"\d{8,10}:[0-9A-Za-z_-]{35}")
    probe = P.LiteralProbe([weak])
    assert probe.by_literal == {}
    assert probe.weak == (weak,)
    token = "12345678:" + "a" * 35
    assert probe.candidates(f"benign\n{token}") == {1: (weak,)}
    assert probe.candidates("benign\nnothing here") == {}


def test_a_weak_pattern_match_claims_every_line_it_touches():
    """`finditer` is non-overlapping, so a match running past a newline eats the
    bytes where the NEXT line's match could have started. Claiming only the
    starting line would drop that swallowed match — a missed secret."""
    weak = re.compile(r"a.{4}z", re.DOTALL)
    probe = P.LiteralProbe([weak])
    assert probe.weak == (weak,)
    assert probe.candidates("xxa12\n4zyy") == {0: (weak,), 1: (weak,)}


def test_a_probe_over_nothing_fails_loud():
    """A probe with neither a literal nor a pattern would answer "no line can
    match" for every input, skipping the scan entirely."""
    with pytest.raises(RuntimeError, match="contributed a literal or a regex"):
        P.LiteralProbe([])


def test_a_denylist_less_plugin_fails_loud(monkeypatch):
    """A covered plugin with no denylist contributes nothing to any probe, and
    the caller skips the expensive path on a miss — so tolerating one would drop
    every secret of its type silently."""

    class _NoDenylist:
        secret_type = "Bare Detector"  # noqa: S105 — a label, not a secret

    with E.configure_plugins():
        with pytest.raises(RuntimeError, match="supplied no denylist"):
            P.denylist_patterns([*get_plugins(), _NoDenylist()])


# ─── the engine cascade ──────────────────────────────────────────────────────


def test_probes_are_rebuilt_for_each_plugin_configuration():
    """Both plugin-derived probes are process-wide functools.cache'd on no
    arguments, so they must be cleared on every configure_plugins() entry and
    exit — the daemon serves the default and high_confidence configs in one
    process, and PLUGINS_HIGH_CONFIDENCE drops the keyword detector."""
    with E.configure_plugins():
        default_literals = set(E._line_probe().by_literal)
        assert E._line_probe.cache_info().currsize == 1
    with E.configure_plugins(high_confidence=True):
        assert E._line_probe.cache_info().currsize == 0
        high_confidence_literals = set(E._line_probe().by_literal)
    # PLUGINS_HIGH_CONFIDENCE drops the keyword detector, and with it the nouns
    # no structural detector also names. `password` is NOT one of them (the
    # keyword-context detectors carry it too), which is why this asserts on the
    # difference rather than on a noun that looks like it should be in it.
    assert "contrasena" in default_literals - high_confidence_literals
    assert not high_confidence_literals - default_literals


def test_a_benign_payload_never_reaches_scan_line(monkeypatch):
    """The point of the cascade: a large wholly-benign payload must not pay
    detect-secrets' per-line dispatch at all. Without the probe the per-line
    loop calls scan_line for every line, so this fails red."""
    calls = []
    monkeypatch.setattr(E, "scan_line", lambda line: calls.append(line) or iter(()))
    text = "\n".join(
        f"2024-01-15T10:30:{i % 60:02d}Z INFO handled request {i} in {i % 97}ms"
        for i in range(500)
    )
    assert run_plain(text) is None
    assert calls == []


def test_a_candidate_line_confirms_against_a_small_subset_of_the_denylists():
    """The per-line win: a line carrying a credential noun is confirmed against
    the patterns that named that noun, not against all of them. Both bounds
    matter — a set that shrank to nothing would stop detecting, and one that grew
    to the whole denylist would mean the index bought nothing."""
    with E.configure_plugins():
        total = len(P.denylist_patterns(get_plugins()))
        candidates = E._line_probe().candidates(
            'a benign line of prose\npassword = "hunter2000000000000"\n'
        )
    assert set(candidates) == {1}, candidates
    assert 0 < len(candidates[1]) < total, (len(candidates[1]), total)


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda s: s["name"])
def test_every_detector_sample_still_redacts_through_the_cascade(sample):
    """One end of the differential claim, per detector: the probes are a
    performance gate, so every sample the corpus covers must still be found."""
    value = "".join(sample["parts"])
    result = run_plain(f'{sample["name"].lower().replace(" ", "_")} = "{value}"', cfg())
    assert result is not None
    assert value not in result["text"]


def _open_every_probe(monkeypatch):
    """Replace all four probes with one that rules nothing out, so the engine
    does the unnarrowed work it did before they existed."""
    catch_all = P.LiteralProbe([re.compile(".", re.DOTALL)])

    def _cached_stub():
        """A stand-in for a functools.cache'd accessor: configure_plugins() calls
        cache_clear() on the real one, so the replacement must answer to it."""
        stub = lambda: catch_all  # noqa: E731 — one expression, named below
        stub.cache_clear = lambda: None
        return stub

    monkeypatch.setattr(E, "_line_probe", _cached_stub())
    monkeypatch.setattr(E, "_eligible_probe", _cached_stub())
    monkeypatch.setattr(E, "_PEM_PROBE", catch_all)
    monkeypatch.setattr(E, "_FIELD_VALUE_PROBE", catch_all)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "\n".join(f'sample_{i} = "{v}"' for i, v in enumerate(SAMPLE_VALUES)),
            id="every-sample",
        ),
        pytest.param("\n".join(SAMPLE_VALUES), id="bare-values"),
        pytest.param(
            "AKIA\nIOSFODNN7EXAMPLE\nghp_\n" + "0123456789abcdefghijklmnopqrstuvwxyz",
            id="newline-split",
        ),
        pytest.param(
            "A​KIAIOSFODNN7EXAMPLE and AKIAIOSFODNN7EXAMPLE", id="invisible-spliced"
        ),
        pytest.param(
            (REPO_ROOT / "python/agent_sanitizer/secrets/engine.py").read_text(),
            id="this-engine-source",
        ),
        pytest.param(
            (REPO_ROOT / "tests/secrets/secret-format-samples.json").read_text(),
            id="the-sample-corpus-file",
        ),
    ],
)
def test_redaction_is_byte_identical_with_and_without_the_probes(text, monkeypatch):
    """The strongest statement of the whole change: the probes only decide WHERE
    to look, never WHAT counts. Output and reported types must match the
    unnarrowed engine exactly — on real secrets, on newline-split ones, on
    invisible-spliced ones, and on a large body of legitimate source."""
    narrowed = run_plain(text, cfg())
    _open_every_probe(monkeypatch)
    unnarrowed = run_plain(text, cfg())
    assert narrowed == unnarrowed


def test_the_differential_corpus_actually_detects_something():
    """Non-vacuity for the test above: an all-None comparison would pass it."""
    result = run_plain("\n".join(SAMPLE_VALUES), cfg())
    assert result is not None
    assert len(set(result["found"])) >= 10, result["found"]
