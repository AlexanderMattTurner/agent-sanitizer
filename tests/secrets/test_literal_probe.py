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


def _engine_probes() -> dict[str, P.LiteralProbe]:
    with E.configure_plugins():
        named = {"line": E._line_probe(), "eligible": E._eligible_probe()}
    return named | {"pem": E._PEM_PROBE}


def _probe_literal_chars() -> set[str]:
    """Every character a probe searches for in a FOLDED haystack.

    ``_FIELD_NAME_ANCHOR`` belongs here alongside the probes: it is compiled
    without ``re.IGNORECASE`` and matched against ``fold``'s view precisely so it
    answers the same case-insensitive question the regex it gates asks, so its
    own letters need the same equivalence coverage. Its literals are not in any
    probe's index (`key`'s `k` and `y` reach the fold through nothing else), so
    omitting it would leave them unchecked."""
    anchor_letters = {char for char in E._FIELD_NAME_ANCHOR.pattern if char.isalpha()}
    return anchor_letters | {
        char
        for probe in _engine_probes().values()
        for lit in probe.by_literal
        for char in lit
    }


def test_every_engine_probe_indexes_at_least_one_literal():
    """Each gate must narrow by LITERAL. A probe whose patterns all fall to
    `weak` answers `may_match` by running the very whole-payload regex the gate
    exists to skip, so it becomes pure overhead — and every other test here
    stays green, because they assert on redaction OUTPUT. Asserted per probe,
    not over their union: the union is non-empty while any one of them is."""
    empty = {name for name, probe in _engine_probes().items() if not probe.by_literal}
    assert empty == set()


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


def test_the_fold_is_context_free_over_all_of_unicode():
    """The other precondition of folding a literal in ISOLATION and searching it
    inside a folded haystack: a code point whose fold depends on its NEIGHBOURS
    would make the two disagree, and the probe would skip the line.

    `str.lower` has one such case — a word-final capital sigma lowers to U+03C2
    and any other to U+03C3 — which the fixup table removes by mapping both
    sigmas onto U+03C3. Checking each code point in isolation, as the test above
    does, cannot see a context-dependent one at all, so this is what makes that
    per-code-point methodology a complete derivation.
    """
    offenders = []
    for code_point in range(0x110000):
        candidate = chr(code_point)
        folded = P.fold(candidate)
        if folded is None:
            continue
        for before, after in (("a", ""), ("", "a")):
            if P.fold(before + candidate + after) != before + folded + after:
                offenders.append(f"U+{code_point:04X} {candidate!r} before {after!r}")
    assert offenders == []
    # Positive marker: a fold that changed nothing would satisfy the loop above
    # vacuously, so pin the case the loop exists for.
    assert P.fold("\u03a3") == P.fold("\u03c2") == "\u03c3"


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


class _CountingText(str):
    """A text that counts every newline scan run over it — both the searches and
    the gap counts, since the walk spends one of each per line it advances."""

    def __new__(cls, body: str) -> "_CountingText":
        text = super().__new__(cls, body)
        text.finds = 0
        text.counts = 0
        return text

    def find(self, *args) -> int:  # type: ignore[override]
        self.finds += 1
        return super().find(*args)

    def count(self, *args) -> int:  # type: ignore[override]
        self.counts += 1
        return super().count(*args)


def test_line_attribution_scans_the_newlines_once_not_once_per_hit():
    """A hit that does not advance the line must not scan the text for a newline:
    one long line with a hit per credential noun is attacker-shaped input against
    a shared daemon, and re-scanning per hit is quadratic in it.

    Bounded on SCAN COUNT, not wall clock, so the guard cannot go quiet on a
    faster runner — and both operations the walk spends are counted, since a
    bound on only one of them would be blind to the other becoming per-hit.
    """
    line = "key " * 4000
    text = _CountingText("\n".join([line] * 3))
    hits = [(m.start(), m.end(), ()) for m in re.finditer("key", text)]
    assert len(hits) == 12000
    P._patterns_by_line(text, hits)
    # 2 newlines to walk, plus the opening search that finds the first one.
    assert text.finds == 3
    # One gap count per line that HAS a hit, never one per hit — and none for the
    # first line, whose index the opening search already settled.
    assert text.counts == 2


def _attribute_naively(text, hits):
    """``_patterns_by_line`` spelled the slow, obviously-correct way: count the
    newlines before each line the span covers, from the start of the text every
    time. The real one carries a running line number and a remembered next-newline
    position instead, and that bookkeeping is what this pins."""
    claims = {}
    for start, end, patterns in hits:
        first = text.count("\n", 0, start)
        for index in range(first, first + text.count("\n", start, end) + 1):
            claims.setdefault(index, set()).update(patterns)
    return {index: tuple(patterns) for index, patterns in claims.items()}


_ATTRIBUTION_TEXTS = [
    "",
    "no newline at all, several key hits: key key key",
    "\n\nkey\n\n",  # blank lines on both sides of the only hit
    "a\nkey\n\nkey key\nb\n",
    "key" + "x" * 300 + "\nkey\n" + "key " * 40,
    "\n".join(f"line {i} key token" for i in range(60)),
    "key" * 200,  # one long line, a hit every 3 chars
]


@pytest.mark.parametrize("text", _ATTRIBUTION_TEXTS, ids=range(len(_ATTRIBUTION_TEXTS)))
@pytest.mark.parametrize("width", [3, 7, 40], ids=lambda w: f"span{w}")
# A weak pattern's match can begin ON a newline, which is the boundary both
# cursors are counted from — so one marker deliberately matches one.
@pytest.mark.parametrize("marker", ["key", "[k\n]"], ids=["key", "key-or-newline"])
def test_line_attribution_matches_the_naive_count(text, width, marker):
    """Spans of several widths over texts with no newline, only newlines, and hits
    that straddle one: the walk's answer must equal the naive count exactly. An
    off-by-one in either cursor claims a neighbouring line instead of the real
    one, which drops the line a secret is on."""
    compiled = re.compile(marker)
    hits = [
        (m.start(), min(m.start() + width, len(text)), (compiled,))
        for m in compiled.finditer(text)
    ]
    # Non-vacuity: an empty hit list makes both sides `{}` for free.
    assert hits or text == ""
    assert P._patterns_by_line(text, hits) == _attribute_naively(text, hits)


def test_a_literal_is_reported_once_per_line_not_once_per_occurrence(monkeypatch):
    """A line is a candidate or it is not, so a literal repeated across it need
    only be reported once. Reporting every occurrence made the attribution below
    scale with the payload's length rather than its line count — the cost that
    took a megabyte of one line into multiple seconds."""
    probe = P.LiteralProbe([re.compile("ghp_[0-9a-f]{36}")])
    reported = []
    monkeypatch.setattr(
        P, "_patterns_by_line", lambda text, hits: reported.append(list(hits)) or {}
    )
    probe.candidates("ghp_" * 4000 + "\nnothing\n" + "ghp_" * 4000)
    starts = [start for start, _end, _patterns in reported[0]]
    assert starts == [0, 16009]


def test_a_multi_line_literal_does_not_skip_an_occurrence_inside_its_own_span():
    """The per-line skip resumes past the line an occurrence STARTS on, not past
    the line it ENDS on. For a literal carrying a newline the two differ, and
    resuming past the end would step over an occurrence beginning inside the
    first one's span — leaving the line its match really sits on unclaimed."""
    pattern = re.compile("aa\naa[0-9]")
    probe = P.LiteralProbe([pattern])
    assert probe.by_literal == {"aa\naa": (pattern,)}
    text = "aa\naa\naa1"
    assert pattern.search(text).start() == 3
    assert probe.candidates(text) == {0: (pattern,), 1: (pattern,), 2: (pattern,)}


def test_the_candidate_probe_yields_to_a_compute_deadline():
    """The probe sweeps the whole payload per literal, so a payload big enough to
    make it expensive is exactly the one whose caller set a budget to stop it.
    Without the check threaded through, the budget could not interrupt this
    stage at all."""
    probe = P.LiteralProbe([re.compile("ghp_[0-9a-f]{36}")])
    stages = []

    def check(stage: str) -> None:
        stages.append(stage)
        raise E.RedactionBudgetExceeded(stage)

    with pytest.raises(E.RedactionBudgetExceeded):
        probe.candidates("ghp_" + "a" * 36, check)
    assert stages == ["candidate-line literal probe"]


def test_the_engine_hands_the_probe_the_requests_own_deadline(monkeypatch):
    """The wiring, not just the parameter: a probe that accepts a deadline check
    it is never given cannot be interrupted. `check` is positional here, so
    omitting it is a TypeError, and the deadline it is bound to must be the one
    carrying the request's budget rather than the unbudgeted singleton."""
    seen = []

    class _Spy:
        def candidates(self, text, check):
            seen.append(check)
            return {}

    def stub() -> _Spy:
        return _Spy()

    stub.cache_clear = lambda: None
    monkeypatch.setattr(E, "_line_probe", stub)
    run_plain("benign prose", cfg(compute_budget_seconds=5.0))
    assert [c.__self__.expires_at is not None for c in seen] == [True]


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
    """Replace every probe with one that rules nothing out, so the engine does the
    unnarrowed work it would without them.

    The catch-all's one pattern has no required literal, so it lands in ``weak``
    and therefore has no window to centre — so its plan narrows nothing and the
    cross-line sweep covers the whole text.
    ``_FIELD_NAME_ANCHOR`` is opened separately, to the empty pattern: it matches
    at every position, so the field-value pass tries its regex everywhere, which
    is exactly what ``re.sub`` does."""
    catch_all = P.LiteralProbe([re.compile(".", re.DOTALL)])
    monkeypatch.setattr(E, "_FIELD_NAME_ANCHOR", re.compile(""))

    def _cached_stub():
        """A stand-in for a functools.cache'd accessor: configure_plugins() calls
        cache_clear() on the real one, so the replacement must answer to it."""
        stub = lambda: catch_all  # noqa: E731 — one expression, named below
        stub.cache_clear = lambda: None
        return stub

    monkeypatch.setattr(E, "_line_probe", _cached_stub())
    monkeypatch.setattr(E, "_eligible_probe", _cached_stub())
    monkeypatch.setattr(E, "_PEM_PROBE", catch_all)


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
            (REPO_ROOT / "python/agent_sanitizer/secrets/engine.py").read_text(
                encoding="utf-8"
            ),
            id="this-engine-source",
        ),
        pytest.param(
            (REPO_ROOT / "tests/secrets/secret-format-samples.json").read_text(
                encoding="utf-8"
            ),
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


# ─── inspect_width: the AST bound the windows rest on ────────────────────────


@pytest.mark.parametrize(
    "pattern, expected",
    [
        # A run of literals is its own width.
        (r"ghp_", 4),
        # A class, a negated class and `.` each consume exactly one character.
        (r"[a-z][^a-z].", 3),
        # A bounded repeat contributes its MAXIMUM, never its minimum.
        (r"a{2,7}", 7),
        (r"(?:ab){3}", 6),
        # An alternation is as wide as its widest arm.
        (r"(?:ab|abcdef)", 6),
        # A start/end-of-text anchor inspects nothing a window can hide.
        (r"^abc$", 3),
        (r"abc\Z", 3),
        # A word boundary reads the character to its RIGHT, so its extent must
        # reach one past it. A LEADING one over-counts by one, which is the safe
        # direction.
        (r"abc\b", 4),
        (r"abc\B", 4),
        (r"\babc", 4),
        # A trailing lookahead's own width is INCLUDED: a caller that truncates
        # at the bound must not cut the assertion short and turn a match into a
        # miss. Same for a negative one.
        (r"abc(?=defg)", 7),
        (r"abc(?!defg)", 7),
        # A lookBEHIND adds nothing — it reads left, which `pos` never hides.
        (r"(?<![A-Za-z0-9])abc", 3),
        # Unbounded repeats have no bound, in any spelling.
        (r"a+", None),
        (r"a*", None),
        (r"a{2,}", None),
        (r"a+?", None),
        # A group whose body is unbounded poisons the whole pattern.
        (r"x(?:ab+)y", None),
        # One unbounded ARM is enough, even beside a bounded one.
        (r"(?:ab|c+)", None),
        # A backreference's width belongs to another group, so it is refused
        # rather than guessed.
        (r"(a)\1", None),
    ],
)
def test_inspect_width_bounds_how_far_right_a_match_reads(pattern, expected):
    assert P.inspect_width(pattern, 0) == expected


@pytest.mark.parametrize(
    "spans, expected",
    [
        ([], ()),
        ([(5, 9), (0, 3)], ((0, 3), (5, 9))),
        # Overlapping ranges merge.
        ([(0, 5), (3, 9)], ((0, 9),)),
        # So do ABUTTING ones: scanned apart, a match straddling their shared
        # edge would fall outside both.
        ([(0, 5), (5, 9)], ((0, 9),)),
        # A range wholly inside another does not shorten it.
        ([(0, 20), (5, 9)], ((0, 20),)),
    ],
)
def test_coalesce_merges_overlapping_and_abutting_ranges(spans, expected):
    assert P._coalesce(spans) == expected


# ─── LiteralProbe.plan ────────────────────────────────────────────────────


def _window_holds(windows, match):
    return any(start <= match.start() and match.end() <= end for start, end in windows)


@pytest.mark.parametrize(
    "pattern, text",
    [
        # The literal sits at the match's START.
        (r"ghp_[A-Za-z0-9]{6}", "noise ghp_abc123 more noise"),
        # …and at its END, so the window must reach LEFT of the hit.
        (
            r"[A-Za-z0-9]{14}\.atlasv1\.[a-z]{4}",
            "x" * 40 + "abcdefghijklmn.atlasv1.wxyz",
        ),
        # A case-insensitive pattern found through the folded haystack.
        (
            r"(?i)-----begin rsa private key-----",
            "j" * 500 + "-----BEGIN RSA PRIVATE KEY-----",
        ),
        # Several occurrences, including two close enough to coalesce.
        (r"kia[0-9]{4}", "kia1234 kia5678" + "q" * 900 + "kia9012"),
        # A match at the very start and one at the very end, where the window
        # would run off either edge if it were not clamped.
        (r"kia[0-9]{4}", "kia1111" + "z" * 800 + "kia2222"),
    ],
)
def test_windows_contain_every_match_of_a_windowable_pattern(pattern, text):
    """The soundness claim the cross-line narrowing rests on: a window holds
    every match of the pattern whose literal centred it, span and all."""
    compiled = re.compile(pattern)
    probe = P.LiteralProbe([compiled])
    assert probe.plan(text).full_scans == (), "pattern should be windowable"
    windows = probe.plan(text).windows
    assert windows is not None
    matches = list(compiled.finditer(text))
    assert matches, "no match to contain — the case would pass vacuously"
    assert [m.group(0) for m in matches if not _window_holds(windows, m)] == []
    # Non-vacuous in the other direction too: the windows must actually NARROW,
    # or they would trivially contain everything.
    assert sum(end - start for start, end in windows) < len(text)


def test_windows_finditer_over_them_finds_what_a_full_sweep_finds():
    """The windows as the engine consumes them — `finditer(text, pos, endpos)`
    per range, which is the form that keeps a lookbehind reading real bytes."""
    compiled = re.compile(r"(?<![A-Za-z0-9])kia[0-9]{4}(?![A-Za-z0-9])")
    probe = P.LiteralProbe([compiled])
    text = "kia1111 xkia2222 " + "z" * 600 + " kia3333x kia4444"
    windows = probe.plan(text).windows
    assert windows is not None
    windowed = [
        m.group(0)
        for start, end in windows
        for m in compiled.finditer(text, start, end)
    ]
    assert windowed == [m.group(0) for m in compiled.finditer(text)]
    assert windowed == ["kia1111", "kia4444"]


def test_windows_keep_a_word_boundary_reading_real_bytes():
    """`endpos` makes the text LOOK like it ends there, and `\\b`/`\\B` read the
    character to their right: `abc\\B` matches in `zabcq` but not in `zabc`. So a
    window has to reach one character past the assertion — bounding it at the
    consumed width instead drops the match with no error."""
    compiled = re.compile(r"abc\B")
    probe = P.LiteralProbe([compiled])
    text = "z" * 400 + "abcq" + "y" * 400
    windows = probe.plan(text).windows
    assert windows is not None
    windowed = [
        m.span() for start, end in windows for m in compiled.finditer(text, start, end)
    ]
    assert windowed == [m.span() for m in compiled.finditer(text)] == [(400, 403)]
    assert sum(end - start for start, end in windows) < len(text)


def test_a_pattern_with_an_unbounded_extent_is_never_windowed():
    """An unbounded match can start arbitrarily far left of its literal, so no
    window can hold it — it must be handed back for a full scan instead."""
    unbounded = re.compile(r"xox[a-z]-[0-9]+-[a-z0-9]+")
    probe = P.LiteralProbe([unbounded])
    assert P.inspect_width(unbounded.pattern, unbounded.flags) is None
    # None, not an empty tuple: an empty tuple means "matches nowhere", and this
    # probe has no way to tell — and the pattern is handed back for a full scan.
    plan = probe.plan("xoxb-1-abc")
    assert plan == P.SweepPlan(None, ())


def test_a_pattern_with_no_indexed_literal_is_never_windowed():
    """Nothing to centre a window on, so it joins the full-scan set."""
    weak = re.compile(r"[MNO][a-zA-Z]{4}\.[a-z]{3}")
    probe = P.LiteralProbe([weak])
    assert probe.by_literal == {}
    assert probe.plan("Mabcd.xyz") == P.SweepPlan(None, ())


def test_a_literal_whose_windows_span_the_whole_text_declines_to_narrow():
    """Windowing that covers everything is pure overhead, and since the caller's
    patterns are shared across literals there is nothing left to narrow: the
    probe says so with None rather than handing back the whole text as a
    'window'."""
    probe = P.LiteralProbe([re.compile(r"ab[0-9]{200}")])
    assert probe.plan("ab" + "0" * 8) == P.SweepPlan(None, ())


def test_windows_finds_overlapping_literal_occurrences():
    """The scan advances one character, not one literal width. `aa` occurs twice
    in `aaa`, and only the SECOND occurrence is inside the real match — a scan
    that resumed past each hit would centre on the first and miss it."""
    compiled = re.compile(r"aa[0-9]")
    probe = P.LiteralProbe([compiled])
    text = "x" * 200 + "aaa1" + "y" * 200
    windows = probe.plan(text).windows
    assert windows is not None
    matches = list(compiled.finditer(text))
    assert [m.group(0) for m in matches] == ["aa1"]
    assert all(_window_holds(windows, m) for m in matches)


def test_the_window_probe_yields_to_a_compute_deadline():
    stages: list[str] = []

    def check(stage: str) -> None:
        stages.append(stage)
        raise RuntimeError("budget spent")

    probe = P.LiteralProbe([re.compile(r"ghp_[a-z]{4}")])
    with pytest.raises(RuntimeError, match="budget spent"):
        probe.plan("ghp_abcd", check)
    assert stages == ["candidate-window literal probe"]


# ─── the field-value anchor ──────────────────────────────────────────────────


def _mark_value(match):
    return match.group("field_prefix") + "<<" + match.group("secret_value") + ">>"


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("", id="empty"),
        pytest.param("token", id="noun-with-no-value"),
        pytest.param("token=" + "a" * 30, id="plain"),
        pytest.param("TOKEN = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'", id="uppercase-noun"),
        # A noun starting INSIDE an earlier noun's span: `secret` consumes six
        # characters, and `token` begins one character inside them. An anchor
        # scan that skipped past each hit would never try this position.
        pytest.param("secretoken: " + "z" * 25, id="overlapping-nouns"),
        pytest.param("passwordtoken=" + "c" * 30, id="adjacent-nouns"),
        # The IGNORECASE equivalences the fold exists for, spliced into a noun.
        pytest.param("api_keİ: " + "q" * 25, id="dotted-capital-i"),
        pytest.param("ſecret: " + "f" * 30, id="long-s"),
        # Multiple matches, so the resume-at-previous-end order is exercised.
        pytest.param("PASSWORD: " + "g" * 30 + " token: " + "h" * 30, id="two-matches"),
        # Every operator spelling, across lines, so `^`/`$` under re.MULTILINE
        # see the same text a full sweep shows them.
        pytest.param(
            "x" * 60 + "\nsecret := " + "d" * 40 + ';\nAUTH_TOKEN=>"' + "e" * 30 + '"',
            id="multiline-operators",
        ),
        pytest.param(
            (REPO_ROOT / "python/agent_sanitizer/secrets/engine.py").read_text(
                encoding="utf-8"
            ),
            id="this-engine-source",
        ),
    ],
)
def test_the_field_value_sweep_is_byte_identical_to_the_full_sub(text):
    """The anchor only decides WHERE `FIELD_VALUE_RE` is tried. Output must equal
    `re.sub`'s exactly — the pass rewrites the payload, so an over-match here
    would mangle legitimate content and an under-match would leak a credential."""
    assert E._redact_field_values(text, _mark_value) == E.FIELD_VALUE_RE.sub(
        _mark_value, text
    )


def test_the_field_value_sweep_corpus_actually_matches_something():
    """Non-vacuity: a corpus the regex never matches would pass the test above
    with two untouched copies of the input."""
    assert "<<" in E._redact_field_values("token=" + "a" * 30, _mark_value)


def test_the_field_value_anchor_matches_wherever_the_regex_can_start():
    """The claim the anchor rests on, stated over the regex itself: every start
    position `FIELD_VALUE_RE` can match at is one the anchor matches at."""
    text = (
        "secretoken: " + "z" * 25 + "\nAPI-KEY => " + "y" * 30 + "\n"
        "mypassword: " + "x" * 30 + "\nclient_secret_v2:=" + "w" * 30
    )
    folded = P.fold(text)
    assert folded is not None
    starts = {m.start() for m in E.FIELD_VALUE_RE.finditer(text)}
    assert starts, "no match — the assertion below would be vacuous"
    uncovered = {
        start for start in starts if E._FIELD_NAME_ANCHOR.match(folded, start) is None
    }
    assert uncovered == set()


def test_the_field_value_sweep_falls_back_when_the_fold_is_refused(monkeypatch):
    """A fold that changed a length would desynchronize the anchor's offsets from
    the text's, so the pass reverts to the full sweep rather than trust them."""
    monkeypatch.setattr(E, "fold", lambda text: None)
    text = "token=" + "a" * 30
    assert E._redact_field_values(text, _mark_value) == E.FIELD_VALUE_RE.sub(
        _mark_value, text
    )
    assert "<<" in E._redact_field_values(text, _mark_value)


def test_the_field_value_sweep_yields_to_a_compute_deadline():
    """The anchor loop is one iteration per credential noun in the payload, so an
    exhausted budget must stop it there rather than after the whole pass."""
    with pytest.raises(E.RedactionBudgetExceeded, match="during field-value scan"):
        E._redact_field_values("token=" + "a" * 30, _mark_value, E._Deadline(-1))


def test_fold_by_replacement_chain_equals_one_translate():
    """`fold` swaps `str.translate` for a chain of `str.replace` on the ground
    that no fixup can feed another. That is checked at import time by
    `_SELF_FEEDING`; this states the consequence it buys."""
    exotics = "".join(chr(code_point) for code_point in P._CASE_EQUIVALENT_FIXUPS)
    for text in (exotics, exotics * 3, "aA" + exotics + "Zz", "plain ascii", ""):
        expected = text.translate(P._CASE_EQUIVALENT_FIXUPS).lower()
        assert P.fold(text) == expected, repr(text)


def test_no_window_is_reported_when_a_windowable_pattern_matches_nowhere():
    """The other side of the None contract: an empty tuple is a real verdict —
    these patterns cannot match anywhere — so the caller may skip the scan."""
    probe = P.LiteralProbe([re.compile(r"ghp_[a-z]{4}")])
    assert probe.plan("nothing credential-shaped here") == P.SweepPlan((), ())


def test_the_field_value_sweep_terminates_under_a_zero_width_anchor(monkeypatch):
    """`Pattern.search(s, pos)` CLAMPS a pos past the end back to `len(s)` instead
    of returning None, so an anchor that can match empty is re-found at the same
    position forever unless the loop bounds its own cursor. The empty anchor is
    also the shape `_open_every_probe` installs to make the pass try every
    position, so this is the differential harness's own precondition."""
    monkeypatch.setattr(E, "_FIELD_NAME_ANCHOR", re.compile(""))
    text = "token=" + "a" * 30 + " tail"
    assert E._redact_field_values(text, _mark_value) == E.FIELD_VALUE_RE.sub(
        _mark_value, text
    )
