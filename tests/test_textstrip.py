"""Tests for the stdlib-only strip (:mod:`agent_sanitizer.textstrip`).

``textstrip.strip_untrusted`` is a pure-Python port of ``src/invisible.mjs``'s
``applyLayer1`` (ANSI + invisible-char removal) for no-Node contexts. These
assert the load-bearing properties directly rather than trusting the port to
match the JS by inspection:

* it deletes EVERY code point in the pinned cross-language charset (so it cannot
  under-strip relative to the JS layer regardless of this interpreter's Unicode
  version — the ``Cf`` version-drift regression);
* over the shared golden corpus it never leaves a payload char that the recorded
  JS output removed, and where a case is comparable at all it matches the
  recording BYTE FOR BYTE — the only place the two regex ENGINES are checked
  against each other on the one pattern they now share; and
* the escape grammar it compiles is usable as a shipped artifact: plain ``re``,
  no flags, no groups, and linear on a repartitioning run.
"""

import json
import re
import time
import unicodedata
import warnings
from collections.abc import Callable

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests._helpers import REPO_ROOT, ensure_python_pkg_on_path

ensure_python_pkg_on_path()

from agent_sanitizer.invisible import (  # noqa: E402
    cf_codepoints,
    control_introducers,
    escape_sequence_pattern,
    extra_codepoints,
    invisible_charset,
)
from agent_sanitizer.textstrip import ANSI_RE, strip_untrusted  # noqa: E402

_INVISIBLE = invisible_charset()


# ─── ANSI / escape grammar ───────────────────────────────────────────────────

# (name, input, expected) — one row per arm of the ANSI alternation plus the
# unconditional lone-ESC sweep. Expected output is the visible remainder.
_ANSI_CASES = [
    ("csi_sgr_color", "a\x1b[31mred\x1b[0mb", "aredb"),
    ("csi_cursor_move", "x\x1b[2Ky", "xy"),
    # No final byte, so this completes NO sequence: the JS layer classifies it
    # orphan-csi and removes only the raw ESC in its residual sweep, leaving
    # `[1` visible. The port's own general arm used to eat the bracket too —
    # deleting a visible byte the authoritative layer keeps, which is the
    # over-strip direction and a divergence no equivalence test could see while
    # each port hand-wrote its own grammar.
    ("csi_truncated_leaves_bracket", "a\x1b[1", "a[1"),
    ("osc_title_bel", "a\x1b]0;title\x07b", "ab"),
    ("osc_title_st", "a\x1b]0;title\x1b\\b", "ab"),
    ("general_charset_select", "a\x1b(Bb", "ab"),
    ("general_ris_reset", "a\x1bcb", "ab"),
    ("general_fe_two_char", "a\x1bMb", "ab"),
    ("lone_esc_end", "ab\x1b", "ab"),
    ("esc_before_newline", "a\x1b\nb", "a\nb"),
    ("double_esc_swept", "a\x1b\x1b", "a"),  # neither ESC starts a sequence; both swept
    # C1 (8-bit) encodings: a single U+009B/U+009D replaces ESC-[ / ESC-] and
    # must be consumed as a whole sequence, not left for the terminal to render.
    ("c1_csi_erase", "hi\x9b2Jbye", "hibye"),
    ("c1_csi_sgr", "a\x9b31mred\x9b0mb", "aredb"),
    ("c1_osc_c1_st", "a\x9d0;evil\x9cb", "ab"),
    ("c1_osc_bel", "a\x9d0;evil\x07b", "ab"),
    # An OSC body is attacker-controlled payload text, so an UNTERMINATED string
    # fails closed: everything from the introducer on is dropped, matching
    # scanOsc. (The port used to leave the body as visible text — an under-strip
    # relative to the JS layer, which the parity guard could not see because the
    # survivors were visible characters, not charset members.)
    ("osc_unterminated_fails_closed", "a\x1b]0;evil-payload", "a"),
    ("c1_osc_unterminated_fails_closed", "a\x9d0;evil-payload", "a"),
    # A bare ESC / a nested C1 OSC ABORTS the string: the token ends before that
    # byte, which is then re-read as its own sequence.
    ("osc_aborted_by_esc", "a\x1b]0;ev\x1b[31mtail", "atail"),
    ("osc_aborted_by_c1_osc", "a\x9d0;ev\x9d9;x\x07tail", "atail"),
    # The other four ECMA-48 control strings — DCS, SOS, PM, APC — carry the
    # same attacker-controlled payload an OSC body does, so the same arm
    # consumes each whole. `ESC P` is the one that hid: `P` is also a CSI final
    # byte, so the general arm took the introducer and left `q#payload` visible.
    ("dcs_st", "a\x1bPq#payload\x1b\\b", "ab"),
    ("sos_st", "a\x1bXpayload\x1b\\b", "ab"),
    ("pm_st", "a\x1b^payload\x1b\\b", "ab"),
    ("apc_st", "a\x1b_payload\x1b\\b", "ab"),
    # All four C1 string introducers, so dropping any one from the arm's
    # introducer class goes red here.
    ("c1_dcs_c1_st", "a\x90payload\x9cb", "ab"),
    ("c1_sos_c1_st", "a\x98payload\x9cb", "ab"),
    ("c1_pm_c1_st", "a\x9epayload\x9cb", "ab"),
    ("c1_apc_c1_st", "a\x9fpayload\x9cb", "ab"),
    ("dcs_aborted_by_esc", "a\x1bPbody\x1b[31mtail", "atail"),
    # Unterminated, so the fail-closed arm drops the tail — the same answer the
    # OSC rows above give, and the reason a lone C1 introducer no longer leaves
    # the text after it in place.
    ("apc_unterminated_fails_closed", "a\x1b_evil-payload", "a"),
    ("c1_dcs_unterminated_fails_closed", "a\x90b", "a"),
    ("c1_apc_unterminated_fails_closed", "a\x9fb", "a"),
    # A line break BOUNDS an unterminated control string: only the rest of that
    # ONE line is dropped, later lines survive. Without the bound a single stray
    # `ESC ]` deleted every later line, so a consumer reading the strip as a
    # RECORD (a model, not a terminal) was blinded to the whole tail behind a
    # clean-looking prefix. The break stays visible; the same-line payload goes.
    (
        "osc_unterminated_bounded_by_newline",
        "line1\n\x1b]stray\nline2 MUST SEE\nline3\n",
        "line1\n\nline2 MUST SEE\nline3\n",
    ),
    (
        "c1_apc_unterminated_bounded_by_newline",
        "keep\n\x9fstray\ntail\n",
        "keep\n\ntail\n",
    ),
    # CAN (U+0018) and SUB (U+001A) cancel a control string, consuming the cancel
    # byte with the body — ECMA-48 and xterm behavior.
    ("osc_cancelled_by_can", "x\x1b]t\x18rest", "xrest"),
    ("osc_cancelled_by_sub", "x\x1b]t\x1arest", "xrest"),
    # The other half of the abort-set decision: a C0 control that is NOT in the
    # set (and DEL) stays BODY. DEC's parser ignores/``put``s these rather than
    # ending the string, so aborting here would splice ``PAYLOAD`` — text the
    # terminal swallows — back into the model's view.
    ("osc_body_swallows_nul", "x\x1b]0;a\x00PAYLOAD\x07y", "xy"),
    ("osc_body_swallows_vt", "x\x1b]0;a\x0bPAYLOAD\x07y", "xy"),
    ("osc_body_swallows_ff", "x\x1b]0;a\x0cPAYLOAD\x07y", "xy"),
    ("osc_body_swallows_us", "x\x1b]0;a\x1fPAYLOAD\x07y", "xy"),
    ("osc_body_swallows_del", "x\x1b]0;a\x7fPAYLOAD\x07y", "xy"),
    # The full ECMA-48 CSI: private parameter markers `<=>`, intermediate bytes
    # (0x20-0x2F), and every final byte 0x40-0x7E.
    ("csi_private_gt_marker", "a\x1b[>4;1mb", "ab"),
    ("csi_private_eq_marker", "a\x1b[=5hb", "ab"),
    ("csi_space_intermediate", "a\x1b[1 qb", "ab"),
    ("csi_sgr_mouse_report", "a\x1b[<0;1;1Mb", "ab"),
    ("csi_save_cursor", "a\x1b[sb", "ab"),
    ("csi_restore_cursor", "a\x1b[ub", "ab"),
    ("c1_csi_private_marker", "a\x9b>4;1mb", "ab"),
    # DEC's parser swallows a malformed CSI body through its final byte too.
    ("csi_malformed_body", "a\x1b[(1mb", "ab"),
    # ECMA-35 escapes: intermediates (0x20-0x2F), then a final (0x30-0x7E).
    ("esc_decsc", "a\x1b7b", "ab"),
    ("esc_deckpam", "a\x1b=b", "ab"),
    ("esc_decaln", "a\x1b#8b", "ab"),
    ("esc_space_intermediate", "a\x1b Fb", "ab"),
    # Another introducer ABORTS a sequence: a terminal drops the swallowed bytes
    # and re-reads the introducer, and a cancelled ESC never joins later text.
    ("csi_aborted_by_esc", "a\x1b[12 \x1b[31mb", "ab"),
    ("cancelled_esc_never_joins", "\x1b\x1b[32m[0m tail", "[0m tail"),
    ("csi_cancelled_by_can", "a\x1b[12\x18b", "ab"),
]


@pytest.mark.parametrize(
    "text,expected",
    [(c[1], c[2]) for c in _ANSI_CASES],
    ids=[c[0] for c in _ANSI_CASES],
)
def test_ansi_sequences_removed(text: str, expected: str) -> None:
    assert strip_untrusted(text) == expected


def test_no_raw_esc_survives() -> None:
    """The unconditional ESC sweep — not the sequence regex — is the guarantee: a
    residual ESC the alternation can't consume must still be gone."""
    for text in ("\x1b", "\x1b\x1b\x1b", "plain\x1b", "\x1b\x00tail", "a\x1b"):
        assert "\x1b" not in strip_untrusted(text), repr(text)


@pytest.mark.parametrize(
    "sequence",
    [
        "\x1b[>4;1m",
        "\x1b[=5h",
        "\x1b[1 q",
        "\x1b[<0;1;1M",
        "\x1b[s",
        "\x1b[u",
        "\x1b[(1m",
        "\x1b7",
        "\x1b=",
        "\x1b#8",
    ],
)
def test_ansi_re_removes_a_whole_sequence(sequence: str) -> None:
    """``ANSI_RE`` alone, with no residual sweep behind it: a stdlib consumer
    that compiles the shipped pattern gets the whole sequence removed."""
    assert ANSI_RE.sub("", sequence) == ""


# The sequences a terminal swallows, spelled from the specs rather than read from
# the shipped pattern, so this is an oracle for that pattern and not a copy of
# it: a CSI as DEC's parser reads it (every 0x20-0x3F byte, then a 0x40-0x7E
# final) and an ECMA-35 escape (0x20-0x2F intermediates, then a 0x30-0x7E final;
# one directly after ESC is not `[`, which opens a CSI instead).
_TERMINAL_SEQUENCE_RE = re.compile(
    "(?:\x1b\\[|\x9b)[\x20-\x3f]*[\x40-\x7e]"
    "|\x1b(?:[\x20-\x2f]+[\x30-\x7e]|(?!\\[)[\x30-\x7e])"
)
_SEQUENCE_PIECES = st.sampled_from(
    ["\x1b", "\x9b", "\x1b]", "\x07", "\x1b\\", "[", "\n", "a", " ", "(", "7"]
) | st.builds(
    "".join,
    st.tuples(
        st.sampled_from(["\x1b[", "\x9b", "\x1b"]),
        st.text(st.characters(min_codepoint=0x20, max_codepoint=0x3F), max_size=4),
        st.characters(min_codepoint=0x30, max_codepoint=0x7E),
    ),
)


@given(st.lists(_SEQUENCE_PIECES, max_size=24).map("".join))
def test_one_pass_is_a_fixed_point_with_no_terminal_sequence(text: str) -> None:
    """One ``ANSI_RE`` pass is final: a second pass changes nothing, and no
    ESC/CSI followed by a sequence a terminal swallows remains."""
    once = ANSI_RE.sub("", text)
    assert ANSI_RE.sub("", once) == once
    assert _TERMINAL_SEQUENCE_RE.search(once) is None


# ─── The shipped grammar is an artifact, not an accident ─────────────────────


def test_pattern_compiles_under_plain_re_with_no_flags() -> None:
    """The whole contract a stdlib-only consumer gets: ``re.compile(pattern)``,
    nothing else. A future rewrite reaching for ``re.VERBOSE``/``(?x)`` — or for
    a named group, which a consumer materializing this into its own regex cannot
    merge — has to fail HERE rather than in a downstream sandbox with no install
    path. ``FutureWarning`` counts as failure too: ``[[…]`` compiles today and is
    a hard error in a future Python."""
    pattern = escape_sequence_pattern()
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        compiled = re.compile(pattern)
    # No inline flag group: an embedded `(?x)`/`(?i)` shows up in `.flags`, which
    # for a plain str pattern is UNICODE and nothing else.
    assert compiled.flags == re.UNICODE
    assert compiled.groups == 0
    assert compiled.groupindex == {}
    # It is the pattern the module actually strips with, not a second copy.
    assert ANSI_RE.pattern == pattern


def _growth(compiled: re.Pattern, text: Callable[[int], str], n: int) -> float:
    """How much longer ``compiled`` takes on ``text(8 * n)`` than on ``text(n)``:
    ~8 when linear, ~64 when quadratic. The best of fifteen runs damps noise."""

    def seconds(subject: str) -> float:
        best = float("inf")
        for _ in range(15):
            start = time.perf_counter()
            compiled.sub("", subject)
            best = min(best, time.perf_counter() - start)
        return best

    return seconds(text(8 * n)) / seconds(text(n))


# Between a linear pattern (~8x ideal, ~16-24x measured at this size under cache
# pressure and load) and the ~64x of a quadratic one.
_LINEAR_GROWTH_BOUND = 32


@pytest.mark.parametrize(
    "text",
    [
        lambda n: "\x1b[" * n,
        lambda n: "\x9b?" * n,
        lambda n: "\x1b " * n,
        lambda n: "\x1b]x" * n,
        lambda n: "\x1b[" + " " * n,
    ],
    ids=["csi-repeat", "c1-csi-repeat", "esc-repeat", "osc-repeat", "csi-run"],
)
def test_pattern_is_linear_on_unterminated_runs(text: Callable[[int], str]) -> None:
    """The generated pattern runs on untrusted input inside a consumer with no
    timeout. Each arm's quantified class is disjoint from what follows it, so a
    run with no final byte fails in one pass. ``regexploit`` does not flag two
    adjacent overlapping stars, so the guard is the cost itself: a ratio on one
    machine, not a wall-clock threshold on an unknown runner."""
    assert _growth(ANSI_RE, text, 20_000) < _LINEAR_GROWTH_BOUND


def test_growth_bound_catches_a_quadratic_pattern() -> None:
    """Non-vacuity: two adjacent stars over one class, the shape the arms avoid,
    exceed the bound on an unterminated run."""
    quadratic = re.compile("\x1b\\[[ -?]*[ -?]*[@-~]")
    growth = _growth(quadratic, lambda n: "\x1b[" + " " * n, 300)
    assert growth > _LINEAR_GROWTH_BOUND


# ─── Invisible charset completeness (the pinned-SSOT guarantee) ───────────────


def test_every_charset_code_point_is_stripped() -> None:
    """strip_untrusted must delete EVERY code point in the pinned cross-language
    charset — the whole point of reading the pinned set instead of resolving
    ``Cf`` from this interpreter. A one-sided diff names any survivor."""
    survivors = sorted(
        hex(cp) for cp in _INVISIBLE if strip_untrusted(f"x{chr(cp)}y") != "xy"
    )
    assert not survivors, f"charset code points not stripped: {survivors}"


def test_charset_is_cf_union_extra() -> None:
    """Guard the deletion set is exactly the documented union, and non-empty (so a
    charset that silently loaded empty can't make the completeness test vacuous)."""
    assert _INVISIBLE == cf_codepoints() | extra_codepoints()
    assert len(_INVISIBLE) > 300


def test_pinned_cf_beats_interpreter_unicode_version() -> None:
    """Regression for the ``Cf`` version-drift bug: a code point that is ``Cf`` in
    the PINNED set (Node's Unicode) but that THIS interpreter's ``unicodedata``
    does not yet classify as ``Cf`` must still be stripped. Resolving ``Cf`` live
    (the pre-consolidation monitor copy) left such a payload in the version delta
    unstripped; reading the pinned set fixes it. U+13439 (EGYPTIAN HIEROGLYPH
    modifier, Unicode 15) is such a point on older CPython builds — the assertion
    holds whether or not this runner's Unicode is new enough to know it."""
    drift = [cp for cp in cf_codepoints() if unicodedata.category(chr(cp)) != "Cf"]
    # If this interpreter is behind Node's Unicode there IS a delta; each such
    # point must be stripped by the pinned-set membership test, never left to a
    # live ``unicodedata`` lookup that misses it.
    for cp in drift:
        assert strip_untrusted(chr(cp)) == "", hex(cp)
    # The specific documented point is in the pinned set on every build.
    assert 0x13439 in cf_codepoints()
    assert strip_untrusted(chr(0x13439)) == ""


def test_live_cf_beyond_pinned_is_stripped(monkeypatch):
    """Newer-host guarantee (the union's other half): a ``Cf`` char absent from the
    pinned set is still stripped via the live category term. Empty the pinned set
    to simulate a host interpreter AHEAD of the package's Unicode version — U+200B
    (``Cf`` on every build) must still be removed, so the port never under-strips
    when the host is newer than the package."""
    monkeypatch.setattr("agent_sanitizer.textstrip.invisible_charset", frozenset)
    assert strip_untrusted(f"a{chr(0x200B)}b") == "ab"


# ─── Deletion-only + idempotent + visible-text preservation ──────────────────

try:
    from hypothesis import given
    from hypothesis import strategies as st

    _HAS_HYPOTHESIS = True
except ImportError:  # pragma: no cover
    _HAS_HYPOTHESIS = False


@pytest.mark.skipif(not _HAS_HYPOTHESIS, reason="hypothesis not installed")
@given(st.text())
def test_deletion_only_and_idempotent(text: str) -> None:
    out = strip_untrusted(text)
    # Deletion-only: the output is a subsequence of the input.
    it = iter(text)
    assert all(c in it for c in out)
    # No payload char survives.
    assert not (set(map(ord, out)) & _INVISIBLE)
    assert "\x1b" not in out
    # Idempotent: a second pass changes nothing.
    assert strip_untrusted(out) == out


# The escape alphabet the line-break property needs. ``st.text()`` draws an ESC
# essentially never, so a property over it cannot reach the shape the shipped
# bug lived in — a control-string body meeting a newline.
_ESCAPE_ALPHABET = "\x1b\x9b\x9d\x90\x98\x9e\x9f\x9c\x07\x18\x1a\x00\x0b\x0c\x7f"
_ESCAPE_ALPHABET += "[]PX^_\\m0;:?(#~2JB \n\rab"


@pytest.mark.skipif(not _HAS_HYPOTHESIS, reason="hypothesis not installed")
@given(st.text(alphabet=_ESCAPE_ALPHABET, max_size=40))
def test_line_breaks_are_never_removed(text: str) -> None:
    """The invariant the control-string bug violated, stated over every input
    that carries a break rather than over the one payload that exposed it: no
    arm of the grammar may span a line break, so the strip preserves every
    ``\\n`` and ``\\r``. ``src/ansi.mjs``'s scanner holds the same property."""
    out = strip_untrusted(text)
    for char in ("\n", "\r"):
        assert out.count(char) == text.count(char), repr(text)


@pytest.mark.parametrize(
    "text",
    [
        "hello world",
        "café — naïve façade",  # Latin diacritics (combining, not Cf)
        "日本語のテキスト",
        "emoji 😀 and 👍 base chars",
        "tabs\tand\nnewlines\r kept",
    ],
)
def test_visible_text_untouched(text: str) -> None:
    """Precision: legitimate visible content (letters, CJK, emoji bases,
    whitespace) must pass through byte-for-byte — no false stripping."""
    assert strip_untrusted(text) == text


# ─── Cross-language: never under-strip vs the recorded JS layer ───────────────


def _from_units(units: list[int]) -> str:
    raw = b"".join(u.to_bytes(2, "little") for u in units)
    return raw.decode("utf-16-le", "surrogatepass")


def _corpus_cases() -> list[tuple[str, str, str]]:
    corpus = json.loads((REPO_ROOT / "tests" / "golden-corpus.json").read_text("utf-8"))
    golden = json.loads((REPO_ROOT / "tests" / "golden.json").read_text("utf-8"))
    assert [c["name"] for c in corpus["cases"]] == [g["name"] for g in golden["cases"]]
    return [
        (c["name"], _from_units(c["units"]), _from_units(g["plain"]["cleaned"]))
        for c, g in zip(corpus["cases"], golden["cases"])
    ]


_CORPUS = _corpus_cases()


@pytest.mark.parametrize(
    "input_text,js_cleaned",
    [(c[1], c[2]) for c in _CORPUS],
    ids=[c[0] for c in _CORPUS],
)
def test_never_understrips_vs_js(input_text: str, js_cleaned: str) -> None:
    """The security invariant that ties the port to the JS layer: every
    payload character (an invisible in the charset, or a raw ESC) that the
    recorded JS output removed must ALSO be gone from the Python strip. The port
    may remove MORE (it does not do the JS layer's linguistic ZWJ/ZWNJ/VS
    preservation — fine for a payload-removal filter), but it must never leave a
    payload the JS layer caught."""
    py = strip_untrusted(input_text)
    in_cp, js_cp, py_cp = (set(map(ord, s)) for s in (input_text, js_cleaned, py))
    # The mask includes the FULL control-introducer set (ESC + the C1 block),
    # not `{0x1B}`: masking to ESC alone made this guard structurally blind to
    # a C1 introducer the JS layer sweeps but the port leaves — the exact
    # divergence it exists to catch (the port shipped that gap while this
    # assertion stayed green).
    removed_by_js = (in_cp - js_cp) & (_INVISIBLE | control_introducers())
    removed_by_py = in_cp - py_cp
    still_present = removed_by_js - removed_by_py
    assert not still_present, sorted(hex(c) for c in still_present)


def _has_lone_surrogate(text: str) -> bool:
    # `_from_units` decodes with `surrogatepass`, so a well-formed pair has
    # already become one astral code point — any surrogate still standing here
    # is by definition lone.
    return any(0xD800 <= ord(c) <= 0xDFFF for c in text)


# Two documented reasons a case cannot be compared for EQUALITY: the JS layer
# preserves a linguistically-used joiner or variation selector this port always
# deletes, and `sanitize` normalizes a lone surrogate to U+FFFD at its boundary
# where `applyLayer1` (and so this port) does not. Everything else must match
# byte for byte.
_EQUALITY_CORPUS = [
    case
    for case in _CORPUS
    if not (set(map(ord, case[1])) & _INVISIBLE) and not _has_lone_surrogate(case[1])
]


def test_equality_corpus_covers_the_control_string_arms() -> None:
    """Non-vacuity for the equality check below, and the reason the corpus grew:
    the arms it discriminates must actually be IN it. A corpus that enumerates
    sequence forms without ever putting a newline in, around and inside a control
    string is what let one bug live identically in both ports — no case
    disagreed, so no cross-port assertion could fire."""
    names = {case[0] for case in _EQUALITY_CORPUS}
    assert {
        "ansi_control_strings_across_lines",
        "ansi_control_string_bodies_meet_newline",
        "ansi_control_string_unterminated_at_eof",
    } <= names
    assert len(_EQUALITY_CORPUS) >= 18


@pytest.mark.parametrize(
    "input_text,js_cleaned",
    [(c[1], c[2]) for c in _EQUALITY_CORPUS],
    ids=[c[0] for c in _EQUALITY_CORPUS],
)
def test_matches_js_exactly_where_comparable(input_text: str, js_cleaned: str) -> None:
    """Two ENGINES, one pattern: the port compiles the grammar
    ``src/ansi.mjs`` pins, but nothing in either language proves JS's and
    Python's regex engines read that pattern the same way. This is where that is
    checked — byte equality against the recorded JS output, not the one-sided
    payload mask above, which passes whenever the port strips MORE."""
    assert strip_untrusted(input_text) == js_cleaned


# ─── The composition loop: one pass is not enough ─────────────────────────────

# The shared corpus carries the composition cases both ports are held to: each
# `layer1_reconstituted_*` input hides an escape behind an invisible inside its
# own introducer, so a single {escape, invisible} pass leaves its body (`[31m`)
# as visible text, and each `layer1_outruns_pass_bound_*` nest needs more
# rounds than the pass bound. test/layer1-ansi.test.mjs iterates the same file.
_COMPOSITION_CASES = [
    case
    for case in _CORPUS
    if case[0].startswith(("layer1_reconstituted_", "layer1_outruns_"))
]


def _strip_charset(text: str) -> str:
    return "".join(
        c for c in text if unicodedata.category(c) != "Cf" and ord(c) not in _INVISIBLE
    )


def _carve_out_inside_escape_body(js_cleaned: str) -> bool:
    """The JS layer kept a carve-out character (a registered `0` + VS1) inside
    what would be CSI parameters once it is gone. That character is what stops
    the escape from forming there, and its introducer has already been swept,
    so the JS output shows the body; the port deletes the character, the escape
    forms, and it goes whole. Both are fixed points; they just differ."""
    return any(
        m.end() < len(js_cleaned) and ord(js_cleaned[m.end()]) in _INVISIBLE
        for m in re.finditer(r"\[[0-?]*", js_cleaned)
    )


_RELATION_CORPUS = [
    case
    for case in _CORPUS
    if not _has_lone_surrogate(case[1]) and not _carve_out_inside_escape_body(case[2])
]


def test_relation_corpus_excludes_only_the_designed_nests() -> None:
    """Non-vacuity both ways: the composition cases are in the corpus, the
    exclusion fires, and only on nests built to put a selector in an escape."""
    assert {c[0] for c in _COMPOSITION_CASES} >= {
        "layer1_reconstituted_nested_split",
        "layer1_outruns_pass_bound_s6_p15_x75",
    }
    excluded = {c[0] for c in _CORPUS if _carve_out_inside_escape_body(c[2])}
    assert excluded
    assert all(name.startswith("layer1_outruns_pass_bound_") for name in excluded)
    assert len(_RELATION_CORPUS) > len(_EQUALITY_CORPUS)


@pytest.mark.parametrize(
    "input_text,js_cleaned",
    [(c[1], c[2]) for c in _RELATION_CORPUS],
    ids=[c[0] for c in _RELATION_CORPUS],
)
def test_is_js_output_minus_the_carve_out(input_text: str, js_cleaned: str) -> None:
    """The exact relation behind both one-sided checks above: the port is the
    JS layer with its linguistic carve-out undone, so removing every charset
    member from the recorded JS output gives the port's output byte for byte —
    including the cases the equality corpus excludes for carrying invisibles,
    and so pinning each composition case's exact output."""
    assert strip_untrusted(input_text) == _strip_charset(js_cleaned)


@pytest.mark.parametrize("text", [c[1] for c in _CORPUS], ids=[c[0] for c in _CORPUS])
def test_is_a_fixed_point(text: str) -> None:
    once = strip_untrusted(text)
    assert strip_untrusted(once) == once
