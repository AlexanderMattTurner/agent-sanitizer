"""Tests for the stdlib-only strip (:mod:`agent_sanitizer.textstrip`).

``textstrip.strip_untrusted`` is a pure-Python port of ``src/invisible.mjs``'s
``applyLayer1`` (ANSI + invisible-char removal) for no-Node contexts. These
assert the two load-bearing properties directly rather than trusting the port to
match the JS by inspection:

* it deletes EVERY code point in the pinned cross-language charset (so it cannot
  under-strip relative to the JS layer regardless of this interpreter's Unicode
  version — the ``Cf`` version-drift regression), and
* over the shared golden corpus it never leaves a payload char that the recorded
  JS output removed.
"""

import json
import unicodedata

import pytest

from tests._helpers import REPO_ROOT, ensure_python_pkg_on_path

ensure_python_pkg_on_path()

from agent_sanitizer.invisible import (  # noqa: E402
    cf_codepoints,
    control_introducers,
    extra_codepoints,
    invisible_charset,
)
from agent_sanitizer.textstrip import strip_untrusted  # noqa: E402

_INVISIBLE = invisible_charset()


# ─── ANSI / escape grammar ───────────────────────────────────────────────────

# (name, input, expected) — one row per arm of the ANSI alternation plus the
# unconditional lone-ESC sweep. Expected output is the visible remainder.
_ANSI_CASES = [
    ("csi_sgr_color", "a\x1b[31mred\x1b[0mb", "aredb"),
    ("csi_cursor_move", "x\x1b[2Ky", "xy"),
    # no final byte; ESC[ swept, digit left
    ("csi_truncated_leaves_body", "a\x1b[1", "a1"),
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
    ("c1_orphan_dcs_swept", "a\x90b", "ab"),
    ("c1_orphan_apc_swept", "a\x9fb", "ab"),
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
