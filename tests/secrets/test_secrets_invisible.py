"""Invisible-charset tests.

The charset is not defined here — it is imported from agent-sanitizer's
shared SSOT. These tests pin the sharing (the redactor's set equals the
sanitizer's), the strip semantics, and the fail-closed behaviour when the shared
dependency is unavailable.
"""

import unicodedata

import pytest

from agent_sanitizer.secrets import strip_invisible
from agent_sanitizer.secrets.invisible import (
    default_charset,
    invisible_run_pattern,
    strip_invisible_with_map,
)

# Cf representatives by code point: zero-width, ZWNJ/ZWJ, word-joiner, BOM, soft
# hyphen, bidi override/isolate, TAG.
_STRIP_CF_CPS = [
    0x200B,
    0x200C,
    0x200D,
    0x2060,
    0xFEFF,
    0x00AD,
    0x202E,
    0x2066,
    0xE0001,
]


def _extra() -> frozenset[int]:
    from agent_sanitizer.invisible import INVISIBLE_EXTRA

    return INVISIBLE_EXTRA


# ─── The charset is shared, not copied ───────────────────────────────────────


def _pinned_cf() -> frozenset[int]:
    from agent_sanitizer.invisible import cf_codepoints

    return cf_codepoints()


def test_default_charset_is_pinned_cf_union_shared_extra():
    """The redactor's charset is exactly the PINNED Cf set UNION the shared non-Cf
    extras — both read from the generated SSOT, so it cannot drift from the
    sanitizer regardless of this interpreter's Unicode version."""
    assert default_charset() == _pinned_cf() | _extra()


def test_default_charset_does_not_depend_on_runtime_unicode_version():
    """The Cf half is PINNED, not resolved from this interpreter's ``unicodedata``.
    U+13439 is general-category Cf in the Unicode version Node pins from (17) but
    NOT in the Unicode 14/15 CPython commonly ships, so a live-Cf resolution would
    OMIT it here and the port would fail to strip a char the JS layer strips. The
    pinned set must contain it regardless of what this interpreter thinks."""
    assert 0x13439 in default_charset()
    assert 0x13439 in _pinned_cf()
    # Demonstrate the pin actually diverges from this interpreter's live Cf on at
    # least this code point when the interpreter predates Unicode 17 (skip the
    # assertion on a newer interpreter where they happen to agree).
    runtime_major = int(unicodedata.unidata_version.split(".")[0])
    if runtime_major < 17:
        assert unicodedata.category(chr(0x13439)) != "Cf"


@pytest.mark.drift_guard
def test_shared_extra_matches_sanitizer_ssot():
    """The extra (non-Cf) set the redactor consumes is the one agent-sanitizer
    publishes from invisible.mjs (VS + BLANK_NON_CF): variation selectors, Hangul
    and Braille fillers, and the zero-width combining marks U+034F/U+17B4/U+17B5.
    A member dropped on either side diverges the two engines.

    The variation selectors are all THREE runs of Unicode's Variation_Selector
    property, not just the two Cf-adjacent ones: the Mongolian free variation
    selectors (U+180B..U+180D, U+180F) are category Mn, so neither `\\p{Cf}` nor
    this interpreter's Cf pin reaches them, and a run of them renders as nothing.
    """
    expected = (
        set(range(0xFE00, 0xFE10))
        | {0x180B, 0x180C, 0x180D, 0x180F}
        | set(range(0xE0100, 0xE01F0))
        | {0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x034F, 0x17B4, 0x17B5}
    )
    assert set(_extra()) == expected


def test_shared_extra_is_disjoint_from_cf():
    """The extras exist precisely to catch payload-capable blanks that are NOT Cf;
    a Cf char sneaking in would be dead weight and signal the two families drifted
    into overlap."""
    assert all(unicodedata.category(chr(cp)) != "Cf" for cp in _extra())


# ─── strip_invisible ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "cp", _STRIP_CF_CPS, ids=[f"Cf-U+{cp:04X}" for cp in _STRIP_CF_CPS]
)
def test_strip_invisible_deletes_each_cf_rep(cp):
    assert unicodedata.category(chr(cp)) == "Cf"
    assert strip_invisible("a" + chr(cp) + "b") == "ab"


def test_strip_invisible_deletes_every_extra_member():
    for cp in sorted(_extra()):
        assert strip_invisible("a" + chr(cp) + "b") == "ab", f"U+{cp:04X}"


def test_strip_invisible_preserves_visible_text():
    visible = "Hello, café — naïve 日本語 résumé! AKIA1234\t\nx"
    assert strip_invisible(visible) == visible


def _is_subsequence(sub: str, full: str) -> bool:
    it = iter(full)
    return all(ch in it for ch in sub)


def test_strip_invisible_is_idempotent_and_deletion_only():
    invis = [chr(cp) for cp in _STRIP_CF_CPS] + [chr(cp) for cp in sorted(_extra())]
    visible = list("the-quick-brown-fox-0123456789")
    woven = []
    for i, v in enumerate(visible):
        woven.append(v)
        if i < len(invis):
            woven.append(invis[i])
    text = "".join(woven) + "".join(invis[len(visible) :])
    once = strip_invisible(text)
    assert once == "".join(visible)
    assert strip_invisible(once) == once
    assert _is_subsequence(once, text)


def test_strip_invisible_explicit_charset_overrides_default():
    """A caller may pin a bespoke charset; only its members are stripped."""
    assert strip_invisible("a​b", frozenset({0x200B})) == "ab"
    assert strip_invisible("a​b", frozenset({0x2060})) == "a​b"


# ─── strip_invisible_with_map ─────────────────────────────────────────────────


def test_strip_invisible_with_map_clean_text_takes_the_identity_fast_path():
    """No charset member present: the `str.translate` presence probe must short
    -circuit to the identity `range`, not fall through to the per-character
    loop."""
    text = "clean text, no invisibles: AKIA1234"
    result_text, offsets = strip_invisible_with_map(text)
    assert result_text == text
    assert isinstance(offsets, range)
    assert list(offsets) == list(range(len(text)))


def test_strip_invisible_with_map_deletes_and_offsets_correctly():
    """With a charset member present, the general per-character path must still
    produce the deleted text and an offset map pointing each stripped
    character back at its original index."""
    text = "a" + chr(0x200B) + "b" + chr(0x200B) + "c"
    result_text, offsets = strip_invisible_with_map(text)
    assert result_text == "abc"
    assert not isinstance(offsets, range)
    assert list(offsets) == [0, 2, 4]
    assert all(text[offsets[i]] == result_text[i] for i in range(len(result_text)))


# ─── invisible_run_pattern domain ────────────────────────────────────────────


def test_env_invis_run_domain_equals_charset():
    """The env-bound run pattern tolerates EXACTLY the charset's code points — no
    subset (a splice using an omitted char would evade the matcher) and no
    superset (dead weight in the class)."""
    import re

    charset = default_charset()
    pattern = invisible_run_pattern(charset)
    inner = re.compile("[" + pattern[1:-2] + "]")
    for cp in sorted(charset):
        assert inner.match(chr(cp)), f"U+{cp:04X} missing from run pattern"
    assert not inner.match("a")
    assert not inner.match(" ")


# ─── Fail closed when the shared dependency is unavailable ───────────────────


def test_default_charset_fails_closed_without_shared_dep(monkeypatch):
    """If the shared SSOT cannot be read, resolution RAISES rather than falling
    back to a partial set — a silent under-match is a security regression."""
    import agent_sanitizer.invisible as inv
    import agent_sanitizer.secrets.invisible as redactor_inv

    def _boom():
        raise RuntimeError("shared charset unavailable")

    monkeypatch.setattr(redactor_inv, "_shared_charset", _boom)
    with pytest.raises(RuntimeError):
        redactor_inv.default_charset()
    # sanity: the real accessor works (guards against a typo neutering the test)
    inv.invisible_charset.cache_clear()
    assert inv.invisible_charset()
