"""Ported cross-line, env-bound, and interior-invisible tests.

Env-bound values now come from a :class:`RedactorConfig` (``provider_vars`` /
``host_cred_vars``) instead of ``os.environ``; the assertions are otherwise the
originals.
"""

import re
import types

import pytest
from detect_secrets.settings import get_plugins

import agent_sanitizer.secrets.engine as E
from agent_sanitizer.secrets import (
    DEFAULT_MIN_SECRET_LEN,
    detected_secret_values,
    redact,
)
from redactor_helpers import cfg, run_plain

AWS_KEY = "AKIA" + "ZYXWVUT123456789"
_LONG = "qZ7vK2mNp9rT4wX1cY6bA8dF3gH5jL0e"  # 32 chars, >= DEFAULT_MIN_SECRET_LEN


# ─── Env-bound secret redaction (_redact_env_bound) ──────────────────────────


@pytest.mark.parametrize(
    "label, field, var, value, text, expect_redacted",
    [
        (
            "redacts configured value",
            "provider_vars",
            "VENICE_INFERENCE_KEY",
            _LONG,
            f"saw {_LONG} here",
            True,
        ),
        ("absent var is a no-op", None, None, None, f"saw {_LONG} here", False),
        (
            "short value is not redacted",
            "provider_vars",
            "ANTHROPIC_API_KEY",
            "fake",
            "saw fake here",
            False,
        ),
        (
            "one below the floor",
            "provider_vars",
            "MONITOR_API_KEY",
            "a" * 15,
            "saw " + "a" * 15,
            False,
        ),
        (
            "exactly at the floor",
            "provider_vars",
            "MONITOR_API_KEY",
            "b" * 16,
            "saw " + "b" * 16,
            True,
        ),
        (
            "value not in text is a no-op",
            "provider_vars",
            "OPENROUTER_API_KEY",
            _LONG,
            "nothing to see",
            False,
        ),
        (
            "host cred: GH_TOKEN",
            "host_cred_vars",
            "GH_TOKEN",
            _LONG,
            f"token={_LONG}",
            True,
        ),
        (
            "host cred: AWS_SECRET_ACCESS_KEY",
            "host_cred_vars",
            "AWS_SECRET_ACCESS_KEY",
            _LONG,
            f"aws {_LONG}",
            True,
        ),
        (
            "host cred: DOCKER_PASSWORD",
            "host_cred_vars",
            "DOCKER_PASSWORD",
            _LONG,
            f"pw {_LONG}",
            True,
        ),
    ],
)
def test_redact_env_bound(label, field, var, value, text, expect_redacted):
    config = cfg(**{field: {var: value}}) if field else cfg()
    found: list[str] = []
    out = E._redact_env_bound(text, found, config)
    if expect_redacted:
        assert value not in out, label
        assert f"[REDACTED: {var}]" in out, label
        assert found == [var], label
    else:
        assert out == text, label
        assert found == [], label


def test_main_redacts_env_bound_value():
    config = cfg(provider_vars={"VENICE_INFERENCE_KEY": _LONG})
    result = run_plain(f"model output mentioning {_LONG} verbatim", config)
    assert result is not None
    assert "VENICE_INFERENCE_KEY" in result["found"]
    assert _LONG not in result["text"]


# ─── Cross-line secret splits (_redact_cross_line) ───────────────────────────


def _fake_scan(monkeypatch, *pairs):
    fakes = [types.SimpleNamespace(type=t, secret_value=v) for t, v in pairs]
    monkeypatch.setattr(
        E, "scan_line", lambda line: [f for f in fakes if f.secret_value in line]
    )
    # _cross_line_candidate_spans now prefilters with the real detectors' own
    # denylist regexes (_eligible_prefilter) before ever calling scan_line, so it
    # only hands scan_line a window around a hit. These tests invent synthetic
    # values ("ABCD", "WXYZ", …) that no real detector shape matches, so the
    # patched scan_line above would never be reached without also patching the
    # prefilter to a catch-all — these tests are exercising _redact_cross_line's
    # offset-translation/overlap logic in isolation from any real detector shape,
    # not the prefilter itself (that has its own soundness test).
    monkeypatch.setattr(E, "_eligible_prefilter", lambda: (re.compile(".", re.DOTALL),))


def _ph(secret_type: str) -> str:
    return f"[REDACTED: {secret_type}]"


def test_redact_line_overlapping_secrets_no_tail_leak(monkeypatch):
    short_val = "abcd1234"
    long_val = "abcd1234efgh5678"
    _fake_scan(monkeypatch, ("Short", short_val), ("Long", long_val))
    found: list[str] = []
    out = E._redact_line(f"x={long_val}", False, None, found)
    assert out == f"x={_ph('Long')}"
    assert short_val not in out and "efgh5678" not in out
    assert found == ["Long"]


def test_cross_line_no_newline_is_noop():
    found: list[str] = []
    assert E._redact_cross_line("no newline here", found, cfg()) == "no newline here"
    assert found == []


def test_cross_line_redacts_split_structural(monkeypatch):
    head, tail = AWS_KEY[:12], AWS_KEY[12:]
    _fake_scan(monkeypatch, ("AWS Access Key", AWS_KEY))
    found: list[str] = []
    out = E._redact_cross_line(f"prefix {head}\n{tail} suffix", found, cfg())
    assert out == f"prefix {_ph('AWS Access Key')} suffix"
    assert found == ["AWS Access Key"]


def test_cross_line_redacts_split_at_offset_zero(monkeypatch):
    _fake_scan(monkeypatch, ("AWS Access Key", "ABCD"))
    found: list[str] = []
    assert E._redact_cross_line("AB\nCD", found, cfg()) == _ph("AWS Access Key")
    assert found == ["AWS Access Key"]


def test_cross_line_redacts_repeated_value_at_two_sites(monkeypatch):
    _fake_scan(monkeypatch, ("AWS Access Key", "WXYZ"))
    found: list[str] = []
    out = E._redact_cross_line("WX\nYZ gap WX\nYZ", found, cfg())
    assert out == f"{_ph('AWS Access Key')} gap {_ph('AWS Access Key')}"
    assert found == ["AWS Access Key", "AWS Access Key"]


def test_cross_line_leaves_within_line_match(monkeypatch):
    _fake_scan(monkeypatch, ("AWS Access Key", AWS_KEY))
    found: list[str] = []
    text = f"first line\nprefix {AWS_KEY} end"
    assert E._redact_cross_line(text, found, cfg()) == text
    assert found == []


def test_cross_line_skips_ineligible_type_and_empty(monkeypatch):
    _fake_scan(monkeypatch, ("Secret Keyword", "abcd"), ("AWS Access Key", ""))
    found: list[str] = []
    assert E._redact_cross_line("ab\ncd", found, cfg()) == "ab\ncd"
    assert found == []


def test_cross_line_overlapping_spans_redact_widest_once(monkeypatch):
    _fake_scan(monkeypatch, ("AWS Access Key", "ABCDEF"), ("GitHub Token", "ABC"))
    found: list[str] = []
    assert E._redact_cross_line("A\nBCDEF", found, cfg()) == _ph("AWS Access Key")
    assert found == ["AWS Access Key"]


def test_cross_line_adjacent_spans_both_kept(monkeypatch):
    _fake_scan(monkeypatch, ("AWS Access Key", "AABB"), ("GitHub Token", "CCDD"))
    found: list[str] = []
    out = E._redact_cross_line("AA\nBBCC\nDD", found, cfg())
    assert out == f"{_ph('AWS Access Key')}{_ph('GitHub Token')}"
    assert found == ["AWS Access Key", "GitHub Token"]


def test_cross_line_redacts_split_env_value(monkeypatch):
    config = cfg(
        provider_vars={"VENICE_INFERENCE_KEY": _LONG, "MONITOR_API_KEY": "short"}
    )
    monkeypatch.setattr(E, "scan_line", lambda line: [])
    head, tail = _LONG[:16], _LONG[16:]
    found: list[str] = []
    # _eligible_prefilter reads the live detect-secrets plugin set (see its
    # doc), so it needs a configured context even though scan_line itself is
    # stubbed to a no-op here — this test only exercises the env-bound path.
    with E.configure_plugins():
        out = E._redact_cross_line(f"key {head}\n{tail} end", found, config)
    assert out == "key [REDACTED: VENICE_INFERENCE_KEY] end"
    assert found == ["VENICE_INFERENCE_KEY"]


def test_cross_line_env_value_at_exact_floor_redacts(monkeypatch):
    value = "Z" * DEFAULT_MIN_SECRET_LEN
    config = cfg(provider_vars={"VENICE_INFERENCE_KEY": value})
    monkeypatch.setattr(E, "scan_line", lambda line: [])
    head, tail = value[:3], value[3:]
    found: list[str] = []
    with E.configure_plugins():
        out = E._redact_cross_line(f"k {head}\n{tail} e", found, config)
    assert out == "k [REDACTED: VENICE_INFERENCE_KEY] e"
    assert found == ["VENICE_INFERENCE_KEY"]


def test_redact_text_catches_real_split_aws():
    head, tail = AWS_KEY[:8], AWS_KEY[8:]
    text = f"log line\nprefix {head}\n{tail} suffix\ntrailer"
    out, found = redact(text)
    assert AWS_KEY not in out.replace("\n", "")
    assert "AWS Access Key" in found


def test_redact_text_leaves_real_split_loose_prefix_intact():
    groq = "gsk_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    head, tail = groq[:10], groq[10:]
    text = f"log line\nprefix {head}\n{tail} suffix"
    out, found = redact(text)
    assert groq in out.replace("\n", "")
    assert found == []


def test_cross_line_offset_map_excludes_only_newlines():
    type_name = "AWS Access Key"
    needle = "\t" + AWS_KEY[:9] + "\n" + AWS_KEY[9:]
    out, found = redact(needle)
    assert out == "\t[REDACTED: " + type_name + "]"
    assert found == [type_name]


# ─── Interior-invisible tolerance in env-bound redaction ─────────────────────
# Zero-width (U+200B), soft hyphen (U+00AD), bidi isolate (U+2066). A direct
# in-process caller that does not strip invisibles first must still catch a key
# with invisibles spliced between its bytes — the exact-substring match alone
# would miss it.


@pytest.mark.parametrize("sep", ["​", "­", "⁦", "​­"])
def test_redact_env_bound_tolerates_interior_invisibles(sep):
    config = cfg(provider_vars={"VENICE_INFERENCE_KEY": _LONG})
    mid = len(_LONG) // 2
    dirty = _LONG[:mid] + sep + _LONG[mid:]
    text = f"leaked {dirty} on disk"

    found: list[str] = []
    out = E._redact_env_bound(text, found, config)
    assert found == ["VENICE_INFERENCE_KEY"], sep
    assert dirty not in out and _LONG not in out, sep
    assert "[REDACTED: VENICE_INFERENCE_KEY]" in out, sep

    assert dirty in detected_secret_values(text, config), sep

    entries: list[tuple[str, str]] = []
    E._redact_env_bound(text, [], config, entries)
    assert entries and entries[0][1] == dirty, sep


@pytest.mark.parametrize(
    "cp",
    [0xFE0F, 0x115F, 0x2800, 0x061C],
    ids=["variation-selector", "hangul-filler", "braille-blank", "arabic-letter-mark"],
)
def test_env_value_re_tolerates_non_enumerated_invisible_splice(cp):
    from agent_sanitizer.secrets.invisible import default_charset

    value = "sk-abcdefghijklmnopqrstuvwxyz0123456789"
    spliced = value[:6] + chr(cp) + value[6:]
    assert E._env_value_re(value, default_charset()).fullmatch(spliced)


# ─── _eligible_prefilter soundness guard ─────────────────────────────────────
# The prefilter's whole premise (see its docstring) is that every
# _CROSS_LINE_ELIGIBLE_TYPES entry is served by a RegexBasedDetector whose
# denylist IS its detection surface, so a prefilter miss cannot hide a real
# detection. This guard states that premise directly rather than trusting it:
# if a future detect-secrets upgrade ever gives an eligible type a detector with
# no denylist regex (a custom analyze_string with no regex backing it), the
# prefilter would silently stop covering that type — this fails loud instead.


def test_cross_line_prefilter_is_sound():
    with E.configure_plugins():
        by_type = {}
        for plugin in get_plugins():
            secret_type = getattr(plugin, "secret_type", None)
            if secret_type in E._CROSS_LINE_ELIGIBLE_TYPES:
                by_type[secret_type] = plugin
        missing = E._CROSS_LINE_ELIGIBLE_TYPES - by_type.keys()
        assert not missing, f"no active plugin for eligible type(s): {missing}"
        for secret_type, plugin in by_type.items():
            denylist = getattr(plugin, "denylist", ())
            assert denylist, (
                f"{secret_type}'s plugin {type(plugin).__name__} has no denylist "
                "regex — _eligible_prefilter cannot cover it, and a cross-line "
                "secret of this type could be missed entirely"
            )

        prefilters = E._eligible_prefilter()
        assert prefilters and all(p.pattern for p in prefilters), (
            "prefilter derived no (or an empty) pattern"
        )
        # Not vacuous: at least one real denylist pattern is actually IN one of
        # the unions, not just that the unions are non-empty text.
        assert any(
            pat.pattern in prefilter.pattern
            for plugin in by_type.values()
            for pat in plugin.denylist
            for prefilter in prefilters
        )
        # Every distinct flag combination among eligible denylists gets its own
        # compiled union — a case-insensitive pattern (Slack, AWS's
        # keyword-context form) must not be silently folded into a flag-less
        # compile that drops its case-insensitivity.
        eligible_flag_sets = {
            pat.flags for plugin in by_type.values() for pat in plugin.denylist
        }
        assert {p.flags for p in prefilters} == eligible_flag_sets


def test_cross_line_prefilter_keeps_case_insensitive_detector_case_insensitive():
    """Slack's denylist pattern is compiled with re.IGNORECASE; a flag-less
    join of the eligible-type union (an earlier version of this prefilter)
    would silently stop matching an upper-cased split token, since
    `xox(?:a|b|p|o|s|r)-...` never matches "XOXB-..." without that flag."""
    value = "XOXB-123-456-ABCDEFGHIJ"
    head, tail = value[:14], value[14:]
    text = f"prefix {head}\n{tail} suffix"
    with E.configure_plugins():
        found: list[str] = []
        out = E._redact_cross_line(text, found, cfg())
    assert out == f"prefix {_ph('Slack Token')} suffix"
    assert found == ["Slack Token"]


def test_cross_line_prefilter_cache_does_not_survive_a_reconfigure():
    """_eligible_prefilter() is process-wide functools.cache'd, keyed on no
    arguments — so it must be cleared on every configure_plugins() entry/exit,
    or a prefilter built under one plugin config (e.g. high_confidence) would
    silently answer for a LATER, differently-configured scan in the same
    process (the daemon serves both configs). Observed via cache_info(), since
    high_confidence and the default set agree on every eligible type today and
    so cannot be told apart by the prefilter's own text."""
    with E.configure_plugins():
        E._eligible_prefilter()
        assert E._eligible_prefilter.cache_info().currsize == 1
    with E.configure_plugins(high_confidence=True):
        assert E._eligible_prefilter.cache_info().currsize == 0
        E._eligible_prefilter()
        assert E._eligible_prefilter.cache_info().currsize == 1
    with E.configure_plugins():
        assert E._eligible_prefilter.cache_info().currsize == 0
