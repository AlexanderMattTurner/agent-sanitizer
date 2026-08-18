"""``_full_prefilter`` — the per-line performance gate ``_redact_line`` checks
before ever calling ``scan_line``.

Sibling to the cross-line prefilter's own soundness suite
(``test_secrets_crossline.py``'s "``_eligible_prefilter`` soundness guard"
section): same premise (every covered plugin is a ``RegexBasedDetector`` whose
denylist IS its detection surface), same failure mode this guards against (a
prefilter miss hiding a real detection), scoped to EVERY active plugin instead
of just the cross-line-eligible subset.
"""

import re

import pytest
from detect_secrets.settings import get_plugins

import agent_sanitizer.secrets.engine as E
from redactor_helpers import cfg, run_plain


def test_full_prefilter_is_sound():
    with E.configure_plugins():
        plugins = list(get_plugins())
        assert plugins, "no active plugin — configure_plugins() left the set empty"
        for plugin in plugins:
            denylist = getattr(plugin, "denylist", ())
            assert denylist, (
                f"{plugin.secret_type}'s plugin {type(plugin).__name__} has no "
                "denylist regex — _full_prefilter cannot cover it, and a secret "
                "of this type could be missed entirely on a large-file scan"
            )

        prefilters = E._full_prefilter()
        assert prefilters and all(p.pattern for p in prefilters), (
            "prefilter derived no (or an empty) pattern"
        )
        # Not vacuous: at least one real denylist pattern's TEXT is actually IN
        # one of the unions (post-_degroup, so compare the degrouped form).
        assert any(
            E._degroup(pat.pattern) in prefilter.pattern
            for plugin in plugins
            for pat in plugin.denylist
            for prefilter in prefilters
        )
        # Every distinct flag combination among ALL active denylists gets its
        # own compiled union — same case-insensitivity concern as the
        # cross-line prefilter, just over the full plugin set.
        all_flag_sets = {pat.flags for plugin in plugins for pat in plugin.denylist}
        assert {p.flags for p in prefilters} == all_flag_sets


def test_full_prefilter_cache_does_not_survive_a_reconfigure():
    """process-wide functools.cache'd, keyed on no arguments — so it must be
    cleared on every configure_plugins() entry/exit, or a prefilter built
    under one plugin config would silently answer for a later, differently
    configured scan sharing the same process (the daemon serves both
    high_confidence and the default config)."""
    with E.configure_plugins():
        E._full_prefilter()
        assert E._full_prefilter.cache_info().currsize == 1
    with E.configure_plugins(high_confidence=True):
        assert E._full_prefilter.cache_info().currsize == 0
        E._full_prefilter()
        assert E._full_prefilter.cache_info().currsize == 1
    with E.configure_plugins():
        assert E._full_prefilter.cache_info().currsize == 0


def test_full_prefilter_differs_between_configs():
    """Unlike _eligible_prefilter (whose two configs happen to agree on every
    cross-line-eligible entry), _full_prefilter covers the keyword detector
    too, and PLUGINS_HIGH_CONFIDENCE drops it — so the two configs' full
    prefilters must not be textually identical, or a stale cache would
    silently serve the wrong config's answer."""
    with E.configure_plugins():
        default_patterns = {p.pattern for p in E._full_prefilter()}
    with E.configure_plugins(high_confidence=True):
        hc_patterns = {p.pattern for p in E._full_prefilter()}
    assert default_patterns != hc_patterns


# ─── scan_line is actually skipped for a benign line ─────────────────────────


def test_benign_multiline_text_never_calls_scan_line(monkeypatch):
    """Non-vacuity for the whole point of the prefilter: a large, wholly benign
    payload must never reach scan_line at all — the per-line loop calls
    scan_line unconditionally for every line whenever the prefilter gate is
    absent or bypassed, so this test fails red without it."""
    calls = []
    monkeypatch.setattr(E, "scan_line", lambda line: calls.append(line) or iter(()))
    text = "\n".join(
        f"this is an ordinary log line number {i} with plain words in it"
        for i in range(500)
    )
    assert run_plain(text) is None
    assert calls == []


def test_a_real_secret_line_still_reaches_scan_line(monkeypatch):
    """The companion non-vacuity check: a line that DOES carry a detectable
    secret must still reach scan_line, proving the skip above is selective,
    not a global no-op that would silently stop detecting everything."""
    calls = []
    real_scan_line = E.scan_line

    def spy(line):
        calls.append(line)
        return real_scan_line(line)

    monkeypatch.setattr(E, "scan_line", spy)
    aws_key = "AKIA" + "ZYXWVUT123456789"
    text = "\n".join(
        [
            "an ordinary line with no secret in it",
            f"AWS_KEY={aws_key}",
            "another ordinary line",
        ]
    )
    result = run_plain(text)
    assert result is not None
    assert result["found"] == ["AWS Access Key"]
    # The prefilter is a NECESSARY, not sufficient, condition, so it may still
    # let an ordinary line reach scan_line (e.g. one that happens to contain a
    # keyword some other plugin's denylist matches on) — the property this
    # test actually needs is that the secret-bearing line was among them.
    assert any(aws_key in line for line in calls)


# ─── _degroup ──────────────────────────────────────────────────────────────


def test_degroup_strips_named_groups_without_changing_match_semantics():
    """The prefilter never reads capture groups — it only asks whether the
    union matched at all — so turning a plugin's named group non-capturing
    must not change WHETHER any real sample for that plugin matches."""
    # Same fixture values as test_secrets_detectors.py's _KEYWORD_CONTEXT_CORPUS
    # (_A24/_V44/_H48): each one's length/charset matches its plugin's own
    # capture group exactly, and detect-secrets' own non-sequential-string
    # filter accepts it (a synthetic "abcdefg..." run would not).
    samples = {
        "Cloudant Credentials": 'cloudant_key = "qxmzfwbnlvkrtdpghsjcyuxb"',
        "IBM Cloud IAM Key": (
            'iam_key = "q9x2mn7pk4rt8wy1cv5bz3df6gh0jl2eq9x2mn7pk4rt"'
        ),
        "IBM COS HMAC Credentials": (
            'cos_secret_access_key = "9af3b71e6c2d80f54e9b1a7c3d6f20e89af3b71e6c2d80f5"'
        ),
    }
    with E.configure_plugins():
        found_named = False
        for plugin in get_plugins():
            sample = samples.get(plugin.secret_type)
            if sample is None:
                continue
            for pat in plugin.denylist:
                if "(?P<" not in pat.pattern:
                    continue
                found_named = True
                degrouped = E._degroup(pat.pattern)
                assert "(?P<" not in degrouped
                compiled = re.compile(degrouped, pat.flags)
                assert bool(compiled.search(sample)) == bool(pat.search(sample)), (
                    f"{plugin.secret_type}: degrouping changed match semantics"
                )
        assert found_named, (
            "no sample exercised a named-group denylist pattern — this test "
            "would pass vacuously if the vocabulary drifted"
        )


def test_degroup_rejects_named_backreferences():
    """A named backreference (`(?P=name)`) breaks under a blind
    s/named-group/non-capturing/ rewrite (its target's name vanishes out
    from under it) — _degroup fails loud rather than silently mis-joining
    a pattern shaped that way."""
    with pytest.raises(RuntimeError, match="named backreference"):
        E._degroup(r"(?P<tag>foo)-(?P=tag)")


def test_full_prefilter_joins_denylists_that_reuse_a_group_name():
    """Two different plugins' denylists (Cloudant's, IBM Cloud IAM's, IBM COS
    HMAC's, SoftLayer's) each define a capture group named ``secret``.
    Joining their raw pattern text with `|` would raise `re.error:
    redefinition of group name` — building the full prefilter must not, since
    it degroups each pattern before joining."""
    with E.configure_plugins():
        E._full_prefilter()


# ─── end-to-end: identical redaction output with the prefilter in play ──────


@pytest.mark.parametrize(
    "field, value",
    [
        ("cloudant_key", "qxmzfwbnlvkrtdpghsjcyuxb"),
        ("iam_key", "q9x2mn7pk4rt8wy1cv5bz3df6gh0jl2eq9x2mn7pk4rt"),
        (
            "cos_secret_access_key",
            "9af3b71e6c2d80f54e9b1a7c3d6f20e89af3b71e6c2d80f5",
        ),
    ],
)
def test_named_group_detector_still_redacts_end_to_end(field, value):
    """The prefilter is purely a performance gate — a real secret served by a
    named-group denylist must still be found and redacted, exactly as before
    _full_prefilter existed."""
    result = run_plain(f'{field} = "{value}"', cfg())
    assert result is not None
    assert value not in result["text"]
