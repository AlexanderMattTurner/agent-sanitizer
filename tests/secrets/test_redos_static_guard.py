"""Static ReDoS guard over every secrets-engine, detector-class, and
detector-JSON regex.

This is the *generalizable* check that would have caught the ``FIELD_VALUE_RE``
ReDoS (audit finding P1) at analysis time. The per-pattern wall-clock test in
``test_secrets_engine.py`` asserts one pattern stays fast today; this instead
analyses every regex the engine can actually run and rejects super-linear
backtracking statically — so a *future* pattern with catastrophic backtracking
fails here automatically, with no timing flakiness.

The inventory is driven by the LIVE detect-secrets registry — every
``plugin.denylist`` entry ``configure_plugins()`` makes active, plus the
``_eligible_prefilter`` unions built from them — and only then supplemented by
module introspection over ``engine.py``, ``detectors.py`` and
``secret-detectors.json``. Introspection alone reached 22 of the 57 live
patterns, and the 35 it could not see were the BUNDLED detect-secrets plugins:
four of them (Cloudant, IBM Cloud IAM, IBM COS HMAC, SoftLayer) carried cubic
backtracking that this guard never looked at, which is the hole
``test_every_live_registry_pattern_is_analysed`` closes.

Analysis is done by ``regexploit`` (a dev dependency). It always exits 0 and
reports a finding on stdout as ``Worst-case complexity: … (exponential|
polynomial)``; a pattern it cannot parse is reported as ``Error parsing:``.
"""

import json
import re
import shutil
import subprocess

import pytest

import agent_sanitizer.secrets.detectors as D
import agent_sanitizer.secrets.engine as E
from detect_secrets.plugins.base import BasePlugin
from detect_secrets.settings import get_plugins
from tests._helpers import REPO_ROOT

# Atomic groups / possessive quantifiers cannot backtrack, so a pattern using
# them is backtracking-safe by construction. regexploit's parser predates
# Python 3.11 possessive quantifiers and raises on them, so we accept its parse
# failure ONLY when the pattern actually carries such a guard — an unexplained
# parse failure is treated as a real problem, not silently passed.
_ATOMIC_MARKERS = ("*+", "++", "?+", "}+", "(?>")

_DETECTORS_JSON = (
    REPO_ROOT
    / "python"
    / "agent_sanitizer"
    / "secrets"
    / "data"
    / "secret-detectors.json"
)


def _engine_patterns() -> dict[str, str]:
    patterns = {}
    for name in dir(E):
        obj = getattr(E, name)
        if isinstance(obj, re.Pattern):
            patterns[name] = obj.pattern
    return patterns


def _json_patterns() -> dict[str, str]:
    data = json.loads(_DETECTORS_JSON.read_text(encoding="utf-8"))
    patterns = {}
    for detector in data["detectors"]:
        for i, pattern in enumerate(detector.get("patterns", [])):
            patterns[f"{detector['const']}[{i}]"] = pattern
    return patterns


def _detector_patterns() -> dict[str, str]:
    """Every ``denylist`` regex carried INLINE by a detector CLASS in
    ``detectors.py`` (``JwtFullTokenDetector``, ``BoundedKeywordDetector``) —
    the one source ``_engine_patterns``/``_json_patterns`` above cannot see,
    since neither walks ``detectors.py``'s classes."""
    patterns = {}
    for name in dir(D):
        obj = getattr(D, name)
        if not (isinstance(obj, type) and issubclass(obj, BasePlugin)):
            continue
        denylist = getattr(obj, "denylist", ())
        # An imported abstract class (RegexBasedDetector itself) never
        # overrides `denylist`, so accessing it on the class returns the
        # unresolved abstractproperty descriptor rather than a list — skip it,
        # it carries no concrete regex to analyze.
        if not isinstance(denylist, (list, tuple)):
            continue
        for i, pattern in enumerate(denylist):
            patterns[f"{name}.denylist[{i}]"] = pattern.pattern
    return patterns


def _live_registry_patterns() -> dict[str, str]:
    """Every denylist regex the LIVE plugin set can run, plus the cross-line
    prefilter unions derived from them.

    This is the inventory that matters: a pattern reaches attacker-shaped input
    because ``configure_plugins()`` enabled its plugin, not because some module
    in this repo happens to hold a reference to it. Read under the default
    config, which is a superset of the high-confidence one (that config only
    drops the keyword detector)."""
    patterns = {}
    with E.configure_plugins():
        for plugin in get_plugins():
            for i, pattern in enumerate(getattr(plugin, "denylist", None) or ()):
                patterns[f"live:{type(plugin).__name__}.denylist[{i}]"] = (
                    pattern.pattern
                )
        for i, prefilter in enumerate(E._eligible_prefilter()):
            patterns[f"live:_eligible_prefilter[{i}]"] = prefilter.pattern
    return patterns


_LIVE_PATTERNS = _live_registry_patterns()
_ALL_PATTERNS = {
    **_engine_patterns(),
    **_json_patterns(),
    **_detector_patterns(),
    **_LIVE_PATTERNS,
}


def test_every_live_registry_pattern_is_analysed() -> None:
    """The partition: every regex the live plugin set can run is in the set the
    parametrized analysis below covers. Introspecting the modules this repo
    happens to import is not the same question — a bundled detect-secrets plugin
    has no module here to introspect, so it landed unanalysed."""
    assert len(_LIVE_PATTERNS) >= 40, (
        f"only {len(_LIVE_PATTERNS)} live patterns discovered — the registry walk "
        "has stopped seeing the plugin set, so this guard would pass vacuously"
    )
    analysed = set(_ALL_PATTERNS.values())
    missing = sorted(
        name for name, pattern in _LIVE_PATTERNS.items() if pattern not in analysed
    )
    assert not missing, f"live patterns nothing analyses: {missing}"
    # Positive markers on both halves of the inventory: a bundled plugin with no
    # module in this repo, and a custom one that also has a JSON row. Without
    # these the assertion above passes on an inventory that lost either half.
    names = set(_LIVE_PATTERNS)
    assert "live:AWSKeyDetector.denylist[0]" in names
    assert "live:BoundedKeywordDetector.denylist[0]" in names
    assert "live:_eligible_prefilter[0]" in names


def test_no_bundled_plugin_with_a_cubic_pattern_is_enabled() -> None:
    """The four bundled keyword-context detectors whose separator
    ``(?: *)(?:=|:|:=|=>| +|::)(?: *)`` backtracks cubically must stay OUT of the
    live set; ``detectors.py`` carries linear replacements with the same
    secret_type. Named by class, since the replacement reuses the label."""
    cubic = {
        "CloudantDetector",
        "IbmCloudIamDetector",
        "IbmCosHmacDetector",
        "SoftlayerDetector",
    }
    live_classes = {name.split(":")[1].split(".")[0] for name in _LIVE_PATTERNS}
    assert not (cubic & live_classes), sorted(cubic & live_classes)
    # The coverage they provided is still live, under the replacements.
    assert {
        "CloudantCredentialsDetector",
        "IbmCloudIamKeyDetector",
        "IbmCosHmacKeyDetector",
        "SoftlayerCredentialsDetector",
    } <= live_classes


def _analyze(pattern: str) -> str:
    exe = shutil.which("regexploit")
    assert exe, "regexploit is not installed — it is a dev dependency (pyproject [dev])"
    return subprocess.run(
        [exe], input=pattern + "\n", capture_output=True, text=True, check=True
    ).stdout


def test_pattern_inventory_is_non_empty() -> None:
    # A refactor that stops discovering patterns would make the parametrized
    # test below pass vacuously; assert every source is actually populated.
    assert len(_engine_patterns()) >= 5
    assert len(_json_patterns()) >= 5
    assert len(_detector_patterns()) >= 4


@pytest.mark.parametrize("name, pattern", sorted(_ALL_PATTERNS.items()))
def test_regex_has_no_super_linear_backtracking(name: str, pattern: str) -> None:
    out = _analyze(pattern)
    assert "Worst-case complexity" not in out, (
        f"{name} exhibits super-linear backtracking (ReDoS):\n{pattern}\n{out}"
    )
    if "Error parsing" in out:
        assert any(marker in pattern for marker in _ATOMIC_MARKERS), (
            f"{name}: regexploit could not analyze this pattern and it carries no "
            f"atomic/possessive guard proving it is backtracking-safe:\n{pattern}"
        )


def test_guard_detects_a_known_vulnerable_pattern() -> None:
    # Non-vacuity control: the exact shape the P1 fix removed — a `[_-]`
    # separator and a `\w` body that both match `_`, so the run repartitions
    # exponentially — must be flagged by the analyzer.
    out = _analyze(r"prefix(?:[_-]\w+)*[:=]tail")
    assert "Worst-case complexity" in out, out
