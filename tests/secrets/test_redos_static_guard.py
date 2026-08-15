"""Static ReDoS guard over every secrets-engine, detector-class, and
detector-JSON regex.

This is the *generalizable* check that would have caught the ``FIELD_VALUE_RE``
ReDoS (audit finding P1) at analysis time. The per-pattern wall-clock test in
``test_secrets_engine.py`` asserts one pattern stays fast today; this instead
introspects EVERY compiled regex in the engine module, EVERY detector class's
own ``denylist`` in ``detectors.py``, and EVERY detector pattern in
``secret-detectors.json``, and rejects super-linear backtracking statically —
so a *future* pattern with catastrophic backtracking fails here automatically,
with no timing flakiness.

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


_ALL_PATTERNS = {**_engine_patterns(), **_json_patterns(), **_detector_patterns()}


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
