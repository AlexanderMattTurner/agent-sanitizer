"""Complexity gate: prove the engine's untrusted-input entry points stay
sub-quadratic in the size of ONE input.

Sibling to ``test_redos_static_guard.py``, which proves the same property for the
engine's REGEXES. That gate collects compiled ``re.Pattern`` objects, so by
construction it can only ever see one of the two ways to reach a stall — and the
other way shipped: ``_redact_line`` tested each candidate span against every
accepted span, which is quadratic in the secrets on one line and cost 7.85s of
CPU on a 256KB payload. Both gates defend the same claim, stated in
``test_redos_static_guard.py``: this text is attacker-shaped, so super-linear
cost is weaponizable — a stall past the caller's timeout is what makes a caller
write its unavailable-sentinel and stop redacting for the rest of the session.

WHAT IS MEASURED, and why not time. The bound is a COUNT of interpreted
bytecode operations at two input sizes, not elapsed seconds. A wall-clock
threshold also reports on the machine that ran it, so it passes locally and reds
under CI load — the flake this suite already carries a scar from (see
``test_a_hostile_variable_name_cannot_stall_the_matcher``). An opcode count is
identical on every machine and every run, and the RATIO between two sizes is
stable across Python versions even as the absolute count moves.

What it does NOT see: work inside C builtins (``str.find``, ``re``) counts as one
opcode. That is deliberate rather than a gap — the regex gate covers the ``re``
half, and an algorithmic mistake written in this package is Python-level by
definition. A quadratic that lives entirely in a dependency (detect-secrets calls
``line.index(secret)`` per secret) is out of both gates' reach and is bounded by
``compute_budget_seconds`` instead.
"""

import hashlib
import sys

import pytest

import agent_sanitizer.secrets as pkg
from agent_sanitizer.secrets import (
    RedactorConfig,
    detected_secret_values,
    mask_secret_lines,
    redact,
    redact_map,
    secret_previews,
    strip_invisible,
)

# Doubling the input doubles the work when the cost is linear and quadruples it
# when it is quadratic. The sizes are what make that gap readable: the engine's
# fixed per-call overhead swamps the N^2 term below a few hundred secrets, and
# the quadratic this gate exists for measured only 1.71x at 100->200 — it would
# have passed. At 400->800 the same defect measures 2.97x against the fixed
# code's 1.69x, so the threshold sits between two MEASURED curves rather than at
# a round number picked from the theory.
_SUPER_LINEAR_RATIO = 2.5
_SMALL = 400
_LARGE = 800


def _opcodes(call) -> int:
    """Interpreted bytecode operations executed by ``call``.

    ``sys.settrace`` with per-frame ``f_trace_opcodes`` is what makes this a
    machine-independent number: it counts the interpreter's own steps rather
    than the host's speed.
    """
    count = 0

    def trace(frame, event, _arg):
        nonlocal count
        if event == "call":
            frame.f_trace_opcodes = True
            return trace
        if event == "opcode":
            count += 1
        return trace

    sys.settrace(trace)
    try:
        call()
    finally:
        sys.settrace(None)
    return count


def _secret_line(n: int) -> str:
    """One line holding ``n`` distinct detectable secrets.

    sha256 of the index so every key is well mixed (detect-secrets drops a
    sequential or low-entropy string) and identical on every machine and run.
    """
    return " ".join(
        "AKIA" + hashlib.sha256(str(i).encode()).hexdigest()[:16].upper()
        for i in range(n)
    )


def _growth_ratio(call_with_text) -> float:
    """Opcode growth from :data:`_SMALL` to :data:`_LARGE` secrets on ONE line.

    A warm-up call first: the engine builds its plugin mapping and compiles its
    prefilters lazily, and charging that one-time cost to the smaller size alone
    would report a ratio far below the truth.
    """
    call_with_text(_secret_line(5))
    small = _opcodes(lambda: call_with_text(_secret_line(_SMALL)))
    large = _opcodes(lambda: call_with_text(_secret_line(_LARGE)))
    assert small > 0, "measured no interpreted work — the entry point never ran"
    return large / small


_CONFIG = RedactorConfig()

# The untrusted-TEXT entry points, each as a one-argument call. Every public
# export is accounted for below, either here or in _NON_TEXT_EXPORTS, and a test
# in this file fails when a new export lands in neither — so the scope of this
# gate is derived from the package's own __all__ rather than from this list.
_TEXT_ENTRY_POINTS = {
    "redact": lambda text: redact(text, _CONFIG),
    "redact_map": lambda text: redact_map(text, _CONFIG),
    "detected_secret_values": lambda text: detected_secret_values(text, _CONFIG),
    "secret_previews": lambda text: secret_previews(text, _CONFIG),
    # Takes the detected values rather than a config, and masking each value
    # across the whole text is the shape most at risk of a per-value rescan.
    "mask_secret_lines": lambda text: mask_secret_lines(
        text, detected_secret_values(text, _CONFIG)
    ),
    "strip_invisible": strip_invisible,
}

# Public exports that take no untrusted text, with the reason each is out of
# scope. A name here is a claim a reader can check, not a silent omission.
_NON_TEXT_EXPORTS = {
    "ANY_SEGMENT_SCOPE": "a scope constant",
    "CREDENTIAL_NAMES_FILE": "a path to the vocabulary file",
    "DEFAULT_MIN_SECRET_LEN": "an int floor",
    "RedactionBudgetExceeded": "an exception type",
    "RedactorConfig": "the caller-supplied config dataclass",
    "TRAILING_SCOPE": "a scope constant",
    "configure_plugins": "a context manager over plugin settings, takes no text",
    "credential_field_name_patterns": "returns the vocabulary's renderings",
    "credential_name_matcher": "a predicate over an env-var NAME, not a document",
    "credential_name_segments": "returns the vocabulary's renderings",
    "default_charset": "returns the invisible-charset set",
    "handle_request": "the daemon's socket frame handler; covered by the daemon suite",
    "non_secret_name_segments": "returns the vocabulary's renderings",
    "parse_credential_names": "parses the packaged vocabulary file, not untrusted text",
    "redact_configured": "the hot-path twin of redact; needs an active configure_plugins",
}


def test_every_public_export_is_classified():
    """The gate's scope comes from ``__all__``, so a new entry point cannot
    silently escape it.

    This is the failure mode the gate itself exists to prevent, one level up: a
    check trusted for what its scope covers, whose scope is a literal that
    drifts below the thing it guards.
    """
    classified = set(_TEXT_ENTRY_POINTS) | set(_NON_TEXT_EXPORTS)
    exported = set(pkg.__all__)
    assert exported - classified == set(), (
        "public export(s) neither covered by this gate nor listed as non-text — "
        "add the call to _TEXT_ENTRY_POINTS or the reason to _NON_TEXT_EXPORTS"
    )
    assert classified - exported == set(), (
        "classified name(s) are no longer public exports — drop them"
    )


@pytest.mark.parametrize("name", sorted(_TEXT_ENTRY_POINTS))
def test_entry_point_is_sub_quadratic_on_one_line(name):
    """One long line must not cost quadratically in the secrets it holds."""
    ratio = _growth_ratio(_TEXT_ENTRY_POINTS[name])
    assert ratio < _SUPER_LINEAR_RATIO, (
        f"{name} grew {ratio:.2f}x when its input doubled "
        f"({_SMALL} -> {_LARGE} secrets on one line); "
        "linear is ~2.0 and quadratic ~4.0, so this is super-linear"
    )


def test_the_measure_catches_a_quadratic():
    """Non-vacuity: the harness must FAIL a routine that really is quadratic.

    Without this, a measure that silently counted nothing would pass every case
    above and the gate would certify the defect it was written for.
    """

    def quadratic(text):
        seen = []
        for token in text.split():
            if not any(s == token for s in seen):
                seen.append(token)

    ratio = _growth_ratio(quadratic)
    assert ratio >= _SUPER_LINEAR_RATIO, (
        f"a deliberately quadratic routine measured {ratio:.2f}x — the harness "
        "cannot tell quadratic from linear, so every assertion above is vacuous"
    )
