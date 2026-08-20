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

WHAT IS MEASURED. The primary bound is a COUNT of interpreted bytecode
operations at two input sizes, not elapsed seconds. A wall-clock threshold also
reports on the machine that ran it, so it passes locally and reds under CI load —
the flake this suite already carries a scar from (see
``test_a_hostile_variable_name_cannot_stall_the_matcher``). An opcode count is
identical on every machine and every run, and the RATIO between two sizes is
stable across Python versions even as the absolute count moves.

An opcode count cannot see inside a C builtin: one ``str`` slice costs one
opcode however many megabytes it copies. That is a hole, not a scope decision,
and a quadratic shipped through it — ``_redact_line`` rebuilt the whole line once
per redacted span, so 1 MiB of ``password="`` on ONE line cost ~28s of CPU
against ~5s for the same bytes at 80 columns.
:func:`test_copy_volume_is_linear_in_line_length` closes it with the one measure
that does see a C-level copy — CPU seconds, taken as a RATIO between two sizes in
one process so the machine's speed cancels. ``time.process_time`` rather than
wall clock is what keeps a loaded CI runner out of the number, and the threshold
sits between two MEASURED curves (see that test) rather than at a round number.

A quadratic that lives entirely in a dependency (detect-secrets calls
``line.index(secret)`` per secret) is out of both gates' reach and is bounded by
``compute_budget_seconds`` instead.
"""

import hashlib
import sys
import time

import pytest

import agent_sanitizer.secrets as pkg
from agent_sanitizer.secrets import (
    RedactorConfig,
    configure_plugins,
    detected_secret_values,
    mask_secret_lines,
    redact,
    redact_configured,
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

    # Restore whatever tracer was installed (a coverage plugin's), not None:
    # clearing it would silently stop coverage for every later test that runs
    # in this process.
    previous = sys.gettrace()
    sys.settrace(trace)
    try:
        call()
    finally:
        sys.settrace(previous)
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


def _growth_ratio(thunk_for) -> float:
    """Opcode growth from :data:`_SMALL` to :data:`_LARGE` secrets on ONE line.

    ``thunk_for(text)`` builds a zero-arg call; only that call is counted, so an
    entry point's setup (the detection pass feeding ``mask_secret_lines``) runs
    outside the measure and cannot bury the measured routine's own growth.

    A warm-up call first: the engine builds its plugin mapping and compiles its
    prefilters lazily, and charging that one-time cost to the smaller size alone
    would report a ratio far below the truth.
    """
    thunk_for(_secret_line(5))()
    small = _opcodes(thunk_for(_secret_line(_SMALL)))
    large = _opcodes(thunk_for(_secret_line(_LARGE)))
    assert small > 0, "measured no interpreted work — the entry point never ran"
    return large / small


_CONFIG = RedactorConfig()


def _mask_secret_lines_thunk(text):
    """Masking measured ALONE: the detection pass that feeds it runs out here,
    before the count starts. Measured together, detection's far larger opcode
    count is the whole ratio, and a mask-side quadratic could hide under a
    linear detection and pass."""
    values = detected_secret_values(text, _CONFIG)
    return lambda: mask_secret_lines(text, values)


def _redact_configured_thunk(text):
    """The daemon's shape: enter ``configure_plugins`` once, then redact. The
    context enter/exit rides inside the count as a per-call constant, which the
    :data:`_SMALL`/:data:`_LARGE` sizes keep far below the per-secret term."""

    def call():
        with configure_plugins():
            redact_configured(text, None, _CONFIG)

    return call


# The untrusted-TEXT entry points, each as a text -> zero-arg thunk. Every public
# export is accounted for below, either here or in _NON_TEXT_EXPORTS, and a test
# in this file fails when a new export lands in neither — so the scope of this
# gate is derived from the package's own __all__ rather than from this list.
_TEXT_ENTRY_POINTS = {
    "redact": lambda text: lambda: redact(text, _CONFIG),
    "redact_map": lambda text: lambda: redact_map(text, _CONFIG),
    "detected_secret_values": lambda text: (
        lambda: detected_secret_values(text, _CONFIG)
    ),
    "secret_previews": lambda text: lambda: secret_previews(text, _CONFIG),
    # Masking each value across the whole text is the shape most at risk of a
    # per-value rescan, so it is measured with detection hoisted out.
    "mask_secret_lines": _mask_secret_lines_thunk,
    # The daemon's per-request hot path — the caller this gate exists to
    # protect — so it is measured directly, not left as redact's twin.
    "redact_configured": _redact_configured_thunk,
    "strip_invisible": lambda text: lambda: strip_invisible(text),
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


# The copy-volume gate's own sizes and threshold. An 8x step, so linear is ~8x
# and quadratic ~64x; the per-call fixed cost pulls the measured linear curve
# slightly under 8. Both curves are MEASURED on the `password="` line below:
# 7.85x for the splice-once code, 30.27x for the whole-line-rebuild it replaced.
# 15.0 sits between them with ~2x margin on each side, which is what keeps a
# noisy runner from reddening it.
_COPY_SMALL_BYTES = 64 * 1024
_COPY_LARGE_BYTES = 512 * 1024
_COPY_GROWTH_LIMIT = 15.0

# One redaction site per 10 bytes, so the number of spans grows WITH the line and
# a per-span whole-line rebuild shows up as the quadratic it is. Every byte is on
# ONE line: the same bytes wrapped at 80 columns cost each rebuild only its own
# short line, which is exactly the asymmetry this gate names.
_FIELD_UNIT = 'password="'


def _long_field_line(nbytes: int) -> str:
    return _FIELD_UNIT * (nbytes // len(_FIELD_UNIT))


def _cpu_seconds(call) -> float:
    """CPU seconds burned by ``call`` — process time, so another process loading
    the runner inflates neither number."""
    start = time.process_time()
    call()
    return time.process_time() - start


def _cpu_growth_ratio(thunk_for) -> float:
    """CPU-time growth from :data:`_COPY_SMALL_BYTES` to :data:`_COPY_LARGE_BYTES`
    on ONE line, with the engine's lazy one-time setup warmed out first (same
    reason :func:`_growth_ratio` warms up)."""
    thunk_for(_long_field_line(1024))()
    small = _cpu_seconds(thunk_for(_long_field_line(_COPY_SMALL_BYTES)))
    large = _cpu_seconds(thunk_for(_long_field_line(_COPY_LARGE_BYTES)))
    assert small > 0, "measured no CPU time — the entry point never ran"
    return large / small


@pytest.mark.parametrize("name", sorted(_TEXT_ENTRY_POINTS))
def test_copy_volume_is_linear_in_line_length(name):
    """Byte-copying must not grow quadratically with the length of one line.

    The opcode gate above is blind to this whole class: a slice of a megabyte is
    one opcode. Same entry points, same claim, the measure that can see it.
    """
    ratio = _cpu_growth_ratio(_TEXT_ENTRY_POINTS[name])
    assert ratio < _COPY_GROWTH_LIMIT, (
        f"{name} burned {ratio:.2f}x the CPU when one line grew 8x "
        f"({_COPY_SMALL_BYTES} -> {_COPY_LARGE_BYTES} bytes); linear is ~8 and "
        "quadratic ~64, so this copies the line once per redacted span"
    )


def _rebuild_per_span(text: str) -> None:
    """The defect this gate exists for, in miniature: replace every 10th-byte span
    by rebuilding the WHOLE string each time. Quadratic in ``len(text)``, and
    every one of those bytes is copied inside a C builtin."""
    out = text
    for start in range(len(text) - len(_FIELD_UNIT), -1, -len(_FIELD_UNIT)):
        out = out[:start] + "X" + out[start + len(_FIELD_UNIT) :]


def test_the_cpu_measure_catches_a_copy_quadratic():
    """Non-vacuity: the CPU harness must FAIL a routine whose quadratic lives
    entirely in C, which is precisely what the opcode harness cannot see."""
    ratio = _cpu_growth_ratio(lambda text: lambda: _rebuild_per_span(text))
    assert ratio >= _COPY_GROWTH_LIMIT, (
        f"a routine that rebuilds the whole string per span measured {ratio:.2f}x "
        "— the harness cannot see a C-level copy quadratic, so every assertion "
        "above is vacuous"
    )


def test_the_opcode_measure_is_blind_to_a_copy_quadratic():
    """The CPU gate's whole rationale, asserted rather than claimed: the opcode
    count does NOT rise super-linearly for :func:`_rebuild_per_span`, so the gate
    above it would certify that routine as linear."""
    ratio = _growth_ratio(lambda text: lambda: _rebuild_per_span(text))
    assert ratio < _SUPER_LINEAR_RATIO, (
        f"the opcode measure reported {ratio:.2f}x for a C-level copy quadratic — "
        "if it can now see this class, the CPU gate's rationale needs rewriting"
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

    ratio = _growth_ratio(lambda text: lambda: quadratic(text))
    assert ratio >= _SUPER_LINEAR_RATIO, (
        f"a deliberately quadratic routine measured {ratio:.2f}x — the harness "
        "cannot tell quadratic from linear, so every assertion above is vacuous"
    )
