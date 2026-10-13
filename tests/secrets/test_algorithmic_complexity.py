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

WHAT IS MEASURED. Every gate here is a fitted growth EXPONENT over three
geometrically spaced sizes, classified against the one pair of thresholds every
complexity gate in the repo shares (``tests/_growth.py``, twin of
``test/helpers/cpu-timing.mjs``) — never a ratio of two samples against a
constant tuned for this file.

The primary measure is a COUNT of interpreted bytecode operations, not elapsed
seconds: identical on every machine and every run, so the exponent it fits is
exact. An opcode count cannot see inside a C builtin, though — one ``str`` slice
costs one opcode however many megabytes it copies. That is a hole, not a scope
decision, and a quadratic shipped through it: ``_redact_line`` rebuilt the whole
line once per redacted span, so 1 MiB of ``password="`` on ONE line cost 35.6s of
CPU against 7.8s for the same bytes at 80 columns.
:func:`test_copy_volume_is_linear_in_line_length` closes it with the one measure
that does see a C-level copy — CPU time, sampled the way the shared estimator
samples it (interleaved, fastest of several, ``time.process_time`` so a loaded
runner charges nothing).

A quadratic that lives entirely in a dependency (detect-secrets calls
``line.index(secret)`` per secret) is out of both gates' reach and is bounded by
``compute_budget_seconds`` instead.
"""

import hashlib
import re

import pytest
from detect_secrets.settings import get_plugins

import agent_sanitizer.secrets as pkg
from agent_sanitizer.secrets import (
    RedactorConfig,
    configure_plugins,
    detected_secret_values,
    is_bare_pem_header,
    mask_secret_lines,
    redact,
    redact_configured,
    redact_map,
    secret_previews,
    strip_invisible,
)
from agent_sanitizer.secrets.placeholders import PLACEHOLDER_RE
from agent_sanitizer.secrets.prefilter import (
    _c as _sre_constants,
    _parser as _sre_parser,
    denylist_patterns,
    required_literals,
)
from tests._growth import (
    LINEAR_MAX_EXPONENT,
    assert_linear,
    assert_superlinear,
    cpu_growth,
    geometric_sizes,
    opcode_growth,
)

# Secrets on ONE line. The sizes are what make the curve readable: the engine's
# fixed per-call overhead swamps the N^2 term below a few hundred secrets, and
# the quadratic this gate exists for measured only 1.71x at 100->200 — exponent
# 0.77, which would have passed. At 400->800 the same defect measured 2.97x
# (exponent 1.57) against the fixed code's 1.69x (0.76); the fit over
# 400/800/1600 reads 0.79-0.80 for every entry point that ships.
_OPCODE_SIZES = geometric_sizes(400, 1600, 3)


def _secret_line(n: int) -> str:
    """One line holding ``n`` distinct detectable secrets.

    sha256 of the index so every key is well mixed (detect-secrets drops a
    sequential or low-entropy string) and identical on every machine and run.
    """
    return " ".join(
        "AKIA" + hashlib.sha256(str(i).encode()).hexdigest()[:16].upper()
        for i in range(n)
    )


def _opcode_curve(thunk_for):
    """Opcode growth across :data:`_OPCODE_SIZES` secrets on ONE line.

    ``thunk_for(text)`` builds a zero-arg call; only that call is counted, so an
    entry point's setup (the detection pass feeding ``mask_secret_lines``) runs
    outside the measure and cannot bury the measured routine's own growth.
    """
    return opcode_growth(lambda n, k: thunk_for(_secret_line(n + k)), _OPCODE_SIZES)


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
    :data:`_OPCODE_SIZES` keep far below the per-secret term."""

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
    # Takes a DETECTED value, which is a slice of the same untrusted document.
    "is_bare_pem_header": lambda text: lambda: is_bare_pem_header(text),
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
    assert_linear(
        f"{name} (opcodes per secrets on one line)",
        _opcode_curve(_TEXT_ENTRY_POINTS[name]),
    )


# The copy-volume gate's sizes, in bytes on ONE line. Large enough that a
# per-span copy dominates the curve: the control below reads exponent 1.98-2.02
# here; a whole-string rebuild per span reads 2.01 here. The control's C work is
# ``translate``, not ``memmove``, so it does NOT evidence that these sizes make a
# memmove-bound rebuild read super-linear on a host with a fast ``memmove``.
# The splicing entry points that ship read 0.97-1.03.
_COPY_SIZES = geometric_sizes(32 * 1024, 256 * 1024, 3)

# `password="<next unit's `password=`>"` redacts once per TWO units, so the span
# count grows with the line and a per-span whole-line rebuild shows as the
# quadratic it is. Every byte is on ONE line: that is the axis this gate bounds,
# since a rebuild on 80-column lines only ever copies its own short line.
_FIELD_UNIT = 'password="'
_FIELD_UNITS_PER_SITE = 2


def _long_field_line(nbytes: int) -> str:
    return _FIELD_UNIT * (nbytes // len(_FIELD_UNIT))


def _cpu_curve(thunk_for):
    """CPU-time growth across :data:`_COPY_SIZES` on ONE line."""
    return cpu_growth(lambda n, k: thunk_for(_long_field_line(n + k)), _COPY_SIZES)


# The entry points whose cost this gate can actually read, and the reason each
# other one is excluded — a name here is a claim a reader can check, not a silent
# omission. Both exclusions are entry points that do no splicing on this payload,
# so their measured CPU is call overhead and their curve is timer noise (once
# measured as the 8x-larger input reading CHEAPER for `strip_invisible`).
_NON_SPLICING_ENTRY_POINTS = {
    "mask_secret_lines": "masks the ONE distinct detected value; splices nothing",
    "strip_invisible": "deletes invisible characters, of which this payload has none",
}
_SPLICING_ENTRY_POINTS = sorted(
    set(_TEXT_ENTRY_POINTS) - set(_NON_SPLICING_ENTRY_POINTS)
)


def test_every_copy_gate_exclusion_is_still_an_entry_point():
    """The gate's scope is :data:`_TEXT_ENTRY_POINTS` MINUS the exclusions, so a
    new entry point joins it automatically; what can rot is an exclusion whose
    entry point is gone, which would then excuse nothing while still reading as a
    considered decision."""
    assert set(_NON_SPLICING_ENTRY_POINTS) - set(_TEXT_ENTRY_POINTS) == set(), (
        "excluded name(s) are not entry points at all — drop them"
    )


def test_the_copy_gate_payload_holds_a_span_per_two_units():
    """Positive marker for the gate below: its ratios only bound splicing while
    this payload really redacts once per two units, so the span count grows with
    the line. A precision change that stopped matching ``password="`` would leave
    every case below measuring an untouched pass-through, green forever."""
    for units in (10, 40):
        line = _FIELD_UNIT * units
        redacted, _found = redact(line, _CONFIG)
        placeholders = PLACEHOLDER_RE.findall(redacted)
        assert len(placeholders) == units // _FIELD_UNITS_PER_SITE


@pytest.mark.parametrize("name", _SPLICING_ENTRY_POINTS)
def test_copy_volume_is_linear_in_line_length(name):
    """Byte-copying must not grow quadratically with the length of one line.

    The opcode gate above is blind to this whole class: a slice of a megabyte is
    one opcode. Same entry points, same claim, the measure that can see it.

    Reaches the per-line splice only. Cross-line reassembly splices whole-document
    offsets, but its per-span detection cost so dominates at every size this suite
    can afford that a rebuild-per-span there measures 7.7x — inside this
    threshold — so a gate over it would pass either way. What covers it instead is
    that both paths splice through the ONE ``_splice`` this gate measures.
    """
    assert_linear(
        f"{name} (CPU per byte on one line)", _cpu_curve(_TEXT_ENTRY_POINTS[name])
    )


# Every byte of the field unit maps to "X": what the control below writes. The
# mapping is irrelevant to its cost; ``translate`` walks every byte regardless.
_REDACT_TABLE = bytes.maketrans(_FIELD_UNIT.encode(), b"X" * len(_FIELD_UNIT))
_SITE_BYTES = len(_FIELD_UNIT) * _FIELD_UNITS_PER_SITE


def _rewrite_tail_per_site(text: str) -> None:
    """Walk the whole remaining line through a C ``translate`` once per site —
    quadratic in ``len(text)``, with every byte handled inside C, which is the
    shape both tests below are about. The first pass maps every ``password="``
    byte to "X", so later passes re-walk an already-redacted tail; the walk, not
    the redaction, is what the curve measures.

    The cost per site is a fixed interpreter overhead ``c`` plus C work ``k*n``
    on the tail, so the fitted exponent depends only on ``k*n/c`` at the
    smallest size: the control reads ~2 only while the C work dwarfs ``c``. A
    ``memmove`` cannot promise that: its per-byte cost swings by more than an
    order of magnitude between hosts. Shifting the tail by one slice assignment
    per span cost 16 ms at 32 KiB on one host and 0.9 ms on a CI runner, where
    ``k*n`` was therefore about ``c`` and the control read exponent 1.68
    against the 1.7 it must clear. ``translate`` is a scalar byte loop on every
    host: at 32 KiB it costs ~7.2 us per site against ~0.25 us of overhead.

    One site per iteration (two units, matching what the engine redacts), not
    one unit: the stride scales the runtime but not the exponent."""
    line = bytearray(text.encode())
    for start in range(0, len(line), _SITE_BYTES):
        line[start:] = line[start:].translate(_REDACT_TABLE)


def test_the_cpu_measure_catches_a_copy_quadratic():
    """Non-vacuity: the CPU harness must classify a routine whose quadratic
    lives entirely in C as super-linear, which is precisely what the opcode
    harness cannot see."""
    assert_superlinear(
        "_rewrite_tail_per_site (CPU)",
        _cpu_curve(lambda text: lambda: _rewrite_tail_per_site(text)),
    )


def test_the_opcode_measure_is_blind_to_a_copy_quadratic():
    """The CPU gate's whole rationale, asserted rather than claimed: the opcode
    count does NOT rise super-linearly for :func:`_rewrite_tail_per_site`, so the
    gate above it would certify that routine as linear."""
    assert_linear(
        "_rewrite_tail_per_site (opcodes) — if the opcode measure can now see this "
        "class, the CPU gate's rationale needs rewriting",
        _opcode_curve(lambda text: lambda: _rewrite_tail_per_site(text)),
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

    assert_superlinear(
        "a token-dedup quadratic (opcodes)",
        _opcode_curve(lambda text: lambda: quadratic(text)),
    )


# ─── Adversarial repetition of a pattern's own opening ───────────────────────
# The quadratic shape a regex gate cannot see from the pattern alone: a pattern
# whose attempts can start inside a run another attempt already read, repeated
# until the run is long. `"sk-" * n` against the bundled OpenAI pattern measured
# 35.8s at 96KB; `"eyJ-" * n` against an unanchored JWT pattern measured 64x CPU
# for 8x input. Sizes are BYTES of payload, so every unit is read over the same
# volume, and the verdict is a CPU growth exponent like the copy gate's.
_SHAPE_SEPARATORS = ("", "-", "=", "_", ".", " ", "/")
_SHAPE_SIZES = geometric_sizes(16 * 1024, 64 * 1024, 3)
# A scan that finishes in tens of microseconds crosses a cache boundary inside
# this range and reads a step that is the memory system's, not the pattern's
# (a literal PEM header read exponent 1.4-1.6 once in ~130 combinations, never
# twice). A quadratic reads ~2 at EVERY size, so a curve is reported only when a
# second fit over sizes four times larger agrees.
_SHAPE_CONFIRM_SIZES = geometric_sizes(64 * 1024, 256 * 1024, 3)
# The control is genuinely quadratic, so it is read at sizes a quarter as large:
# its exponent is unmistakable there and the fit does not spend seconds on it.
_SHAPE_CONTROL_SIZES = geometric_sizes(4 * 1024, 16 * 1024, 3)


def _leading_literal(pattern: re.Pattern[str]) -> str:
    """The literal a match of ``pattern`` opens with (after a leading lookbehind),
    or, when it opens on a class or an alternation, its rarest required literal."""
    out = []
    for op, arg in _sre_parser.parse(pattern.pattern, pattern.flags):
        if op is _sre_constants.ASSERT_NOT and not out:
            continue
        if op is not _sre_constants.LITERAL:
            break
        out.append(chr(arg))
    if out:
        return "".join(out)
    literals = required_literals(pattern.pattern, pattern.flags)
    return min(literals, key=lambda lit: (len(lit), lit)) if literals else "a"


def _live_denylist_patterns() -> list[re.Pattern[str]]:
    with configure_plugins():
        return denylist_patterns(get_plugins())


def _shape_curve(call_for, sizes=_SHAPE_SIZES):
    """CPU growth across ``sizes`` bytes of an adversarial payload.
    ``call_for(nbytes)`` builds the zero-arg call; the sampler's per-call attempt
    index is added to the byte count so no two inputs are identical."""
    return cpu_growth(lambda n, k: call_for(n + k), sizes)


def _repeat_to(unit: str, nbytes: int) -> str:
    return unit * (nbytes // len(unit))


def _scan(pattern: re.Pattern[str], text: str):
    """The call to measure, with ``text`` already built: the repetition is an
    allocation whose page-fault cost steps with size and is not the pattern's."""
    return lambda: list(pattern.finditer(text))


def test_no_live_pattern_is_quadratic_on_its_own_opening_repeated():
    """Every live denylist pattern, fed its own opening literal repeated with
    each separator a token body may admit."""
    patterns = _live_denylist_patterns()
    assert len(patterns) >= 40, len(patterns)
    slow = []
    for pattern in patterns:
        literal = _leading_literal(pattern)
        for sep in _SHAPE_SEPARATORS:
            unit = literal + sep

            def call_for(n, unit=unit, pattern=pattern):
                return _scan(pattern, _repeat_to(unit, n))

            growth = _shape_curve(call_for)
            if growth.exponent < LINEAR_MAX_EXPONENT:
                continue
            confirm = _shape_curve(call_for, _SHAPE_CONFIRM_SIZES)
            if confirm.exponent >= LINEAR_MAX_EXPONENT:
                slow.append((pattern.pattern[:60], unit, str(growth), str(confirm)))
    assert slow == [], slow


def test_the_shape_measure_catches_an_unanchored_quadratic():
    """Non-vacuity: the bundled OpenAI shape, unanchored and unbounded, must
    classify as super-linear."""
    quadratic = re.compile(r"sk-[A-Za-z0-9_-]*[A-Za-z0-9]{20}T3BlbkFJ")
    assert_superlinear(
        "an unanchored OpenAI-shaped pattern (CPU)",
        _shape_curve(
            lambda n: _scan(quadratic, _repeat_to("sk-", n)),
            _SHAPE_CONTROL_SIZES,
        ),
    )


# Whole-engine payloads for the field-value and PEM passes, which run patterns
# the denylist sweep above never sees. Each unit repeats the pass's own opening.
# Sizes here are repetitions of the unit, not bytes: the shapes differ in unit
# length and several divide `n` themselves.
_ENGINE_SIZES = geometric_sizes(2000, 8000, 3)
_ENGINE_SHAPES = {
    "identifier segments": lambda n: "token" + "_token" * n + "!",
    "segment then junk": lambda n: "password_" + "a_" * n + "!",
    "noun then whitespace": lambda n: ("password" + " " * 50) * (n // 8),
    "nested benign url": lambda n: "token_url=" + "https://a/token=" * n,
    "nested benign metadata": lambda n: "token_type=" + "xtoken_type=" * n,
    "pem headers": lambda n: "-----BEGIN PRIVATE KEY-----" * (n // 4),
    "pem body lines": lambda n: "-----BEGIN PRIVATE KEY-----\n" + "QUFB\n" * n,
    "pem json body": lambda n: "-----BEGIN PRIVATE KEY-----" + "\\nQUFB" * n,
    "pem deep json body": lambda n: "-----BEGIN PRIVATE KEY-----" + "\\\\nQUFB" * n,
    "pem field dashes": lambda n: (
        "-----BEGIN PRIVATE KEY-----\nProc-Type: " + "----a" * n
    ),
    "pem blocks": lambda n: "-----BEGIN PRIVATE KEY-----\nQUFB QUFB\n" * (n // 4),
    "pem markers in prose": lambda n: (
        "-----BEGIN PRIVATE KEY----- a " * (n // 4) + "-----END PRIVATE KEY-----"
    ),
}


def _redact_text(text: str, config: RedactorConfig):
    return lambda: redact(text, config)


@pytest.mark.parametrize("shape", sorted(_ENGINE_SHAPES))
@pytest.mark.parametrize("web_ingress", [False, True])
def test_engine_pass_is_linear_on_its_own_opening_repeated(shape, web_ingress):
    """The field-value pass is tried at every credential noun and the PEM pass
    at every header, so each must bound one attempt — `token` + `_token` * n
    measured 87s at 96KB before the field key's segment run was bounded."""
    config = RedactorConfig(web_ingress=web_ingress)
    make = _ENGINE_SHAPES[shape]
    assert_linear(
        f"{shape} (CPU per unit)",
        _shape_curve(lambda n: _redact_text(make(n), config), _ENGINE_SIZES),
    )
