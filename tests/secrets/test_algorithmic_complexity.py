"""Complexity gate: the engine's untrusted-input entry points must not go
super-linear in the size of ONE input.

Sibling to ``test_redos_static_guard.py``, which proves the same property for the
engine's REGEXES statically. That gate collects compiled ``re.Pattern`` objects,
so by construction it can only ever see one of the ways to reach a stall — and
the others shipped: ``_redact_line`` tested each candidate span against every
accepted span (7.85s of CPU on a 256KB payload); ``_redact_line`` rebuilt the
whole line once per redacted span (1 MiB of ``password="`` on ONE line cost
35.6s); the bundled OpenAI pattern retried at every ``sk-`` (35.8s at 96KB).
Both gates defend the same claim, stated in ``test_redos_static_guard.py``: this
text is attacker-shaped, so super-linear cost is weaponizable — a stall past the
caller's timeout is what makes a caller write its unavailable-sentinel and stop
redacting for the rest of the session.

WHAT IS MEASURED. Every gate here runs one call ONCE, after a warm-up, against
an absolute CPU ceiling (``tests/_budget.py``, twin of
``test/helpers/budget.mjs``). Each input is sized so the shipped code costs at
most a few tenths of a second and the ceiling sits ten times or more above that
reading. A path that turns quadratic at these sizes overshoots it by an order of
magnitude; a constant-factor slowdown passes, by design.

What that gives up is stated where it applies: an entry point whose LINEAR work
is heavy (the detection pass costs ~60us per secret) only shows a quadratic
with a small constant at sizes no commit can afford to time. The per-span copy
is gated where the copy lives, on ``_splice`` itself, at a size where one
rebuild per span is unmistakable.

A quadratic that lives entirely in a dependency (detect-secrets calls
``line.index(secret)`` per secret) is out of reach here and is bounded by
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
from agent_sanitizer.secrets.engine import SpliceSpan, _splice
from agent_sanitizer.secrets.placeholders import PLACEHOLDER_RE
from agent_sanitizer.secrets.prefilter import (
    _c as _sre_constants,
    _parser as _sre_parser,
    denylist_patterns,
    required_literals,
)
from tests._budget import assert_under_budget

# Secrets on ONE line: ~84KB, which the dearest shipped entry point
# (`secret_previews`) reads in ~0.42s of CPU.
_SECRETS_ON_ONE_LINE = 4000
_SECRETS_CEILING_SECONDS = 5.0


def _secret_line(n: int) -> str:
    """One line holding ``n`` distinct detectable secrets.

    sha256 of the index so every key is well mixed (detect-secrets drops a
    sequential or low-entropy string) and identical on every machine and run.
    """
    return " ".join(
        "AKIA" + hashlib.sha256(str(i).encode()).hexdigest()[:16].upper()
        for i in range(n)
    )


_CONFIG = RedactorConfig()


def _mask_secret_lines_thunk(text):
    """Masking measured ALONE: the detection pass that feeds it runs out here,
    before the clock starts. Measured together, detection's far larger cost
    would be the whole reading, and a mask-side quadratic could hide under it."""
    values = detected_secret_values(text, _CONFIG)
    return lambda: mask_secret_lines(text, values)


def _redact_configured_thunk(text):
    """The daemon's shape: enter ``configure_plugins`` once, then redact. The
    context enter/exit rides inside the clock as a per-call constant."""

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
def test_entry_point_stays_under_budget_on_one_line(name):
    """One long line of secrets, through every untrusted-text entry point.
    ``thunk_for(text)`` builds the zero-arg call, so an entry point's setup (the
    detection pass feeding ``mask_secret_lines``) runs outside the clock."""
    assert_under_budget(
        f"{name} on {_SECRETS_ON_ONE_LINE} secrets on one line",
        lambda k: _TEXT_ENTRY_POINTS[name](_secret_line(_SECRETS_ON_ONE_LINE + k)),
        _SECRETS_CEILING_SECONDS,
    )


# The copy-volume payload, in bytes on ONE line; the dearest entry point
# (`detected_secret_values`) reads it in ~0.29s of CPU.
_COPY_BYTES = 64 * 1024
_COPY_CEILING_SECONDS = 3.0

# `password="<next unit's `password=`>"` redacts once per TWO units, so the span
# count grows with the line and a per-span whole-line rebuild shows as the
# quadratic it is. Every byte is on ONE line: that is the axis this gate bounds,
# since a rebuild on 80-column lines only ever copies its own short line.
_FIELD_UNIT = 'password="'
_FIELD_UNITS_PER_SITE = 2


def _long_field_line(nbytes: int) -> str:
    return _FIELD_UNIT * (nbytes // len(_FIELD_UNIT))


# The entry points whose cost this gate can actually read, and the reason each
# other one is excluded — a name here is a claim a reader can check, not a silent
# omission. Both exclusions are entry points that do no splicing on this payload,
# so a budget on them would bound call overhead and nothing this gate is about.
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
    """Positive marker for the gate below: it only bounds splicing while
    this payload really redacts once per two units, so the span count grows with
    the line. A precision change that stopped matching ``password="`` would leave
    every case below measuring an untouched pass-through, green forever."""
    for units in (10, 40):
        line = _FIELD_UNIT * units
        redacted, _found = redact(line, _CONFIG)
        placeholders = PLACEHOLDER_RE.findall(redacted)
        assert len(placeholders) == units // _FIELD_UNITS_PER_SITE


@pytest.mark.parametrize("name", _SPLICING_ENTRY_POINTS)
def test_copy_volume_stays_under_budget_on_one_line(name):
    """Every splicing entry point over one long line of ``password="``. What
    this alone cannot see at an affordable size is a per-span whole-line
    rebuild: the detection pass dominates, and the shipped rebuild cost 35.6s
    against 7.8s only at 1 MiB. ``test_splice_is_one_pass`` below gates that
    copy where it lives."""
    assert_under_budget(
        f"{name} on {_COPY_BYTES} bytes of password= on one line",
        lambda k: _TEXT_ENTRY_POINTS[name](_long_field_line(_COPY_BYTES + k)),
        _COPY_CEILING_SECONDS,
    )


# One span per `_SITE_BYTES` across 4 MiB: ~200K spans. One pass over the text
# costs ~0.04s of CPU; a rebuild of the whole text per span copies ~200K x 4 MiB.
_SPLICE_BYTES = 4 * 1024 * 1024
_SITE_BYTES = len(_FIELD_UNIT) * _FIELD_UNITS_PER_SITE
_SPLICE_CEILING_SECONDS = 0.5


def _splice_call(nbytes: int):
    text = "x" * nbytes
    spans = [
        SpliceSpan(start, start + len(_FIELD_UNIT), "[REDACTED]")
        for start in range(0, nbytes - len(_FIELD_UNIT), _SITE_BYTES)
    ]
    return lambda: _splice(text, spans, None)


def test_splice_is_one_pass():
    """Byte-copying must not grow with spans x line length. Both the per-line
    and the cross-line redaction splice through this one function, so this is
    where a rebuild-per-span would land — and where it is visible: the per-span
    detection cost that hides it at the entry points is outside the clock."""
    assert_under_budget(
        f"_splice over {_SPLICE_BYTES // _SITE_BYTES} spans in {_SPLICE_BYTES} bytes",
        lambda k: _splice_call(_SPLICE_BYTES + k),
        _SPLICE_CEILING_SECONDS,
    )


def test_the_splice_payload_carries_a_span_per_site():
    """Positive marker for the gate above: a builder that produced no spans
    would time an empty loop."""
    text = "x" * 200
    spans = [
        SpliceSpan(start, start + len(_FIELD_UNIT), "[R]")
        for start in range(0, len(text) - len(_FIELD_UNIT), _SITE_BYTES)
    ]
    assert len(spans) == 10
    assert _splice(text, spans, None).count("[R]") == 10


# ─── Adversarial repetition of a pattern's own opening ───────────────────────
# The quadratic shape a regex gate cannot see from the pattern alone: a pattern
# whose attempts can start inside a run another attempt already read, repeated
# until the run is long. `"sk-" * n` against the bundled OpenAI pattern measured
# 35.8s at 96KB; `"eyJ-" * n` against an unanchored JWT pattern measured 64x CPU
# for 8x input. A linear scan of 128KB costs milliseconds — the dearest, the
# npm pattern's bounded `{1,256}` runs over `///`, ~0.26s — and the OpenAI
# quadratic at 128KB costs about a minute.
_SHAPE_SEPARATORS = ("", "-", "=", "_", ".", " ", "/")
_SHAPE_BYTES = 128 * 1024
_SHAPE_CEILING_SECONDS = 3.0


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
    for pattern in patterns:
        literal = _leading_literal(pattern)
        for sep in _SHAPE_SEPARATORS:
            unit = literal + sep
            assert_under_budget(
                f"{pattern.pattern[:60]!r} on {unit!r} x {_SHAPE_BYTES // len(unit)}",
                lambda k, unit=unit, pattern=pattern: _scan(
                    pattern, _repeat_to(unit, _SHAPE_BYTES + k)
                ),
                _SHAPE_CEILING_SECONDS,
            )


# Whole-engine payloads for the field-value and PEM passes, which run patterns
# the denylist sweep above never sees. Each unit repeats the pass's own opening.
# The size is in repetitions of the unit, not bytes: the shapes differ in unit
# length and several divide `n` themselves. The dearest shape ("nested benign
# url") costs ~0.11s of CPU at this size.
_ENGINE_REPETITIONS = 8000
_ENGINE_CEILING_SECONDS = 2.0
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
def test_engine_pass_stays_under_budget_on_its_own_opening_repeated(shape, web_ingress):
    """The field-value pass is tried at every credential noun and the PEM pass
    at every header, so each must bound one attempt — `token` + `_token` * n
    measured 87s at 96KB before the field key's segment run was bounded."""
    config = RedactorConfig(web_ingress=web_ingress)
    make = _ENGINE_SHAPES[shape]
    assert_under_budget(
        f"{shape} x {_ENGINE_REPETITIONS}",
        lambda k: _redact_text(make(_ENGINE_REPETITIONS + k), config),
        _ENGINE_CEILING_SECONDS,
    )
