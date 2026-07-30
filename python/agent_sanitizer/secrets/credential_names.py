"""The published credential-noun vocabulary: the words that make a name a secret.

``data/credential-names.json`` is the single source; this module validates it and
renders it for the two matchers that need it, which are deliberately NOT unified:

* an env-var **NAME** matcher inspects no value, so it wants whole-name segments
  (``API_KEY``, ``APIKEY``) — :func:`credential_name_segments`;
* a ``field = value`` **redaction** matcher wants regex fragments tolerant of the
  separator the author wrote (``api[_-]?key``) — :func:`credential_field_name_patterns`,
  which the engine's ``_FIELD_NAMES`` alternation is built from.

Rendering the same nouns two ways is the point: unifying the *predicates* would
either weaken the name scrub or flood the redactor with false positives, so only
the vocabulary is shared. A noun the JSON marks ``env-name`` only is excluded from
the field-value rendering for exactly that reason.

A malformed spec raises rather than degrading: an empty list yields an alternation
that matches nothing (every credential forwarded verbatim) and a part carrying a
regex metacharacter yields one that matches everything (all output blanked), so
neither may reach a consumer's pattern builder.

The same file is published to JavaScript consumers as the npm subpath export
``agent-sanitizer/credential-names``.
"""

import functools
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import NamedTuple

CREDENTIAL_NAMES_FILE = (
    Path(__file__).resolve().parent / "data" / "credential-names.json"
)

# a-z0-9 only is what lets a part interpolate into a consumer's pattern unescaped.
# Matched with fullmatch, not `$`, because Python's `$` also matches just before a
# trailing newline — `"token\n"` must be rejected here, not accepted and then
# rejected by a JavaScript consumer applying the same rule to the same file.
_PART_RE = re.compile(r"[a-z0-9]+")

ENV_NAME_USE = "env-name"
FIELD_VALUE_USE = "field-value"
_USES = frozenset({ENV_NAME_USE, FIELD_VALUE_USE})

_FILE_LABEL = "credential-names.json"


class CredentialNames(NamedTuple):
    """The renderings of a validated vocabulary spec."""

    segments: tuple[str, ...]
    field_name_patterns: tuple[str, ...]
    non_secret_segments: tuple[str, ...]


def _dedupe(values: Sequence[str]) -> tuple[str, ...]:
    """``values`` with duplicates dropped, first-occurrence order preserved."""
    return tuple(dict.fromkeys(values))


def _segment_forms(parts: Sequence[str]) -> tuple[str, ...]:
    """The whole-name forms of ``parts``: underscore-joined and bare-joined, upper.

    Both are emitted because both spellings occur in the wild (``API_KEY`` and
    ``APIKEY``) and a name matcher anchored on underscore-delimited segments sees
    them as different tokens. A single-part noun collapses to one form.
    """
    return _dedupe(["_".join(parts).upper(), "".join(parts).upper()])


def _parts(value: object, field: str) -> tuple[str, ...]:
    """``value`` as a validated tuple of noun parts, or raise naming ``field``."""
    parts = tuple(value) if isinstance(value, (list, tuple)) else ()
    if not parts:
        raise ValueError(f"{_FILE_LABEL}: {field} is empty or missing")
    bad = [p for p in parts if not (isinstance(p, str) and _PART_RE.fullmatch(p))]
    if bad:
        raise ValueError(f"{_FILE_LABEL}: bad part(s) {bad} in {field}")
    return parts


def _uses(value: object, field: str) -> frozenset[str]:
    """``value`` as a validated non-empty subset of the known uses, or raise.

    An unknown use is a refusal, not a skip: silently ignoring it would drop the
    noun from every rendering, which is how a credential noun becomes inert.
    """
    uses = tuple(value) if isinstance(value, (list, tuple)) else ()
    if not uses:
        raise ValueError(f"{_FILE_LABEL}: {field} is empty or missing")
    unknown = sorted(set(uses) - _USES)
    if unknown:
        raise ValueError(f"{_FILE_LABEL}: unknown use(s) {unknown} in {field}")
    return frozenset(uses)


def _sequence(value: object, field: str) -> tuple[object, ...]:
    """``value`` as a validated non-empty tuple, or raise naming ``field``."""
    items = tuple(value) if isinstance(value, (list, tuple)) else ()
    if not items:
        raise ValueError(f"{_FILE_LABEL}: {field} is empty or missing")
    return items


def parse_credential_names(spec: Mapping[str, object]) -> CredentialNames:
    """Validate ``spec`` and return its renderings.

    Pure and public so a consumer — and the fail-closed tests — can drive the
    validator with a substitute spec instead of only through the packaged file.
    """
    segments: list[str] = []
    patterns: list[str] = []
    for index, noun in enumerate(_sequence(spec.get("nouns"), "nouns")):
        if not isinstance(noun, Mapping):
            raise ValueError(f"{_FILE_LABEL}: nouns[{index}] is not an object")
        parts = _parts(noun.get("parts"), f"nouns[{index}].parts")
        uses = _uses(noun.get("uses"), f"nouns[{index}].uses")
        if ENV_NAME_USE in uses:
            segments.extend(_segment_forms(parts))
        if FIELD_VALUE_USE in uses:
            patterns.append("[_-]?".join(parts))

    non_secret: list[str] = []
    for index, suffix in enumerate(
        _sequence(spec.get("nonSecretSuffixes"), "nonSecretSuffixes")
    ):
        non_secret.extend(_segment_forms(_parts(suffix, f"nonSecretSuffixes[{index}]")))

    # A vocabulary that renders nothing for one matcher would hand that consumer an
    # empty alternation, which matches nothing and forwards every credential.
    if not segments:
        raise ValueError(f"{_FILE_LABEL}: no noun is marked {ENV_NAME_USE}")
    if not patterns:
        raise ValueError(f"{_FILE_LABEL}: no noun is marked {FIELD_VALUE_USE}")
    return CredentialNames(
        segments=_dedupe(segments),
        field_name_patterns=_dedupe(patterns),
        non_secret_segments=_dedupe(non_secret),
    )


@functools.cache
def _rendered() -> CredentialNames:
    """The validated renderings of the packaged vocabulary. Raises if the data file
    is absent (fail closed — a partial vocabulary silently under-matches)."""
    return parse_credential_names(
        json.loads(CREDENTIAL_NAMES_FILE.read_text(encoding="utf-8"))
    )


def credential_name_segments() -> tuple[str, ...]:
    """Upper-case whole-name forms of every noun usable against a variable NAME.

    A name whose trailing underscore-delimited segment is one of these holds a
    credential (``DEPLOY_API_KEY``), so a consumer matching by trailing segment
    self-populates from this list instead of curating its own.
    """
    return _rendered().segments


def credential_field_name_patterns() -> tuple[str, ...]:
    """Regex fragments for every noun usable as a ``field = value`` field name.

    Each fragment tolerates the separator the author wrote (``api_key``,
    ``api-key``, ``apikey``) and carries no metacharacter of its own, so a caller
    may join them into an alternation directly.
    """
    return _rendered().field_name_patterns


def non_secret_name_segments() -> tuple[str, ...]:
    """Upper-case whole-name forms of the trailing words that mark a
    credential-shaped name as holding a NON-secret (``KEY_ID``, ``PUBLIC_KEY``).

    A consumer matching by trailing segment must decline these, or it redacts an
    identifier or a public key out of legitimate output.
    """
    return _rendered().non_secret_segments
