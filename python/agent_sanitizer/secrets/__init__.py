"""The secret-redaction engine: an agent-agnostic redactor.

Plain text in, redacted text (or a rehydration map) out. detect-secrets is the
single detection oracle, supplemented with custom detectors for formats it lacks,
a field-value regex, PEM collapse, cross-line reassembly, and exact-match
redaction of caller-supplied env-var values.

Configuration is passed in, never discovered — see :class:`RedactorConfig`.

Public entry points:

* :func:`redact` — ``(redacted_text, found_types)``.
* :func:`redact_map` — ``{text, pairs, found}`` for lossless rehydration; each
  pair is ``{placeholder, original, start}``.
* :func:`detected_secret_values` / :func:`secret_previews` — harvest or mask.
* :func:`strip_invisible` — delete payload-capable invisible chars.
* :func:`configure_plugins` / :func:`redact_configured` — configure once, redact
  many (the daemon's hot path).
* :func:`credential_name_segments` / :func:`credential_field_name_patterns` /
  :func:`non_secret_name_segments` — the published credential-noun vocabulary,
  rendered for a name matcher or a ``field = value`` matcher. Exported so a
  consumer with its own matcher (an env-var scrubber, a hook pre-gate) derives it
  from this list instead of forking one; the same source is published to
  JavaScript as the npm subpath export ``agent-sanitizer/credential-names``.
"""

from .config import DEFAULT_MIN_SECRET_LEN, RedactorConfig
from .credential_names import (
    CREDENTIAL_NAMES_FILE,
    credential_field_name_patterns,
    credential_name_segments,
    non_secret_name_segments,
)
from .engine import (
    configure_plugins,
    detected_secret_values,
    handle_request,
    mask_secret_lines,
    redact,
    redact_configured,
    redact_map,
    secret_previews,
)
from .invisible import (
    default_charset,
    strip_invisible,
)

__all__ = [
    "RedactorConfig",
    "DEFAULT_MIN_SECRET_LEN",
    "CREDENTIAL_NAMES_FILE",
    "credential_name_segments",
    "credential_field_name_patterns",
    "non_secret_name_segments",
    "default_charset",
    "redact",
    "redact_map",
    "detected_secret_values",
    "secret_previews",
    "mask_secret_lines",
    "strip_invisible",
    "configure_plugins",
    "redact_configured",
    "handle_request",
]
