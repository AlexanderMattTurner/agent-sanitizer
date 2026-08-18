"""Invisible-character handling — charset SOURCED from agent-sanitizer.

The redactor strips payload-capable invisible characters before detection and
tolerates them spliced *between* the characters of an env-bound key (an attacker
who wedges a zero-width char into a leaked key must not slip it past exact-match
redaction). That charset is a cross-package security boundary: it MUST equal
agent-sanitizer's deletion set, or a key spliced with a code point one side
omits escapes BOTH layers.

So this module does NOT define the set — it imports it from the shared SSOT
(:mod:`agent_sanitizer.invisible`, the sibling package). There is
deliberately no local copy and no fallback: if the SSOT data file is absent,
:func:`default_charset` raises (fail closed) rather than silently under-matching
with a partial set.
"""

import bisect
import functools
import re
from collections.abc import Sequence

# strip logic and the env-bound run-pattern live here; the CHARSET is imported.
from ..invisible import invisible_charset as _shared_charset


def default_charset() -> frozenset[int]:
    """The payload-capable invisible code points to strip / tolerate, from the
    shared agent-sanitizer SSOT. Raises (fail closed) if that dependency is
    unavailable — a partial charset silently under-matches, which is a security
    regression, so no fallback is offered."""
    return _shared_charset()


def strip_invisible(text: str, charset: frozenset[int] | None = None) -> str:
    """DETECTION-NORMALIZATION ONLY: delete every code point of ``charset`` from
    ``text`` UNCONDITIONALLY (deletion only — the result is a subsequence of the
    input).

    This is deliberately NOT JS-parity-safe for user-facing stripping. Unlike
    ``src/invisible.mjs`` (which carves out legitimate joiners/selectors — ZWNJ,
    ZWJ, variation selectors, tag characters — so it does not corrupt real text),
    this drops the WHOLE charset with no carve-out, because the secrets engine
    needs the most aggressive normalization to defeat invisible chars spliced into
    a leaked key. Do NOT reuse it to sanitize text you will show a user; use the
    JS deletion set (or a carve-out-aware variant) for that.

    ``charset`` defaults to :func:`default_charset` (the shared SSOT). Standalone
    normalization only — the engine's detection pipeline calls
    :func:`strip_invisible_with_map` instead, since redaction must translate a
    match found in the stripped view back to the ORIGINAL text's offsets (this
    function throws that mapping away, which is fine for a caller that only wants
    clean text back, but wrong for in-place redaction)."""
    if charset is None:
        charset = default_charset()
    return text.translate(_deletion_table(charset))


@functools.cache
def _deletion_table(charset: frozenset[int]) -> dict[int, None]:
    """``str.translate`` table deleting every code point in ``charset``: the
    whole of :func:`strip_invisible`, and the fast presence probe
    :func:`strip_invisible_with_map` runs before paying for its own
    per-character offset-map loop. Cached per charset like
    :func:`invisible_run_pattern`, since the hot path always passes the same
    (SSOT) charset."""
    return dict.fromkeys(charset)


@functools.cache
def _invisible_class(charset: frozenset[int]) -> str:
    """A regex character class matching any single code point in ``charset``.

    Contiguous code points are emitted as RANGES, not one escape each. The
    charset is 400-odd code points falling in a couple of dozen runs, and `re`
    walks a class's members per input character — so the collapsed form scans a
    megabyte an order of magnitude faster while matching exactly the same set.
    Cached per charset, since the hot path always passes the same (SSOT) one.
    """
    runs: list[list[int]] = []
    for code_point in sorted(charset):
        if runs and code_point == runs[-1][1] + 1:
            runs[-1][1] = code_point
            continue
        runs.append([code_point, code_point])
    return (
        "["
        + "".join(
            re.escape(chr(low))
            if low == high
            else f"{re.escape(chr(low))}-{re.escape(chr(high))}"
            for low, high in runs
        )
        + "]"
    )


@functools.cache
def _invisible_char_re(charset: frozenset[int]) -> re.Pattern[str]:
    """:func:`_invisible_class` compiled, for locating deleted positions."""
    return re.compile(_invisible_class(charset))


class DeletionOffsets(Sequence[int]):
    """``self[i]`` is the index, in an original string, of the ``i``-th character
    that survived deleting the characters at ``deleted`` — the offset map every
    caller that detects on a reduced view of a text needs to translate a match
    span back before redacting.

    Stored as the shift each deletion introduces rather than one entry per
    surviving character: a payload is megabytes long and its deletions are a
    handful (usually none), so a materialized per-character list costs a Python
    int object per byte of the request while this costs one per deletion.
    ``__getitem__`` binary-searches those shifts, which is why they are built
    once here instead of recomputed per lookup.
    """

    __slots__ = ("_kept_before", "_length")

    def __init__(self, deleted: Sequence[int], length: int) -> None:
        # The j-th deletion sits after `deleted[j] - j` surviving characters, so
        # that value is both non-decreasing and exactly the index shift the
        # deletion adds to every stripped index at or beyond it.
        self._kept_before = [position - j for j, position in enumerate(deleted)]
        self._length = length

    def __len__(self) -> int:
        return self._length

    def __getitem__(self, index: int) -> int:  # type: ignore[override]
        if not 0 <= index < self._length:
            raise IndexError(
                f"stripped index {index} is outside the stripped text's "
                f"{self._length} characters"
            )
        return index + bisect.bisect_right(self._kept_before, index)


def newline_offsets(text: str) -> Sequence[int]:
    """The offset map from ``text.replace("\\n", "")`` back to ``text``."""
    newlines: list[int] = []
    at = text.find("\n")
    while at != -1:
        newlines.append(at)
        at = text.find("\n", at + 1)
    return DeletionOffsets(newlines, len(text) - len(newlines))


def strip_invisible_with_map(
    text: str, charset: frozenset[int] | None = None
) -> tuple[str, Sequence[int]]:
    """Like :func:`strip_invisible`, but also return ``offsets`` where
    ``offsets[i]`` is ``text``'s index of the stripped result's ``i``-th
    character.

    Run before detection so a key with invisible chars spliced between its bytes
    is seen whole by every detector, not just the env-bound matcher's own
    tolerance — the engine's per-line and cross-line passes scan the STRIPPED
    text, then use ``offsets`` to translate any match span back to the ORIGINAL
    text before redacting, so the invisible characters inside a redacted span are
    removed along with the secret and everything outside a match is untouched
    byte-for-byte.

    The overwhelmingly common case is that ``text`` contains none of the
    charset's code points at all: then the offsets are the identity map, which a
    bare `range` represents with no allocation (the only uses downstream are
    `offsets[i]` and `offsets[end - 1]`, both of which `range` supports). Both
    branches stay at C speed — `str.translate` does the stripping and a
    single-character class locates the deletions — so neither the size of the
    payload nor the presence of one zero-width character buys a Python-level
    per-character loop over megabytes."""
    if charset is None:
        charset = default_charset()
    stripped = text.translate(_deletion_table(charset))
    if len(stripped) == len(text):
        return text, range(len(text))
    deleted = [m.start() for m in _invisible_char_re(charset).finditer(text)]
    return stripped, DeletionOffsets(deleted, len(stripped))


@functools.cache
def invisible_run_pattern(charset: frozenset[int]) -> str:
    """A regex fragment matching an optional run of any code point in ``charset``
    (``[...]*``), for tolerating invisibles spliced between a value's characters.

    Cached per charset so the hot path never rebuilds it. Required literals sit
    between every optional run, so the pattern stays linear (no ReDoS)."""
    return _invisible_class(charset) + "*"
