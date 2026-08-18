"""Literal probes: which text can possibly match a pattern, answered in one pass.

The engine's expensive stages are per-line ``scan_line`` dispatch (~300us a call —
every active plugin routed through detect-secrets' reflection-based injector) and
a handful of `re.sub`/`finditer` passes over the WHOLE payload. On a megabyte of
ordinary tool output almost none of that work can match anything, and paying for
it is what made a large redaction take tens of seconds.

A :class:`LiteralProbe` answers the necessary condition cheaply. It is derived
from the pattern's own parsed AST, never from its source text, two ways:

* A **required literal** — a string every match of the pattern must contain.
  Searched with ``str.find``, which is C-speed and beats a regex by an order of
  magnitude.
* The **pattern itself**, for a pattern whose only required literal is too short
  to narrow anything (a lone ``.`` or ``:``). Run once over the whole text
  rather than per line.

A probe is a NECESSARY condition, never a detection decision, and every
approximation here is in the *safe* direction — a literal we fail to derive means
more text gets scanned, never less. ``tests/secrets/test_literal_probe.py`` pins both
ends: the per-pattern soundness property, and the stronger end-to-end claim that
redaction output is byte-identical with the probes in play and without them.
"""

import re
from collections.abc import Callable, Iterable, Sequence

# `re._parser`/`re._constants` are the 3.11+ spelling of the stdlib regex parser;
# 3.10 (this package's floor) exposes the same module as `sre_parse`. The AST is
# the authoritative reading of a pattern — a hand-rolled scan over pattern TEXT
# cannot tell a literal `.` from a wildcard, an escaped `\(` from a group, or a
# literal inside a character class from one outside it.
try:  # Python 3.11+
    from re import _constants as _c
    from re import _parser as _parser
except ImportError:  # Python 3.10
    import sre_constants as _c  # type: ignore[no-redef]
    import sre_parse as _parser  # type: ignore[no-redef]

# A required literal shorter than this narrows nothing — `.` and `:` occur on
# almost every line of real text, so probing on one would hand every line to the
# expensive path while still paying for the search. A pattern below this floor is
# run as itself instead. 2 keeps genuinely selective short prefixes (AWS's
# `KIA`/`SIA`, GitLab's `gl`) on the cheap path; only single-character literals
# fall through.
LITERAL_MIN_LEN = 2

_NAMED_GROUP_RE = re.compile(r"\(\?P<[^>]+>")

# Repeat opcodes whose `min` bound decides whether the body is required at all.
# POSSESSIVE_REPEAT is 3.11+, so it is read defensively; a `None` placeholder
# never matches a real opcode.
_REPEATS = (
    _c.MAX_REPEAT,
    _c.MIN_REPEAT,
    getattr(_c, "POSSESSIVE_REPEAT", None),
)

# Code points `re.IGNORECASE` treats as equivalent to an ASCII letter that
# `str.lower` does NOT map onto it, so folding a haystack with `.lower()` alone
# would lose an equivalence the detector's own match has — and a lost
# equivalence, under a probe, is a missed secret. Mapped one-code-point-to-one so
# the fold stays length-preserving (see :func:`fold`).
#
# tests/secrets/test_literal_probe.py::test_case_fold_covers_every_ignorecase_equivalent
# is this table's derivation: it brute-forces every Unicode code point against
# every literal character the live detectors actually contribute, so a
# detect-secrets upgrade that introduces a character with a new exception fails
# there instead of silently under-matching here.
_CASE_EQUIVALENT_FIXUPS = {
    0x130: "i",  # LATIN CAPITAL LETTER I WITH DOT ABOVE
    0x131: "i",  # LATIN SMALL LETTER DOTLESS I
    0x17F: "s",  # LATIN SMALL LETTER LONG S
    # `str.lower` maps a WORD-FINAL capital sigma to U+03C2 and any other to
    # U+03C3, the only lowering in Python that reads a character's neighbours.
    # A probe folds its literal in isolation and searches it inside a folded
    # haystack, so a context-dependent fold makes the two disagree and the probe
    # misses the line; mapping both sigmas onto U+03C3 first removes the context.
    0x3A3: "\u03c3",  # GREEK CAPITAL LETTER SIGMA
    0x3C2: "\u03c3",  # GREEK SMALL LETTER FINAL SIGMA
}


def fold(text: str) -> str | None:
    """``text`` case-folded for probing, or ``None`` when it cannot be folded
    without changing its length.

    Length preservation is what lets a probe map an offset in the folded view
    back to the line it came from, so a fold that changed a length is refused
    outright rather than allowed to desynchronize one. No code point reaches that
    branch today — the one that lowers to two characters is in the fixup table
    above, mapped one-to-one, and
    test_literal_probe.py::test_fold_preserves_length_over_all_of_unicode is what
    says so — but a fold that silently shifted offsets would skip lines with
    secrets on them, and returning ``None`` only makes the caller scan
    everything: slow, never wrong.
    """
    folded = text.translate(_CASE_EQUIVALENT_FIXUPS).lower()
    return folded if len(folded) == len(text) else None


def degroup(pattern: str) -> str:
    """A pattern's source text with named groups turned non-capturing, so joining
    two patterns that reuse a group name (several detectors define
    ``(?P<secret>...)``) into one union cannot raise ``re.error: redefinition of
    group name``. A union is only ever asked WHETHER it matched, so dropping the
    capture changes nothing observable.

    A backreference of either spelling is refused. ``(?P=name)`` loses its
    target's name to the rewrite; a NUMBERED ``\\1`` is the dangerous one,
    because it keeps compiling while both this rewrite and the ``|`` join
    renumber the groups around it — so it would silently point at a different,
    often unset group and the union would quietly under-match. Under a detection
    gate an under-match is a missed secret, so this fails loud.
    """
    if "(?P=" in pattern or re.search(r"\\[1-9]", pattern):
        raise RuntimeError(
            f"denylist pattern {pattern!r} uses a named backreference or a "
            "numbered one — degroup cannot safely strip its group name, and "
            "joining patterns into one union renumbers their groups"
        )
    return _NAMED_GROUP_RE.sub("(?:", pattern)


def _most_selective(candidates: list[frozenset[str]]) -> frozenset[str] | None:
    """The candidate set that eliminates the most text: the one whose SHORTEST
    member is longest (a set is only as selective as its weakest alternative),
    breaking ties toward fewer alternatives."""
    usable = [s for s in candidates if s]
    if not usable:
        return None
    return max(usable, key=lambda s: (min(len(x) for x in s), -len(s)))


def _required(seq) -> frozenset[str] | None:
    """Strings such that any match of the parsed ``seq`` contains at least one,
    or None when no such set can be derived.

    ``seq`` is a concatenation, so EVERY element must match — which means any
    single element's required set is a valid answer for the whole, and we are
    free to pick the most selective one. Consecutive literals are first merged
    into one long string, since a run like ``BEGIN RSA PRIVATE KEY`` is far more
    selective than any single character of it.
    """
    candidates: list[frozenset[str]] = []
    run: list[str] = []
    for op, av in seq:
        if op is _c.LITERAL:
            run.append(chr(av))
            continue
        if run:
            candidates.append(frozenset(["".join(run)]))
            run = []
        if op is _c.BRANCH:
            # Any ONE alternative may be what matches, so the answer is the
            # union — and an alternative with no derivable literal means the
            # whole alternation has none.
            alternatives = [_required(alt) for alt in av[1]]
            if all(alt is not None for alt in alternatives):
                candidates.append(frozenset().union(*alternatives))
        elif op is _c.SUBPATTERN:
            nested = _required(av[3])
            if nested is not None:
                candidates.append(nested)
        elif op is getattr(_c, "ATOMIC_GROUP", None):
            nested = _required(av)
            if nested is not None:
                candidates.append(nested)
        elif op in _REPEATS:
            minimum, _maximum, body = av
            # A body that may repeat ZERO times is not required to appear.
            if minimum >= 1:
                nested = _required(body)
                if nested is not None:
                    candidates.append(nested)
        # Everything else contributes nothing, which is always safe: a character
        # class, `.`, an anchor and a backreference carry no fixed text, and a
        # lookaround (positive or negative) must not be read as required — a
        # negative one asserts its content is ABSENT.
    if run:
        candidates.append(frozenset(["".join(run)]))
    return _most_selective(candidates)


def required_literals(pattern: str, flags: int) -> frozenset[str] | None:
    """Strings such that any match of ``pattern`` contains at least one of them,
    or None when none could be derived (the caller must then scan everything).
    """
    return _required(_parser.parse(pattern, flags))


def denylist_patterns(
    plugins: Iterable, types: frozenset[str] | None = None
) -> list[re.Pattern[str]]:
    """Every ``denylist`` pattern of ``plugins`` (restricted to those whose
    ``secret_type`` is in ``types``, or all of them when ``types`` is None).

    A covered plugin that supplies no denylist contributes nothing, and both
    consumers SKIP the expensive scan on a miss — so silently tolerating one
    would drop every secret of its type with no runtime signal. This raise is
    what keeps a detect-secrets upgrade from turning a detector into a hole.
    """
    patterns = []
    for plugin in plugins:
        if types is not None and getattr(plugin, "secret_type", None) not in types:
            continue
        denylist = getattr(plugin, "denylist", ())
        if not denylist:
            raise RuntimeError(
                f"active plugin {type(plugin).__name__} "
                f"({getattr(plugin, 'secret_type', None)!r}) supplied no denylist "
                "regex — no probe can cover it, so secrets of this type would be "
                "skipped before scan_line ever ran"
            )
        patterns.extend(denylist)
    return patterns


def _no_deadline_check(stage: str) -> None:
    """The deadline check of a caller that set no compute budget."""


class LiteralProbe:
    """The necessary condition for a set of patterns, evaluated over whole text.

    Each pattern lands on one of two sides. Its required literals are INDEXED to
    it, so a text position that hit literal ``l`` narrows the work to the
    patterns that named ``l`` — a line carrying the word ``key`` is confirmed
    against the keyword detector alone, not against all 57 denylists. A pattern
    whose most selective literal is a single character has no usable index entry
    and is kept to be run as itself.

    Patterns are kept individually rather than joined into one alternation: a
    distinct leading character class lets ``re`` skip ahead, which an alternation
    defeats.
    """

    def __init__(self, patterns: Iterable[re.Pattern[str]]) -> None:
        by_literal: dict[str, list[re.Pattern[str]]] = {}
        weak: list[re.Pattern[str]] = []
        for pattern in patterns:
            found = required_literals(pattern.pattern, pattern.flags)
            if found is None or min(len(lit) for lit in found) < LITERAL_MIN_LEN:
                weak.append(pattern)
                continue
            for literal in found:
                # Folded and searched against a folded haystack, so one search
                # serves both a case-sensitive and a case-insensitive pattern.
                # That over-matches for the case-sensitive ones (a lowercase copy
                # of `AKIA` also passes), which only sends extra text to the
                # expensive path — the safe direction.
                by_literal.setdefault(fold(literal) or literal, []).append(pattern)
        self.by_literal = {lit: tuple(pats) for lit, pats in by_literal.items()}
        self.weak = tuple(weak)
        if not self.by_literal and not self.weak:
            raise RuntimeError(
                "no pattern contributed a literal or a regex to this probe — "
                "probing on nothing would skip every line; see "
                "tests/secrets/test_literal_probe.py"
            )

    def may_match(self, text: str) -> bool:
        """False only when no pattern can match anywhere in ``text``."""
        folded = fold(text)
        if folded is None:
            return True
        return any(lit in folded for lit in self.by_literal) or any(
            pattern.search(text) for pattern in self.weak
        )

    def candidates(
        self, text: str, check: Callable[[str], None] = _no_deadline_check
    ) -> dict[int, tuple[re.Pattern[str], ...]] | None:
        """Each line index (into ``text.split("\\n")``) that could hold a match,
        mapped to the patterns that could produce it — or None meaning "nothing
        could be ruled out, confirm every line against every pattern".

        A line ABSENT from the returned mapping cannot match any pattern, so the
        caller may skip it outright. A line present must still be confirmed
        against its own patterns: a required literal is necessary, not
        sufficient.

        ``text`` must be the invisible-stripped view the caller will scan, so a
        key with a zero-width character spliced into it is probed on the same
        bytes the detector will see. Stripping never removes a newline, so the
        stripped text's line boundaries are the original's.

        ``check`` is the caller's compute-deadline check, called between the
        probe's units of work — one literal's sweep of the text, one weak
        pattern's, and the line attribution. Each of those is linear in the
        text, so the work between two checks is bounded; without it a payload
        big enough to make this stage expensive would run to completion past a
        budget the caller set precisely to stop it.
        """
        folded = fold(text)
        if folded is None:
            return None
        hits: list[tuple[int, int, tuple[re.Pattern[str], ...]]] = []
        for literal, patterns in self.by_literal.items():
            check("candidate-line literal probe")
            width = len(literal)
            at = folded.find(literal)
            while at != -1:
                hits.append((at, at + width, patterns))
                # A second occurrence STARTING on this same line claims exactly
                # what this one did — the literal is fixed, so every occurrence
                # spans the same number of lines from the line it starts on — so
                # the scan resumes past the end of the line this one STARTS on.
                # Resuming past its END instead would skip an occurrence starting
                # inside a multi-line literal's own span. Without the skip, one
                # long line of `key key key ...` yields a hit per word and the
                # attribution below pays for every one of them.
                eol = folded.find("\n", at)
                at = -1 if eol == -1 else folded.find(literal, eol + 1)
        for pattern in self.weak:
            check("candidate-line pattern probe")
            # EVERY line the match touches is claimed, not just the one it starts
            # on. `finditer` yields non-overlapping matches, so a match that runs
            # past a newline consumes bytes on the following line where a second
            # match could otherwise have started — claiming the whole span is what
            # keeps that swallowed start from becoming a missed secret.
            hits.extend(
                (m.start(), m.end(), (pattern,)) for m in pattern.finditer(text)
            )
        check("candidate-line attribution")
        return _patterns_by_line(text, hits)


def _patterns_by_line(
    text: str, hits: Sequence[tuple[int, int, tuple[re.Pattern[str], ...]]]
) -> dict[int, tuple[re.Pattern[str], ...]]:
    """Every line index any hit span touches, mapped to that hit's patterns.

    Walks the newlines once in span-start order rather than calling ``str.count``
    per span (quadratic) or materializing a line-start table as long as the file
    even when two lines matched.

    ``ahead`` is what makes that walk once: it holds the position of the next
    newline at or after the current line's start, so a hit that does not advance
    the line REUSES that answer instead of re-running ``text.find`` over the same
    suffix. Searching per hit instead is quadratic in the worst case that
    matters — one very long line with a hit on every key-ish word, each hit
    rescanning the whole remaining text — which is attacker-shaped input against
    a shared daemon, not a hypothetical. ``-1`` (no newline left) is likewise a
    remembered answer, so the single-line payload costs one search in total.
    """
    claims: dict[int, set[re.Pattern[str]]] = {}
    # A line's Nth hit on the same literal claims exactly what its first did, and
    # one line can hold hundreds of thousands of them, so each (line, patterns)
    # pair is merged into `claims` once. Bounded by lines times literals, where
    # the hits are bounded only by the payload's length. This dedupes the MERGE
    # only, never the span walk below: two matches of one weak pattern can start
    # on the same line and reach different lines, and skipping the second's walk
    # would leave the lines only it touches unclaimed — a missed secret.
    merged: set[tuple[int, tuple[re.Pattern[str], ...]]] = set()

    def claim(index: int, patterns: tuple[re.Pattern[str], ...]) -> None:
        if (index, patterns) in merged:
            return
        merged.add((index, patterns))
        claims.setdefault(index, set()).update(patterns)

    line = 0
    ahead = text.find("\n")
    for start, end, patterns in sorted(hits, key=lambda hit: hit[0]):
        while ahead != -1 and ahead < start:
            line += 1
            ahead = text.find("\n", ahead + 1)
        claim(line, patterns)
        # A span's interior newlines are walked on a private cursor so `ahead`
        # stays parked at this span's START, which the sort keeps monotone.
        span_line, span_ahead = line, ahead
        while span_ahead != -1 and span_ahead < end:
            span_line += 1
            span_ahead = text.find("\n", span_ahead + 1)
            claim(span_line, patterns)
    return {index: tuple(patterns) for index, patterns in claims.items()}
