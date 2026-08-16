"""Static ReDoS guard over every regex in the JS that runs on untrusted input.

The Python twin (``tests/secrets/test_redos_static_guard.py``) covers the
secrets engine and detector JSON; nothing covered the JS side, where
``src/html.mjs`` alone concentrates dozens of security-relevant regexes. This
test drives the SAME analyzer (``regexploit``) over an inventory extracted by
``scripts/extract-js-regexes.mjs`` — a real-parser (TypeScript AST) walk that
collects every regex literal and resolves every ``RegExp(…)`` construction to
the pattern it builds — so a future super-linear pattern fails here statically,
with no timing flakiness.

The extractor's scope is every ``.mjs`` this package SHIPS, read from
``scripts/shipped-sources.mjs`` — the engine, the hooks that hand it tool output
and prompts, and the CLI the wheel ships. A super-linear pattern in any of them
runs inside a host's hook, where an overrun reads as a non-blocking error and
shows the model the raw text. A newly shipped module joins this guard with no
edit here.

Every ``RegExp(…)`` construction site is partitioned, never dropped: the
extractor either resolves it to static text (which then goes through
``regexploit`` like any literal) or reports it unresolved, and
``UNRESOLVABLE_SITES`` below carries one entry per unresolved site with the
reason. ``test_construction_sites_are_resolved_or_exempted`` asserts the two
sets are exactly complementary, so a new dynamically built pattern is a red
build. A count over the inventory cannot do that job — an unresolved site
contributes no inventory entry, so no count moves when one appears.

JS-only syntax regexploit's parser cannot read is handled explicitly, never
silently:

* named groups ``(?<name>…)`` are translated to Python's ``(?P<name>…)``
  (an exact, backtracking-neutral rewrite) before analysis;
* codepoint escapes ``\\u{H…}`` are translated to Python's ``\\uHHHH`` /
  ``\\UHHHHHHHH`` (exact: both spell one code point);
* patterns using ``\\p{…}`` (no Python ``re`` equivalent) are listed in
  ``UNANALYZABLE_JS_ONLY`` below — each entry is asserted to still exist in the
  inventory AND to still fail regexploit's parser, so the skip list can neither
  rot nor grow to hide an analyzable pattern.
"""

import collections
import json
import re
import shutil
import subprocess

import pytest

from tests._helpers import REPO_ROOT

# Every `RegExp(…)` construction site the extractor cannot resolve to static
# text, keyed by (file, normalized expression) with the reason. The pattern such
# a site builds is invisible to regexploit, so each entry is a hole in this
# guard's coverage and has to earn its place. Keying by the expression rather
# than by the line number means an entry goes stale loudly when the site
# changes, and moving the site around its file does not.
UNRESOLVABLE_SITES = {
    (
        "claude-hooks/lib/secret-annotate.mjs",
        "new RegExp( [...value] .map((ch) => ch.replace"
        '(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&")) .join(ENV_INVIS_RUN), "u", )',
    ): (
        "The pattern is the caller's env-var VALUE, escaped character by "
        "character — a runtime string with no static spelling. Its shape is "
        "fixed: escaped literals joined by the constant ENV_INVIS_RUN, which is "
        "a character class, so the pattern carries no quantifier at all."
    ),
    (
        "src/html.mjs",
        'new RegExp(`</${rawText}(?![a-z0-9-])`, "i")',
    ): (
        "`rawText` is the raw-text tag name the markdown walk is currently "
        "inside — a runtime value. The pattern is a literal tag name plus a "
        "negative lookahead over a character class, with no quantifier."
    ),
    (
        "src/invisible.mjs",
        "new RegExp(CF_CLASS_SOURCE, REGEX_FLAGS)",
    ): (
        "CF_CLASS_SOURCE is built by calling cfClassSource(CF_CODEPOINTS), and "
        "invisible.mjs does not export it, so there is no live value to read "
        "either. It is a bare character class, and that same text IS analyzed "
        "as the first alternative of STRIP (src/invisible.mjs:123), which this "
        "guard does resolve."
    ),
}

# Patterns regexploit cannot parse even after the translations below, keyed by
# (file, pattern). All use \p{...} property escapes — single-character-class
# constructs with no backtracking ambiguity of their own, but with no Python-re
# spelling regexploit could analyze. Reviewed by hand: each is a bare character
# class (optionally in a small alternation) with no nested quantifier.
UNANALYZABLE_JS_ONLY = {
    ("src/invisible.mjs", r"[\p{Extended_Pictographic}\p{Emoji_Modifier}]"),
    ("src/invisible.mjs", r"\p{Extended_Pictographic}"),
    (
        "src/invisible.mjs",
        r"[\p{Unified_Ideograph}\u{F900}-\u{FAFF}\u{2F800}-\u{2FA1F}]",
    ),
    ("src/invisible.mjs", r"\p{Script=Braille}"),
    ("src/invisible.mjs", r"\p{Script=Hangul}"),
}

# JS `(?<name>` -> Python `(?P<name>`, leaving lookbehinds `(?<=` / `(?<!`
# untouched. Exact and backtracking-neutral: group naming has no effect on the
# matcher's backtracking behavior.
_NAMED_GROUP_RE = re.compile(r"\(\?<(?![=!])")

# JS `\u{H…}` -> Python `\uHHHH` (BMP) / `\UHHHHHHHH` (astral). Both spellings
# denote exactly one code point in their own engine, inside a character class or
# out, so the rewrite is exact and backtracking-neutral. The leading
# `(?P<pairs>…)` group consumes complete escaped-backslash pairs and the lookbehind
# rejects an odd one, so a pattern matching a literal backslash followed by the
# TEXT `u{…}` is left alone.
_CODEPOINT_ESCAPE_RE = re.compile(
    r"(?<!\\)(?P<pairs>(?:\\\\)*)\\u\{(?P<hex>[0-9A-Fa-f]{1,6})\}"
)


def _run_extractor(*args: str) -> dict:
    out = subprocess.run(
        ["node", "scripts/extract-js-regexes.mjs", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return json.loads(out)


def _keyed_by_location(entries: list[dict]) -> dict[str, str]:
    """`file:line` -> pattern, with a `#n` suffix when a line carries several.

    Two regexes on one line (`src/html.mjs` has a pair) would otherwise collapse
    onto one key and drop one of them from analysis without a word.
    """
    seen: collections.Counter = collections.Counter()
    keyed = {}
    for entry in entries:
        base = f"{entry['file']}:{entry['line']}"
        seen[base] += 1
        key = base if seen[base] == 1 else f"{base}#{seen[base]}"
        keyed[key] = entry["pattern"]
    return keyed


_EXTRACTED = _run_extractor()
_INVENTORY = _EXTRACTED["patterns"]
_SITES = _EXTRACTED["constructionSites"]
_ALL = _keyed_by_location(
    [p for p in _INVENTORY if (p["file"], p["pattern"]) not in UNANALYZABLE_JS_ONLY]
)


def _analyze(pattern: str) -> str:
    exe = shutil.which("regexploit")
    assert exe, "regexploit is not installed — it is a dev dependency (pyproject [dev])"
    return subprocess.run(
        [exe], input=pattern + "\n", capture_output=True, text=True, check=True
    ).stdout


def _widen_codepoint_escape(match: re.Match) -> str:
    codepoint = int(match.group("hex"), 16)
    spelling = f"\\u{codepoint:04x}" if codepoint <= 0xFFFF else f"\\U{codepoint:08x}"
    return match.group("pairs") + spelling


def _to_python_syntax(pattern: str) -> str:
    named = _NAMED_GROUP_RE.sub("(?P<", pattern)
    return _CODEPOINT_ESCAPE_RE.sub(_widen_codepoint_escape, named)


def test_pattern_inventory_is_non_empty() -> None:
    # A refactor that breaks the extractor (or an emptied src/) would make the
    # parametrized test below pass vacuously; the JS sources carry well over
    # this floor of regexes today.
    assert len(_INVENTORY) >= 50
    assert len(_ALL) >= 50 - len(UNANALYZABLE_JS_ONLY)


def test_construction_sites_are_resolved_or_exempted() -> None:
    # The partition that closes the hole a count cannot see: every RegExp
    # construction site either resolves to a pattern this guard analyzes, or is
    # listed above with a reason. A new dynamic site lands in neither set and
    # fails here.
    unresolved = {(s["file"], s["expr"]) for s in _SITES if not s["resolved"]}
    assert unresolved == set(UNRESOLVABLE_SITES), (
        "RegExp construction sites are no longer partitioned. A site the "
        "extractor cannot resolve must be listed in UNRESOLVABLE_SITES with a "
        "reason; an entry it now resolves must be removed from it.\n"
        f"unresolved but unlisted: {sorted(unresolved - set(UNRESOLVABLE_SITES))}\n"
        f"listed but now resolved: {sorted(set(UNRESOLVABLE_SITES) - unresolved)}"
    )


def test_resolved_construction_sites_reach_the_analyzer() -> None:
    # Positive marker for the partition test above: resolution does real work,
    # and every pattern it produced is in the analyzed inventory rather than
    # resolved and then dropped on the floor.
    resolved = [s for s in _SITES if s["resolved"]]
    assert len(resolved) >= 15, (
        f"only {len(resolved)} of {len(_SITES)} construction sites resolved"
    )
    inventory_keys = {(p["file"], p["line"]) for p in _INVENTORY}
    for site in resolved:
        assert (site["file"], site["line"]) in inventory_keys, (
            f"{site['file']}:{site['line']} resolved but produced no inventory "
            f"entry: {site['expr']}"
        )


def test_skip_list_entries_are_live_and_actually_unanalyzable() -> None:
    # Every skip entry must still exist in the inventory (no rot) and must
    # still fail regexploit's parser (no silently skipping an analyzable
    # pattern under the skip flag).
    inventory_keys = {(p["file"], p["pattern"]) for p in _INVENTORY}
    for file, pattern in sorted(UNANALYZABLE_JS_ONLY):
        assert (file, pattern) in inventory_keys, (
            f"stale skip-list entry (pattern no longer in {file}): {pattern}"
        )
        out = _analyze(_to_python_syntax(pattern))
        assert "Error parsing" in out, (
            f"skip-list entry IS analyzable now — remove it from "
            f"UNANALYZABLE_JS_ONLY so it gets analyzed: {pattern}\n{out}"
        )


@pytest.mark.parametrize("name, pattern", sorted(_ALL.items()))
def test_js_regex_has_no_super_linear_backtracking(name: str, pattern: str) -> None:
    out = _analyze(_to_python_syntax(pattern))
    assert "Worst-case complexity" not in out, (
        f"{name} exhibits super-linear backtracking (ReDoS):\n{pattern}\n{out}"
    )
    assert "Error parsing" not in out, (
        f"{name}: regexploit could not analyze this pattern; if it uses "
        f"JS-only syntax with no Python translation, add it to "
        f"UNANALYZABLE_JS_ONLY with review:\n{pattern}\n{out}"
    )


def test_guard_detects_a_known_vulnerable_pattern() -> None:
    # Non-vacuity control (same shape as the Python guard's): a separator and a
    # body that both match `_` repartition exponentially — the analyzer must
    # flag it, or every pass above is meaningless.
    out = _analyze(r"prefix(?:[_-]\w+)*[:=]tail")
    assert "Worst-case complexity" in out, out


def test_named_group_translation_is_applied() -> None:
    # Positive marker that the translation path actually runs on real
    # inventory: at least one live pattern carries a JS named group, and its
    # translated form parses cleanly.
    named = [p for p in _ALL.values() if _NAMED_GROUP_RE.search(p)]
    assert named, "expected at least one (?<name>…) pattern in src/*.mjs"
    for pattern in named:
        assert "Error parsing" not in _analyze(_to_python_syntax(pattern))


def test_codepoint_escape_translation_is_applied() -> None:
    # Twin of the marker above for the `\u{…}` rewrite, which is what lets the
    # resolved Cf class (and every pattern built over it) reach the analyzer.
    escaped = [p for p in _ALL.values() if _CODEPOINT_ESCAPE_RE.search(p)]
    assert escaped, r"expected at least one \u{…} pattern in the inventory"
    for pattern in escaped:
        assert "Error parsing" not in _analyze(_to_python_syntax(pattern))


def test_codepoint_escape_translation_is_exact() -> None:
    # A pattern matching a literal backslash followed by the TEXT `u{41}` is not
    # a codepoint escape; rewriting it would change the language matched.
    assert _to_python_syntax(r"\\u{41}") == r"\\u{41}"
    assert _to_python_syntax(r"\u{41}") == "\\u0041"
    assert _to_python_syntax(r"[\u{1F600}-\u{1F64F}]") == "[\\U0001f600-\\U0001f64f]"


_RESOLVABLE_FIXTURE = """\
const LABEL_CHARS = "A-Za-z0-9";
const MAX_LEN = 8;
export const LABEL_RE = new RegExp(`^[${LABEL_CHARS}]{1,${MAX_LEN}}$`, "u");
"""

_DYNAMIC_FIXTURE = """\
export function valueRegex(parts) {
  return new RegExp(parts.map((part) => `(?:${part})`).join("|"), "u");
}
"""

# The resolvable fixture's own shape, with the one difference that a parameter
# rebinds LABEL_CHARS. The extractor knows the syntax, not the scopes, so it
# must decline this rather than analyze the module-level value.
_SHADOWED_FIXTURE = """\
const LABEL_CHARS = "A-Za-z0-9";
export function labelRegex(LABEL_CHARS) {
  return new RegExp(`^[${LABEL_CHARS}]{1,8}$`, "u");
}
"""


def test_extractor_resolves_a_const_backed_construction(tmp_path) -> None:
    # Dogfood: the shape this guard exists to see through. Against the
    # extractor this replaced — which collected a site only when argument 0 was
    # a plain string literal — the same file yields no site and no pattern.
    fixture = tmp_path / "resolvable.mjs"
    fixture.write_text(_RESOLVABLE_FIXTURE, encoding="utf-8")

    extracted = _run_extractor(str(fixture))
    assert [s["resolved"] for s in extracted["constructionSites"]] == [True]
    assert [(p["pattern"], p["flags"]) for p in extracted["patterns"]] == [
        (r"^[A-Za-z0-9]{1,8}$", "u")
    ]


def test_extractor_reports_a_genuinely_dynamic_construction(tmp_path) -> None:
    # The other half of the partition: a pattern built from a function argument
    # is reported unresolved, and its expression matches no UNRESOLVABLE_SITES
    # entry — so `test_construction_sites_are_resolved_or_exempted` fails on a
    # site of this shape rather than never seeing it.
    fixture = tmp_path / "dynamic.mjs"
    fixture.write_text(_DYNAMIC_FIXTURE, encoding="utf-8")

    sites = _run_extractor(str(fixture))["constructionSites"]
    assert [s["resolved"] for s in sites] == [False]
    exempt_exprs = {expr for _, expr in UNRESOLVABLE_SITES}
    assert not exempt_exprs & {s["expr"] for s in sites}


def test_extractor_declines_a_shadowed_const(tmp_path) -> None:
    # Resolving a name an inner scope rebinds would put a pattern in the
    # inventory that no shipped regex ever compiles — a false analysis, which
    # is worse than the gap. The fixture differs from the resolvable one only
    # in the shadowing, and gets the opposite verdict.
    fixture = tmp_path / "shadowed.mjs"
    fixture.write_text(_SHADOWED_FIXTURE, encoding="utf-8")

    extracted = _run_extractor(str(fixture))
    assert [s["resolved"] for s in extracted["constructionSites"]] == [False]
    assert extracted["patterns"] == []
