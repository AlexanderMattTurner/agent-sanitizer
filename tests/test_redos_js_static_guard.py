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

Backtracking is half the hazard; the other half is SIZE. A pattern whose
source is built from data that exists only at call time — a parameter, tool
output, a prompt, ``process.env`` — is as long as that data, and V8 refuses
one past its size limit with ``Invalid regular expression: regular expression
too large``, on every call. The extractor reports, per construction site, every
binding through which its pattern can read such data (``callTimeInputs``), and
``test_no_construction_site_reads_call_time_data`` requires none: a pattern
derived only from module constants or shipped data has a size fixed when the
package is built. ``test_no_string_is_compiled_as_a_regex_implicitly`` closes
the same hole for ``.match``/``.matchAll``/``.search``, which compile a string
argument with ``new RegExp`` behind the call.

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
# guard's coverage and has to earn its place on both halves of the hazard: why
# it cannot backtrack, and why its size is fixed at build time. The size half is
# also checked mechanically — every site here must report no call-time input.
# Keying by the expression rather than by the line number means an entry goes
# stale loudly when the site changes, and moving it around its file does not.
UNRESOLVABLE_SITES = {
    (
        "claude-hooks/lib/secret-annotate.mjs",
        'new RegExp( "[" + [...new Set([...charset.cf_codepoints, '
        "...charset.extra_codepoints])] .map((cp) => `\\\\u{${cp.toString(16)}}`) "
        '.join("") + "]", "gu", )',
    ): (
        "The class members come from the generated invisible-charset JSON, a "
        "data import with no static spelling here. Size: one class over that "
        "shipped charset, built once at module load. Backtracking: a bare "
        "character class carries no quantifier."
    ),
    (
        "src/ansi.mjs",
        "new RegExp(ESC_DIRECT_FINAL_CLASS)",
    ): (
        "ESC_DIRECT_FINAL_CLASS is built by calling charClass() over 0x30-0x7E "
        "minus `[` and the string introducers, and ansi.mjs does not export it. "
        "Size: at most 79 members, fixed in source. Backtracking: a bare "
        "character class carries no quantifier."
    ),
    (
        "src/gates.mjs",
        'new RegExp( credentialNames().fieldNamePatterns.join("|"), "i", )',
    ): (
        "The secret pre-gate's keyword arm is the credential vocabulary's "
        "field-value nouns, joined: data validated from the packaged "
        "credential-names.json at first use. Size: that shipped vocabulary, "
        "built once per process by a zero-parameter memo. Backtracking: each "
        "noun is `[a-z0-9]+` parts joined by `[_-]?`, so every alternative is a "
        "bounded literal and the alternation has no nested quantifier. "
        "test_redos_js_exemption_instances.py builds it from the shipped "
        "vocabulary and analyzes it."
    ),
    (
        "src/invisible.mjs",
        "new RegExp(CF_CLASS_SOURCE, REGEX_FLAGS)",
    ): (
        "CF_CLASS_SOURCE is built by calling cfClassSource(CF_CODEPOINTS), and "
        "invisible.mjs does not export it, so there is no live value to read "
        "either. Size: one class over the generated Cf table, built at module "
        "load. Backtracking: a bare character class, and that same text IS "
        "analyzed as the first alternative of STRIP, which this guard resolves."
    ),
}

# Patterns regexploit cannot parse even after the translations below, keyed by
# (file, pattern), each reviewed by hand. Empty: its only members were the
# \p{...} property escapes src/invisible.mjs and src/confusables.mjs used to ask
# the runtime for, and test/unicode-property-pin.test.mjs now fails on any such
# escape in src/, so those properties are pinned range tables rather than regexes.
UNANALYZABLE_JS_ONLY: set[tuple[str, str]] = set()

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
    return match.group("pairs") + _python_escape(int(match.group("hex"), 16))


def _python_escape(codepoint: int) -> str:
    return f"\\u{codepoint:04x}" if codepoint <= 0xFFFF else f"\\U{codepoint:08x}"


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


def test_no_construction_site_reads_call_time_data() -> None:
    # The size invariant, over EVERY site — a resolved one included, since a
    # module-scope `new RegExp(process.env.X ?? "a")` resolves to whatever the
    # extractor's own environment held. The unresolved sites are the ones this
    # walk is the only check on, so they must be in the inventory it covered.
    assert len(_SITES) >= 20, f"only {len(_SITES)} construction sites found"
    assert {(s["file"], s["expr"]) for s in _SITES} >= set(UNRESOLVABLE_SITES)
    reads = {
        f"{s['file']}:{s['line']} {s['expr']}": s["callTimeInputs"]
        for s in _SITES
        if s["callTimeInputs"]
    }
    assert not reads, (
        "RegExp construction sites whose pattern can read call-time data, so "
        "its size scales with that data (V8 throws `regular expression too "
        "large` past its limit). Build the pattern from module constants or "
        "shipped data, or match without a regex (substring search):\n"
        + json.dumps(reads, indent=2)
    )


def test_no_string_is_compiled_as_a_regex_implicitly() -> None:
    # `s.match(x)` / `s.matchAll(x)` / `s.search(x)` run `new RegExp(x)` when x
    # is not already a RegExp — a construction site no `RegExp(` token marks.
    # The floor proves the type-checked walk saw the calls it is judging.
    assert len(_EXTRACTED["coercionSites"]) >= 10
    coerced = [c for c in _EXTRACTED["coercionSites"] if not c["isRegExp"]]
    assert not coerced, (
        "string methods handed a non-RegExp argument, which the engine compiles "
        "as a pattern; pass a RegExp built from constants:\n"
        + json.dumps(coerced, indent=2)
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

# A module-scope `let`/`var` holds a different value at each point of the
# module, so neither its initializer nor the value an import reads is reliably
# the one a site compiles. Each fixture below states the mismatch outright: the
# first compiles `^[0-9]{1,8}$` while the initializer spells `A-Za-z0-9`, and
# the second's line-4 site compiles `^a+$` while the imported binding holds
# `^b+$`. Resolving either produces a pattern no regex in the file compiles.
_MUTABLE_FIXTURES = {
    "let-const-map": """\
let LABEL_CHARS = "A-Za-z0-9";
LABEL_CHARS = "0-9";
const LABEL_RE = new RegExp(`^[${LABEL_CHARS}]{1,8}$`, "u");
export const matches = (text) => LABEL_RE.test(text);
""",
    "exported-let-live-value": """\
function initialSource() {
  return "^a+$";
}
export let RE = new RegExp(initialSource(), "u");
RE = new RegExp("^b+$", "u");
""",
}

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


@pytest.mark.parametrize(
    "name, expected_verdicts",
    [("let-const-map", [False]), ("exported-let-live-value", [False, True])],
)
def test_extractor_declines_a_mutable_binding(
    tmp_path, name: str, expected_verdicts: list[bool]
) -> None:
    # Sibling of the shadow rule: resolving a reassignable binding puts a
    # pattern in the inventory that the file never compiles, which is a false
    # analysis rather than a gap. The second fixture's trailing `True` is a site
    # built from a plain string literal, which stays resolvable — the refusal is
    # scoped to the site that reads the mutable name.
    fixture = tmp_path / f"{name}.mjs"
    fixture.write_text(_MUTABLE_FIXTURES[name], encoding="utf-8")

    extracted = _run_extractor(str(fixture))
    sites = extracted["constructionSites"]
    assert [s["resolved"] for s in sites] == expected_verdicts

    # The partition test sees this shape: a declined site is reported, and it
    # matches no exemption entry, so it fails there instead of vanishing.
    unresolved_lines = {s["line"] for s in sites if not s["resolved"]}
    assert not unresolved_lines & {p["line"] for p in extracted["patterns"]}
    assert not {expr for _, expr in UNRESOLVABLE_SITES} & {s["expr"] for s in sites}


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


# The defect this guard's size half is for: a pattern spliced from an env
# secret's VALUE, a ~4 KB invisible-character class between every pair of
# characters, so a 10 000-character key overflows V8's regex size limit on every
# tool output. Its pattern reads the value through `visible`.
_ENV_VALUE_FIXTURE = r"""
import charset from "./charset.json" with { type: "json" };
const ENV_INVIS_CODEPOINTS = [...new Set(charset.cf_codepoints)].sort((a, b) => a - b);
const ENV_INVIS_SET = new Set(ENV_INVIS_CODEPOINTS);
const ENV_INVIS_RUN =
  "[" + ENV_INVIS_CODEPOINTS.map((cp) => `\\u{${cp.toString(16)}}`).join("") + "]*";
const escapeLiteral = (ch) => ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
export function envValueRegex(value) {
  const visible = [...value].filter((ch) => !ENV_INVIS_SET.has(ch.codePointAt(0)));
  return new RegExp(visible.map(escapeLiteral).join(ENV_INVIS_RUN), "u");
}
"""

# Each fixture's one construction site reads call-time data through a different
# route, with the kind of input the walk must name for it.
_CALL_TIME_FIXTURES = {
    "parameter": (_DYNAMIC_FIXTURE, ["parameter parts"]),
    "env-value-splice": (_ENV_VALUE_FIXTURE, ["local visible"]),
    "module-scope-env": (
        'export const RE = new RegExp(process.env.PATTERN ?? "a+");\n',
        ["global process"],
    ),
    "env-through-const-and-function": (
        "function readPattern() {\n"
        '  return process.env.PATTERN ?? "a+";\n'
        "}\n"
        "const SOURCE = readPattern();\n"
        "export const RE = new RegExp(SOURCE);\n",
        ["global process"],
    ),
    "module-let-set-by-a-caller": (
        'let SOURCE = "a+";\n'
        "export function configure(source) {\n"
        "  SOURCE = source;\n"
        "}\n"
        "export const build = () => new RegExp(SOURCE);\n",
        ["parameter source"],
    ),
}

# Patterns that cannot depend on call-time data even though the site sits in a
# function or reads data with no static spelling: the gates.mjs memoized
# builder over a shipped JSON vocabulary, and a module-scope class over shipped
# charset data.
_LOAD_TIME_FIXTURES = {
    "memoized-builder-over-shipped-json": (
        'import names from "./charset.json" with { type: "json" };\n'
        "let memo;\n"
        "function nounPattern() {\n"
        '  return (memo ??= new RegExp(names.nouns.join("|"), "i"));\n'
        "}\n"
        "export const hasNoun = (text) => nounPattern().test(text);\n"
    ),
    "module-scope-class-over-shipped-json": (
        'import charset from "./charset.json" with { type: "json" };\n'
        "const INVIS = new RegExp(\n"
        '  "[" + charset.cf_codepoints.map((cp) => `\\\\u{${cp.toString(16)}}`)'
        '.join("") + "]",\n'
        '  "gu",\n'
        ");\n"
        "export const hasInvisible = (text) => INVIS.test(text);\n"
    ),
}

_CHARSET_JSON = '{"cf_codepoints": [173, 8203], "nouns": ["token", "secret"]}\n'


def _write_fixture(tmp_path, name: str, source: str) -> str:
    (tmp_path / "charset.json").write_text(_CHARSET_JSON, encoding="utf-8")
    fixture = tmp_path / f"{name}.mjs"
    fixture.write_text(source, encoding="utf-8")
    return str(fixture)


@pytest.mark.parametrize("name", sorted(_CALL_TIME_FIXTURES))
def test_extractor_names_a_call_time_input(tmp_path, name: str) -> None:
    source, expected = _CALL_TIME_FIXTURES[name]
    sites = _run_extractor(_write_fixture(tmp_path, name, source))["constructionSites"]
    assert len(sites) == 1, sites
    kinds = [entry.split(" at ")[0] for entry in sites[0]["callTimeInputs"]]
    assert kinds == expected


@pytest.mark.parametrize("name", sorted(_LOAD_TIME_FIXTURES))
def test_extractor_passes_a_load_time_construction(tmp_path, name: str) -> None:
    sites = _run_extractor(_write_fixture(tmp_path, name, _LOAD_TIME_FIXTURES[name]))[
        "constructionSites"
    ]
    # Positive marker: the site was found, and it is one the static resolver
    # cannot spell — so the empty input list is the walk's verdict, not a
    # resolved literal's.
    assert [(s["resolved"], s["callTimeInputs"]) for s in sites] == [(False, [])]


def test_extractor_reports_an_implicit_string_to_regex_coercion(tmp_path) -> None:
    fixture = _write_fixture(
        tmp_path,
        "coercion",
        "/** @param {string} text @param {string} needle */\n"
        "export const find = (text, needle) => text.search(needle);\n"
        "/** @param {string} text */\n"
        "export const digits = (text) => text.match(/[0-9]+/g);\n",
    )
    coercions = _run_extractor(fixture)["coercionSites"]
    assert [(c["expr"], c["isRegExp"]) for c in coercions] == [
        ("text.search(needle)", False),
        ("text.match(/[0-9]+/g)", True),
    ]
