"""Static ReDoS guard over every regex in the JS that runs on untrusted input.

The Python twin (``tests/secrets/test_redos_static_guard.py``) covers the
secrets engine and detector JSON; nothing covered the JS side, where
``src/html.mjs`` alone concentrates dozens of security-relevant regexes. This
test drives the SAME analyzer (``regexploit``) over an inventory extracted by
``scripts/extract-js-regexes.mjs`` — a real-parser (TypeScript AST) walk that
collects every regex literal and every ``new RegExp("...")`` string pattern —
so a future super-linear pattern fails here statically, with no timing
flakiness.

The extractor's scope is every ``.mjs`` this package SHIPS, read from
``scripts/shipped-sources.mjs`` — the engine, the hooks that hand it tool output
and prompts, and the CLI the wheel ships. A super-linear pattern in any of them
runs inside a host's hook, where an overrun reads as a non-blocking error and
shows the model the raw text. A newly shipped module joins this guard with no
edit here.

JS-only syntax regexploit's parser cannot read is handled explicitly, never
silently:

* named groups ``(?<name>…)`` are translated to Python's ``(?P<name>…)``
  (an exact, backtracking-neutral rewrite) before analysis;
* patterns using ``\\p{…}`` / ``\\u{…}`` (no Python ``re`` equivalent) are
  listed in ``UNANALYZABLE_JS_ONLY`` below — each entry is asserted to still
  exist in the inventory AND to still fail regexploit's parser, so the skip
  list can neither rot nor grow to hide an analyzable pattern.
"""

import json
import re
import shutil
import subprocess

import pytest

from tests._helpers import REPO_ROOT

# Patterns regexploit cannot parse even after named-group translation, keyed by
# (file, pattern). All use \p{...} property escapes or \u{...} codepoint
# escapes — single-character-class constructs with no backtracking ambiguity of
# their own, but with no Python-re spelling regexploit could analyze. Reviewed
# by hand: each is a bare character class (optionally in a small alternation)
# with no nested quantifier.
UNANALYZABLE_JS_ONLY = {
    ("src/invisible.mjs", r"[\p{Extended_Pictographic}\p{Emoji_Modifier}]"),
    ("src/invisible.mjs", r"\p{Extended_Pictographic}"),
    ("src/invisible.mjs", r"[\u{E0000}-\u{E007F}]"),
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


def _extract_inventory() -> dict:
    out = subprocess.run(
        ["node", "scripts/extract-js-regexes.mjs"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return json.loads(out)


_EXTRACTED = _extract_inventory()
_INVENTORY = _EXTRACTED["patterns"]
_ALL = {
    f"{p['file']}:{p['line']}": p["pattern"]
    for p in _INVENTORY
    if (p["file"], p["pattern"]) not in UNANALYZABLE_JS_ONLY
}


def _analyze(pattern: str) -> str:
    exe = shutil.which("regexploit")
    assert exe, "regexploit is not installed — it is a dev dependency (pyproject [dev])"
    return subprocess.run(
        [exe], input=pattern + "\n", capture_output=True, text=True, check=True
    ).stdout


def _to_python_syntax(pattern: str) -> str:
    return _NAMED_GROUP_RE.sub("(?P<", pattern)


def test_pattern_inventory_is_non_empty() -> None:
    # A refactor that breaks the extractor (or an emptied src/) would make the
    # parametrized test below pass vacuously; the JS sources carry well over
    # this floor of regexes today.
    assert len(_INVENTORY) >= 50
    assert len(_ALL) >= 50 - len(UNANALYZABLE_JS_ONLY)


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
