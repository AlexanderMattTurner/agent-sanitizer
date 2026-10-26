"""Build the runtime patterns UNRESOLVABLE_SITES exempts, and analyze them.

An ``UNRESOLVABLE_SITES`` entry in ``test_redos_js_static_guard.py`` is a hole in
the static ReDoS guard: the extractor cannot spell the pattern, so regexploit
never sees it, and the entry's reason is prose nothing checks. The
secret-annotate entry's prose said its pattern "carries no quantifier at all"
while every gap in it is a starred class. Where the shipped module can build the
pattern itself, this asks it to and runs the same analyzer over the real output,
so the exemption's safety claim is measured rather than asserted.
"""

import json
import re
import subprocess

import pytest

from tests._helpers import REPO_ROOT
from tests.test_redos_js_static_guard import (
    UNRESOLVABLE_SITES,
    _analyze,
    _to_python_syntax,
)

SECRET_ANNOTATE = "claude-hooks/lib/secret-annotate.mjs"
GATES = "src/gates.mjs"

_CHARSET = json.loads(
    (REPO_ROOT / "python/agent_sanitizer/data/invisible-charset.json").read_text(
        "utf-8"
    )
)
# The code points `ENV_INVIS_RUN` is a class of.
INVISIBLES = {*_CHARSET["cf_codepoints"], *_CHARSET["extra_codepoints"]}

# A plain token, every metacharacter the escape map covers, an astral character
# (the code-point split must escape it whole), and values that themselves hold a
# member of ENV_INVIS_RUN — the shape that put a required literal inside both
# neighbouring starred classes. A zero-width space (Cf) and a variation selector
# (a non-Cf extra) cover both halves of the charset the run is built from.
ENV_VALUES = [
    "sk-live-abc123",
    ".*+?^${}()|[]\\",
    "a\U0001f600b",
    "a\u200ba",
    "ab\ufe0fcd",
]


def _env_value_sources(values: list[str]) -> list[str]:
    """`envValueRegex(value).source` for each value, from the shipped module."""
    module = (REPO_ROOT / SECRET_ANNOTATE).as_uri()
    script = (
        f"import {{ envValueRegex }} from {json.dumps(module)};\n"
        "const values = JSON.parse(process.argv[1]);\n"
        "process.stdout.write(JSON.stringify("
        "values.map((value) => envValueRegex(value).source)));"
    )
    out = subprocess.run(
        ["node", "--input-type=module", "-e", script, json.dumps(values)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return json.loads(out)


_ENV_SOURCES = _env_value_sources(ENV_VALUES)


def test_secret_annotate_site_is_still_exempted() -> None:
    # The instances below stand in for this exemption; if the extractor ever
    # resolves the site, the static guard analyzes it and this file is moot.
    assert any(file == SECRET_ANNOTATE for file, _ in UNRESOLVABLE_SITES)


@pytest.mark.parametrize(
    "value, source",
    list(zip(ENV_VALUES, _ENV_SOURCES)),
    ids=["token", "metacharacters", "astral", "cf-invisible", "vs-invisible"],
)
def test_env_value_pattern_has_no_super_linear_backtracking(
    value: str, source: str
) -> None:
    # Positive marker: the built pattern carries the starred gap the exemption
    # describes, so the analyzer is judging the quantified shape, not a literal.
    assert "]*" in source, source
    # regexploit does not flag `[C]*x[C]*` when the literal x is itself in C (it
    # returned nothing for the pre-fix pattern of `a<ZWSP>a`), so the analyzer
    # below cannot stand alone for this shape: also assert no required literal is
    # a member of the run's class, the one condition the linearity argument needs.
    literals = re.sub(r"\[[^\]]*\]\*", "", source)
    leaked = sorted(f"U+{ord(ch):04X}" for ch in literals if ord(ch) in INVISIBLES)
    assert not leaked, (
        f"{value!r}: literals {leaked} sit between two runs that contain them"
    )
    out = _analyze(_to_python_syntax(source))
    assert "Error parsing" not in out, f"{value!r}: {out}"
    assert "Worst-case complexity" not in out, (
        f"envValueRegex({value!r}) exhibits super-linear backtracking:\n{out}"
    )


def test_invisible_only_value_builds_a_quantifier_free_pattern() -> None:
    # The exemption's second arm: with no visible character to anchor a gap on,
    # the value is matched exactly. Positive marker: the pattern is non-empty and
    # holds every character of the value, so the no-quantifier claim is about
    # the pattern that was built rather than an empty one.
    value = "\u200b\u200c"
    (source,) = _env_value_sources([value])
    assert source, source
    assert "*" not in source, source
    assert all(f"\\u{{{ord(ch):x}}}" in source or ch in source for ch in value)


def _field_name_hint_source() -> str:
    """The secret pre-gate's keyword arm, built from the shipped vocabulary the
    way src/gates.mjs builds it: the field-value patterns joined by `|`."""
    module = (REPO_ROOT / "src/credential-names.mjs").as_uri()
    script = (
        f"import {{ credentialNames }} from {json.dumps(module)};\n"
        'process.stdout.write(credentialNames().fieldNamePatterns.join("|"));'
    )
    return subprocess.run(
        ["node", "--input-type=module", "-e", script],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def test_field_name_hint_has_no_super_linear_backtracking() -> None:
    assert any(file == GATES for file, _ in UNRESOLVABLE_SITES)
    source = _field_name_hint_source()
    # Positive marker: the built pattern is the multi-noun alternation, with the
    # optional separators the exemption reasons about.
    assert "passphrase" in source and "[_-]?" in source, source
    out = _analyze(_to_python_syntax(source))
    assert "Error parsing" not in out, out
    assert "Worst-case complexity" not in out, (
        f"the secret pre-gate's keyword arm backtracks super-linearly:\n{out}"
    )
