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
import subprocess

import pytest

from tests._helpers import REPO_ROOT
from tests.test_redos_js_static_guard import (
    UNRESOLVABLE_SITES,
    _analyze,
    _to_python_syntax,
)

SECRET_ANNOTATE = "claude-hooks/lib/secret-annotate.mjs"

# A plain token, every metacharacter the escape map covers, and an astral
# character (the code-point split must escape it whole).
ENV_VALUES = ["sk-live-abc123", ".*+?^${}()|[]\\", "a\U0001f600b"]


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
    ids=["token", "metacharacters", "astral"],
)
def test_env_value_pattern_has_no_super_linear_backtracking(
    value: str, source: str
) -> None:
    # Positive marker: the built pattern carries the starred gap the exemption
    # describes, so the analyzer is judging the quantified shape, not a literal.
    assert "]*" in source, source
    out = _analyze(_to_python_syntax(source))
    assert "Error parsing" not in out, f"{value!r}: {out}"
    assert "Worst-case complexity" not in out, (
        f"envValueRegex({value!r}) exhibits super-linear backtracking:\n{out}"
    )
