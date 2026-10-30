"""Build the runtime patterns UNRESOLVABLE_SITES exempts, and analyze them.

An ``UNRESOLVABLE_SITES`` entry in ``test_redos_js_static_guard.py`` is a hole in
the static ReDoS guard: the extractor cannot spell the pattern, so regexploit
never sees it, and the entry's reason is prose nothing checks. Where the
shipped module can build the pattern itself, this asks it to and runs the same
analyzer over the real output, so the exemption's safety claim is measured
rather than asserted.
"""

import json
import subprocess


from tests._helpers import REPO_ROOT
from tests.test_redos_js_static_guard import (
    UNRESOLVABLE_SITES,
    _analyze,
    _to_python_syntax,
)

GATES = "src/gates.mjs"


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
