"""Tests for .github/scripts/check-test-repo-root.py.

The lint has three rules: no depth-based ``Path(__file__)`` repo-root walks, no
module-level re-inlined ``git rev-parse --show-toplevel`` calls (both must route
through ``tests/_helpers.REPO_ROOT``), and no module-level ``sys.path`` mutation
(must route through ``ensure_python_pkg_on_path()``). Each rule gets a positive case
proving it fires (with its message, so the test can't pass on the other rule's
hit) and negative cases pinning the deliberate carve-outs — including that the
``tests/_helpers.py`` exemption is keyed on the PATH, not on the call shape.
"""

import subprocess
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT

SCRIPT = REPO_ROOT / ".github" / "scripts" / "check-test-repo-root.py"

# The exact block the four historical copies re-inlined (sans the helper's
# `cwd=` argument — the live divergence the lint exists to prevent).
REV_PARSE_BLOCK = """\
import subprocess
from pathlib import Path

REPO_ROOT = Path(
    subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
)
"""


def run_lint(*paths: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["python3", str(SCRIPT), *map(str, paths)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def lint_source(tmp_path: Path, source: str) -> subprocess.CompletedProcess:
    target = tmp_path / "tests" / "test_sample.py"
    target.parent.mkdir(exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return run_lint(target)


@pytest.mark.parametrize(
    "source, expected_message",
    [
        # Depth-based walks (the original rule).
        (
            "from pathlib import Path\nROOT = Path(__file__).resolve().parent.parent\n",
            "depth-based repo-root walk",
        ),
        (
            "from pathlib import Path\nROOT = Path(__file__).parents[2]\n",
            "depth-based repo-root walk",
        ),
        # A module-level re-inlined rev-parse block (the new rule).
        (REV_PARSE_BLOCK, "module-level `git rev-parse --show-toplevel`"),
        # Hand-inserted package-dir bootstrap, in each mutation spelling.
        (
            "import sys\nfrom tests._helpers import REPO_ROOT\n"
            "sys.path.insert(0, str(REPO_ROOT / 'python'))\n",
            "module-level `sys.path` mutation",
        ),
        (
            "import sys\nsys.path.append('python')\n",
            "module-level `sys.path` mutation",
        ),
    ],
)
def test_flags_violations(tmp_path: Path, source: str, expected_message: str) -> None:
    result = lint_source(tmp_path, source)
    assert result.returncode == 1
    assert expected_message in result.stderr


@pytest.mark.parametrize(
    "source",
    [
        # One .parent (anchoring a cwd at the file's own dir) is fine.
        "from pathlib import Path\nHERE = Path(__file__).resolve().parent\n",
        # The canonical fix passes clean.
        "from tests._helpers import REPO_ROOT\nX = REPO_ROOT / 'python'\n",
        # rev-parse WITHOUT --show-toplevel (e.g. HEAD) is not the helper's job.
        "import subprocess\n"
        'SHA = subprocess.run(["git", "rev-parse", "HEAD"]).stdout\n',
        # A call inside a function body exercises git behavior, not a re-inline.
        "import subprocess\n"
        "def repo_root(cwd):\n"
        '    return subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=cwd)\n',
        # The canonical bootstrap fix.
        "from tests._helpers import ensure_python_pkg_on_path\n"
        "ensure_python_pkg_on_path()\n",
        # A sys.path insert INSIDE a source string a test hands to a subprocess
        # does not mutate this module's path — the ast keeps it from tripping.
        "PROGRAM = \"import sys; sys.path.insert(0, 'python')\"\n",
        # An unrelated object with a `path` attribute is not sys.path.
        "import argparse\nparser = argparse.ArgumentParser()\n"
        "parser.path.append('x')\n",
    ],
)
def test_allows_clean_sources(tmp_path: Path, source: str) -> None:
    result = lint_source(tmp_path, source)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""


def test_helpers_module_itself_is_exempt() -> None:
    """The real tests/_helpers.py hosts the one allowed rev-parse call."""
    result = run_lint(Path("tests") / "_helpers.py")
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""


def test_helpers_exemption_is_path_keyed(tmp_path: Path) -> None:
    """The exemption is by path, not vacuous: the SAME helper source at any
    other path is flagged — and the real helper really contains the call this
    lint would otherwise catch (guards against the check going stale if the
    helper's implementation moves off rev-parse)."""
    helper_source = (REPO_ROOT / "tests" / "_helpers.py").read_text(encoding="utf-8")
    assert "--show-toplevel" in helper_source
    result = lint_source(tmp_path, helper_source)
    assert result.returncode == 1
    assert "module-level `git rev-parse --show-toplevel`" in result.stderr
