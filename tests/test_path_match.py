"""Behavior tests for .github/scripts/lib-path-match.sh.

The guarantee under test: a path gate never reads a grep FAILURE as "nothing
matched". grep exits 1 for a clean no-match and 2 for a failure of its own (a
malformed regex, an unreadable input), and every helper here must widen to the
whole changed-file list on the latter — a wasted job run is safe, a required
check that greens without scanning the diff is not.
"""

import subprocess
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT

LIB = REPO_ROOT / ".github" / "scripts" / "lib-path-match.sh"

CHANGED = "src/a.mjs\ndocs/b.md\n.github/workflows/c.yaml"

# Each helper with the argument that selects `src/a.mjs` out of CHANGED: a regex
# for the pattern arm, a whole-line literal list for the derived-closure arm.
HELPERS = {
    "path_gate_matching_lines": r"^src/",
    "path_gate_matching_fixed_lines": "src/a.mjs\nsrc/absent.mjs",
}


def run_helper(
    fn: str, arg: str, changed: str = CHANGED, path: str | None = None
) -> subprocess.CompletedProcess:
    script = f'. "{LIB}"; {fn} "$1" "$2"'
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", script, "bash", arg, changed],
        capture_output=True,
        text=True,
        env={"PATH": path or "/usr/bin:/bin"},
    )


@pytest.mark.parametrize("fn", sorted(HELPERS))
def test_clean_match_returns_only_the_matching_lines(fn: str) -> None:
    result = run_helper(fn, HELPERS[fn])
    assert result.returncode == 0, result.stderr
    assert result.stdout == "src/a.mjs\n"


@pytest.mark.parametrize("fn", sorted(HELPERS))
def test_clean_no_match_returns_nothing(fn: str) -> None:
    """grep's exit 1 is the one status that means no watched path changed."""
    result = run_helper(fn, "no/such/path.txt")
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("fn", sorted(HELPERS))
def test_grep_failure_widens_to_every_changed_file(tmp_path: Path, fn: str) -> None:
    """The fail-open posture, driven for real: a grep that exits 2 must yield
    the whole list, not the empty answer that would skip the gated job.

    A stub on PATH rather than a crafted input, because the two helpers reach
    exit 2 by different routes (a malformed ERE, an unreadable pattern file) and
    the posture is one contract.
    """
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "grep"
    # Drains stdin before exiting: the caller feeds the changed list in, and a
    # stub that exits without reading leaves the writer with EPIPE.
    stub.write_text("#!/bin/bash\ncat >/dev/null 2>&1\nexit 2\n")
    stub.chmod(0o755)

    result = run_helper(fn, HELPERS[fn], path=f"{stub_dir}:/usr/bin:/bin")
    assert result.returncode == 0, result.stderr
    assert result.stdout == CHANGED + "\n"
