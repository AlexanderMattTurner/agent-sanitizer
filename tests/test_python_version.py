"""Guard the Python client's version-coupling contract.

Because the wheel bundles a build of `src/`, the Python distribution and the npm
package are the same logic in two ecosystems, so they share ONE version. The
release workflow derives it from Conventional Commits, publishes npm and PyPI at
that number from the same commit, and injects it into `python/pyproject.toml` at
build time (working tree only) — exactly as it injects the npm version into
package.json. The committed `python/pyproject.toml` version is therefore a frozen
`0.0.0` placeholder, never shipped.

Two ways this rots: a maintainer hand-edits the placeholder thinking it drives
the release (it doesn't), or the old "independent, hand-bumped" policy creeps
back into the docs. This pins the sentinel and asserts the coupling rationale is
written down, so either slip fails CI.
"""

import re
import subprocess
from pathlib import Path

from tests._helpers import REPO_ROOT

# The frozen placeholder committed to python/pyproject.toml. The release workflow
# overwrites this in the working tree with the real version before building; the
# committed value is never published.
PLACEHOLDER_VERSION = "0.0.0"


def _read_version(pyproject: Path) -> str:
    """Pull the ``version = "..."`` line out of a pyproject without a TOML lib.

    Avoids ``tomllib`` so the guard runs unchanged on Python 3.10 (the package's
    floor; ``tomllib`` is 3.11+).
    """
    for line in pyproject.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        match = re.match(r'version\s*=\s*"(?P<value>[^"]+)"', stripped)
        if match:
            return match.group("value")
    raise AssertionError(f"no version field found in {pyproject}")


def test_committed_python_version_is_the_frozen_placeholder() -> None:
    version = _read_version(REPO_ROOT / "python" / "pyproject.toml")
    assert version == PLACEHOLDER_VERSION, (
        f"python/pyproject.toml version is {version!r}, expected the frozen "
        f"{PLACEHOLDER_VERSION!r} placeholder. The version is injected at release "
        "time from the npm/tag release version — do not hand-edit it here; the "
        "release workflow (auto-version.yaml) sets it."
    )


def test_coupling_policy_is_documented() -> None:
    """The coupling policy must stay written down next to the version, so a
    future maintainer who notices the 0.0.0 placeholder reads *why* before
    "fixing" it. Asserts positive markers that we are on the intended lines (a
    deleted rationale is the regression), and sanity-checks that the npm
    package.json version is a parseable frozen placeholder too — proving both
    ecosystems share the same injected-at-release model.
    """
    pyproject_text = (REPO_ROOT / "python" / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert "FROZEN PLACEHOLDER" in pyproject_text, (
        "the frozen-placeholder marker was dropped from python/pyproject.toml — "
        "restore the version-coupling rationale before changing the policy"
    )
    assert "same version" in pyproject_text.lower(), (
        "the npm/PyPI version-coupling rationale was dropped from "
        "python/pyproject.toml — restore it before changing the policy"
    )
    npm_version = re.search(
        r'"version":\s*"(?P<value>[^"]+)"',
        (REPO_ROOT / "package.json").read_text(encoding="utf-8"),
    )
    assert npm_version and npm_version.group("value"), (
        "npm package.json version missing"
    )


def test_version_injection_script_produces_a_valid_release(tmp_path: Path) -> None:
    """Run the REAL injector (scripts/set-pyproject-version.sh, invoked by the
    release workflow) on a copy and assert it rewrites the placeholder to a plain
    PEP 440 release. Catches a regression in the injection path here, not at
    publish time. The script targets the relative path python/pyproject.toml, so
    stage a copy under a temp cwd and run it there — the committed file is
    untouched.
    """
    sample = "4.5.6"
    staged = tmp_path / "python" / "pyproject.toml"
    staged.parent.mkdir(parents=True)
    staged.write_text(
        (REPO_ROOT / "python" / "pyproject.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "set-pyproject-version.sh"), sample],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    injected = _read_version(staged)
    assert injected == sample and re.fullmatch(r"\d+\.\d+\.\d+", injected)
    # Exactly one version line changed: the description/other lines are intact.
    assert 'name = "agent-sanitizer"' in staged.read_text(encoding="utf-8")
