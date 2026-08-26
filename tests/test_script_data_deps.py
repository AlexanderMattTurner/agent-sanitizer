"""Every data file a CI script reads by path must actually be in the tree.

`.github/scripts/*.sh` scripts run under `set -euo pipefail`, so a `source
"${here}/../tool-versions.sh"` or a `tr … <"${SCRIPT_DIR}/../claude-cli-version"`
against a missing file kills the job on that line. Such a file is invisible to
every other guard here: it is not a workflow, not an import, and shellcheck's
`source=` directives only cover shell libraries, not data.

This is not hypothetical. Both pin files above arrived in the template as
dependencies of scripts that DO sync, while the files themselves sat outside
`SYNC_PATHS` — so `Sync from Template` failed on every run from 2026-08-07,
inside the one workflow whose job was to deliver the fix.
"""

import os
import re
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT

SCRIPT_DIR = REPO_ROOT / ".github" / "scripts"

# `"${SCRIPT_DIR}/../x"`, `"$here/../../config/y"` — a path resolved against the
# script's own location, which is the idiom for reaching a data file. Bare
# relative paths are deliberately not matched: those resolve against the caller's
# cwd, so this test could not say where they were meant to point.
SELF_RELATIVE_PATH = re.compile(
    r"""\$\{?(?:SCRIPT_DIR|here|HERE|script_dir)\}?(?P<suffix>(?:/\.\.)+/[A-Za-z0-9._/-]+)"""
)

# Suffixes that name a shell library rather than data. Those are already covered
# by shellcheck's `source=` resolution, and listing them here would double-report.
LIB_PREFIX = "/lib/"


def _referenced_paths() -> list[tuple[str, Path]]:
    """(script name, repo-relative data path) for every self-relative reference."""
    found = []
    for script in sorted(SCRIPT_DIR.rglob("*.sh")):
        for match in SELF_RELATIVE_PATH.finditer(script.read_text(encoding="utf-8")):
            suffix = match.group("suffix")
            if LIB_PREFIX in suffix:
                continue
            # normpath, not resolve(): collapsing `..` lexically keeps the result
            # under REPO_ROOT (which git reports unresolved), so the failure
            # message below can render it repo-relative even when the checkout
            # sits behind a symlink.
            target = Path(os.path.normpath(script.parent / suffix.lstrip("/")))
            found.append((str(script.relative_to(REPO_ROOT)), target))
    return found


REFERENCES = _referenced_paths()


def test_references_were_actually_found() -> None:
    """Non-vacuity: the regex must still match the idiom it was written for.

    Without this, rewriting the scripts to a different path idiom turns every
    assertion below into a loop over an empty list that passes forever.
    """
    assert len(REFERENCES) >= 3, f"found only {len(REFERENCES)} self-relative refs"
    named = {path.name for _, path in REFERENCES}
    for expected in {"tool-versions.sh", "claude-cli-version"}:
        assert expected in named, f"{expected} reference no longer detected"


@pytest.mark.parametrize(
    ("script", "target"),
    REFERENCES,
    ids=[f"{s}->{t.name}" for s, t in REFERENCES],
)
def test_referenced_data_file_exists(script: str, target: Path) -> None:
    assert target.is_file(), (
        f"{script} reads {target.relative_to(REPO_ROOT)}, which is not in the tree"
    )
