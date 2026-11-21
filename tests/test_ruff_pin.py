"""Behavioral tests for .hooks/ruff.sh: the real script and PyYAML runner read a
fixture config; only `uvx` and `ruff` are stubs that print their argv."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT

URL = "repo: https://github.com/astral-sh/ruff-pre-commit"
SHA = "488940d9de1b658fac229e34c521d75a6ea476f2"


@pytest.mark.parametrize(
    "entry, pin",
    [
        (f"{URL}\n    rev: {SHA}  # frozen: v0.14.5", "0.14.5"),
        (f"rev: v0.14.5\n    {URL}", "0.14.5"),
        (f"{URL}\n    # rev: v0.4.0\n    rev: {SHA}  # v0.14.5", "0.14.5"),
        (f"{URL}\n    rev: {SHA}", None),
    ],
    ids=["frozen-comment", "rev-before-repo", "commented-out-rev", "unpinned-sha"],
)
def test_pin_comes_from_the_ruff_entry(
    tmp_path: Path, entry: str, pin: str | None
) -> None:
    for rel in (
        ".hooks/ruff.sh",
        ".github/scripts/run-with-pyyaml.sh",
        ".github/tool-versions.sh",
    ):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO_ROOT / rel, tmp_path / rel)
    other = "  - repo: https://x/y\n    rev: v0.4.0\n    hooks: []\n"
    (tmp_path / ".pre-commit-config.yaml").write_text(f"repos:\n{other}  - {entry}\n")
    (tmp_path / "bin").mkdir()
    for tool in ("uvx", "ruff"):
        (tmp_path / "bin" / tool).write_text(f'#!/bin/bash\necho "{tool} $*"\n')
        (tmp_path / "bin" / tool).chmod(0o755)
    env = {**os.environ, "PATH": f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}"}
    run = subprocess.run(
        ["bash", str(tmp_path / ".hooks/ruff.sh"), "check"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout == (f"uvx ruff@{pin} check\n" if pin else "ruff check\n")
    assert ("no ruff pin" in run.stderr) == (pin is None)
