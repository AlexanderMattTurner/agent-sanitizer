"""Tests for .github/scripts/mutation-changed.sh.

The relevance list is not hand-maintained in the script: it parses
mutation.yaml's on.push.paths (the SSOT) and translates the globs to a regex.
These tests run the real script against the real workflow file inside a
throwaway git repo, proving the parse is non-vacuous, that in-list files are
classified relevant (including .github/actions/setup-base-env/action.yaml —
the entry the old hand-copied regex had dropped), that out-of-list files are
not, and that a parse yielding zero paths fails loudly (exit >= 2, never a
silent "skip").
"""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests._helpers import REPO_ROOT, commit_all, git_env, init_test_repo

SCRIPT = REPO_ROOT / ".github" / "scripts" / "mutation-changed.sh"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "mutation.yaml"


def push_paths() -> list[str]:
    """on.push.paths from the real workflow, via a real YAML parser."""
    # `on` parses as the YAML boolean True.
    paths = yaml.safe_load(WORKFLOW.read_text())[True]["push"]["paths"]
    assert paths, "mutation.yaml on.push.paths is empty"
    return paths


def make_sandbox(tmp_path: Path, workflow_text: str) -> Path:
    repo = tmp_path / "sandbox"
    init_test_repo(repo)
    scripts = repo / ".github" / "scripts"
    workflows = repo / ".github" / "workflows"
    scripts.mkdir(parents=True)
    workflows.mkdir(parents=True)
    shutil.copy(SCRIPT, scripts / "mutation-changed.sh")
    (workflows / "mutation.yaml").write_text(workflow_text)
    return repo


def run_script(repo: Path, changed_file: str) -> subprocess.CompletedProcess:
    """Commit a base, then a head touching `changed_file`; run the script."""
    (repo / "README.base").write_text("base\n")
    base = commit_all(repo, "base")
    target = repo / changed_file
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        # e.g. the workflow or script copy itself: append a comment so the file
        # is changed without destroying what the script needs to read/run.
        target.write_text(target.read_text() + "# changed\n")
    else:
        target.write_text("changed\n")
    head = commit_all(repo, "head")
    return subprocess.run(
        ["bash", ".github/scripts/mutation-changed.sh"],
        cwd=repo,
        env={**git_env(), "BASE_SHA": base, "HEAD_SHA": head},
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    "changed_file",
    [
        "src/foo.mjs",
        "src/nested/deep/bar.mjs",
        # The realized drift: present in on.push.paths, missing from the old
        # hand-copied regex, so PRs touching only this file skipped mutation.
        ".github/actions/setup-base-env/action.yaml",
        "stryker.conf.json",
        "package.json",
    ],
)
def test_in_list_file_is_relevant(tmp_path: Path, changed_file: str) -> None:
    repo = make_sandbox(tmp_path, WORKFLOW.read_text())
    result = run_script(repo, changed_file)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "changed_file",
    [
        "README.md",
        "src/foo.py",  # under src/, but not a .mjs
        "docs/src/foo.mjs",  # .mjs, but not under a mutated root
        ".github/workflows/lint.yaml",
    ],
)
def test_out_of_list_file_is_not_relevant(tmp_path: Path, changed_file: str) -> None:
    repo = make_sandbox(tmp_path, WORKFLOW.read_text())
    result = run_script(repo, changed_file)
    assert result.returncode == 1, (result.returncode, result.stdout, result.stderr)


def test_every_push_path_glob_matches_itself(tmp_path: Path) -> None:
    """Non-vacuity: the script's parse found every on.push.paths entry.

    For each glob in the real workflow, derive a concrete filename that the
    glob must match (replace `**/*` and `*` with a literal segment) and assert
    the script classifies it relevant. If the shell parser silently dropped an
    entry, its derived file would come back "not relevant" here.
    """
    for glob in push_paths():
        concrete = glob.replace("**/", "a/b/").replace("*", "x")
        repo = make_sandbox(tmp_path / concrete.replace("/", "_"), WORKFLOW.read_text())
        result = run_script(repo, concrete)
        assert result.returncode == 0, (
            f"{concrete!r} (from glob {glob!r}) not classified relevant: "
            f"{result.stderr}"
        )


def test_a_comment_inside_the_paths_block_does_not_truncate_it(
    tmp_path: Path,
) -> None:
    """A comment between entries must not end the parse.

    The parser used to treat any non-entry line as the end of the block, so a
    comment silently dropped every path below it — and the failure mode is a
    clean exit 1, which the workflow reads as "nothing relevant, skip". Pinned
    on a synthetic workflow rather than on the live one having a comment, so
    removing that comment cannot quietly retire this case.
    """
    workflow = (
        "name: Mutation tests\n"
        "on:\n"
        "  push:\n"
        "    paths:\n"
        '      - "src/**/*.mjs"\n'
        "      # a comment, and a blank line, in the middle of the list\n"
        "\n"
        '      - "below-the-comment.mjs"\n'
        "  pull_request:\n"
        "jobs: {}\n"
    )
    repo = make_sandbox(tmp_path, workflow)
    result = run_script(repo, "below-the-comment.mjs")
    assert result.returncode == 0, (result.returncode, result.stderr)


def test_zero_parsed_paths_fails_loudly(tmp_path: Path) -> None:
    """A workflow whose paths block the parser cannot find is exit >= 2 (fail
    the job), never exit 1 (which the workflow reads as a clean skip)."""
    gutted = "\n".join(
        line
        for line in WORKFLOW.read_text().splitlines()
        if not line.lstrip().startswith(("paths:", '- "'))
    )
    repo = make_sandbox(tmp_path, gutted)
    result = run_script(repo, "src/foo.mjs")
    assert result.returncode >= 2, (result.returncode, result.stdout)
    assert "ZERO entries" in result.stderr


def test_missing_base_fails_open(tmp_path: Path) -> None:
    repo = make_sandbox(tmp_path, WORKFLOW.read_text())
    (repo / "README.base").write_text("base\n")
    head = commit_all(repo, "head")
    result = subprocess.run(
        ["bash", ".github/scripts/mutation-changed.sh"],
        cwd=repo,
        env={**git_env(), "BASE_SHA": "", "HEAD_SHA": head},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
