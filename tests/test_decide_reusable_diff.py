"""Behavior tests for .github/scripts/decide-reusable-diff.sh.

The script decides whether a gated CI job runs. Every wrong answer it can give
is asymmetric: `run=true` when nothing matched wastes a runner, while `run=false`
when something did skips the job AND greens its `always()` reporter, so a real
break lands on main behind a required check that never looked at the diff. These
tests drive the real script over real git ranges and pin each arm of that
asymmetry — the fail-open ones (no diffable range) and the fail-loud ones (a gate
configured with no trigger at all, an unreadable paths-regex-file).

`decide-reusable-diff.sh` cites this module by name for the SIGPIPE-safety of its
keyword scan, which `test_keyword_scan_survives_a_long_commit_list` covers.
"""

import os
import subprocess
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT, commit_all, init_test_repo

SCRIPT = REPO_ROOT / ".github" / "scripts" / "decide-reusable-diff.sh"

#: Git's repo-location overrides leak in from a calling git hook and would point
#: the sandbox's git at the real repo.
_GIT_LOCATION_PREFIX = "GIT_"

#: Every input the script reads, cleared so an inherited value from the ambient
#: CI environment cannot decide a test's outcome.
DECIDE_INPUTS = (
    "BASE_SHA",
    "HEAD_SHA",
    "PATHS_REGEX",
    "PATHS_REGEX_FILE",
    "PYTEST_TARGETS",
    "SHELL_TARGETS",
    "TRIGGER_KEYWORD",
    "KEYWORD_SCOPE",
    "IGNORE_COMMENT_ONLY",
    "BASE_REF",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "SKIP_ON_DRAFT",
    "IS_DRAFT",
    "MEMO_ANCHOR_JOBS",
    "GITHUB_EVENT_NAME",
    "GITHUB_EVENT_PATH",
)


class Decide:
    """A sandbox repo plus the runner that decides over its history."""

    def __init__(self, repo: Path) -> None:
        self.repo = repo
        self.output = repo / "github_output"
        self.output.write_text("")

    def write(self, name: str, body: str) -> None:
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)

    def commit(self, message: str) -> str:
        return commit_all(self.repo, message)

    def run(self, **inputs: str) -> subprocess.CompletedProcess:
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(_GIT_LOCATION_PREFIX) and k not in DECIDE_INPUTS
        }
        env.update(GITHUB_OUTPUT=str(self.output), **inputs)
        return subprocess.run(
            ["bash", str(SCRIPT)],
            cwd=self.repo,
            capture_output=True,
            text=True,
            env=env,
        )

    def verdict(self, **inputs: str) -> str:
        """The `run=` value the script emitted, asserting it exited clean."""
        result = self.run(**inputs)
        assert result.returncode == 0, result.stderr
        emitted = [
            line
            for line in self.output.read_text().splitlines()
            if line.startswith("run=")
        ]
        assert len(emitted) == 1, self.output.read_text()
        return emitted[0].removeprefix("run=")


@pytest.fixture
def decide(tmp_path: Path) -> Decide:
    """A two-commit repo: `src/app.mjs` on the base, `docs/guide.md` on the head."""
    repo = tmp_path / "repo"
    init_test_repo(repo)
    sandbox = Decide(repo)
    sandbox.write("src/app.mjs", "export const x = 1;\n")
    sandbox.base = sandbox.commit("chore: base")
    sandbox.write("docs/guide.md", "# guide\n")
    sandbox.head = sandbox.commit("docs: add a guide")
    return sandbox


def test_matching_path_runs_the_gate(decide: Decide) -> None:
    verdict = decide.verdict(
        BASE_SHA=decide.base, HEAD_SHA=decide.head, PATHS_REGEX="^docs/"
    )
    assert verdict == "true"


def test_unmatched_path_skips_the_gate(decide: Decide) -> None:
    verdict = decide.verdict(
        BASE_SHA=decide.base, HEAD_SHA=decide.head, PATHS_REGEX="^src/"
    )
    assert verdict == "false"


@pytest.mark.parametrize(
    "base",
    ["", "0000000000000000000000000000000000000000", "deadbeef" * 5],
    ids=["absent", "all-zeros", "not-in-history"],
)
def test_an_undiffable_range_runs_everything(decide: Decide, base: str) -> None:
    """Fail OPEN: a range this checkout cannot diff must never read as "nothing
    changed", which would skip the gate and green its reporter."""
    verdict = decide.verdict(BASE_SHA=base, HEAD_SHA=decide.head, PATHS_REGEX="^src/")
    assert verdict == "true"


def test_a_gate_with_no_trigger_is_a_loud_misconfiguration(decide: Decide) -> None:
    """A mistyped env key leaves every trigger empty, and such a gate can only
    ever emit run=false — a permanent false green. It must go red instead."""
    result = decide.run(BASE_SHA=decide.base, HEAD_SHA=decide.head)
    assert result.returncode == 1
    assert "no PATHS_REGEX" in result.stderr
    assert decide.output.read_text() == ""


def test_keyword_in_a_range_commit_title_runs_the_gate(decide: Decide) -> None:
    decide.write("src/app.mjs", "export const x = 2;\n")
    head = decide.commit("chore: unrelated tail commit")
    verdict = decide.verdict(
        BASE_SHA=decide.base, HEAD_SHA=head, TRIGGER_KEYWORD="add a guide"
    )
    assert verdict == "true"


def test_head_scope_ignores_a_keyword_from_an_earlier_commit(decide: Decide) -> None:
    """Each `head`-scoped opt-in is per-commit: a later untagged push to the same
    PR must not re-fire the expensive job the keyword bought once."""
    decide.write("src/app.mjs", "export const x = 2;\n")
    head = decide.commit("chore: unrelated tail commit")
    verdict = decide.verdict(
        BASE_SHA=decide.base,
        HEAD_SHA=head,
        TRIGGER_KEYWORD="add a guide",
        KEYWORD_SCOPE="head",
    )
    assert verdict == "false"


def test_keyword_scan_survives_a_long_commit_list(decide: Decide) -> None:
    """The scan captures `git log` into a variable before matching. Piping it to
    `grep -q` instead would let grep close the pipe on the first match and
    SIGPIPE-kill git, which `set -o pipefail` reports as a failed step — a
    timing-dependent red that only appears once the range is long enough.
    """
    head = decide.base
    for i in range(200):
        decide.write("src/app.mjs", f"export const x = {i};\n")
        head = decide.commit(f"chore: churn {i} [run-eval]")
    verdict = decide.verdict(
        BASE_SHA=decide.base, HEAD_SHA=head, TRIGGER_KEYWORD="[run-eval]"
    )
    assert verdict == "true"


def test_keyword_matches_case_insensitively(decide: Decide) -> None:
    verdict = decide.verdict(
        BASE_SHA=decide.base, HEAD_SHA=decide.head, TRIGGER_KEYWORD="ADD A GUIDE"
    )
    assert verdict == "true"


def test_paths_regex_file_supplies_the_regex(decide: Decide) -> None:
    decide.write("gate.sh", "GATE_PATHS_REGEX='^docs/'\n")
    head = decide.commit("chore: add the gate snippet")
    verdict = decide.verdict(
        BASE_SHA=decide.base, HEAD_SHA=head, PATHS_REGEX_FILE="gate.sh"
    )
    assert verdict == "true"


@pytest.mark.parametrize(
    ("inputs", "expected"),
    [
        (
            {"PATHS_REGEX": "^docs/", "PATHS_REGEX_FILE": "gate.sh"},
            "paths-regex OR paths-regex-file",
        ),
        ({"PATHS_REGEX_FILE": "absent.sh"}, "not found in the checkout"),
        ({"PATHS_REGEX_FILE": "empty.sh"}, "did not define GATE_PATHS_REGEX"),
    ],
    ids=["both-set", "missing-file", "file-defines-nothing"],
)
def test_a_bad_paths_regex_file_fails_closed(
    decide: Decide, inputs: dict[str, str], expected: str
) -> None:
    """Every one of these resolves to an empty regex, which would skip every
    gated job silently. The decide step goes red instead."""
    decide.write("gate.sh", "GATE_PATHS_REGEX='^docs/'\n")
    decide.write("empty.sh", "# defines nothing\n")
    head = decide.commit("chore: add the gate snippets")
    result = decide.run(BASE_SHA=decide.base, HEAD_SHA=head, **inputs)
    assert result.returncode == 1
    assert expected in result.stderr
    assert decide.output.read_text() == ""


def test_comment_only_churn_skips_an_opted_in_gate(decide: Decide) -> None:
    decide.write("src/app.mjs", "// a new note\nexport const x = 1;\n")
    head = decide.commit("docs: annotate app.mjs")
    verdict = decide.verdict(
        BASE_SHA=decide.base,
        HEAD_SHA=head,
        PATHS_REGEX="^src/",
        IGNORE_COMMENT_ONLY="true",
    )
    assert verdict == "false"


def test_substantive_change_runs_an_opted_in_gate(decide: Decide) -> None:
    """The counterpart the skip above must not swallow: with the same opt-in, a
    real edit to a watched file still fires the gate."""
    decide.write("src/app.mjs", "export const x = 99;\n")
    head = decide.commit("fix: change the value")
    verdict = decide.verdict(
        BASE_SHA=decide.base,
        HEAD_SHA=head,
        PATHS_REGEX="^src/",
        IGNORE_COMMENT_ONLY="true",
    )
    assert verdict == "true"


def test_a_draft_pull_request_defers_an_opted_in_gate(decide: Decide) -> None:
    verdict = decide.verdict(
        BASE_SHA=decide.base,
        HEAD_SHA=decide.head,
        PATHS_REGEX="^docs/",
        SKIP_ON_DRAFT="true",
        IS_DRAFT="true",
    )
    assert verdict == "false"


#: A real entry point and a library it sources. The closure is computed from this
#: repo's own index (shell-run-closure.py resolves the repo from its own location,
#: not from the caller's cwd), so the derived-path tests name real files and let
#: the sandbox history claim them as changed.
CLOSURE_ENTRY = ".github/scripts/decide-reusable-diff.sh"


def closure_member() -> str:
    """A file the entry point reaches that is not the entry point itself.

    Read from the closure script rather than hardcoded: the reachable set moves
    with the entry point's text, and a stale literal here would test nothing.
    """
    members = subprocess.run(
        [
            "python3",
            str(REPO_ROOT / ".github" / "scripts" / "shell-run-closure.py"),
            CLOSURE_ENTRY,
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    reachable = [m for m in members if m != CLOSURE_ENTRY]
    assert reachable, f"{CLOSURE_ENTRY} reaches nothing — the closure test is vacuous"
    return reachable[0]


def test_a_derived_shell_closure_widens_the_watched_paths(decide: Decide) -> None:
    """shell-targets watches what an entry point can RUN, not what a regex spells:
    editing a file it reaches must fire the gate even though no regex names it.
    """
    decide.write(closure_member(), "# edited\n")
    head = decide.commit("fix: change a sourced library")
    verdict = decide.verdict(
        BASE_SHA=decide.base, HEAD_SHA=head, SHELL_TARGETS=CLOSURE_ENTRY
    )
    assert verdict == "true"


def test_a_file_outside_the_derived_closure_skips_the_gate(decide: Decide) -> None:
    """The counterpart that proves the closure discriminates rather than matching
    everything: the fixture's own head commit touches only `docs/guide.md`."""
    verdict = decide.verdict(
        BASE_SHA=decide.base, HEAD_SHA=decide.head, SHELL_TARGETS=CLOSURE_ENTRY
    )
    assert verdict == "false"


def test_an_underivable_shell_target_fails_closed(decide: Decide) -> None:
    result = decide.run(
        BASE_SHA=decide.base, HEAD_SHA=decide.head, SHELL_TARGETS="tools/absent.sh"
    )
    assert result.returncode == 1
    assert "could not derive the shell run closure" in result.stderr
    assert decide.output.read_text() == ""
