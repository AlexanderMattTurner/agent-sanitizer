"""A job's `sparse-checkout` list must fetch every file its scripts source.

PROBLEM CLASS — a workflow job that checks out a script but not the library the
script sources. Nothing fails at checkout time: the file is simply absent, and
the `source` line then dies under `set -e` on the first real run. For the review
gates that means a required commit status or check run is never posted, so every
open pull request hangs at "Expected — Waiting" on a context nothing will send.

The requirement is DERIVED, never restated: this module reads each job's `run:`
steps for the scripts they execute, parses those scripts with the bash grammar to
find what they `source`, and walks that transitively. A list that omits a member
of the closure reds here. Adding a `source` to a script therefore fails CI until
every narrow list that fetches it grows the new file, which is the whole reason
`.github/scripts/lib/reviewer-identity.bash` can be shared by scripts the review
workflows fetch one file at a time.

Jobs whose list already covers a whole directory (`.github/scripts`) pass
trivially, and that is correct — the closure IS in their checkout.
"""

import re

import pytest
import yaml

from tests._helpers import REPO_ROOT
from tests._source_closure import (
    source_closure,
    tracked_files,
    unresolved_sources,
)

WORKFLOWS = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yaml"))

#: A `.github/scripts` shell script named anywhere in a `run:` block. Deliberately
#: over-broad — a script named in a comment and never executed only ADDS a
#: requirement, and this check's failure mode must be a job that fetches too much
#: rather than one that fetches too little.
SCRIPT_REF = re.compile(r"\.github/scripts/[A-Za-z0-9_./-]+\.(?:sh|bash)")

TRACKED = tracked_files()


def _covers(entry: str, path: str) -> bool:
    """True when sparse-checkout pattern `entry` fetches `path`."""
    entry = entry.strip().strip("/")
    return entry in ("", ".") or path == entry or path.startswith(entry + "/")


def _jobs_with_a_sparse_list():
    """(workflow name, job id, sparse entries, joined `run:` text) per job."""
    for workflow in WORKFLOWS:
        document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        for job_id, job in (document.get("jobs") or {}).items():
            steps = job.get("steps") or []
            entries: set[str] = set()
            for step in steps:
                listed = (step.get("with") or {}).get("sparse-checkout")
                if listed:
                    entries |= {
                        line.strip()
                        for line in str(listed).splitlines()
                        if line.strip()
                    }
            runs = "\n".join(str(step["run"]) for step in steps if step.get("run"))
            if entries and runs:
                yield workflow.name, job_id, entries, runs


CASES = [
    pytest.param(name, job_id, entries, runs, id=f"{name}:{job_id}")
    for name, job_id, entries, runs in _jobs_with_a_sparse_list()
]


def test_the_scan_found_jobs_to_check() -> None:
    # Non-vacuity: every assertion below lives in a parametrization, so an
    # empty case list would report a green suite that checked nothing.
    assert CASES, "no workflow job pairs a sparse-checkout list with a run: step"


@pytest.mark.parametrize(("name", "job_id", "entries", "runs"), CASES)
def test_a_sparse_list_fetches_every_file_its_scripts_source(
    name: str, job_id: str, entries: set[str], runs: str
) -> None:
    scripts = {ref for ref in SCRIPT_REF.findall(runs) if ref in TRACKED}
    missing = sorted(
        path
        for path in source_closure(scripts)
        if not any(_covers(e, path) for e in entries)
    )
    assert not missing, (
        f"{name}:{job_id} runs {sorted(scripts)}, which source {missing}, but its "
        f"sparse-checkout list {sorted(entries)} does not fetch them — the job would "
        "die at the `source` line under `set -e`. Add each file to the list."
    )


def test_the_review_gate_lists_are_checked_against_a_real_source_closure() -> None:
    """The narrow lists this check exists for, and proof the closure is not empty.

    `review-gate.sh` is fetched one file at a time by three jobs; the moment it
    sources a library, that library has to appear in all three lists. Without
    this assertion the parametrized check above passes just as happily on a
    closure computation that resolved nothing.
    """
    gate = ".github/scripts/review-gate.sh"
    closure = source_closure({gate})
    assert closure > {gate}, f"{gate} sources nothing — the closure walk proves nothing"

    narrow = {
        f"{name}:{job_id}"
        for name, job_id, entries, runs in _jobs_with_a_sparse_list()
        if gate in runs
        and not any(_covers(entry, gate) and entry != gate for entry in entries)
    }
    assert narrow, (
        "no job fetches review-gate.sh through a file-level sparse-checkout list"
    )
    for path in closure:
        assert (REPO_ROOT / path).is_file()

    # Every `source` inside the closure has to reach a tracked file. One the walk
    # skipped is a checkout requirement nothing states, and the three jobs that
    # fetch review-gate.sh one file at a time would each be short a library.
    skipped = {
        f"{path}: {written}"
        for path in closure
        for written in unresolved_sources(path, TRACKED)
    }
    assert not skipped, (
        f"the {gate} closure skipped {sorted(skipped)} — each is a file the narrow "
        "sparse-checkout lists are never told to fetch"
    )
