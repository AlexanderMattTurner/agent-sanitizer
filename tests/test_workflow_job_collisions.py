"""No two workflows may run the same job under the same concurrency group.

Regression: template sync #169 (`ae17eb7`) added the template's consolidated
`pr-meta.yaml` / `pr-meta-privileged.yaml` while this repo still carried the
standalone predecessors they replace. Each pair declared the SAME job `name:`
under the SAME `concurrency.group`, so on every push the two copies raced and
whichever started second cancelled the first. GitHub reports that as a
cancelled check, not an error, and the surviving copy does the work — so the
duplication is invisible until someone asks why checks keep cancelling.

Worse than the wasted runner: which copy survives is a race, and the copies are
not equivalent. `remerge-diff-report.yaml` ran the renderer from the PR-head
checkout in the same job that held `pull-requests: write`; `pr-meta.yaml` splits
that into an unprivileged render and a default-branch-checkout comment. A race
that can be won by the weaker-isolation copy is a security property decided by
scheduling luck.

The sync cannot catch this on its own: it only ever COPIES files the template
has, so a file the template deleted lingers locally forever. It reports the
deletion in the PR body as "consider removing", which is prose in a long
description that nobody actioned across several syncs.

WHAT A PASS DOES NOT MEAN. This detects CANCELLATION, not duplication. A stale
copy whose group is derived from `${{ github.workflow }}` — the idiom about half
this repo's workflows use — resolves to a group unique to its own file, so it
never cancels its replacement: both copies simply run, doing the work twice.
`history-integrity.yaml` and `cancel-on-pr-close.yaml` were exactly that shape,
and this guard never saw them; they were found by reading `pr-meta.yaml`'s
`# ── <file> ──` provenance headers, not by any check. Widening the predicate to
catch that shape would flag every legitimate `${{ github.workflow }}` user, so
the check stays narrow on purpose and this paragraph carries the rest: a green
run here means nothing is cancelling its twin, NOT that no leftovers exist.
"""

import re
from collections import defaultdict
from pathlib import Path

import pytest
import yaml

from tests._helpers import REPO_ROOT

WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"


def workflow_files() -> list[Path]:
    return sorted(
        p
        for p in WORKFLOW_DIR.iterdir()
        if p.suffix in (".yaml", ".yml") and p.is_file()
    )


def concurrency_group(block) -> str | None:
    """The `group:` of a `concurrency:` block, or None.

    A bare string `concurrency: foo` is the shorthand for `group: foo`.
    """
    if isinstance(block, str):
        return block
    if isinstance(block, dict):
        group = block.get("group")
        return group if isinstance(group, str) else None
    return None


def resolve_group(group: str, workflow_name: str) -> str:
    """`group` with `github.workflow` substituted for this workflow's name.

    Two files can carry the byte-identical group template
    `${{ github.workflow }}-${{ …number }}` and never collide, because that
    context expands to each workflow's OWN name. Comparing the raw templates
    would flag every such pair — this repo has one (`hook-lifecycle` and
    `zizmor` both call a reusable `decide` job). Resolve the one context that
    distinguishes files before comparing, so a match means a real collision.
    """
    return re.sub(r"\$\{\{\s*github\.workflow\s*\}\}", lambda _: workflow_name, group)


def job_slots(path: Path) -> list[tuple[str, str, str, bool]]:
    """Every (display name, effective group, job id, group-is-job-level) here.

    The effective group is the job's own when it has one, else the workflow's —
    the same precedence GitHub applies. Jobs with no group either way cannot
    cancel anything, so they are not slots.

    The last element records WHICH level supplied the group, because the two are
    claimed differently: a job-level group is claimed per job, a workflow-level
    one once by the whole run. Siblings that merely inherit the workflow's group
    therefore never cancel each other — see `find_collisions`.
    """
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        return []
    # An unnamed workflow displays as its path, which is also what
    # `github.workflow` expands to in that case.
    workflow_name = doc.get("name") or f".github/workflows/{path.name}"
    workflow_group = concurrency_group(doc.get("concurrency"))
    slots = []
    for job_id, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        own_group = concurrency_group(job.get("concurrency"))
        group = own_group or workflow_group
        if group is None:
            continue
        group = resolve_group(group, workflow_name)
        # An unnamed job displays as its id, which is what a status check and a
        # branch-protection rule match on.
        name = job.get("name") or job_id
        if not isinstance(name, str):
            continue
        slots.append((name, group, job_id, own_group is not None))
    return slots


def find_collisions(
    slots_by_file: dict[str, list[tuple[str, str, str, bool]]],
) -> dict[tuple[str, str], list[str]]:
    """Slots that name the same job under a group they genuinely contend for.

    Two rules, because the two concurrency levels are claimed differently:

    * ACROSS files — any pair collides. Two runs wanting one group is the
      cancellation regardless of which level declared it on either side.
    * WITHIN one file — only job-level groups collide. A workflow-level group is
      claimed once by the run, so every job inheriting it shares that single
      claim and none cancels a sibling. Counting those would report a
      cancellation that cannot happen, and send the reader to delete a job that
      was doing no harm.
    """
    owners: dict[tuple[str, str], list[tuple[str, str, bool]]] = defaultdict(list)
    for filename, slots in slots_by_file.items():
        for name, group, job_id, job_level in slots:
            owners[(name, group)].append((filename, job_id, job_level))

    collisions = {}
    for slot, sites in owners.items():
        contending = (
            sites
            if len({filename for filename, _, _ in sites}) > 1
            else [site for site in sites if site[2]]
        )
        if len(contending) > 1:
            collisions[slot] = sorted(f"{f}:{j}" for f, j, _ in contending)
    return collisions


def test_workflow_dir_is_not_empty() -> None:
    """Guard the guard: an empty sweep would pass the collision test vacuously."""
    files = workflow_files()
    assert len(files) > 10, f"only found {len(files)} workflows — bad glob?"
    assert any(job_slots(p) for p in files), "no workflow declared a concurrency group"


def test_no_two_jobs_share_a_job_name_and_concurrency_group() -> None:
    """Same display name + same group == the two jobs cancel each other.

    Both halves must match. Two workflows sharing a group on purpose (to
    serialize against each other) is legitimate and stays passing; so does the
    same job name under different groups. It is the pair that means one job is a
    stale duplicate of the other.

    Not scoped to distinct FILES: two jobs in one workflow that each declare the
    same job-level group collide the same way, and that is why `pr-meta.yaml`'s
    `report_render` and `report_comment` carry distinct groups.
    """
    collisions = find_collisions({p.name: job_slots(p) for p in workflow_files()})
    assert not collisions, "\n".join(
        f"job {name!r} runs at {sites} under the same concurrency group "
        f"{group!r} — the second to start cancels the first; delete the "
        "stale copy"
        for (name, group), sites in sorted(collisions.items())
    )


# One slot as job_slots emits it. `True` marks a group the JOB declared; `False`
# one it inherited from the workflow.
def slot(name: str, group: str, job_id: str, job_level: bool = True):
    return (name, group, job_id, job_level)


@pytest.mark.parametrize(
    "slots_by_file, expected",
    [
        pytest.param(
            {"a.yaml": [slot("dupe", "g", "j1")], "b.yaml": [slot("dupe", "g", "j2")]},
            {("dupe", "g"): ["a.yaml:j1", "b.yaml:j2"]},
            id="cross-file, same name and group",
        ),
        pytest.param(
            {"a.yaml": [slot("dupe", "g", "j1"), slot("dupe", "g", "j2")]},
            {("dupe", "g"): ["a.yaml:j1", "a.yaml:j2"]},
            id="same file, both job-level",
        ),
        pytest.param(
            {
                "a.yaml": [
                    slot("dupe", "g", "j1", False),
                    slot("dupe", "g", "j2", False),
                ]
            },
            {},
            id="same file, both inherit the workflow group — one claim, no race",
        ),
        pytest.param(
            {"a.yaml": [slot("dupe", "g", "j1"), slot("dupe", "g", "j2", False)]},
            {},
            id="same file, only one job-level — nothing to contend with",
        ),
        pytest.param(
            {
                "a.yaml": [slot("dupe", "g", "j1", False)],
                "b.yaml": [slot("dupe", "g", "j2", False)],
            },
            {("dupe", "g"): ["a.yaml:j1", "b.yaml:j2"]},
            id="cross-file inherited groups still contend — two runs, one group",
        ),
        pytest.param(
            {
                "a.yaml": [slot("same", "g1", "j1")],
                "b.yaml": [slot("same", "g2", "j2")],
            },
            {},
            id="same name, different groups",
        ),
        pytest.param(
            {"a.yaml": [slot("one", "g", "j1")], "b.yaml": [slot("two", "g", "j2")]},
            {},
            id="same group, different names — deliberate serialization",
        ),
        pytest.param({}, {}, id="no workflows"),
    ],
)
def test_find_collisions(slots_by_file, expected) -> None:
    assert find_collisions(slots_by_file) == expected


@pytest.mark.parametrize(
    "block, expected",
    [
        ("plain-group", "plain-group"),
        ({"group": "g", "cancel-in-progress": True}, "g"),
        ({"cancel-in-progress": True}, None),
        (None, None),
    ],
)
def test_concurrency_group_shapes(block, expected) -> None:
    assert concurrency_group(block) == expected


@pytest.mark.parametrize(
    "template, name, expected",
    [
        ("${{ github.workflow }}-1", "Lint", "Lint-1"),
        ("${{github.workflow}}-1", "Lint", "Lint-1"),
        (
            "fixed-${{ github.event.number }}",
            "Lint",
            "fixed-${{ github.event.number }}",
        ),
    ],
)
def test_resolve_group(template: str, name: str, expected: str) -> None:
    assert resolve_group(template, name) == expected
