"""Behavioral tests for .github/scripts/review-findings-gate.sh — the stateless
merge gate: RED until the automated reviewer has posted at least one review AND
no unresolved reviewer-rooted thread still carries a gating finding (🔴
blocking / 🟡 warning — read from the hidden `<!-- severity: … -->` marker on
the thread's ROOT comment, with the leading emoji as a fallback for threads
posted before the marker existed); GREEN otherwise.

Two modes, one predicate:
  * REPORT_SHA set — the verdict is POSTed as a COMMIT STATUS under the context
    "Review findings resolved" on that sha; the run exits 0 whatever the verdict,
    and a failed POST is a hard red (a gate that cannot report leaves the
    required check hanging at "Expected").
  * REPORT_SHA unset — the exit status IS the report (merge_group mode; the
    workflow parses the PR number out of the merge-group ref, tested below).

Drives the REAL script (sourcing the real lib/pr-reviews.bash and
lib/review-threads.bash) with a fake `gh` on PATH that serves the two GraphQL
reads from canned node arrays by running the script's OWN --jq programs through
REAL jq — so the reviewer filter, the severity selection, and the emoji
fallback are exercised, never re-implemented — and records the status POST's
fields for assertion. gh is stubbed because there is no live GitHub to ask; the
node shapes mirror the GraphQL documents in the two lib files (in particular:
GraphQL returns an app bot's login WITHOUT the REST `[bot]` suffix).
"""

import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from tests._helpers import REPO_ROOT
from tests._source_closure import source_closure

GATE_REL = ".github/scripts/review-findings-gate.sh"
SCRIPT = REPO_ROOT / GATE_REL
# The merge-queue leg lives in its own merge_group-only workflow so no PR event
# can ever report the required context as a passing `skipped` instance.
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "review-findings-merge-gate.yaml"

# The status context the gate posts under must be byte-identical to the
# merge_gate job's `name:` (one required-check context, two reporting surfaces),
# so the expected context is READ from the workflow rather than restated here.
GATE_CONTEXT = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"][
    "merge_gate"
]["name"]

# The severity SSOT the gate builds its predicate from at runtime — the tests
# iterate its gating list member-by-member so a severity added to the config
# without gate coverage fails here, not in production.
SEVERITY_CONFIG = json.loads(
    (REPO_ROOT / "config" / "review-severities.json").read_text(encoding="utf-8")
)
GATING = SEVERITY_CONFIG["gating"]
GATING_ICONS = [SEVERITY_CONFIG["icons"][sev] for sev in GATING]


def _marker(severity: str) -> str:
    """The hidden severity marker post-pr-review.mjs stamps on a finding."""
    return f"<!-- severity: {severity} -->"


BLOCKING = _marker("blocking")
WARNING = _marker("warning")

_FAKE_GH = r"""#!/usr/bin/env python3
# gh stub for the gate: serves the two GraphQL reads from canned node files,
# running the CALLER'S --jq through real jq (those filters are the logic under
# test), and records the status POST's fields. Anything else is unhandled
# (exit 2), so a stray API call — a review post, a mutation — reds the run.
import json, os, shutil, subprocess, sys

JQ = shutil.which("jq")
if JQ is None:
    # Loud, never a silent degrade: without real jq this stub would have to
    # fake the filters under test and every assertion would be worthless.
    sys.stderr.write("fake gh: jq not found on PATH\n")
    sys.exit(3)

args = sys.argv[1:]
assert args and args[0] == "api", args
args = args[1:]

method, jq, path, fields = "GET", None, None, {}
i = 0
while i < len(args):
    a = args[i]
    if a == "--paginate":
        i += 1
    elif a in ("-X", "--method"):
        method, i = args[i + 1], i + 2
    elif a == "--jq":
        jq, i = args[i + 1], i + 2
    elif a in ("-F", "-f"):
        k, _, v = args[i + 1].partition("=")
        fields[k] = v
        i += 2
    elif not a.startswith("-"):
        path, i = a, i + 1
    else:
        i += 1


def emit(doc):
    r = subprocess.run(
        [JQ, "-r", jq], input=json.dumps(doc), text=True, capture_output=True
    )
    sys.stderr.write(r.stderr)
    sys.stdout.write(r.stdout)
    sys.exit(r.returncode)


if path == "graphql":
    if os.environ.get("FAIL_READS") == "1":
        sys.stderr.write("fake gh: HTTP 502 on the GraphQL read\n")
        sys.exit(1)
    query = fields.get("query", "")
    if "reviewThreads(" in query:
        with open(os.environ["GH_THREADS"], encoding="utf-8") as f:
            nodes = json.load(f)
        emit(
            {
                "data": {
                    "repository": {
                        "pullRequest": {"reviewThreads": {"nodes": nodes}}
                    }
                }
            }
        )
    if "reviews(" in query:
        with open(os.environ["GH_REVIEWS"], encoding="utf-8") as f:
            nodes = json.load(f)
        emit({"data": {"repository": {"pullRequest": {"reviews": {"nodes": nodes}}}}})

if path and "/statuses/" in path and method == "POST":
    if os.environ.get("FAIL_STATUS_POST") == "1":
        sys.stderr.write("fake gh: HTTP 502 posting the status\n")
        sys.exit(1)
    # The sha rides in the path, so it is recorded beside the fields the caller
    # passed — an assertion on WHICH head got the verdict has nothing else to read.
    fields["sha"] = path.rsplit("/", 1)[-1]
    with open(os.environ["STATUS_LOG"], "a", encoding="utf-8") as f:
        f.write(json.dumps(fields) + "\n")
    sys.exit(0)

sys.stderr.write("fake gh: unhandled %r\n" % (sys.argv,))
sys.exit(2)
"""


def _review(login: str = "github-actions") -> dict:
    """A completed review node, shaped per REVIEWS_QUERY in lib/pr-reviews.bash."""
    return {
        "author": {"login": login},
        "state": "COMMENTED",
        "body": "## Review\n\nfindings…",
        "submittedAt": "2026-07-01T00:00:00Z",
    }


def _thread(
    body: str,
    *,
    resolved: bool = False,
    login: str = "github-actions",
    path: str = "src/a.mjs",
    line: int = 3,
) -> dict:
    """A review-thread node, shaped per REVIEW_THREADS_QUERY in
    lib/review-threads.bash; `body`/`login` are the ROOT comment's."""
    return {
        "id": "PRRT_x",
        "isResolved": resolved,
        "path": path,
        "line": line,
        "comments": {"nodes": [{"author": {"login": login}, "body": body}]},
    }


def _run(
    tmp_path: Path,
    *,
    reviews: list[dict],
    threads: list[dict],
    report_sha: str | None = None,
    fail_post: bool = False,
    fail_reads: bool = False,
    gate_unreported: bool = False,
) -> tuple[subprocess.CompletedProcess, list[dict]]:
    """Run the real gate script against canned review/thread nodes; return the
    process and the statuses the fake gh recorded."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    gh = bin_dir / "gh"
    gh.write_text(_FAKE_GH)
    gh.chmod(0o755)
    (tmp_path / "reviews.json").write_text(json.dumps(reviews))
    (tmp_path / "threads.json").write_text(json.dumps(threads))
    log = tmp_path / "statuses"
    log.write_text("")
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GH_TOKEN": "fake",
        "GH_REPO": "o/r",
        "PR": "5",
        "RETRY_BASE_DELAY": "0",  # a failing API call must not sleep out the backoff
        "GH_REVIEWS": str(tmp_path / "reviews.json"),
        "GH_THREADS": str(tmp_path / "threads.json"),
        "STATUS_LOG": str(log),
    }
    if report_sha is not None:
        env["REPORT_SHA"] = report_sha
    if fail_post:
        env["FAIL_STATUS_POST"] = "1"
    if fail_reads:
        env["FAIL_READS"] = "1"
    if gate_unreported:
        env["GATE_UNREPORTED"] = "1"
    proc = subprocess.run(
        ["bash", str(SCRIPT)], capture_output=True, text=True, env=env
    )
    posted = [json.loads(ln) for ln in log.read_text().splitlines() if ln.strip()]
    return proc, posted


def test_red_when_the_reviewer_never_reviewed(tmp_path: Path) -> None:
    # Zero findings from zero reviews is vacuous — and a HUMAN review alone
    # must not satisfy (a): the reviewer filter is under test, not emptiness.
    proc, posted = _run(tmp_path, reviews=[_review(login="somehuman")], threads=[])
    assert proc.returncode == 1
    assert "not reviewed" in proc.stderr
    assert posted == []


@pytest.mark.parametrize("severity", GATING)
def test_red_on_an_unresolved_gating_severity_marker(
    tmp_path: Path, severity: str
) -> None:
    # No leading emoji: the hidden marker alone must gate, so this case cannot
    # pass through the emoji fallback. Parametrized over the config's gating
    # list so every gating severity is proven to gate, not just today's two.
    body = f"Consider restoring the guard.\n\n{_marker(severity)}\n"
    proc, _ = _run(tmp_path, reviews=[_review()], threads=[_thread(body)])
    assert proc.returncode == 1
    assert "src/a.mjs:3" in proc.stderr  # the reason names where the finding sits


@pytest.mark.parametrize("emoji", GATING_ICONS)
def test_red_via_the_emoji_fallback_for_pre_marker_threads(
    tmp_path: Path, emoji: str
) -> None:
    proc, _ = _run(
        tmp_path,
        reviews=[_review()],
        threads=[_thread(f"{emoji} legacy finding with no severity marker")],
    )
    assert proc.returncode == 1


def test_a_quoted_marker_in_prose_does_not_gate(tmp_path: Path) -> None:
    # The predicate matches a WHOLE line, so a nit that merely mentions the
    # marker (documenting it, quoting a diff) must not gate — otherwise writing
    # about the mechanism would block merges.
    body = f"🔵 nit: the writer stamps `{BLOCKING}` inline.\n\n{_marker('nit')}\n"
    proc, _ = _run(tmp_path, reviews=[_review()], threads=[_thread(body)])
    assert proc.returncode == 0, proc.stderr


def test_green_when_only_nits_or_non_reviewer_threads_are_unresolved(
    tmp_path: Path,
) -> None:
    threads = [
        # 🔵 nits are advisory — never gate.
        _thread("🔵 nit: rename this helper"),
        # A gating-severity thread ROOTED by a human is not the reviewer's.
        _thread(f"🔴 human concern\n\n{BLOCKING}\n", login="somehuman"),
    ]
    proc, _ = _run(tmp_path, reviews=[_review()], threads=threads)
    assert proc.returncode == 0, proc.stderr


def test_the_bot_suffixed_login_spelling_also_matches(tmp_path: Path) -> None:
    # Both lib queries strip a REST `[bot]` suffix before comparing, so a thread
    # whose root author arrives as `github-actions[bot]` is still the reviewer's.
    # Getting this wrong once made has_threads always false and the resolver
    # never ran, so it is pinned on the gate's side too.
    proc, _ = _run(
        tmp_path,
        reviews=[_review(login="github-actions[bot]")],
        threads=[_thread(f"🔴 open\n\n{BLOCKING}\n", login="github-actions[bot]")],
    )
    assert proc.returncode == 1


def test_red_on_a_file_level_finding_names_the_path_without_a_line(
    tmp_path: Path,
) -> None:
    # A file-level comment has line: null; it must still gate, and the reason
    # must render the bare path, never a "path:None"/"path:null" suffix jq's
    # tostring could have produced.
    thread = _thread(
        f"🔴 needs a human read\n\n{BLOCKING}\n", path="docs/notes.md", line=None
    )
    proc, _ = _run(tmp_path, reviews=[_review()], threads=[thread])
    assert proc.returncode == 1
    assert "the merge: docs/notes.md — resolve" in proc.stderr
    assert ":None" not in proc.stderr and ":null" not in proc.stderr


def test_an_empty_body_review_does_not_count_as_reviewed(tmp_path: Path) -> None:
    # GitHub synthesizes a body-less COMMENTED review by the bot around every
    # standalone review-comment POST; the shared read filters those out, so a PR
    # whose ONLY bot review is empty-bodied has never actually been reviewed and
    # the gate stays red on the not-reviewed leg — never green vacuously.
    proc, posted = _run(tmp_path, reviews=[_review() | {"body": ""}], threads=[])
    assert proc.returncode == 1
    assert "not reviewed" in proc.stderr
    assert posted == []


def test_a_failed_api_read_fails_closed_with_no_status(tmp_path: Path) -> None:
    # Can't-verify is RED, never green: a read that exhausts the retry ladder
    # must exit non-zero WITHOUT posting any status — a gate that reported a
    # verdict it could not compute would let a PR merge past findings nobody
    # read (success), or hide the outage behind a plausible red (failure).
    proc, posted = _run(
        tmp_path,
        reviews=[_review()],
        threads=[],
        report_sha="cafe1234",
        fail_reads=True,
    )
    assert proc.returncode != 0
    assert posted == []


def _copy_gate_tree(
    dest: Path, *, with_config: bool, gating: list | None = None
) -> Path:
    """Lay the gate script + its libs out under `dest` the way the repo does
    (scripts at .github/scripts, config at ../../config), optionally omitting or
    rewriting the severity config. Returns the copied script's path."""
    # The file set is DERIVED from what the gate script sources, not listed here:
    # a hand-written list is a second spelling of the script's own `source` lines,
    # and the copy that goes stale produces a "No such file" the assertions below
    # read as the failure they were checking for. The closure also names
    # config/review-severities.json (an assignment, not a `source`), but this
    # fixture is the thing that varies that exact file via `with_config`, so the
    # script closure here is scripts only.
    for rel in source_closure({GATE_REL}):
        if not rel.endswith((".sh", ".bash")):
            continue
        copied = dest / rel
        copied.parent.mkdir(parents=True, exist_ok=True)
        copied.write_bytes((REPO_ROOT / rel).read_bytes())
    if with_config:
        cfg = dest / "config"
        cfg.mkdir()
        spec = dict(SEVERITY_CONFIG)
        if gating is not None:
            spec["gating"] = gating
        (cfg / "review-severities.json").write_text(json.dumps(spec))
    return dest / GATE_REL


def _run_copied(script: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        env={
            "PATH": os.environ["PATH"],
            "GH_TOKEN": "fake",
            "GH_REPO": "o/r",
            "PR": "5",
            # These runs must refuse BEFORE any API read. If one ever reaches the
            # network the retry ladder would sleep out ~30s and the failure would
            # read as a config bug, so cap it to one immediate attempt.
            "RETRY_MAX": "1",
            "RETRY_BASE_DELAY": "0",
        },
    )


def test_a_missing_severity_config_fails_closed(tmp_path: Path) -> None:
    # The gate cannot know which severities gate without the SSOT, so it must
    # refuse BEFORE any API read rather than run a predicate that gates on
    # nothing. The message names the missing file, so a green-looking gate can
    # never be the silent result of a lost config.
    proc = _run_copied(_copy_gate_tree(tmp_path, with_config=False))
    assert proc.returncode == 1
    assert "review-severities.json" in proc.stderr
    assert "failing closed" in proc.stderr


def test_an_empty_gating_list_refuses_to_run(tmp_path: Path) -> None:
    # A config whose `gating` is empty would build an empty predicate and call
    # every PR green — a gate that can never gate. It must refuse instead.
    proc = _run_copied(_copy_gate_tree(tmp_path, with_config=True, gating=[]))
    assert proc.returncode == 1
    assert "can never gate" in proc.stderr


def test_a_gating_severity_with_no_icon_fails_loud(tmp_path: Path) -> None:
    # The predicate needs both the marker and the emoji fallback for each gating
    # severity, so a config naming one with no icon is malformed — jq must error
    # out rather than the loop silently dropping that severity from the gate.
    proc = _run_copied(
        _copy_gate_tree(tmp_path, with_config=True, gating=[*GATING, "apocalyptic"])
    )
    assert proc.returncode != 0
    assert "apocalyptic" in proc.stderr


def test_green_once_every_gating_thread_is_resolved(tmp_path: Path) -> None:
    threads = [
        _thread(f"🔴 fixed now\n\n{BLOCKING}\n", resolved=True),
        _thread(f"🟡 also fixed\n\n{WARNING}\n", resolved=True),
    ]
    proc, _ = _run(tmp_path, reviews=[_review()], threads=threads)
    assert proc.returncode == 0, proc.stderr


# ── REPORT_SHA mode: the verdict is a commit status ─────────────────────────


def test_report_mode_posts_a_success_status(tmp_path: Path) -> None:
    proc, posted = _run(
        tmp_path, reviews=[_review()], threads=[], report_sha="cafe1234"
    )
    assert proc.returncode == 0, proc.stderr
    assert len(posted) == 1
    status = posted[0]
    # The context must match the merge_gate job's `name:` — one required-check
    # context, two reporting surfaces — so it is read from the workflow, and a
    # rename that desyncs the two surfaces reds here.
    assert status["context"] == GATE_CONTEXT
    assert status["sha"] == "cafe1234"
    assert status["state"] == "success"


def test_report_mode_posts_a_failure_status_and_still_exits_zero(
    tmp_path: Path,
) -> None:
    # The status IS the report: a red verdict lands as state=failure on the sha
    # while the posting run itself stays green.
    proc, posted = _run(
        tmp_path,
        reviews=[_review()],
        threads=[_thread(f"🔴 open finding\n\n{BLOCKING}\n")],
        report_sha="cafe1234",
    )
    assert proc.returncode == 0, proc.stderr
    assert [(r["context"], r["sha"], r["state"]) for r in posted] == [
        (GATE_CONTEXT, "cafe1234", "failure")
    ]


def test_a_red_description_is_truncated_to_the_status_cap(tmp_path: Path) -> None:
    # GitHub caps a status description at 140 characters, and EVERY red reason
    # exceeds it (the count, the path list, and the how-to-clear tail), so
    # post_verdict's truncation is on the common path, not an edge case. `<=`
    # rather than `==` because bash cuts by bytes and the reason carries an em
    # dash, so the character count lands under the byte budget.
    proc, posted = _run(
        tmp_path,
        reviews=[_review()],
        threads=[_thread(f"🔴 open finding\n\n{BLOCKING}\n")],
        report_sha="cafe1234",
    )
    assert proc.returncode == 0, proc.stderr
    description = posted[0]["description"]
    assert len(description) <= 140
    assert description.endswith("...")
    # The head survives the cut: a truncation that kept the tail, or dropped the
    # ellipsis, would leave the merge box saying nothing about what is wrong.
    assert description.startswith("1 unresolved reviewer finding(s)")


def test_an_unevaluated_gate_reports_red_rather_than_going_unreported(
    tmp_path: Path,
) -> None:
    # The caller's always() arm. An evaluation that dies before its POST leaves
    # the head with NO status under a REQUIRED context, which renders as
    # "Expected — Waiting for status to be reported" and blocks the merge on a
    # check nothing will ever send: resolving a thread fires no workflow event,
    # so nothing re-derives the gate until the next push or a recheck label.
    # Reported red, that same state is one the merge box can act on.
    #
    # Driven with reviews/threads that would evaluate GREEN, so a run that fell
    # through to the predicate instead of taking this mode would post success —
    # this asserts the mode is what answered, not merely that something did.
    proc, posted = _run(
        tmp_path,
        reviews=[_review()],
        threads=[],
        report_sha="cafe1234",
        gate_unreported=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert [(r["context"], r["sha"], r["state"]) for r in posted] == [
        (GATE_CONTEXT, "cafe1234", "failure")
    ]


def test_an_unevaluated_gate_refuses_to_report_against_no_sha(tmp_path: Path) -> None:
    # Fail loud rather than POST against an empty sha: a status on "" satisfies
    # nothing and would strand the head exactly as the silence it replaced does.
    proc, posted = _run(tmp_path, reviews=[_review()], threads=[], gate_unreported=True)
    assert proc.returncode != 0
    assert "REPORT_SHA" in proc.stderr
    assert posted == []


def test_a_failed_status_post_fails_the_run_loudly(tmp_path: Path) -> None:
    # A verdict that cannot be reported leaves the required check hanging at
    # "Expected" — the POST failure must red this run, never be swallowed.
    proc, posted = _run(
        tmp_path, reviews=[_review()], threads=[], report_sha="cafe1234", fail_post=True
    )
    assert proc.returncode != 0
    assert posted == []


# ── merge_group mode: the workflow parses the PR out of the queue ───────


def test_merge_gate_workflow_triggers_only_on_merge_group() -> None:
    # The workflow must NEVER gain a PR-event trigger: GitHub counts a `skipped`
    # check run as satisfying a required check, so any PR event reaching this
    # workflow would overwrite a red gate on the head with a passing skipped
    # instance. merge_group-only is what makes that impossible.
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    on = workflow.get("on", workflow.get(True))  # PyYAML reads bare `on:` as True
    assert set(on) == {"merge_group"}


def _merge_gate_run_block() -> str:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    step = next(
        s
        for s in workflow["jobs"]["merge_gate"]["steps"]
        if s.get("name") == "Evaluate the gate for the queued PR"
    )
    return step["run"]


def _run_merge_gate_block(
    tmp_path: Path, mg_ref: str
) -> tuple[subprocess.CompletedProcess, Path]:
    """Run the workflow's REAL ref-parsing block with a stub gate script that
    records the PR env it received."""
    scripts = tmp_path / ".github" / "scripts"
    scripts.mkdir(parents=True)
    stub = scripts / "review-findings-gate.sh"
    stub.write_text('printf \'%s\\n\' "${PR:-unset}" >"$GATE_RECORD"\n')
    record = tmp_path / "gate_pr"
    proc = subprocess.run(
        ["bash", "-c", _merge_gate_run_block()],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={
            "PATH": os.environ["PATH"],
            "MG_REF": mg_ref,
            "GATE_RECORD": str(record),
        },
    )
    return proc, record


def test_merge_group_ref_parsing_extracts_the_pr_number(tmp_path: Path) -> None:
    proc, record = _run_merge_gate_block(
        tmp_path, "refs/heads/gh-readonly-queue/main/pr-190-0123abcd456789ef"
    )
    assert proc.returncode == 0, proc.stderr
    assert record.read_text() == "190\n"


def test_an_unparseable_merge_group_ref_fails_loud(tmp_path: Path) -> None:
    # A ref the regex cannot name a PR from must red the job, never evaluate
    # some other PR's gate (or none) silently.
    proc, record = _run_merge_gate_block(tmp_path, "refs/heads/main")
    assert proc.returncode != 0
    assert "cannot parse" in proc.stderr
    assert not record.exists()


# ── PR-head leg: cancellation must never strand the required check ──────────
# The evaluate job in review-findings-gate.yaml posts the required check on the
# PR head. A cancelled evaluation posts nothing, so the only safe cancellation
# is a strict supersession: a queued run displaced by a newer run that itself
# executes and posts. Two properties make that structural, pinned here.

PR_GATE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "review-findings-gate.yaml"


def _evaluate_job() -> dict:
    return yaml.safe_load(PR_GATE_WORKFLOW.read_text(encoding="utf-8"))["jobs"][
        "evaluate"
    ]


def test_the_evaluate_job_never_cancels_a_running_verdict_post() -> None:
    # GitHub cancels mid-step, so cancel-in-progress: true can kill the run
    # between reading the PR state and POSTing the verdict — that verdict is
    # lost and the head keeps a stale one. With false, a running evaluation
    # always finishes its POST; only the queued run is ever displaced.
    concurrency = _evaluate_job()["concurrency"]
    assert concurrency["cancel-in-progress"] is False


def test_the_concurrency_group_is_keyed_per_head_not_per_pr() -> None:
    # Webhook delivery is unordered: with a PR-only group key, a
    # late-delivered event for a STALE head can displace the queued
    # evaluation for the current head and post its verdict on the stale sha,
    # leaving the live head with no check. The head sha in the key confines
    # displacement to runs that would post to the same sha, so every head
    # always gets its own verdict.
    group = _evaluate_job()["concurrency"]["group"]
    assert "${{ github.event.pull_request.number }}" in group
    assert "${{ github.event.pull_request.head.sha }}" in group


def test_the_evaluate_job_runs_unconditionally_so_every_entrant_posts() -> None:
    # A job-level `if:` would create runs that can displace a queued
    # evaluation from the concurrency group and then skip without posting —
    # cancel-without-replacement, stranding the check at its stale value.
    assert "if" not in _evaluate_job()


def test_the_label_removal_step_is_first_and_unconditional() -> None:
    # A `labeled` run displaced while queued executes zero steps, so the
    # displaced run can never free its own recheck-review-gate label — and a
    # label left sitting makes every future re-add a no-op that fires no
    # `labeled` event (a dead recheck hatch). The run that displaced it must
    # consume the label instead: per-head grouping means any survivor
    # evaluates the head the label asked about, so removal is unconditional.
    # First position frees the label even when the evaluation itself fails.
    steps = _evaluate_job()["steps"]
    removal = steps[0]
    assert removal["name"] == "Remove the recheck-review-gate command label"
    assert "if" not in removal
    # A label on a PR is checked against pull-requests, not issues: under
    # `issues: write` alone the DELETE 403s and the label stays stuck, which is
    # the dead hatch above, reached at runtime instead of by displacement. Only
    # a static assertion catches a narrowing back — the 403 is invisible until
    # someone uses the hatch on a live PR and reads the warning annotation.
    assert _evaluate_job()["permissions"].get("pull-requests") == "write"


def test_the_evaluate_job_actually_posts_a_verdict_on_the_head() -> None:
    # The job's reason to exist, and the one property none of the concurrency
    # and label assertions above imply: a job that removes the label and posts
    # nothing leaves the required context unreported on every new head, so the
    # PR blocks forever on a check that never arrives. REPORT_SHA is what routes
    # the verdict to the head's status context.
    steps = _evaluate_job()["steps"]
    gate_steps = [s for s in steps if "review-findings-gate.sh" in (s.get("run") or "")]
    # Two arms, and both must route to the HEAD's status context: the evaluation
    # itself, and the always() arm that reports red when the evaluation posted
    # nothing. Without the second, a run that dies before its POST strands the
    # required context at "Expected — Waiting for status to be reported", which
    # is the same forever-block this test exists for, reached by a crash rather
    # than by a missing step.
    assert len(gate_steps) == 2
    for step in gate_steps:
        assert (step.get("env") or {}).get("REPORT_SHA") == (
            "${{ github.event.pull_request.head.sha }}"
        )
    evaluate, unreported = gate_steps
    assert evaluate.get("id") == "evaluate"
    assert (unreported.get("env") or {}).get("GATE_UNREPORTED")
    # And the evaluation arm must NOT carry it: GATE_UNREPORTED there skips the
    # predicate, so every run would POST a red verdict on the required context.
    assert "GATE_UNREPORTED" not in (evaluate.get("env") or {})
    # `always()` is the whole point — a plain `if:` would skip exactly when the
    # evaluation failed, which is the case that leaves the check unreported.
    assert "always()" in unreported.get("if", "")
    assert "steps.evaluate.outcome" in unreported.get("if", "")
    # The script is read from the DEFAULT branch, never the event's sha: this
    # job runs in the base repo's context under pull_request_target, so a
    # head-ref checkout would execute PR-authored code with statuses:write.
    checkouts = [s for s in steps if "actions/checkout" in (s.get("uses") or "")]
    assert len(checkouts) == 1
    assert (
        checkouts[0]["with"]["ref"] == "${{ github.event.repository.default_branch }}"
    )
    assert steps.index(checkouts[0]) < steps.index(gate_steps[0])


# ── Re-post wiring ───────────────────────────────────────────────────────────
# A review posted with GITHUB_TOKEN fires no pull_request_review webhook, so the
# gate verdict only ever flips because the job that changed the predicate re-posts
# it. Every such job must carry a re-post step, or the required check silently
# never reds after a review. Thread RESOLUTION fires no event either, and nothing
# re-posts on it: the `recheck-review-gate` label and the hold-clear cron cover
# that side.

REPOST_JOBS = [
    (".github/workflows/claude-pr-review.yaml", "review"),
]


@pytest.mark.parametrize(("workflow", "job"), REPOST_JOBS)
def test_every_predicate_changing_job_reposts_the_gate_on_the_head(
    workflow: str, job: str
) -> None:
    jobs = yaml.safe_load((REPO_ROOT / workflow).read_text(encoding="utf-8"))["jobs"]
    steps = jobs[job]["steps"]
    gate_steps = [s for s in steps if "review-findings-gate.sh" in (s.get("run") or "")]
    assert len(gate_steps) == 1, (
        f"job '{job}' in {workflow} must re-post the gate verdict exactly once "
        f"after its review/thread write; found {len(gate_steps)} gate step(s)"
    )
    env = gate_steps[0].get("env") or {}
    # REPORT_SHA on the PR head is what routes the verdict to the required
    # check's context — without it the script runs in exit-status mode and posts
    # nothing.
    assert env.get("REPORT_SHA") == "${{ github.event.pull_request.head.sha }}"
    # A red description is cut at the 140-char status cap, so target_url is the
    # only place the rest of the finding list survives — a site that posts the
    # verdict without RUN_URL truncates with nothing to link to.
    assert env.get("RUN_URL") == (
        "${{ github.server_url }}/${{ github.repository }}/actions/runs/"
        "${{ github.run_id }}"
    )
    # The re-post must come AFTER the write it reports on, or it reads the
    # pre-write state and posts a stale verdict.
    assert gate_steps[0] is not steps[0]
    # Posting the verdict needs statuses:write, or the re-post 403s at runtime.
    assert jobs[job]["permissions"].get("statuses") == "write"


def test_the_skipped_class_is_cleared_under_the_same_context() -> None:
    # A PR the reviewer deliberately skips gets no review, so the gate's
    # reviewed-at-all leg is red on it and the class would be blocked forever.
    # The auto-approve job clears it by posting the SAME required context — a
    # rename here (or in the gate script) would silently re-block the class.
    jobs = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/claude-pr-review.yaml").read_text(
            encoding="utf-8"
        )
    )["jobs"]
    job = jobs["auto-approve-skipped"]
    clearing = [s for s in job["steps"] if "/statuses/" in (s.get("run") or "")]
    assert len(clearing) == 1
    assert f"context={GATE_CONTEXT}" in clearing[0]["run"]
    assert "state=success" in clearing[0]["run"]
    assert job["permissions"].get("statuses") == "write"

    # GitHub truncates a status description past 140 characters, and this one is
    # the whole explanation the class gets — the gate script's own descriptions
    # are truncated deliberately (post_verdict), but this literal has no such
    # guard, so the cap is asserted where it can actually be exceeded.
    described = re.search(r'description=(?P<text>.*?)"', clearing[0]["run"], re.S)
    assert described is not None
    assert len(described["text"]) <= 140

    # A status is per-SHA and does not carry over to a new head, while the
    # gate posts RED on every head of a skipped PR (nothing reviewed it). So the
    # clearing step must fire on EVERY event the job sees, including
    # `synchronize` — gate it to the first-look events and a skipped PR merges on
    # its first head and is blocked forever after its second.
    #
    # `always()` is REQUIRED, not merely permitted. A bare step reads as
    # unconditional but is not: a failed predecessor skips it. The approval step
    # above fails outright wherever "Allow GitHub Actions to create and approve
    # pull requests" is disabled for the repo, and with no condition here that
    # failure took the gate down with it — leaving every chore/style/release and
    # bot PR stranded on a permanently red required check.
    assert clearing[0].get("if") == "always()", (
        "the clearing step must be `if: always()` so neither an event filter nor "
        "a failed approval step can skip it"
    )
    approval = [
        s for s in job["steps"] if "auto-approve-skipped-pr.sh" in (s.get("run") or "")
    ]
    assert len(approval) == 1
    # The approval itself stays a first-look act (it persists across pushes), so
    # the two steps must NOT share one condition — that is why the job-level `if:`
    # carries no event filter.
    assert "opened" in approval[0]["if"]
    assert "opened" not in (job["if"] or "")


def test_drift_guard_the_gate_context_is_duplicated_in_the_gate_script() -> None:
    """DRIFT GUARD — this asserts two copies of one string agree, which means the
    context is duplicated rather than sourced once. Naming it honestly instead
    of "…agree on the context", which launders exactly the smell a drift guard
    should expose.

    Why a true SSOT is infeasible here: the required-check context is a GitHub job
    `name:`, and a job name cannot be computed — it must be a static literal in the
    workflow YAML. The gate script needs the same string at runtime to POST its
    statuses under that context. Nothing can generate both, and having the script
    grep the name out of the workflow at runtime trades this guard for hand-rolled
    YAML parsing in bash, which is worse.

    What the drift costs if it happens: every PR head reports a context nothing
    requires, and the required context is never reported at all — so PRs hang at
    "Expected" forever. That is why the duplication is guarded rather than left bare.
    """
    assert f'GATE_CONTEXT="{GATE_CONTEXT}"' in SCRIPT.read_text(encoding="utf-8")
