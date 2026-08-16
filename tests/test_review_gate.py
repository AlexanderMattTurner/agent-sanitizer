"""Behavioral tests for .github/scripts/review-gate.sh — the "Automated review
posted" commit status.

The predicate is stateless and PR-scoped: the status is `success` when a review
BY THE AUTOMATED REVIEWER stands undismissed on the pull request, `pending`
otherwise. Whose review counts is the whole gate — a gate that accepts any
actor's review is cleared by the PR author submitting a COMMENT review on their
own PR, and the required context then asserts an automated review that never
ran.

Drives the REAL script with a fake `gh` on PATH that serves the reviews list
from a canned array through REAL jq — so the script's own reviewer filter is
exercised rather than re-implemented — and records the status POST's fields.
The REST endpoint spells an app bot's login WITH the `[bot]` suffix, which is
why both spellings are tested.
"""

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT

SCRIPT = REPO_ROOT / ".github" / "scripts" / "review-gate.sh"
FINDINGS_GATE = REPO_ROOT / ".github" / "scripts" / "review-findings-gate.sh"

_FAKE_GH = r"""#!/usr/bin/env python3
# gh stub: serves the PR reviews list from a canned file, running the CALLER'S
# --jq through real jq (that filter is the logic under test), and records the
# status POST's fields. Anything else is unhandled (exit 2), so a stray API
# call reds the run.
import json, os, shutil, subprocess, sys

JQ = shutil.which("jq")
if JQ is None:
    # Loud, never a silent degrade: without real jq the stub would have to fake
    # the filter under test and every assertion would be worthless.
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

if path and path.endswith("/reviews") and method == "GET":
    if os.environ.get("FAIL_READS") == "1":
        sys.stderr.write("fake gh: HTTP 502 on the reviews read\n")
        sys.exit(1)
    with open(os.environ["GH_REVIEWS"], encoding="utf-8") as f:
        doc = json.load(f)
    r = subprocess.run(
        [JQ, "-r", jq], input=json.dumps(doc), text=True, capture_output=True
    )
    sys.stderr.write(r.stderr)
    sys.stdout.write(r.stdout)
    sys.exit(r.returncode)

if path and "/statuses/" in path and method == "POST":
    with open(os.environ["STATUS_LOG"], "a", encoding="utf-8") as f:
        f.write(json.dumps({"path": path, **fields}) + "\n")
    sys.exit(0)

sys.stderr.write("fake gh: unhandled %r\n" % (sys.argv,))
sys.exit(2)
"""

HEAD_SHA = "deadbeef"


def _review(login: str, *, state: str = "COMMENTED") -> dict:
    """A review as the REST pulls/{n}/reviews endpoint returns it."""
    return {"user": {"login": login}, "state": state}


def _run(
    tmp_path: Path, reviews: list[dict], *, fail_reads: bool = False
) -> tuple[subprocess.CompletedProcess, list[dict]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    gh = bin_dir / "gh"
    gh.write_text(_FAKE_GH)
    gh.chmod(0o755)
    (tmp_path / "reviews.json").write_text(json.dumps(reviews))
    log = tmp_path / "statuses"
    log.write_text("")
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GH_TOKEN": "fake",
        "GH_REPO": "o/r",
        "PR": "5",
        "HEAD_SHA": HEAD_SHA,
        "GH_REVIEWS": str(tmp_path / "reviews.json"),
        "STATUS_LOG": str(log),
    }
    if fail_reads:
        env["FAIL_READS"] = "1"
    proc = subprocess.run(
        ["bash", str(SCRIPT)], capture_output=True, text=True, env=env
    )
    posted = [json.loads(ln) for ln in log.read_text().splitlines() if ln.strip()]
    return proc, posted


def _only(posted: list[dict]) -> dict:
    assert len(posted) == 1, posted
    assert posted[0]["path"].endswith(f"/statuses/{HEAD_SHA}")
    return posted[0]


def test_a_non_reviewer_comment_review_leaves_the_gate_pending(tmp_path: Path) -> None:
    # The finding: a PR author can submit a COMMENT review on their own PR, so
    # accepting any actor's review lets the author clear the gate themselves.
    proc, posted = _run(tmp_path, [_review("pr-author", state="COMMENTED")])
    assert proc.returncode == 0, proc.stderr
    assert _only(posted)["state"] == "pending"


@pytest.mark.parametrize("state", ["COMMENTED", "APPROVED", "CHANGES_REQUESTED"])
def test_no_state_of_a_human_review_clears_the_gate(tmp_path: Path, state: str) -> None:
    proc, posted = _run(tmp_path, [_review("somehuman", state=state)])
    assert proc.returncode == 0, proc.stderr
    assert _only(posted)["state"] == "pending"


@pytest.mark.parametrize("login", ["github-actions[bot]", "github-actions"])
def test_the_reviewer_clears_the_gate_under_either_login_spelling(
    tmp_path: Path, login: str
) -> None:
    # REST returns the `[bot]` suffix, GraphQL does not; the gate must accept both.
    proc, posted = _run(tmp_path, [_review(login)])
    assert proc.returncode == 0, proc.stderr
    status = _only(posted)
    assert status["state"] == "success"
    assert status["description"] == f"Reviewed by {login}"


def test_a_dismissed_reviewer_review_returns_the_gate_to_pending(
    tmp_path: Path,
) -> None:
    proc, posted = _run(
        tmp_path,
        [
            _review("github-actions[bot]", state="DISMISSED"),
            _review("somehuman", state="APPROVED"),
        ],
    )
    assert proc.returncode == 0, proc.stderr
    assert _only(posted)["state"] == "pending"


def test_the_reviewer_is_found_behind_earlier_human_reviews(tmp_path: Path) -> None:
    # The filter must scan every review, not just the first one.
    proc, posted = _run(
        tmp_path,
        [
            _review("somehuman", state="APPROVED"),
            _review("another-human"),
            _review("github-actions[bot]"),
        ],
    )
    assert proc.returncode == 0, proc.stderr
    assert _only(posted)["state"] == "success"


def test_a_pr_with_no_reviews_is_pending(tmp_path: Path) -> None:
    proc, posted = _run(tmp_path, [])
    assert proc.returncode == 0, proc.stderr
    assert _only(posted)["state"] == "pending"


def test_a_failed_reviews_read_fails_closed_with_no_status(tmp_path: Path) -> None:
    # Can't-verify is never green: a gate that fails open lets a PR merge past a
    # review nobody read.
    proc, posted = _run(tmp_path, [], fail_reads=True)
    assert proc.returncode != 0
    assert posted == []


@pytest.mark.drift_guard
def test_drift_guard_both_gates_name_the_same_reviewer_login() -> None:
    """DRIFT GUARD — two copies of one login, asserted equal. Named honestly
    rather than as "the gates agree", which would launder the duplication.

    Why a true SSOT is infeasible here: five workflows fetch review-gate.sh
    ALONE via `sparse-checkout: .github/scripts/review-gate.sh`, so a lib it
    sourced would be missing from those checkouts and kill the gate at runtime
    under `set -e`. Moving the login into a lib means adding it to every one of
    those checkout lists first.

    What the drift costs: the two required contexts would answer to different
    reviewers, so one of them could never be cleared by the reviewer that runs.
    """
    pattern = re.compile(r'REVIEWER_LOGIN_BARE="(?P<login>[^"]+)"')
    logins = {
        path.name: pattern.findall(path.read_text(encoding="utf-8"))
        for path in (SCRIPT, FINDINGS_GATE)
    }
    # Positive marker: each assignment must actually exist, or the equality
    # below passes on two empty lists.
    for name, found in logins.items():
        assert found, f"{name} no longer assigns REVIEWER_LOGIN_BARE"
    assert set(logins[SCRIPT.name]) == set(logins[FINDINGS_GATE.name])
