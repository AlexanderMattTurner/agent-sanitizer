"""Behavioral tests for .github/scripts/decide-pr-review-trigger.sh — which
pull_request_target events buy a review, and on which model.

The `synchronize` predicate is the one with teeth: a push runs the FIRST
whole-diff pass when the reviewer has never reviewed this PR, and is never a
re-read otherwise. Keying it on the latest review's STATE instead would fire on
every push forever, because every review now posts as COMMENTED (the merge
consequence lives in the review-findings gate, not the review event).

Drives the real script with a fake `gh` on PATH that serves the reviews list
from a canned array through REAL jq — so the script's own filter (reviewer
login, the empty-body discriminator, the two-level page flatten) is exercised
rather than re-implemented — and reads the run=/model= it writes to
GITHUB_OUTPUT.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT

SCRIPT = REPO_ROOT / ".github" / "scripts" / "decide-pr-review-trigger.sh"

_FAKE_GH = r"""#!/usr/bin/env python3
# gh stub: serves `repos/.../pulls/N/reviews` and `repos/.../commits/SHA` from
# canned files, running the caller's --jq through real jq. REVIEWS_RC forces the
# reviews read to fail so the fail-safe branch can be tested.
import json, os, shutil, subprocess, sys

JQ = shutil.which("jq")
if JQ is None:
    sys.stderr.write("fake gh: jq not found on PATH\n")
    sys.exit(3)

args = sys.argv[1:]
assert args and args[0] == "api", args
args, jq, path = args[1:], None, None
i = 0
while i < len(args):
    a = args[i]
    if a in ("--paginate", "--slurp"):
        i += 1
    elif a == "--jq":
        jq, i = args[i + 1], i + 2
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


if path and path.endswith("/reviews"):
    rc = int(os.environ.get("REVIEWS_RC", "0"))
    if rc:
        sys.stderr.write("fake gh: HTTP 502 on the reviews read\n")
        sys.exit(rc)
    with open(os.environ["GH_REVIEWS"], encoding="utf-8") as f:
        reviews = json.load(f)
    # --slurp over --paginate yields one element PER PAGE; one page here.
    emit([reviews])

if path and "/commits/" in path:
    emit({"commit": {"message": os.environ.get("HEAD_MESSAGE", "chore: push\n")}})

sys.stderr.write("fake gh: unhandled %r\n" % (sys.argv,))
sys.exit(2)
"""

REVIEWER = "github-actions[bot]"


def _review(
    state: str = "COMMENTED", *, login: str = REVIEWER, body: str = "## Review"
) -> dict:
    return {"user": {"login": login}, "state": state, "body": body}


def _decide(
    tmp_path: Path,
    *,
    action: str,
    reviews: list[dict] | None = None,
    head_message: str = "chore: push\n",
    label: str | None = None,
    reviews_rc: int = 0,
) -> dict[str, str]:
    """Run the real script; return the key=value pairs it wrote to GITHUB_OUTPUT."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    gh = bin_dir / "gh"
    gh.write_text(_FAKE_GH)
    gh.chmod(0o755)
    (tmp_path / "reviews.json").write_text(json.dumps(reviews or []))
    out = tmp_path / "gh_output"
    out.write_text("")
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GH_TOKEN": "fake",
        "ACTION": action,
        "REPO": "o/r",
        "HEAD_SHA": "cafe1234",
        "PR": "5",
        "GITHUB_OUTPUT": str(out),
        "GH_REVIEWS": str(tmp_path / "reviews.json"),
        "HEAD_MESSAGE": head_message,
        "REVIEWS_RC": str(reviews_rc),
    }
    if label is not None:
        env["LABEL"] = label
    proc = subprocess.run(
        ["bash", str(SCRIPT)], capture_output=True, text=True, env=env
    )
    assert proc.returncode == 0, proc.stderr
    parsed = {}
    for line in out.read_text().splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            parsed[k] = v
    return parsed


@pytest.mark.parametrize("action", ["opened", "ready_for_review"])
def test_a_first_look_event_always_reviews_on_opus(tmp_path: Path, action: str) -> None:
    got = _decide(tmp_path, action=action)
    assert got["run"] == "true"
    assert "opus" in got["model"]


def test_the_on_demand_label_reviews_on_opus(tmp_path: Path) -> None:
    got = _decide(tmp_path, action="labeled", label="needs-auto-review")
    assert got["run"] == "true"
    assert "opus" in got["model"]


def test_an_unrelated_label_is_a_no_op(tmp_path: Path) -> None:
    got = _decide(tmp_path, action="labeled", label="documentation")
    assert got["run"] == "false"


def test_a_push_runs_the_first_pass_when_nothing_ever_reviewed(
    tmp_path: Path,
) -> None:
    got = _decide(tmp_path, action="synchronize", reviews=[])
    assert got["run"] == "true"
    # The automatic pass never spends Opus; only the [opus-review] opt-in does.
    assert "haiku" in got["model"]


def test_a_push_is_not_a_re_read_once_the_reviewer_has_reviewed(
    tmp_path: Path,
) -> None:
    # The regression this pins: every review now posts as COMMENTED, so a
    # predicate keyed on "latest state is non-approving" would fire here — and on
    # every subsequent push, forever.
    got = _decide(tmp_path, action="synchronize", reviews=[_review("COMMENTED")])
    assert got["run"] == "false"


def test_a_human_review_does_not_count_as_the_reviewer_having_reviewed(
    tmp_path: Path,
) -> None:
    got = _decide(tmp_path, action="synchronize", reviews=[_review(login="somehuman")])
    assert got["run"] == "true"


def test_an_empty_bodied_bot_review_does_not_suppress_the_first_pass(
    tmp_path: Path,
) -> None:
    # GitHub synthesizes a body-less review by this same bot around every
    # standalone review-comment POST the thread resolver makes. Counting one as
    # "already reviewed" would permanently deny the PR its only real read.
    got = _decide(tmp_path, action="synchronize", reviews=[_review(body="")])
    assert got["run"] == "true"


def test_the_opus_opt_in_in_the_head_title_forces_a_full_re_read(
    tmp_path: Path,
) -> None:
    got = _decide(
        tmp_path,
        action="synchronize",
        reviews=[
            _review("COMMENTED")
        ],  # already reviewed: only the opt-in gets through
        head_message="fix: thing [opus-review]\n\nbody\n",
    )
    assert got["run"] == "true"
    assert "opus" in got["model"]


def test_the_opt_in_is_matched_on_the_subject_not_the_body(tmp_path: Path) -> None:
    got = _decide(
        tmp_path,
        action="synchronize",
        reviews=[_review("COMMENTED")],
        head_message="fix: thing\n\nsomeone wrote [opus-review] down here\n",
    )
    assert got["run"] == "false"


def test_a_failed_reviews_read_does_not_review(tmp_path: Path) -> None:
    # A failed query yields the same empty string as "nobody ever reviewed", and
    # the two mean opposite things: folding them together would review on every
    # push whenever the API is flaky. The documented fail-safe is no review.
    got = _decide(tmp_path, action="synchronize", reviews=[], reviews_rc=1)
    assert got["run"] == "false"


def test_an_unhandled_action_does_not_review(tmp_path: Path) -> None:
    got = _decide(tmp_path, action="closed")
    assert got["run"] == "false"
