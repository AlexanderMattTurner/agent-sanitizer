"""Behavioral tests for .github/scripts/decide-pr-review-trigger.sh — which
pull_request_target events buy a review, and on which model.

The `synchronize` predicate is the one with teeth: a push reviews ONLY on the
`[opus-review]` opt-in in the head commit title, and is never a read otherwise.
A push-time catch-up trigger ("nobody has reviewed this PR yet, so review now")
used to live here and is deliberately gone: the first pass posts its review in
its LAST step, so the reviews list reads empty for that whole run and a push
landing during it bought a second whole-diff pass whose concurrency group then
cancelled the first (#340). The `needs-auto-review` label serves the same PRs
without the race, so the script asks nothing about review state at all — which
the read-surface case below pins.

Drives the real script with a fake `gh` on PATH that serves the head commit from
the environment and logs every path it is asked for, so a case can assert both
the verdict and that the script asked for nothing else.
"""

import os
import subprocess
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT

SCRIPT = REPO_ROOT / ".github" / "scripts" / "decide-pr-review-trigger.sh"

_FAKE_GH = r"""#!/usr/bin/env python3
# gh stub: serves `repos/.../commits/SHA` from HEAD_MESSAGE through real jq, and
# fails loudly on any other path — the script must not read review state, run
# state, or anything else. Every requested path is appended to GH_LOG.
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
    if a == "--jq":
        jq, i = args[i + 1], i + 2
    elif not a.startswith("-"):
        path, i = a, i + 1
    else:
        i += 1

with open(os.environ["GH_LOG"], "a", encoding="utf-8") as log:
    log.write("%s\n" % (path,))

if path and "/commits/" in path:
    doc = {"commit": {"message": os.environ.get("HEAD_MESSAGE", "chore: push\n")}}
    if jq is None:
        sys.stdout.write(json.dumps(doc))
        sys.exit(0)
    r = subprocess.run(
        [JQ, "-r", jq], input=json.dumps(doc), text=True, capture_output=True
    )
    sys.stderr.write(r.stderr)
    sys.stdout.write(r.stdout)
    sys.exit(r.returncode)

sys.stderr.write("fake gh: unhandled %r\n" % (sys.argv,))
sys.exit(2)
"""


def _decide(
    tmp_path: Path,
    *,
    action: str,
    head_message: str = "chore: push\n",
    label: str | None = None,
) -> dict[str, str]:
    """Run the real script; return the key=value pairs it wrote to GITHUB_OUTPUT.

    The paths the stub was asked for land in `tmp_path / "gh.log"`, in order.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    gh = bin_dir / "gh"
    gh.write_text(_FAKE_GH, encoding="utf-8")
    gh.chmod(0o755)
    (tmp_path / "gh.log").write_text("", encoding="utf-8")
    out = tmp_path / "gh_output"
    out.write_text("", encoding="utf-8")
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GH_TOKEN": "fake",
        "ACTION": action,
        "REPO": "o/r",
        "HEAD_SHA": "cafe1234",
        "GITHUB_OUTPUT": str(out),
        "GH_LOG": str(tmp_path / "gh.log"),
        "HEAD_MESSAGE": head_message,
    }
    if label is not None:
        env["LABEL"] = label
    proc = subprocess.run(
        ["bash", str(SCRIPT)], capture_output=True, text=True, env=env
    )
    assert proc.returncode == 0, proc.stderr
    parsed = {}
    for line in out.read_text(encoding="utf-8").splitlines():
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


def test_an_ordinary_push_never_reviews(tmp_path: Path) -> None:
    # The catch-up trigger this replaces reviewed here whenever the reviews list
    # was empty — which is also how a first pass that is still RUNNING looks, so
    # a push during the `opened` review bought a duplicate and cancelled it.
    got = _decide(tmp_path, action="synchronize")
    assert got["run"] == "false"


def test_a_push_reads_only_the_head_commit(tmp_path: Path) -> None:
    # The read surface IS the guard: a trigger keyed on review state or on
    # sibling-run state cannot be reintroduced without a read showing up here.
    _decide(tmp_path, action="synchronize")
    paths = [
        p for p in (tmp_path / "gh.log").read_text(encoding="utf-8").splitlines() if p
    ]
    assert paths == ["repos/o/r/commits/cafe1234"], paths


@pytest.mark.parametrize(
    "action", ["opened", "ready_for_review", "labeled", "closed", "reopened"]
)
def test_every_non_push_verdict_is_decided_without_an_api_call(
    tmp_path: Path, action: str
) -> None:
    # Every other verdict is decided from the event payload alone, so no runner
    # spends an API call to reach it.
    _decide(tmp_path, action=action, label="needs-auto-review")
    assert (tmp_path / "gh.log").read_text(encoding="utf-8") == ""


def test_the_opus_opt_in_in_the_head_title_forces_a_full_re_read(
    tmp_path: Path,
) -> None:
    got = _decide(
        tmp_path,
        action="synchronize",
        head_message="fix: thing [opus-review]\n\nbody\n",
    )
    assert got["run"] == "true"
    assert "opus" in got["model"]


def test_the_opt_in_is_matched_on_the_subject_not_the_body(tmp_path: Path) -> None:
    got = _decide(
        tmp_path,
        action="synchronize",
        head_message="fix: thing\n\nsomeone wrote [opus-review] down here\n",
    )
    assert got["run"] == "false"


def test_a_failed_head_commit_read_does_not_review(tmp_path: Path) -> None:
    # The documented fail-safe: an API failure yields no review and no red,
    # rather than a review nobody asked for. The stub 502s by refusing to serve
    # a commit path it was not given a message for.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    gh = bin_dir / "gh"
    gh.write_text("#!/bin/sh\necho 'HTTP 502' >&2\nexit 1\n", encoding="utf-8")
    gh.chmod(0o755)
    out = tmp_path / "gh_output"
    out.write_text("", encoding="utf-8")
    proc = subprocess.run(
        ["bash", str(SCRIPT)],
        capture_output=True,
        text=True,
        env={
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "GH_TOKEN": "fake",
            "ACTION": "synchronize",
            "REPO": "o/r",
            "HEAD_SHA": "cafe1234",
            "GITHUB_OUTPUT": str(out),
        },
    )
    assert proc.returncode == 0, proc.stderr
    assert "run=false" in out.read_text(encoding="utf-8")


def test_an_unhandled_action_does_not_review(tmp_path: Path) -> None:
    got = _decide(tmp_path, action="closed")
    assert got["run"] == "false"
