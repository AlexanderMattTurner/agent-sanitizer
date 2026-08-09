"""The bug-only-path issue-prompt contract across the dev hook stack.

Every hook state that is only reachable through a bug in the hook stack — a
safe-launch degradation (runtime exit 2, parse error, missing target), a corrupt
safe-launch.sh caught by the settings.json bootstrap, or a fault swallowed by an
advisory .mjs hook — must point the operator at the issue tracker. And no
healthy path may: an issue prompt on normal operation is alert-fatigue noise
that trains operators to ignore the real signal.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT
from tests.test_safe_launch import (
    ALL_POSTURES,
    degraded_reason,
    make_sandbox,
    posture_env,
    pretooluse_commands,
    run_bootstrap,
    run_safe_launch,
    write_bootstrap_target,
    write_target,
)

ISSUE_URL = "https://github.com/AlexanderMattTurner/agent-sanitizer/issues/new"

# One target body per bug-only degradation path of safe-launch.sh.
FAULT_BODIES = {
    "runtime-exit-2": 'echo "boom" >&2; exit 2',
    "parse-error": "<<<<<<< HEAD",
}


def test_issue_url_matches_this_repo() -> None:
    """Positive marker: the URL the prompts point at is this repo's tracker —
    a fork that repoints package.json must repoint the prompts too."""
    package = json.loads((REPO_ROOT / "package.json").read_text())
    repo_url = package["repository"]["url"]
    assert (
        ISSUE_URL.removesuffix("/issues/new").split("github.com/")[1].lower()
        in repo_url.lower()
    )


@pytest.mark.parametrize("fault", sorted(FAULT_BODIES))
@pytest.mark.parametrize("fail_open", ALL_POSTURES)
def test_safe_launch_degradations_prompt_issue_filing(
    tmp_path: Path, fail_open: str | None, fault: str
) -> None:
    """Every degraded verdict — under BOTH postures — carries the issue URL in
    the response text (what the model relays) and on stderr (what the operator
    sees in the hook log)."""
    sandbox = make_sandbox(tmp_path)
    target = write_target(sandbox, FAULT_BODIES[fault])
    result = run_safe_launch(sandbox, target, extra_env=posture_env(fail_open))
    assert result.returncode == 0, result.stderr
    assert ISSUE_URL in degraded_reason(result.stdout, fail_open)
    assert ISSUE_URL in result.stderr


@pytest.mark.parametrize("fail_open", ALL_POSTURES)
def test_missing_target_prompts_issue_filing(
    tmp_path: Path, fail_open: str | None
) -> None:
    sandbox = make_sandbox(tmp_path)
    result = run_safe_launch(
        sandbox,
        sandbox / ".claude" / "hooks" / "gone.sh",
        extra_env=posture_env(fail_open),
    )
    assert result.returncode == 0, result.stderr
    assert ISSUE_URL in degraded_reason(result.stdout, fail_open)


@pytest.mark.parametrize("fail_open", ALL_POSTURES)
def test_bootstrap_degradation_prompts_issue_filing(
    tmp_path: Path, fail_open: str | None
) -> None:
    """A corrupt safe-launch.sh itself degrades through the inline settings.json
    bootstrap, whose arms must carry the issue URL too — run verbatim from the
    shipped settings.json."""
    for cmd in pretooluse_commands():
        sandbox = make_sandbox(tmp_path / "corrupt")
        write_bootstrap_target(sandbox, cmd)
        wrapper = sandbox / ".claude" / "hooks" / "safe-launch.sh"
        wrapper.write_text("#!/bin/bash\n<<<<<<< HEAD\n")
        result = run_bootstrap(cmd, sandbox, extra_env=posture_env(fail_open))
        assert result.returncode == 0, result.stderr
        assert ISSUE_URL in degraded_reason(result.stdout, fail_open)
        shutil.rmtree(sandbox)


@pytest.mark.parametrize("fail_open", ALL_POSTURES)
def test_healthy_paths_never_prompt_issue_filing(
    tmp_path: Path, fail_open: str | None
) -> None:
    """Healthy pass-through, an advisory exit 1, and the self-repair carve-out
    are all reachable without a bug — none may mention the tracker."""
    sandbox = make_sandbox(tmp_path)
    deny = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"policy"}}'
    healthy = write_target(sandbox, f"printf '%s\\n' '{deny}'", name="healthy.sh")
    advisory = write_target(
        sandbox, 'echo "checks failed" >&2; exit 1', name="advisory.sh"
    )
    broken = write_target(sandbox, "<<<<<<< HEAD", name="broken.sh")
    repair_payload = json.dumps(
        {
            "tool_name": "Edit",
            "tool_input": {
                "file_path": str(broken),
                "old_string": "",
                "new_string": "",
            },
        }
    )
    runs = [
        run_safe_launch(sandbox, healthy, extra_env=posture_env(fail_open)),
        run_safe_launch(sandbox, advisory, extra_env=posture_env(fail_open)),
        run_safe_launch(
            sandbox, broken, payload=repair_payload, extra_env=posture_env(fail_open)
        ),
    ]
    for result in runs:
        assert ISSUE_URL not in result.stdout
        assert ISSUE_URL not in result.stderr


def run_node_hook(name: str, stdin: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["node", str(REPO_ROOT / ".claude" / "hooks" / name)],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


@pytest.mark.parametrize(
    "name",
    ["parallelism-nudge.mjs", "drop-superseded-ci-events.mjs"],
)
def test_mjs_hook_fault_prompts_issue_filing(name: str) -> None:
    """A fault inside an advisory .mjs hook (here: unparsable stdin) stays
    non-blocking (exit 0, no verdict) but names the tracker on stderr instead of
    being swallowed silently."""
    result = run_node_hook(name, "this is not JSON")
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert ISSUE_URL in result.stderr


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("parallelism-nudge.mjs", json.dumps({"hook_event_name": "SessionStart"})),
        (
            "drop-superseded-ci-events.mjs",
            json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "hello"}),
        ),
    ],
)
def test_mjs_hook_healthy_run_never_prompts_issue_filing(
    name: str, payload: str
) -> None:
    result = run_node_hook(name, payload)
    assert result.returncode == 0, result.stderr
    assert ISSUE_URL not in result.stderr
