"""Behavior tests for .claude/hooks/safe-launch.sh and its settings.json bootstrap.

The guarantee under test: no fault in the PreToolUse hook stack — target
runtime crash (exit 2), target parse error, missing target, or a corrupt
safe-launch.sh itself — can ever surface as Claude Code's hard-block signal
(exit 2) or an unrecoverable lockout.

What a fault degrades TO is the `AGENT_SANITIZER_FAIL_OPEN` posture knob,
mirroring `plugin/scripts/safe-launch.sh` and `failOpenEnabled()` in
`claude-hooks/lib/hook-io.mjs`:

* default (unset / any other value) — fail OPEN: the tool runs, and a non-empty
  `additionalContext` warning records that it ran unguarded. Nothing prompts.
* `0` / `false` — fail CLOSED: `permissionDecision="ask"`, the posture a host
  like agent-glovebox pins on so an unguarded tool call is never silent.

Both postures are asserted on every fault path: an open-only shim strands the
closed hosts, and a closed-only shim reintroduces the prompt stall.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT

SETTINGS = json.loads((REPO_ROOT / ".claude" / "settings.json").read_text())

BASH_PAYLOAD = json.dumps(
    {"tool_name": "Bash", "tool_input": {"command": "git push origin main"}}
)

# Values that select the fail-CLOSED posture, and values that must NOT — the
# same split `FAIL_CLOSED_VALUES` makes in claude-hooks/lib/hook-io.mjs. `None`
# means the variable is left unset entirely.
CLOSED_VALUES = ["0", "false"]
OPEN_VALUES = [None, "1", "", "no", "off", "true"]


def posture_env(fail_open_value: str | None) -> dict[str, str]:
    return (
        {}
        if fail_open_value is None
        else {"AGENT_SANITIZER_FAIL_OPEN": fail_open_value}
    )


def make_sandbox(tmp_path: Path) -> Path:
    """Sandbox with the real safe-launch.sh + its parser helper installed."""
    hooks = tmp_path / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    for name in ("safe-launch.sh", "safe-launch-parse.py"):
        shutil.copy(REPO_ROOT / ".claude" / "hooks" / name, hooks / name)
    (hooks / "safe-launch.sh").chmod(0o755)
    return tmp_path


def write_target(sandbox: Path, body: str, name: str = "target.sh") -> Path:
    path = sandbox / ".claude" / "hooks" / name
    path.write_text(f"#!/bin/bash\n{body}\n")
    path.chmod(0o755)
    return path


def run_safe_launch(
    sandbox: Path,
    target: Path,
    payload: str = BASH_PAYLOAD,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(sandbox / ".claude" / "hooks" / "safe-launch.sh"), str(target)],
        input=payload,
        capture_output=True,
        text=True,
        env={
            "PATH": "/usr/bin:/bin",
            "CLAUDE_PROJECT_DIR": str(sandbox),
            **(extra_env or {}),
        },
        cwd=sandbox,
    )


def closed_verdict(stdout: str) -> str:
    """Assert stdout is exactly one fail-CLOSED ask verdict; return its reason."""
    out = json.loads(stdout)["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse"
    assert out["permissionDecision"] == "ask"
    return out["permissionDecisionReason"]


def open_verdict(stdout: str) -> str:
    """Assert stdout is exactly one fail-OPEN warning; return its context.

    The absence of `permissionDecision` is the load-bearing half: with one
    present the tool would still halt for a human, which is the stall the open
    posture exists to remove.
    """
    out = json.loads(stdout)["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse"
    assert "permissionDecision" not in out
    assert "UNCHECKED" in out["additionalContext"]
    return out["additionalContext"]


def degraded_reason(stdout: str, fail_open_value: str | None) -> str:
    """The degraded response's reason text, whichever posture is in force."""
    if fail_open_value in CLOSED_VALUES:
        return closed_verdict(stdout)
    return open_verdict(stdout)


ALL_POSTURES = CLOSED_VALUES + OPEN_VALUES


def test_posture_values_are_disjoint_and_populated() -> None:
    """Positive marker: the posture-parametrized tests below iterate these
    lists, so an empty or overlapping split would let them pass vacuously."""
    assert not set(CLOSED_VALUES) & {v for v in OPEN_VALUES if v is not None}
    assert len(CLOSED_VALUES) >= 2 and len(OPEN_VALUES) >= 2


def test_healthy_target_stdout_and_exit_code_pass_through(tmp_path: Path) -> None:
    """A deliberate JSON verdict (here: deny) from a healthy target reaches
    Claude Code byte-identical, and exit 0 is preserved."""
    sandbox = make_sandbox(tmp_path)
    deny = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"policy"}}'
    target = write_target(sandbox, f"printf '%s\\n' '{deny}'")
    result = run_safe_launch(sandbox, target)
    assert result.returncode == 0, result.stderr
    assert result.stdout == deny + "\n"


@pytest.mark.parametrize("fail_open", ALL_POSTURES)
def test_healthy_target_verdict_is_posture_blind(
    tmp_path: Path, fail_open: str | None
) -> None:
    """The knob covers the shim's OWN failures only: a healthy hook's deliberate
    deny survives under every posture, including fail-open."""
    sandbox = make_sandbox(tmp_path)
    deny = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"policy"}}'
    target = write_target(sandbox, f"printf '%s\\n' '{deny}'")
    result = run_safe_launch(sandbox, target, extra_env=posture_env(fail_open))
    assert result.returncode == 0, result.stderr
    assert result.stdout == deny + "\n"


def test_healthy_target_stdout_is_byte_identical(tmp_path: Path) -> None:
    """Multi-line stdout with NO trailing newline must survive untouched — a
    command-substitution-based pass-through would strip/normalize trailing
    newlines, silently rewriting a hook's verdict bytes."""
    sandbox = make_sandbox(tmp_path)
    target = write_target(sandbox, "printf 'line1\\nline2'")
    result = run_safe_launch(sandbox, target)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "line1\nline2"


def test_healthy_target_exit_1_stays_non_blocking(tmp_path: Path) -> None:
    """Exit 1 (Claude Code's non-blocking error) passes through unchanged —
    no verdict is fabricated for an advisory failure."""
    sandbox = make_sandbox(tmp_path)
    target = write_target(sandbox, 'echo "checks failed" >&2; exit 1')
    result = run_safe_launch(sandbox, target)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "checks failed" in result.stderr


@pytest.mark.parametrize("fail_open", ALL_POSTURES)
def test_runtime_exit_2_degrades_per_posture(
    tmp_path: Path, fail_open: str | None
) -> None:
    """The hard-block exit code from a target runtime fault never reaches Claude
    Code: it becomes an ask verdict when closed and an unguarded-run warning
    when open, either way exit 0, either way carrying the target's stderr. The
    crashed target's partial stdout is dropped rather than forwarded."""
    sandbox = make_sandbox(tmp_path)
    target = write_target(
        sandbox, 'echo "partial output"; echo "boom: usage error" >&2; exit 2'
    )
    result = run_safe_launch(sandbox, target, extra_env=posture_env(fail_open))
    assert result.returncode == 0, result.stderr
    # A single parseable JSON object => the partial stdout was dropped.
    reason = degraded_reason(result.stdout, fail_open)
    assert "boom: usage error" in reason
    assert "exited 2" in result.stderr


@pytest.mark.parametrize("fail_open", OPEN_VALUES)
def test_fail_open_warns_loudly_on_stderr(
    tmp_path: Path, fail_open: str | None
) -> None:
    """Failing open gives up enforcement, not visibility: the operator gets a
    stderr line naming the knob that would restore strictness."""
    sandbox = make_sandbox(tmp_path)
    target = write_target(sandbox, "exit 2")
    result = run_safe_launch(sandbox, target, extra_env=posture_env(fail_open))
    assert "failing open" in result.stderr
    assert "AGENT_SANITIZER_FAIL_OPEN=0" in result.stderr


@pytest.mark.parametrize("fail_open", ALL_POSTURES)
def test_exit_2_stderr_with_json_metachars_still_yields_valid_json(
    tmp_path: Path, fail_open: str | None
) -> None:
    """The degraded response embeds the target's stderr; quotes and backslashes
    in it must be escaped so the response stays parseable under either posture —
    invalid JSON reads as no verdict at all, i.e. an unintended fail-open."""
    sandbox = make_sandbox(tmp_path)
    target = write_target(sandbox, "echo 'he said \"x\" \\ y' >&2; exit 2")
    result = run_safe_launch(sandbox, target, extra_env=posture_env(fail_open))
    assert result.returncode == 0, result.stderr
    reason = degraded_reason(result.stdout, fail_open)  # json.loads => escaping held
    assert 'he said "x" \\ y' in reason


@pytest.mark.parametrize("fail_open", ALL_POSTURES)
def test_exit_2_degrades_even_when_mktemp_is_broken(
    tmp_path: Path, fail_open: str | None
) -> None:
    """With TMPDIR pointing nowhere, mktemp fails and the fallback branch must
    still convert exit 2 (without a stderr snippet)."""
    sandbox = make_sandbox(tmp_path)
    target = write_target(sandbox, 'echo "boom" >&2; exit 2')
    result = run_safe_launch(
        sandbox,
        target,
        extra_env={
            "TMPDIR": str(sandbox / "does-not-exist"),
            **posture_env(fail_open),
        },
    )
    assert result.returncode == 0, result.stderr
    assert "no stderr" in degraded_reason(result.stdout, fail_open)
    assert "boom" in result.stderr  # stderr still streams through directly


@pytest.mark.parametrize("fail_open", ALL_POSTURES)
def test_parse_error_degrades_per_posture_for_non_edit_tools(
    tmp_path: Path, fail_open: str | None
) -> None:
    """A target with unresolved merge-conflict markers (bash parse error) yields
    a degraded response for a guarded Bash call, never a hard block."""
    sandbox = make_sandbox(tmp_path)
    target = write_target(sandbox, "<<<<<<< HEAD\nexit 0\n=======\nexit 1\n>>>>>>> x")
    result = run_safe_launch(sandbox, target, extra_env=posture_env(fail_open))
    assert result.returncode == 0, result.stderr
    degraded_reason(result.stdout, fail_open)


@pytest.mark.parametrize("fail_open", ALL_POSTURES)
def test_parse_error_allows_self_repair_edit(
    tmp_path: Path, fail_open: str | None
) -> None:
    """With a broken target, an Edit landing inside .claude/hooks/ is allowed
    (exit 0, no verdict) under BOTH postures — the closed posture must still let
    the session repair the hook it is halted on, or it is a lockout."""
    sandbox = make_sandbox(tmp_path)
    target = write_target(sandbox, "<<<<<<< HEAD")
    payload = json.dumps(
        {
            "tool_name": "Edit",
            "tool_input": {
                "file_path": str(target),
                "old_string": "",
                "new_string": "",
            },
        }
    )
    result = run_safe_launch(
        sandbox, target, payload=payload, extra_env=posture_env(fail_open)
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert "self-repair" in result.stderr


@pytest.mark.parametrize("fail_open", ALL_POSTURES)
def test_missing_target_degrades_per_posture(
    tmp_path: Path, fail_open: str | None
) -> None:
    sandbox = make_sandbox(tmp_path)
    result = run_safe_launch(
        sandbox,
        sandbox / ".claude" / "hooks" / "gone.sh",
        extra_env=posture_env(fail_open),
    )
    assert result.returncode == 0, result.stderr
    degraded_reason(result.stdout, fail_open)


def pretooluse_commands() -> list[str]:
    return [
        hook["command"]
        for group in SETTINGS["hooks"]["PreToolUse"]
        for hook in group["hooks"]
        if hook["type"] == "command"
    ]


def run_bootstrap(
    cmd: str, sandbox: Path, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", cmd],
        input=BASH_PAYLOAD,
        capture_output=True,
        text=True,
        env={
            "PATH": "/usr/bin:/bin",
            "CLAUDE_PROJECT_DIR": str(sandbox),
            **(extra_env or {}),
        },
        cwd=sandbox,
    )


def test_settings_has_pretooluse_commands() -> None:
    """Positive marker pairing the bootstrap tests below: they iterate this
    list, so it must be non-empty or they pass vacuously."""
    assert len(pretooluse_commands()) >= 1


def test_bootstrap_runs_target_when_wrapper_is_healthy(tmp_path: Path) -> None:
    """The commands actually configured in settings.json, run verbatim against
    a healthy sandbox, reach the wrapped target."""
    for cmd in pretooluse_commands():
        sandbox = make_sandbox(tmp_path / "healthy")
        write_target(sandbox, 'echo "TARGET-RAN"', name="pre-push-check.sh")
        result = run_bootstrap(cmd, sandbox)
        assert result.returncode == 0, result.stderr
        assert result.stdout == "TARGET-RAN\n"
        shutil.rmtree(sandbox)


@pytest.mark.parametrize("fail_open", ALL_POSTURES)
def test_bootstrap_degrades_per_posture_when_wrapper_is_corrupt(
    tmp_path: Path, fail_open: str | None
) -> None:
    """A merge-conflict marker in safe-launch.sh ITSELF — the fault no wrapper
    script can guard against — must degrade through the inline bootstrap, which
    applies the same posture knob as the shim it replaces."""
    for cmd in pretooluse_commands():
        sandbox = make_sandbox(tmp_path / "corrupt")
        write_target(sandbox, 'echo "TARGET-RAN"', name="pre-push-check.sh")
        wrapper = sandbox / ".claude" / "hooks" / "safe-launch.sh"
        wrapper.write_text("#!/bin/bash\n<<<<<<< HEAD\n")
        result = run_bootstrap(cmd, sandbox, extra_env=posture_env(fail_open))
        assert result.returncode == 0, result.stderr
        assert "safe-launch.sh" in degraded_reason(result.stdout, fail_open)
        assert "TARGET-RAN" not in result.stdout
        shutil.rmtree(sandbox)


@pytest.mark.parametrize("fail_open", ALL_POSTURES)
def test_bootstrap_degrades_per_posture_when_wrapper_is_missing(
    tmp_path: Path, fail_open: str | None
) -> None:
    for cmd in pretooluse_commands():
        sandbox = tmp_path / "missing"
        (sandbox / ".claude" / "hooks").mkdir(parents=True)
        result = run_bootstrap(cmd, sandbox, extra_env=posture_env(fail_open))
        assert result.returncode == 0, result.stderr
        degraded_reason(result.stdout, fail_open)
        shutil.rmtree(sandbox)
