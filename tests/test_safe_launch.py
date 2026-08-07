"""Behavior tests for .claude/hooks/safe-launch.sh and its settings.json bootstrap.

The guarantee under test: no fault in the PreToolUse hook stack — target
runtime crash (exit 2), target parse error, missing target, or a corrupt
safe-launch.sh itself — can ever surface as Claude Code's hard-block signal
(exit 2) or an unrecoverable lockout. The worst permitted posture is a
permissionDecision="ask" verdict, which the user can always override.
"""

import json
import shutil
import subprocess
from pathlib import Path

from tests._helpers import REPO_ROOT

SETTINGS = json.loads((REPO_ROOT / ".claude" / "settings.json").read_text())

BASH_PAYLOAD = json.dumps(
    {"tool_name": "Bash", "tool_input": {"command": "git push origin main"}}
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


def ask_verdict(stdout: str) -> dict:
    """Parse stdout as exactly one JSON object and assert it is an ask verdict."""
    verdict = json.loads(stdout)
    out = verdict["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse"
    assert out["permissionDecision"] == "ask"
    return out


def test_healthy_target_stdout_and_exit_code_pass_through(tmp_path: Path) -> None:
    """A deliberate JSON verdict (here: deny) from a healthy target reaches
    Claude Code byte-identical, and exit 0 is preserved."""
    sandbox = make_sandbox(tmp_path)
    deny = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"policy"}}'
    target = write_target(sandbox, f"printf '%s\\n' '{deny}'")
    result = run_safe_launch(sandbox, target)
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
    no ask verdict is fabricated for an advisory failure."""
    sandbox = make_sandbox(tmp_path)
    target = write_target(sandbox, 'echo "checks failed" >&2; exit 1')
    result = run_safe_launch(sandbox, target)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "checks failed" in result.stderr


def test_runtime_exit_2_degrades_to_ask(tmp_path: Path) -> None:
    """The hard-block exit code from a target runtime fault is converted to an
    ask verdict (exit 0) carrying the target's stderr, and any partial stdout
    the crashed target produced is dropped rather than forwarded as a verdict."""
    sandbox = make_sandbox(tmp_path)
    target = write_target(
        sandbox, 'echo "partial output"; echo "boom: usage error" >&2; exit 2'
    )
    result = run_safe_launch(sandbox, target)
    assert result.returncode == 0, result.stderr
    out = ask_verdict(result.stdout)  # single JSON object => partial was dropped
    assert "boom: usage error" in out["permissionDecisionReason"]
    assert "exited 2" in result.stderr


def test_exit_2_stderr_with_json_metachars_still_yields_valid_json(
    tmp_path: Path,
) -> None:
    """The ask verdict embeds the target's stderr; quotes and backslashes in it
    must be escaped so the verdict stays parseable — invalid JSON would read as
    no verdict at all (allow), a silent fail-open."""
    sandbox = make_sandbox(tmp_path)
    target = write_target(sandbox, "echo 'he said \"x\" \\ y' >&2; exit 2")
    result = run_safe_launch(sandbox, target)
    assert result.returncode == 0, result.stderr
    out = ask_verdict(result.stdout)
    assert 'he said "x"' in out["permissionDecisionReason"]


def test_exit_2_converts_even_when_mktemp_is_broken(tmp_path: Path) -> None:
    """With TMPDIR pointing nowhere, mktemp fails and the fallback branch must
    still convert exit 2 to ask (without a stderr snippet)."""
    sandbox = make_sandbox(tmp_path)
    target = write_target(sandbox, 'echo "boom" >&2; exit 2')
    result = run_safe_launch(
        sandbox, target, extra_env={"TMPDIR": str(sandbox / "does-not-exist")}
    )
    assert result.returncode == 0, result.stderr
    out = ask_verdict(result.stdout)
    assert "no stderr" in out["permissionDecisionReason"]
    assert "boom" in result.stderr  # stderr still streams through directly


def test_parse_error_degrades_to_ask_for_non_edit_tools(tmp_path: Path) -> None:
    """A target with unresolved merge-conflict markers (bash parse error) yields
    an ask verdict for a guarded Bash call, not a hard block."""
    sandbox = make_sandbox(tmp_path)
    target = write_target(sandbox, "<<<<<<< HEAD\nexit 0\n=======\nexit 1\n>>>>>>> x")
    result = run_safe_launch(sandbox, target)
    assert result.returncode == 0, result.stderr
    ask_verdict(result.stdout)


def test_parse_error_allows_self_repair_edit(tmp_path: Path) -> None:
    """With a broken target, an Edit landing inside .claude/hooks/ is allowed
    (exit 0, no verdict) so the session can repair the hook it is locked on."""
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
    result = run_safe_launch(sandbox, target, payload=payload)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert "self-repair" in result.stderr


def test_missing_target_degrades_to_ask(tmp_path: Path) -> None:
    sandbox = make_sandbox(tmp_path)
    result = run_safe_launch(sandbox, sandbox / ".claude" / "hooks" / "gone.sh")
    assert result.returncode == 0, result.stderr
    ask_verdict(result.stdout)


def pretooluse_commands() -> list[str]:
    return [
        hook["command"]
        for group in SETTINGS["hooks"]["PreToolUse"]
        for hook in group["hooks"]
        if hook["type"] == "command"
    ]


def run_bootstrap(cmd: str, sandbox: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", cmd],
        input=BASH_PAYLOAD,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "CLAUDE_PROJECT_DIR": str(sandbox)},
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


def test_bootstrap_degrades_to_ask_when_wrapper_is_corrupt(tmp_path: Path) -> None:
    """A merge-conflict marker in safe-launch.sh ITSELF — the fault no wrapper
    script can guard against — must degrade to ask via the inline bootstrap."""
    for cmd in pretooluse_commands():
        sandbox = make_sandbox(tmp_path / "corrupt")
        write_target(sandbox, 'echo "TARGET-RAN"', name="pre-push-check.sh")
        wrapper = sandbox / ".claude" / "hooks" / "safe-launch.sh"
        wrapper.write_text("#!/bin/bash\n<<<<<<< HEAD\n")
        result = run_bootstrap(cmd, sandbox)
        assert result.returncode == 0, result.stderr
        out = ask_verdict(result.stdout)
        assert "safe-launch.sh" in out["permissionDecisionReason"]
        assert "TARGET-RAN" not in result.stdout
        shutil.rmtree(sandbox)


def test_bootstrap_degrades_to_ask_when_wrapper_is_missing(tmp_path: Path) -> None:
    for cmd in pretooluse_commands():
        sandbox = tmp_path / "missing"
        (sandbox / ".claude" / "hooks").mkdir(parents=True)
        result = run_bootstrap(cmd, sandbox)
        assert result.returncode == 0, result.stderr
        ask_verdict(result.stdout)
        shutil.rmtree(sandbox)
