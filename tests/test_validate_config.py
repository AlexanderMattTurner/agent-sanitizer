"""Tests for .github/scripts/validate-config.sh."""

import json
import subprocess
from pathlib import Path
from typing import Callable

import pytest


def write_settings(sandbox: Path, settings: dict) -> None:
    (sandbox / ".claude").mkdir(exist_ok=True)
    (sandbox / ".claude" / "settings.json").write_text(json.dumps(settings))


def make_hook(sandbox: Path, rel_path: str, executable: bool = True) -> Path:
    path = sandbox / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/usr/bin/env bash\n")
    path.chmod(0o755 if executable else 0o644)
    return path


def run_validator(
    sandbox: Path, copy_script: Callable[[str, Path], Path]
) -> subprocess.CompletedProcess:
    scripts_dir = sandbox / ".github" / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    copy_script("validate-config.sh", scripts_dir)
    return subprocess.run(
        ["bash", ".github/scripts/validate-config.sh"],
        cwd=sandbox,
        capture_output=True,
        text=True,
    )


def _command(path: str) -> dict:
    return {
        "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": path}]}]}
    }


@pytest.mark.parametrize(
    "settings, hooks_to_create, expected_returncode, expected_substring",
    [
        # Happy path
        (
            _command('"$CLAUDE_PROJECT_DIR"/.claude/hooks/session-setup.sh'),
            [(".claude/hooks/session-setup.sh", True), (".hooks/pre-commit", True)],
            0,
            "All checks passed",
        ),
        # Referenced hook script doesn't exist
        (
            _command('"$CLAUDE_PROJECT_DIR"/.claude/hooks/missing.sh'),
            [(".hooks/pre-commit", True)],
            1,
            "missing.sh",
        ),
        # Hook file exists but isn't executable (.hooks/)
        (
            {"hooks": {}},
            [(".hooks/pre-commit", False)],
            1,
            "not executable",
        ),
        # Hook file under .claude/hooks/ isn't executable
        (
            {"hooks": {}},
            [(".claude/hooks/session-setup.sh", False)],
            1,
            "not executable",
        ),
    ],
    ids=["valid", "missing-hook", "non-executable-hook", "non-executable-claude-hook"],
)
def test_validate_config(
    tmp_path: Path,
    copy_script,
    settings: dict,
    hooks_to_create: list[tuple[str, bool]],
    expected_returncode: int,
    expected_substring: str,
) -> None:
    write_settings(tmp_path, settings)
    for rel_path, executable in hooks_to_create:
        make_hook(tmp_path, rel_path, executable=executable)
    result = run_validator(tmp_path, copy_script)
    assert result.returncode == expected_returncode, result.stdout + result.stderr
    assert expected_substring in result.stdout + result.stderr


def test_fails_when_settings_missing(tmp_path: Path, copy_script) -> None:
    make_hook(tmp_path, ".hooks/pre-commit", executable=True)
    result = run_validator(tmp_path, copy_script)
    assert result.returncode == 1
    assert ".claude/settings.json not found" in result.stdout


def test_fails_when_settings_json_is_malformed(tmp_path: Path, copy_script) -> None:
    """Corrupted settings.json must be reported as an error for every jq call site,
    not silently swallowed. The script parses settings.json at three sites (the
    hook-path scan, the safe-launch check, and the matcher-content check), so a
    malformed file surfaces the error three times."""
    (tmp_path / ".claude").mkdir(exist_ok=True)
    (tmp_path / ".claude" / "settings.json").write_text("{not valid json}")
    make_hook(tmp_path, ".hooks/pre-commit", executable=True)
    result = run_validator(tmp_path, copy_script)
    assert result.returncode == 1
    assert (result.stdout + result.stderr).count("could not be parsed") == 3


def test_rejects_hook_with_syntax_error(tmp_path: Path, copy_script) -> None:
    """Hook scripts with bash syntax errors must be caught with a useful message."""
    write_settings(tmp_path, {"hooks": {}})
    path = tmp_path / ".hooks" / "bad.sh"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/usr/bin/env bash\nif [[\n")  # unclosed [[ is a syntax error
    path.chmod(0o755)
    result = run_validator(tmp_path, copy_script)
    assert result.returncode == 1
    assert "has a bash syntax error" in result.stdout + result.stderr


@pytest.mark.parametrize(
    "rel_path, content, expected_substring",
    [
        (
            ".hooks/bad.mjs",
            "const x = {;\n",
            "has a JavaScript syntax error",
        ),
        (
            ".hooks/bad.json",
            '{"pairs": }\n',
            "is not valid JSON",
        ),
    ],
    ids=["mjs-syntax-error", "json-invalid"],
)
def test_rejects_non_bash_hook_files_with_errors(
    tmp_path: Path, copy_script, rel_path: str, content: str, expected_substring: str
) -> None:
    """.mjs/.json hook helpers are checked with their own syntax tools, not bash -n
    (which would reject even VALID files of those types)."""
    write_settings(tmp_path, {"hooks": {}})
    path = tmp_path / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    result = run_validator(tmp_path, copy_script)
    assert result.returncode == 1, result.stdout + result.stderr
    assert expected_substring in result.stdout + result.stderr


def test_accepts_valid_mjs_and_json_hook_files(tmp_path: Path, copy_script) -> None:
    """Valid .mjs/.json helpers in .hooks/ must pass — the old bash -n check
    flagged them as bash syntax errors."""
    write_settings(tmp_path, {"hooks": {}})
    hooks_dir = tmp_path / ".hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    (hooks_dir / "helper.mjs").write_text('export const ok = { a: ["b"] };\n')
    (hooks_dir / "data.json").write_text('{"pairs": {"a": ["b"]}}\n')
    result = run_validator(tmp_path, copy_script)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "All checks passed" in result.stdout + result.stderr


def _pretooluse_settings(cmd: str) -> dict:
    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": cmd}],
                }
            ]
        }
    }


# The canonical PreToolUse bootstrap: syntax-check safe-launch.sh, exec through
# it on success, degrade to an "ask" verdict when the shim itself is corrupt.
BOOTSTRAP_CMD = (
    'bash -n "$CLAUDE_PROJECT_DIR"/.claude/hooks/safe-launch.sh 2>/dev/null'
    ' && exec bash "$CLAUDE_PROJECT_DIR"/.claude/hooks/safe-launch.sh'
    ' "$CLAUDE_PROJECT_DIR"/.claude/hooks/pre-push-check.sh;'
    " printf '%s\\n'"
    ' \'{"hookSpecificOutput":{"hookEventName":"PreToolUse",'
    '"permissionDecision":"ask","permissionDecisionReason":"corrupt"}}\''
)


@pytest.mark.parametrize(
    "cmd, description",
    [
        (
            '"$CLAUDE_PROJECT_DIR"/.claude/hooks/pre-push-check.sh',
            "bare hook, no safe-launch at all",
        ),
        (
            '"$CLAUDE_PROJECT_DIR"/.claude/hooks/safe-launch.sh "$CLAUDE_PROJECT_DIR"/.claude/hooks/pre-push-check.sh',
            "first-token safe-launch without the self-checking bootstrap",
        ),
        (
            'bash -n "$CLAUDE_PROJECT_DIR"/.claude/hooks/safe-launch.sh 2>/dev/null && exec bash "$CLAUDE_PROJECT_DIR"/.claude/hooks/safe-launch.sh "$CLAUDE_PROJECT_DIR"/.claude/hooks/pre-push-check.sh',
            "bootstrap prefix without the ask-verdict fallback",
        ),
    ],
    ids=["bare-hook", "unguarded-safe-launch", "no-ask-fallback"],
)
def test_pretooluse_without_bootstrap_fails(
    tmp_path: Path, copy_script, cmd: str, description: str
) -> None:
    """PreToolUse hooks that bypass the safe-launch bootstrap must be rejected.
    All hook files exist so the failure isolates check 3, not the missing-file
    check."""
    write_settings(tmp_path, _pretooluse_settings(cmd))
    make_hook(tmp_path, ".claude/hooks/safe-launch.sh")
    make_hook(tmp_path, ".claude/hooks/pre-push-check.sh")
    result = run_validator(tmp_path, copy_script)
    assert result.returncode == 1, description
    assert "must use the safe-launch bootstrap" in result.stdout + result.stderr


def test_pretooluse_with_bootstrap_passes(tmp_path: Path, copy_script) -> None:
    """The canonical bootstrap must pass — including check 1's path scan, which
    must strip the `;` that word-splitting glues onto the target path in a
    compound command."""
    write_settings(tmp_path, _pretooluse_settings(BOOTSTRAP_CMD))
    make_hook(tmp_path, ".claude/hooks/safe-launch.sh")
    make_hook(tmp_path, ".claude/hooks/pre-push-check.sh")
    result = run_validator(tmp_path, copy_script)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "All checks passed" in result.stdout
