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
import re
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


def write_node_target(sandbox: Path, body: str, name: str) -> Path:
    """A `.mjs` hook target — safe-launch runs it through `node`, not bash."""
    path = sandbox / ".claude" / "hooks" / name
    path.write_text(f"#!/usr/bin/env node\n{body}\n")
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


# ── The posture parity table ────────────────────────────────────────────────
#
# `AGENT_SANITIZER_FAIL_OPEN` is decided in more than one language, so the
# closed set gets spelled out more than once. `plugin/scripts/lib/fail-open.sh`
# is GENERATED from `FAIL_CLOSED_VALUES` in `claude-hooks/lib/hook-io.mjs` and
# sourced by the plugin launcher (that round trip is asserted in
# plugin/test/fail-open-parity.test.mjs), but two implementations cannot reach
# it: the repo's own `.claude/hooks/safe-launch.sh`, which ships to downstream
# repos that have no `plugin/` tree, and the inline bootstrap in
# `.claude/settings.json`, which guards the wrapper itself.
#
# So every implementation is RUN here, for real, over every posture value —
# and the partition test below refuses to let a new one appear without landing
# in this table.


def _hook_io_says_open(fail_open: str | None, tmp_path: Path) -> bool:
    """The JS source of truth, run for real."""
    script = (
        "import(process.argv[1]).then(m => "
        "process.stdout.write(String(m.failOpenEnabled(JSON.parse(process.argv[2])))))"
    )
    result = subprocess.run(
        [
            "node",
            "-e",
            script,
            str(REPO_ROOT / "claude-hooks" / "lib" / "hook-io.mjs"),
            json.dumps(posture_env(fail_open)),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout == "true"


def _fail_open_lib_says_open(fail_open: str | None, tmp_path: Path) -> bool:
    """The generated shell function, sourced and called."""
    lib = REPO_ROOT / "plugin" / "scripts" / "lib" / "fail-open.sh"
    result = subprocess.run(
        ["bash", "-c", f'. "{lib}"; agent_sanitizer_fail_open'],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", **posture_env(fail_open)},
    )
    assert result.returncode in (0, 1), result.stderr
    return result.returncode == 0


def _repo_shim_says_open(fail_open: str | None, tmp_path: Path) -> bool:
    """The repo's own PreToolUse shim, driven onto its missing-target fault."""
    sandbox = make_sandbox(tmp_path / "repo-shim")
    result = run_safe_launch(
        sandbox,
        sandbox / ".claude" / "hooks" / "gone.sh",
        extra_env=posture_env(fail_open),
    )
    assert result.returncode == 0, result.stderr
    return "permissionDecision" not in json.loads(result.stdout)["hookSpecificOutput"]


def _plugin_shim_says_open(fail_open: str | None, tmp_path: Path) -> bool:
    """The shipped plugin launcher, driven onto its no-bundle fault."""
    sandbox = tmp_path / "plugin-shim"
    shutil.copytree(REPO_ROOT / "plugin" / "scripts", sandbox / "plugin" / "scripts")
    result = subprocess.run(
        [
            "bash",
            str(sandbox / "plugin" / "scripts" / "safe-launch.sh"),
            "PreToolUse",
            "--hook=pretooluse-sanitize",
        ],
        input=BASH_PAYLOAD,
        capture_output=True,
        text=True,
        # node must be findable: the launcher's no-node arm is a DIFFERENT fault
        # path, and taking it here would test the wrong branch.
        env={"PATH": _path_with_node(), **posture_env(fail_open)},
    )
    assert result.returncode == 0, result.stderr
    return "permissionDecision" not in json.loads(result.stdout)["hookSpecificOutput"]


def _bootstrap_says_open(fail_open: str | None, tmp_path: Path) -> bool:
    """The settings.json inline bootstrap, driven onto its corrupt-wrapper fault."""
    commands = pretooluse_commands()
    assert commands, "settings.json declares no PreToolUse command to exercise"
    sandbox = make_sandbox(tmp_path / "bootstrap")
    (sandbox / ".claude" / "hooks" / "safe-launch.sh").write_text(
        "#!/bin/bash\n<<<<<<< HEAD\n"
    )
    result = run_bootstrap(commands[0], sandbox, extra_env=posture_env(fail_open))
    assert result.returncode == 0, result.stderr
    return "permissionDecision" not in json.loads(result.stdout)["hookSpecificOutput"]


def _path_with_node() -> str:
    node = shutil.which("node")
    assert node, "node is required to exercise the plugin launcher"
    return f"{Path(node).parent}:/usr/bin:/bin"


PARITY_IMPLEMENTATIONS = {
    "claude-hooks/lib/hook-io.mjs": _hook_io_says_open,
    "plugin/scripts/lib/fail-open.sh": _fail_open_lib_says_open,
    "plugin/scripts/safe-launch.sh": _plugin_shim_says_open,
    ".claude/hooks/safe-launch.sh": _repo_shim_says_open,
    ".claude/settings.json": _bootstrap_says_open,
}

# Files that spell the closed set out but are deliberately NOT in the table,
# each with the reason. Empty is the healthy state.
PARITY_ALLOWLIST: dict[str, str] = {
    ".claude/README.md": (
        "prose: quotes the settings.json bootstrap as the shape to copy when adding "
        "a hook. It decides nothing at runtime; the bootstrap it quotes is a table row."
    ),
    ".claude/rules/hooks.md": (
        "prose: quotes the bootstrap's posture arms while explaining the contract."
    ),
    ".github/scripts/validate-config.sh": (
        "validator, not an implementation: check 3 asserts settings.json's PreToolUse "
        "command HAS both posture arms. The literals appear only in the comment "
        "documenting the shape and in a glob, never in a decision on the value."
    ),
}

# Table rows that state no literals of their own — they are exercised end to end
# because delegation is exactly what can break, but they must not be expected to
# match the implementation idioms.
PARITY_DELEGATES = {
    "plugin/scripts/safe-launch.sh": "sources the generated plugin/scripts/lib/fail-open.sh",
}


@pytest.mark.parametrize("impl", sorted(PARITY_IMPLEMENTATIONS))
@pytest.mark.parametrize("fail_open", ALL_POSTURES)
def test_every_posture_implementation_agrees(
    impl: str, fail_open: str | None, tmp_path: Path
) -> None:
    """Every implementation of the posture knob, run for real, over every value.
    A prose comment saying "mirroring X so the three cannot drift" is not a
    guard; this is."""
    assert PARITY_IMPLEMENTATIONS[impl](fail_open, tmp_path) is (
        fail_open not in CLOSED_VALUES
    ), f"{impl} disagrees on {fail_open!r}"


# A file DECIDES the posture (rather than merely setting or documenting it) when
# it states the closed set itself: a shell `case` arm over the two literals, or
# the JS set they are generated from. Anything else that merely mentions the
# variable is a consumer or a doc.
IMPLEMENTATION_IDIOMS = (
    re.compile(r"0\s*\|\s*false\)"),
    re.compile(r"FAIL_CLOSED_VALUES\s*="),
)

# Tests assert ABOUT the literals; they are not implementations of the posture.
_TEST_PATH = re.compile(r"(?:^|/)tests?/|\.test\.(?:mjs|py)$")


def posture_implementation_files() -> list[str]:
    """Tracked files that decide the posture, from the whole repo."""
    listed = subprocess.run(
        ["git", "grep", "-l", "AGENT_SANITIZER_FAIL_OPEN"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return sorted(
        path
        for path in listed
        # dist/ is a generated bundle of the sources already covered here.
        if not path.startswith("plugin/dist/")
        and not _TEST_PATH.search(path)
        and any(
            idiom.search((REPO_ROOT / path).read_text())
            for idiom in IMPLEMENTATION_IDIOMS
        )
    )


def test_posture_implementations_are_all_in_the_parity_table() -> None:
    """The partition: every file that decides the posture is either exercised by
    the table above or allowlisted with a stated reason. A fourth copy of
    `0 | false)` landing anywhere in the repo fails here."""
    found = posture_implementation_files()
    # Positive marker: the idioms still match something, so a refactor that
    # renamed them cannot leave this test passing over an empty set.
    assert len(found) >= 3, f"the implementation idioms matched almost nothing: {found}"
    unclaimed = [
        path
        for path in found
        if path not in PARITY_IMPLEMENTATIONS and path not in PARITY_ALLOWLIST
    ]
    assert not unclaimed, (
        "these files decide AGENT_SANITIZER_FAIL_OPEN but nothing proves they agree — "
        f"add them to PARITY_IMPLEMENTATIONS or PARITY_ALLOWLIST with a reason: {unclaimed}"
    )
    # And the table cannot name a file that no longer decides anything: a stale
    # row would keep passing while covering a path that moved.
    stale = [
        path
        for path in PARITY_IMPLEMENTATIONS
        if path not in found and path not in PARITY_DELEGATES
    ]
    assert not stale, f"parity table rows that no longer decide the posture: {stale}"


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


@pytest.mark.parametrize("fail_open", ALL_POSTURES)
def test_healthy_target_exit_1_stays_non_blocking(
    tmp_path: Path, fail_open: str | None
) -> None:
    """Exit 1 (Claude Code's non-blocking error) passes through unchanged under
    every posture — no verdict is fabricated for an advisory failure."""
    sandbox = make_sandbox(tmp_path)
    target = write_target(sandbox, 'echo "checks failed" >&2; exit 1')
    result = run_safe_launch(sandbox, target, extra_env=posture_env(fail_open))
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


# The target each bootstrap command wraps: the SECOND `.claude/hooks/…` path in
# it, the first being safe-launch.sh itself.
_WRAPPED_TARGET_RE = re.compile(r"\.claude/hooks/(?P<name>[\w.-]+)")


def wrapped_target(cmd: str) -> str:
    """The hook filename a bootstrap command hands to safe-launch.

    Derived rather than hard-coded. These tests iterate every command shipped in
    settings.json but used to write one fixed target name, so the first handler
    wrapping a different script made the sandbox miss the file the command
    actually invokes — and the assertion failed on a missing hook rather than on
    the behaviour under test.
    """
    names = _WRAPPED_TARGET_RE.findall(cmd)
    assert len(names) >= 2, f"no wrapped target in: {cmd[:80]}"
    return names[1]


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
        name = wrapped_target(cmd)
        # safe-launch picks the interpreter from the suffix, so the target has
        # to be written in the language its own name promises.
        if name.endswith((".mjs", ".cjs", ".js")):
            write_node_target(sandbox, 'console.log("TARGET-RAN");', name=name)
        else:
            write_target(sandbox, 'echo "TARGET-RAN"', name=name)
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
