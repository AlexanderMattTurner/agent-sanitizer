"""Behavioral tests for .github/scripts/prepare-pr-review-input.sh — the step
that fetches the untrusted PR diff/metadata and runs them through the
sanitizer before the review agent sees them.

Contract:
  * At or under MAX_DIFF_LINES: oversized=false, diff.txt/meta.txt written.
  * Over MAX_DIFF_LINES: oversized=true, oversized-notice.txt written, and
    diff.txt/meta.txt are NOT written (the review is skipped for size).
  * `gh pr diff` is always called with --allow-escape-sequences, since a diff
    holding a raw terminal escape byte would otherwise refuse to print and the
    sanitizer would never run (observed on #320).

The tests drive the REAL script with a fake `gh` (emits an N-file unified diff /
PR metadata) and a fake `node` (stands in for the sanitizer, passing stdin
through) on PATH.
"""

import subprocess
from pathlib import Path

from tests._helpers import REPO_ROOT

SCRIPT = REPO_ROOT / ".github" / "scripts" / "prepare-pr-review-input.sh"

# Each fake file section is this many lines (header + ---/+++ + @@ + one body
# line), so a diff's line count is a simple multiple of its file count.
LINES_PER_FILE = 5

# What `gh pr diff` prints when the diff holds a raw terminal escape byte and
# --allow-escape-sequences is missing from the call.
ESCAPE_SEQUENCE_STDERR = (
    "the diff contains terminal escape sequences; pass --allow-escape-sequences "
    "to output it anyway"
)


def _fake_bins(tmp_path: Path, *, files: int, escape_byte: bool = False) -> None:
    """Put a fake `gh` and a fake `node` (the sanitizer stand-in: cats stdin) on
    PATH. The fake `gh` emits a `files`-file unified diff for `pr diff` and JSON
    for `pr view`, and refuses `pr diff` without --allow-escape-sequences —
    mirroring the real CLI's guard — so every test also asserts the script
    keeps passing that flag. `escape_byte` adds one hunk holding a literal ESC
    byte, mirroring the payload `gh pr diff` would otherwise refuse to print.
    """
    escape = ""
    if escape_byte:
        escape = (
            '  echo "diff --git a/escape.txt b/escape.txt"\n'
            '  echo "@@ -0,0 +1,1 @@"\n'
            '  printf "+escaped \x1b[31mred\x1b[0m line\\n"\n'
        )
    gh = tmp_path / "gh"
    gh.write_text(
        "#!/usr/bin/env bash\n"
        'if [[ "$2" == "diff" ]]; then\n'
        "  allowed=false\n"
        '  for arg in "$@"; do [[ "$arg" == "--allow-escape-sequences" ]] && allowed=true; done\n'
        f'  if [[ "$allowed" != true ]]; then echo "{ESCAPE_SEQUENCE_STDERR}" >&2; exit 1; fi\n'
        f"  for ((i = 0; i < {files}; i++)); do\n"
        '    echo "diff --git a/f$i.py b/f$i.py"\n'
        '    echo "--- a/f$i.py"\n'
        '    echo "+++ b/f$i.py"\n'
        '    echo "@@ -0,0 +1,1 @@"\n'
        '    echo "+added line $i"\n'
        "  done\n"
        f"{escape}"
        'elif [[ "$2" == "view" ]]; then\n'
        '  printf \'%s\' \'{"title":"t","body":"b","author":{"login":"a"},"files":[]}\'\n'
        "fi\n",
        encoding="utf-8",
    )
    gh.chmod(0o755)
    node = tmp_path / "node"
    node.write_text('#!/usr/bin/env bash\ntee -a "$SANITIZE_INPUT"\n', encoding="utf-8")
    node.chmod(0o755)


def _run(
    tmp_path: Path, *, files: int, max_diff_lines: int, escape_byte: bool = False
) -> tuple[subprocess.CompletedProcess, dict[str, str], Path]:
    _fake_bins(tmp_path, files=files, escape_byte=escape_byte)
    out_file = tmp_path / "github_output"
    out_file.write_text("", encoding="utf-8")
    input_dir = tmp_path / "pr-input"
    proc = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env={
            "PATH": f"{tmp_path}:/usr/bin:/bin",
            "GITHUB_OUTPUT": str(out_file),
            "SANITIZE_INPUT": str(tmp_path / "sanitizer_input"),
            "GH_TOKEN": "fake",
            "GH_REPO": "owner/repo",
            "PR": "123",
            "PR_INPUT_DIR": str(input_dir),
            "MAX_DIFF_LINES": str(max_diff_lines),
            # Keeps a regressed (flag-dropped) run's retry ladder off the
            # 2+4+8+16s backoff: a bare assertion failure beats a 30s-per-test
            # wait for a run that is going to fail either way.
            "RETRY_MAX": "1",
            "RETRY_BASE_DELAY": "0",
        },
    )
    outputs = dict(
        ln.split("=", 1)
        for ln in out_file.read_text(encoding="utf-8").splitlines()
        if "=" in ln
    )
    return proc, outputs, input_dir


def test_normal_diff_is_sanitized(tmp_path: Path) -> None:
    proc, outputs, input_dir = _run(tmp_path, files=2, max_diff_lines=100)
    assert proc.returncode == 0, proc.stderr
    assert outputs["oversized"] == "false"
    diff_body = (input_dir / "diff.txt").read_text(encoding="utf-8")
    assert diff_body.count("diff --git ") == 2
    assert "+added line 0" in diff_body and "+added line 1" in diff_body
    assert (input_dir / "meta.txt").is_file()
    assert not (input_dir / "oversized-notice.txt").exists()
    assert (tmp_path / "sanitizer_input").exists(), "the sanitizer must run"


def test_oversized_diff_skips_the_review(tmp_path: Path) -> None:
    proc, outputs, input_dir = _run(tmp_path, files=6, max_diff_lines=10)
    assert proc.returncode == 0, proc.stderr
    assert outputs["oversized"] == "true"
    assert outputs["diff_lines"] == str(6 * LINES_PER_FILE)
    assert (input_dir / "oversized-notice.txt").is_file()
    assert not (input_dir / "diff.txt").exists()
    assert not (input_dir / "meta.txt").exists(), "the size skip must also skip meta"


def test_a_diff_with_a_raw_escape_byte_still_reaches_the_sanitizer(
    tmp_path: Path,
) -> None:
    """`gh pr diff` refuses to emit a diff holding a raw terminal escape byte
    unless --allow-escape-sequences is passed, so a PR carrying one (observed
    on #320) would die before the sanitizer ever ran. Safe to pass always: the
    bytes reach only the sanitizer, never a real terminal."""
    proc, outputs, input_dir = _run(
        tmp_path, files=2, max_diff_lines=100, escape_byte=True
    )
    assert proc.returncode == 0, proc.stderr
    assert ESCAPE_SEQUENCE_STDERR not in proc.stderr
    assert outputs["oversized"] == "false"
    sanitizer_saw = (tmp_path / "sanitizer_input").read_text(encoding="utf-8")
    assert "\x1b[31m" in sanitizer_saw, "the raw byte must reach the sanitizer intact"
