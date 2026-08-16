"""Behavioral tests for .github/scripts/prepare-pr-review-input.sh — the step
that fetches the untrusted PR diff/metadata and runs them through the
sanitizer before the review agent sees them.

Contract:
  * At or under MAX_DIFF_LINES: oversized=false, diff.txt/meta.txt written.
  * Over MAX_DIFF_LINES: oversized=true, oversized-notice.txt written, and
    diff.txt/meta.txt are NOT written (the review is skipped for size).
  * The diff is fetched with `curl`, not `gh api`/`gh pr diff` (#322): gh's
    escape-sequence guard fires identically on both gh subcommands (observed
    on #320, then again on #321's `gh api` swap), so only a client with no
    such guard can pass a raw escape byte through to the sanitizer.

The tests drive the REAL script with a fake `curl` (emits an N-file unified
diff), a fake `gh` (emits PR metadata for `pr view`), and a fake `node` (stands
in for the sanitizer, passing stdin through) on PATH.
"""

import subprocess
from pathlib import Path

from tests._helpers import REPO_ROOT

SCRIPT = REPO_ROOT / ".github" / "scripts" / "prepare-pr-review-input.sh"

# Each fake file section is this many lines (header + ---/+++ + @@ + one body
# line), so a diff's line count is a simple multiple of its file count.
LINES_PER_FILE = 5


def _fake_bins(tmp_path: Path, *, files: int, escape_byte: bool = False) -> None:
    """Put a fake `curl`, `gh`, and `node` (the sanitizer stand-in: cats stdin)
    on PATH. The fake `curl` emits a `files`-file unified diff unconditionally
    (curl carries no escape-sequence guard, unlike `gh`), and the fake `gh`
    answers `pr view` with PR metadata JSON. `escape_byte` adds one hunk
    holding a literal ESC byte, mirroring the payload `gh` would refuse to
    print but `curl` passes through untouched.
    """
    escape = ""
    if escape_byte:
        escape = (
            '  echo "diff --git a/escape.txt b/escape.txt"\n'
            '  echo "@@ -0,0 +1,1 @@"\n'
            '  printf "+escaped \x1b[31mred\x1b[0m line\\n"\n'
        )
    curl = tmp_path / "curl"
    curl.write_text(
        "#!/usr/bin/env bash\n"
        f"for ((i = 0; i < {files}; i++)); do\n"
        '  echo "diff --git a/f$i.py b/f$i.py"\n'
        '  echo "--- a/f$i.py"\n'
        '  echo "+++ b/f$i.py"\n'
        '  echo "@@ -0,0 +1,1 @@"\n'
        '  echo "+added line $i"\n'
        "done\n"
        f"{escape}",
        encoding="utf-8",
    )
    curl.chmod(0o755)
    gh = tmp_path / "gh"
    gh.write_text(
        "#!/usr/bin/env bash\n"
        'if [[ "$2" == "view" ]]; then\n'
        '  printf \'%s\' \'{"title":"t","body":"b","author":{"login":"a"},"files":[]}\'\n'
        "else\n"
        '  echo "fake gh: unexpected invocation: $*" >&2\n'
        "  exit 1\n"
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
    """gh's client-side guard refuses to print a diff holding a raw terminal
    escape byte (observed on #320, then again on #321's `gh api` swap, since
    the guard applies identically to both gh subcommands). #322 switched the
    fetch to `curl`, which carries no such guard. This proves the byte still
    reaches the sanitizer intact end to end."""
    proc, outputs, input_dir = _run(
        tmp_path, files=2, max_diff_lines=100, escape_byte=True
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["oversized"] == "false"
    sanitizer_saw = (tmp_path / "sanitizer_input").read_text(encoding="utf-8")
    assert "\x1b[31m" in sanitizer_saw, "the raw byte must reach the sanitizer intact"


def test_missing_gh_token_fails_loud(tmp_path: Path) -> None:
    """The curl-based fetch builds its own Authorization header, so it needs
    GH_TOKEN explicitly rather than relying on gh's ambient auth — assert the
    script's own `: "${GH_TOKEN:?}"` guard, not a curl 401 four steps later."""
    _fake_bins(tmp_path, files=1)
    env = {
        "PATH": f"{tmp_path}:/usr/bin:/bin",
        "GITHUB_OUTPUT": str(tmp_path / "github_output"),
        "SANITIZE_INPUT": str(tmp_path / "sanitizer_input"),
        "GH_REPO": "owner/repo",
        "PR": "123",
        "PR_INPUT_DIR": str(tmp_path / "pr-input"),
        "MAX_DIFF_LINES": "100",
    }
    proc = subprocess.run(
        ["bash", str(SCRIPT)], cwd=REPO_ROOT, capture_output=True, text=True, env=env
    )
    assert proc.returncode != 0
    assert "GH_TOKEN required" in proc.stderr
