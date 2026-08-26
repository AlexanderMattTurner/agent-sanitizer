"""Tests for .github/scripts/phone-home-extract.js."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None and not os.environ.get("CI"),
    reason="node not available",
)

SCRIPT = REPO_ROOT / ".github" / "scripts" / "phone-home-extract.js"
# The script hardcodes this output dir, so these tests must run serially
# (no pytest-xdist); the autouse fixture clears it before/after each test.
PHONE_HOME_DIR = Path("/tmp/phone-home")


def run_extract(
    tmp_path: Path,
    pr_body: str,
    repo: str = "owner/repo",
    template_repo: str = "tmpl/repo",
) -> tuple[dict, subprocess.CompletedProcess]:
    """Invoke phone-home-extract.js with a mock github-script environment.

    The captured core.setOutput() values are written to a dedicated JSON file
    (not stdout) so the script's own console.log lines can't corrupt them."""
    wrapper = tmp_path / "run.js"
    out_file = tmp_path / "outputs.json"
    wrapper.write_text(
        f"""
const fs = require("fs");
const extract = require({json.dumps(str(SCRIPT))});
const outputs = {{}};
const core = {{ setOutput: (k, v) => {{ outputs[k] = v; }} }};
const [repoOwner, repoName] = (process.env.REPO || "owner/repo").split("/");
const context = {{
  payload: {{
    pull_request: {{
      body: process.env.PR_BODY || "",
      title: "Test PR",
      html_url: `https://github.com/${{process.env.REPO}}/pull/1`,
    }},
  }},
  repo: {{ owner: repoOwner, repo: repoName }},
}};
extract({{ context, core }}).then(() => {{
  fs.writeFileSync(process.env.OUT_FILE, JSON.stringify(outputs));
}}).catch((err) => {{
  process.stderr.write(err.message + "\\n");
  process.exit(1);
}});
""",
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "PR_BODY": pr_body,
        "REPO": repo,
        "TEMPLATE_REPO": template_repo,
        "OUT_FILE": str(out_file),
    }
    result = subprocess.run(
        ["node", str(wrapper)], env=env, capture_output=True, text=True
    )
    outputs: dict = {}
    if result.returncode == 0 and out_file.exists():
        try:
            outputs = json.loads(out_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            pytest.fail(
                f"wrapper wrote unparseable JSON {out_file.read_text(encoding='utf-8')!r}: {exc}"
            )
    return outputs, result


@pytest.fixture(autouse=True)
def clean_phone_home_dir():
    """Remove any stale lessons.txt before each test."""
    lessons = PHONE_HOME_DIR / "lessons.txt"
    lessons.unlink(missing_ok=True)
    yield
    lessons.unlink(missing_ok=True)


def test_extracts_lessons_with_double_hash(tmp_path: Path) -> None:
    pr_body = (
        "## Summary\n\nSome changes.\n\n"
        "## Lessons Learned\n\n"
        "- Use jq instead of node for JSON parsing.\n\n"
        "## Other\n\nNothing.\n"
    )
    outputs, result = run_extract(tmp_path, pr_body)
    assert result.returncode == 0, result.stderr
    assert outputs.get("has_lessons") == "true"
    content = (PHONE_HOME_DIR / "lessons.txt").read_text(encoding="utf-8")
    assert "Use jq instead of node for JSON parsing." in content
    assert "Nothing." not in content  # the following ## section must terminate


def test_extracts_lessons_with_triple_hash(tmp_path: Path) -> None:
    """### Lessons Learned (3 hashes) must be recognised and terminated by the
    next heading, regardless of that heading's level."""
    pr_body = (
        "## Summary\n\nSome changes.\n\n"
        "### Lessons Learned\n\n"
        "- Always validate input before processing.\n\n"
        "### Notes\n\nnoise-after-section.\n"
    )
    outputs, result = run_extract(tmp_path, pr_body)
    assert result.returncode == 0, result.stderr
    assert outputs.get("has_lessons") == "true"
    content = (PHONE_HOME_DIR / "lessons.txt").read_text(encoding="utf-8")
    assert "Always validate input before processing." in content
    assert "noise-after-section." not in content


def test_lessons_not_cut_short_by_internal_blank_line(tmp_path: Path) -> None:
    """Multi-paragraph lessons must not be truncated at the first blank line."""
    pr_body = (
        "## Lessons Learned\n\n- First bullet.\n\n- Second bullet after blank line.\n"
    )
    outputs, result = run_extract(tmp_path, pr_body)
    assert result.returncode == 0, result.stderr
    assert outputs.get("has_lessons") == "true"
    content = (PHONE_HOME_DIR / "lessons.txt").read_text(encoding="utf-8")
    assert "First bullet." in content
    assert "Second bullet after blank line." in content


def test_skips_when_no_lessons_section(tmp_path: Path) -> None:
    pr_body = "## Summary\n\nSome changes.\n\n## Notes\n\nNothing here.\n"
    outputs, result = run_extract(tmp_path, pr_body)
    assert result.returncode == 0, result.stderr
    assert "has_lessons" not in outputs


def test_skips_empty_lessons_section(tmp_path: Path) -> None:
    pr_body = "## Lessons Learned\n\n\n\n## Other Section\n\nContent.\n"
    outputs, result = run_extract(tmp_path, pr_body)
    assert result.returncode == 0, result.stderr
    assert "has_lessons" not in outputs


def test_skips_template_repo(tmp_path: Path) -> None:
    pr_body = "## Lessons Learned\n\n- Important lesson.\n"
    outputs, result = run_extract(
        tmp_path, pr_body, repo="tmpl/repo", template_repo="tmpl/repo"
    )
    assert result.returncode == 0, result.stderr
    assert "has_lessons" not in outputs


def test_filters_session_links(tmp_path: Path) -> None:
    pr_body = (
        "## Lessons Learned\n\n"
        "- Real lesson here.\n"
        "https://claude.ai/code/session_abc123\n"
    )
    outputs, result = run_extract(tmp_path, pr_body)
    assert result.returncode == 0, result.stderr
    assert outputs.get("has_lessons") == "true"
    content = (PHONE_HOME_DIR / "lessons.txt").read_text(encoding="utf-8")
    assert "claude.ai" not in content
