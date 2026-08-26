"""Tests for .github/scripts/fetch-security-report.sh.

Regression guard for the `gh api --arg` bug: `gh api` has no `--arg` flag, so the
old code aborted every call and only ever wrote the fallback text — real alerts
were never surfaced. This stubs `gh` with a seeded Dependabot alert and asserts
the alert actually appears in the report (a positive marker, not just "no error").
"""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    (shutil.which("jq") is None or shutil.which("bash") is None)
    and not os.environ.get("CI"),
    reason="jq and bash are required",
)

SEEDED_SUMMARY = "SEEDED_ADVISORY_lodash_prototype_pollution"

# A fake `gh` that returns a seeded Dependabot alert and empty results elsewhere.
# It branches on the API endpoint (its second arg), ignoring every other flag —
# including the `--jq` the real socket/pulls calls pass — so the socket loop sees
# no open PRs and does nothing.
FAKE_GH = f"""#!/usr/bin/env bash
endpoint="$2"
case "$endpoint" in
  *dependabot/alerts*)
    cat <<'JSON'
[{{"security_advisory":{{"severity":"high","summary":"{SEEDED_SUMMARY}"}},"number":42,"dependency":{{"package":{{"name":"lodash","ecosystem":"npm"}}}}}}]
JSON
    ;;
  *pulls*) : ;;
  *) echo "[]" ;;
esac
"""


def test_seeded_dependabot_alert_is_surfaced(tmp_path: Path, copy_script) -> None:
    script = copy_script("fetch-security-report.sh", tmp_path)

    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake_gh = bindir / "gh"
    fake_gh.write_text(FAKE_GH, encoding="utf-8")
    fake_gh.chmod(fake_gh.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    report = tmp_path / "report.md"
    env = {
        **os.environ,
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
        "GH_TOKEN": "x",
        "REPO": "owner/repo",
        "GITHUB_ENV": os.devnull,
        "REPORT_PATH": str(report),
    }
    result = subprocess.run(
        ["bash", str(script)], cwd=tmp_path, env=env, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    text = report.read_text(encoding="utf-8")
    # Positive marker: the seeded advisory (summary + severity + package) is
    # actually rendered, proving the gh->jq pipeline reads real alert data.
    assert SEEDED_SUMMARY in text, text
    assert "**HIGH**" in text, text
    assert "`lodash` (npm)" in text, text
    # And the fallback text must NOT be present — its appearance would mean the
    # call failed and we regressed to the swallowed-error behavior.
    assert "Could not fetch Dependabot alerts" not in text, text
