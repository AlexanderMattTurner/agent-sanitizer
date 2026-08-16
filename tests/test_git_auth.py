"""Behavior tests for .github/scripts/lib-git-auth.sh.

The guarantee under test: the credential git is handed reaches github.com and
nothing else. `http.extraheader` written without a URL scope is a repo-wide
default, so git sends it to whatever host the operation ends up talking to — a
redirect, an `insteadOf` rewrite, a submodule URL. `git config --get-urlmatch`
is git's own resolver for that question, so these tests ask it rather than
inspecting the key's spelling.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from tests._helpers import (
    REPO_ROOT,
    commit_all,
    env_without_git_location,
    git_env,
    init_test_repo,
)

LIB = REPO_ROOT / ".github" / "scripts" / "lib-git-auth.sh"
DECIDE = REPO_ROOT / ".github" / "scripts" / "decide-reusable-diff.sh"

GITHUB_URL = "https://github.com/owner/repo.git"
OTHER_HOST_URL = "https://attacker.example/owner/repo.git"

#: The bare key the helper replaces, kept as the control case below.
UNSCOPED_KEY = "http.extraheader"


def without_git_config(env: dict[str, str]) -> dict[str, str]:
    """`env` with git's own config injection removed.

    A caller can already have GIT_CONFIG_COUNT and friends set (an agent
    sandbox does), and those settings both answer `--get-urlmatch` and survive
    into the scripts under test — so a test that asks what the helper put there
    must start from a known-empty baseline.
    """
    return {k: v for k, v in env.items() if not k.startswith("GIT_CONFIG_")}


def clean_env() -> dict[str, str]:
    return without_git_config(env_without_git_location())


def bash(script: str, *args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", script, "bash", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=clean_env(),
    )


def urlmatch(repo: Path, config: str, url: str) -> subprocess.CompletedProcess:
    """What git resolves `http.extraheader` to for `url`, given one `-c` setting."""
    return subprocess.run(
        ["git", "-c", config, "config", "--get-urlmatch", "http.extraheader", url],
        cwd=repo,
        capture_output=True,
        text=True,
        env=clean_env(),
    )


def auth_config(repo: Path, token: str = "s3cret") -> str:
    """The `-c` argument the helper builds, as the scripts assemble it."""
    built = bash(
        f'. "{LIB}"; git_auth_header_value auth "$1"; '
        "printf '%s\\n' \"$GIT_AUTH_HEADER_KEY=$auth\"",
        token,
        cwd=repo,
    )
    assert built.returncode == 0, built.stderr
    return built.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    sandbox = tmp_path / "repo"
    init_test_repo(sandbox)
    return sandbox


def test_the_header_reaches_github(repo: Path) -> None:
    resolved = urlmatch(repo, auth_config(repo), GITHUB_URL)
    assert resolved.returncode == 0, resolved.stderr
    assert resolved.stdout.strip().startswith("AUTHORIZATION: basic ")


def test_the_header_does_not_reach_another_host(repo: Path) -> None:
    """The property the scoped key buys, asked of git's own resolver."""
    resolved = urlmatch(repo, auth_config(repo), OTHER_HOST_URL)
    assert resolved.returncode != 0
    assert resolved.stdout == ""


def test_an_unscoped_header_would_reach_every_host(repo: Path) -> None:
    """Non-vacuity control: the bare `http.extraheader` spelling this helper
    replaces hands the same token to an unrelated host, so the assertion above
    is a real constraint rather than a property git gives away for free."""
    resolved = urlmatch(
        repo, f"{UNSCOPED_KEY}=AUTHORIZATION: basic leak", OTHER_HOST_URL
    )
    assert resolved.returncode == 0, resolved.stderr
    assert resolved.stdout.strip() == "AUTHORIZATION: basic leak"


def test_the_per_command_helper_leaves_the_environment_alone(repo: Path) -> None:
    """A caller that needs auth on ONE command must not re-point git's config for
    whatever else the job runs afterwards, so the value-builder exports nothing."""
    built = bash(
        f'. "{LIB}"; git_auth_header_value auth "$1"; '
        'printf \'%s\\n\' "${GIT_CONFIG_COUNT:-unset}" "${GIT_CONFIG_KEY_0:-unset}"',
        "s3cret",
        cwd=repo,
    )
    assert built.returncode == 0, built.stderr
    assert built.stdout == "unset\nunset\n"


def test_the_process_wide_helper_scopes_the_same_key(repo: Path) -> None:
    """The multi-step flows keep the exported form; it must be the same scope."""
    built = bash(
        f'. "{LIB}"; git_auth_header "$1"; '
        'printf \'%s\\n\' "$GIT_CONFIG_COUNT" "$GIT_CONFIG_KEY_0"',
        "s3cret",
        cwd=repo,
    )
    assert built.returncode == 0, built.stderr
    assert built.stdout == "1\nhttp.https://github.com/.extraheader\n"


@pytest.mark.parametrize(
    "call", ("git_auth_header_value auth ''", 'git_auth_header ""')
)
def test_a_missing_token_is_loud(repo: Path, call: str) -> None:
    """An empty token must abort, never authenticate as nobody: the header would
    still be sent, and the failure would surface as an unrelated 404."""
    result = bash(f'. "{LIB}"; {call}', cwd=repo)
    assert result.returncode != 0
    assert "token required" in result.stderr


def stub_git(bin_dir: Path, record: Path) -> None:
    """A `git` that records one fetch's argv and auth environment, then stops.

    Every other subcommand runs the real git, so the script under test keeps
    diffing the local history it was given.
    """
    real = shutil.which("git")
    assert real, "git must be on PATH"
    bin_dir.mkdir(parents=True, exist_ok=True)
    stub = bin_dir / "git"
    stub.write_text(
        "#!/bin/bash\n"
        'if [[ " $* " == *" fetch "* ]]; then\n'
        f'  printf "argv:%s\\n" "$*" >>"{record}"\n'
        f'  printf "key0:%s\\n" "${{GIT_CONFIG_KEY_0:-none}}" >>"{record}"\n'
        "  exit 1\n"
        "fi\n"
        f'exec {real} "$@"\n'
    )
    stub.chmod(0o755)


def test_the_base_reanchor_fetch_scopes_its_header(tmp_path: Path) -> None:
    """decide-reusable-diff.sh re-anchors to the live base tip over the network.

    Before this fix it passed `-c http.extraheader=…` on that fetch, which is
    the repo-wide default the control case above shows reaches any host. The
    stub reports what the fetch was actually handed.
    """
    sandbox = tmp_path / "repo"
    init_test_repo(sandbox)
    (sandbox / "src").mkdir()
    (sandbox / "src" / "app.mjs").write_text("export const x = 1;\n")
    base = commit_all(sandbox, "chore: base")
    (sandbox / "src" / "app.mjs").write_text("export const x = 2;\n")
    head = commit_all(sandbox, "fix: edit")

    record = tmp_path / "fetch.log"
    stub_git(tmp_path / "bin", record)
    env = without_git_config(git_env())
    result = subprocess.run(
        ["bash", str(DECIDE)],
        cwd=sandbox,
        capture_output=True,
        text=True,
        env={
            **env,
            "PATH": f"{tmp_path / 'bin'}:{env['PATH']}",
            "GITHUB_OUTPUT": str(tmp_path / "out"),
            "BASE_SHA": base,
            "HEAD_SHA": head,
            "BASE_REF": "main",
            "GH_TOKEN": "s3cret",
            "PATHS_REGEX": "^src/",
        },
    )
    assert result.returncode == 0, result.stderr
    recorded = record.read_text()
    assert "-c http.https://github.com/.extraheader=AUTHORIZATION: basic " in recorded
    assert f"-c {UNSCOPED_KEY}=" not in recorded, recorded
    # Per-command, so the fetch's own environment must carry no auth override —
    # whatever else the job runs after this step keeps git's config unchanged.
    assert "key0:none\n" in recorded, recorded
