#!/bin/bash
# Session setup script for Claude Code
# Installs dependencies and configures environment for git hooks

set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

#######################################
# Helpers
#######################################

SETUP_WARNINGS=0
warn() {
  echo "WARNING: $1" >&2
  SETUP_WARNINGS=$((SETUP_WARNINGS + 1))
}
is_root() { [ "$(id -u)" = "0" ]; }

# Install a command via uv if missing
uv_install_if_missing() {
  local cmd="$1" pkg="${2:-$1}"
  if ! command -v "$cmd" &>/dev/null; then
    uv tool install --quiet "$pkg" || warn "Failed to install $pkg"
  fi
}

# Install a Go-based tool at a PINNED version via `go install module@vX.Y.Z`.
# $1 = command name, $2 = module path with an explicit @version.
# This replaced a `curl https://webi.sh/... | sh` bootstrap, which fetched and
# executed a dynamically generated installer with NO integrity check — a
# fetch-and-run-remote-code supply-chain hole squarely in this repo's threat
# model. `go install` instead pins the version AND verifies every module against
# the Go checksum database (sum.golang.org) before building, so the bytes cannot
# be swapped by a compromised mirror. It downloads nothing via curl/wget, so
# there is no artifact for check-pinned-downloads to flag and no exemption.
# Returns non-zero (without warning) when go is absent so the caller can fall
# back to the signed-apt path.
go_install_pinned() {
  local cmd="$1" module="$2"
  command -v "$cmd" &>/dev/null && return 0
  command -v go &>/dev/null || return 1
  go install "$module" || {
    warn "Failed to install $cmd via go install ($module)"
    return 1
  }
}

# Install a command from the OS package manager if missing. apt verifies every
# package against the distro's signed repository metadata — genuine integrity,
# and (like go install) no curl artifact for check-pinned-downloads to flag.
# Only possible as root on a Debian-family image; elsewhere the tool — an
# optional dev convenience the hooks warn-and-continue without, and which CI
# installs properly — is left uninstalled. That is strictly safer than fetching
# and running an unverified remote installer.
apt_updated=0
apt_install_if_missing() {
  local cmd="$1" pkg="${2:-$1}"
<<<<<<< local
  command -v "$cmd" &>/dev/null && return 0
  if ! is_root || ! command -v apt-get &>/dev/null; then
    warn "$cmd not found and cannot be auto-installed (needs root + apt); install it manually"
    return 0
  fi
  if [ "$apt_updated" -eq 0 ]; then
    apt-get update -qq || warn "apt-get update failed"
    apt_updated=1
||||||| base
  if ! command -v "$cmd" &>/dev/null; then
    local installer
    installer=$(mktemp "${TMPDIR:-/tmp}/webi-${cmd}-XXXXXX.sh")
    # webi.sh serves a per-tool bootstrap generated on the fly, so there is no
    # stable digest to pin; we harden with HTTPS-only (--proto =https), the
    # shebang check below, and a version-pinned $pkg instead.
    # pin-exempt: webi.sh bootstrap is generated per-request, no stable digest
    if curl --proto '=https' -fsSL "https://webi.sh/$pkg" -o "$installer" 2>/dev/null; then
      first_line="$(head -n 1 "$installer")"
      if grep -q '^#!' <<<"$first_line"; then
        sh "$installer" >/dev/null 2>&1 || warn "Failed to install $cmd"
      else
        warn "Installer for $cmd is not a shell script (missing shebang) — skipping"
      fi
    else
      warn "Failed to download installer for $cmd"
    fi
    rm -f "$installer"
=======
  if ! command -v "$cmd" &>/dev/null; then
    local installer
    installer=$(mktemp "${TMPDIR:-/tmp}/webi-${cmd}-XXXXXX.sh")
    # webi.sh serves a per-tool bootstrap generated on the fly, so there is no
    # stable digest to pin; we harden with HTTPS-only (--proto =https), the
    # shebang check below, and a version-pinned $pkg instead.
    # pin-exempt: webi.sh bootstrap is generated per-request, no stable digest
    if curl --proto '=https' -fsSL --retry 3 --retry-delay 2 "https://webi.sh/$pkg" -o "$installer" 2>/dev/null; then
      first_line="$(head -n 1 "$installer")"
      if grep -q '^#!' <<<"$first_line"; then
        sh "$installer" >/dev/null 2>&1 || warn "Failed to install $cmd"
      else
        warn "Installer for $cmd is not a shell script (missing shebang) — skipping"
      fi
    else
      warn "Failed to download installer for $cmd"
    fi
    rm -f "$installer"
>>>>>>> template
  fi
  apt-get install -y -qq "$pkg" || warn "Failed to install $pkg"
}

#######################################
# Hook syntax validation
#######################################

# A hook script with a syntax error (e.g. unresolved merge conflict markers)
# exits non-zero before any logic runs, which Claude Code treats as a block.
# Surface broken hooks at session start so they can be fixed before the first
# tool call dies with no explanation.
_check_hook_syntax() {
  local dir file out
  for dir in "$PROJECT_DIR/.claude/hooks" "$PROJECT_DIR/.hooks"; do
    [ -d "$dir" ] || continue
    while IFS= read -r -d '' file; do
      # Filter — only extensions this function knows how to syntax-check are
      # handled; any other file is correctly skipped.
      # case-default-ok: no-match is the intended no-op, not a missed case.
      case "$file" in
      *.sh | *.bash)
        if ! out=$(bash -n "$file" 2>&1); then
          warn "hook has bash syntax error: ${file#"$PROJECT_DIR/"}"
          [ -n "$out" ] && echo "$out" >&2
        fi
        ;;
      *.py)
        if command -v python3 &>/dev/null && ! out=$(python3 -m py_compile "$file" 2>&1); then
          warn "hook has python syntax error: ${file#"$PROJECT_DIR/"}"
          [ -n "$out" ] && echo "$out" >&2
        fi
        ;;
      esac
    done < <(find "$dir" -maxdepth 1 -type f -print0)
  done
}

_check_hook_syntax

#######################################
# PATH setup
#######################################

export PATH="$HOME/.local/bin:$PATH"
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >>"$CLAUDE_ENV_FILE"
fi

# Put the Go install bin dir on PATH so a `go install`-ed tool (shfmt) is
# discoverable by `command -v` below and by later hooks.
if command -v go &>/dev/null; then
  gobin="$(go env GOBIN)"
  [ -n "$gobin" ] || gobin="$(go env GOPATH)/bin"
  export PATH="$gobin:$PATH"
  if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
    echo "export PATH=\"$gobin:\$PATH\"" >>"$CLAUDE_ENV_FILE"
  fi
fi

#######################################
# Tool installation (optional - warn on failure)
#######################################

<<<<<<< local
# Install dev tools with a genuine integrity mechanism — never an unverified
# remote installer. shfmt is a Go module, so pin it and let the Go checksum DB
# verify it; fall back to signed apt if go is unavailable. gh/jq/shellcheck come
# from apt's signed repositories. All are optional: on a non-root or non-Debian
# host without go they are skipped with a warning, and CI installs them properly.
# shfmt is pinned to match .pre-commit-config.yaml (shfmt v3.12.0) so local
# lint-staged formatting matches CI.
go_install_pinned shfmt "mvdan.cc/sh/v3/cmd/shfmt@v3.12.0" || apt_install_if_missing shfmt
apt_install_if_missing gh
apt_install_if_missing jq
apt_install_if_missing shellcheck
||||||| base
# Install tools quietly — only warn on failure (versions pinned for supply-chain safety)
webi_install_if_missing shfmt shfmt@3
webi_install_if_missing gh gh@2
webi_install_if_missing jq jq@1.7
if ! command -v shellcheck &>/dev/null && is_root; then
  { apt-get update -qq && apt-get install -y -qq shellcheck; } || warn "Failed to install shellcheck"
fi
=======
# Install tools quietly — only warn on failure (versions pinned for supply-chain safety)
webi_install_if_missing shfmt shfmt@3
webi_install_if_missing gh gh@2
webi_install_if_missing jq jq@1.7
if ! command -v shellcheck &>/dev/null && is_root; then
  # pin-exempt: last-resort session-bootstrap fallback; apt's shellcheck version
  # varies by base image, and the authoritative pin is the shellcheck-py
  # pre-commit hook's rev, not this fallback binary.
  { apt-get update -qq && apt-get install -y -qq shellcheck; } || warn "Failed to install shellcheck"
fi
>>>>>>> template

# Python projects: the pre-commit and pre-push hooks shell out to ruff, which
# isn't a project dependency. Install it (pinned to match .pre-commit-config.yaml
# so local hooks format identically to CI). Skip for non-Python repos.
if { [ -f "$PROJECT_DIR/pyproject.toml" ] || [ -f "$PROJECT_DIR/uv.lock" ]; } && command -v uv &>/dev/null; then
  uv_install_if_missing ruff "ruff==0.14.5"
  uv_install_if_missing zizmor "zizmor==1.25.2"
fi

#######################################
# Git setup
#######################################

cd "$PROJECT_DIR" || exit 1
git config core.hooksPath .hooks

# Pre-fetch the base branch so diffs against $CLAUDE_CODE_BASE_REF work
# immediately (e.g. when creating PRs). Failure is non-fatal.
<<<<<<< local
if [ -n "${CLAUDE_CODE_BASE_REF:-}" ]; then
  timeout --kill-after=10 60 git fetch origin "$CLAUDE_CODE_BASE_REF" --quiet 2>/dev/null ||
||||||| base
if [[ -n "${CLAUDE_CODE_BASE_REF:-}" ]]; then
  git fetch origin "$CLAUDE_CODE_BASE_REF" --quiet 2>/dev/null ||
=======
if [[ -n "${CLAUDE_CODE_BASE_REF:-}" ]]; then
  timeout --kill-after=10 60 git fetch origin "$CLAUDE_CODE_BASE_REF" --quiet 2>/dev/null ||
>>>>>>> template
    warn "Failed to fetch base branch $CLAUDE_CODE_BASE_REF"
fi

#######################################
# Syntax-aware merges (mergiraf)
#######################################

# .gitattributes marks file types `merge=mergiraf`, and every one of those
# attributes is INERT until this checkout has the binary on PATH and
# merge.mergiraf.driver in its git config. Git says nothing when either is
# missing — it falls back to its built-in line merge — so a session resolving a
# conflict by hand silently got the line merge. CI registers the driver in
# template-sync's checkout and nowhere else; this is the session's half.
#
# .github/scripts/install-mergiraf.sh owns the pinned download, the sha256
# refusal, the `solve -p` contract probe, the `git config` pair, and the skip
# when all of them already hold, so this only calls it and reports.
install_mergiraf() {
  local installer="$PROJECT_DIR/.github/scripts/install-mergiraf.sh"
  [[ -f "$installer" ]] || return 0

  # The installer downloads a linux_amd64 asset and reads it with sha256sum, so
  # on any other host it would install a binary that cannot run. Say so rather
  # than warn about a download that was never going to work.
  if [[ "$(uname -s) $(uname -m)" != "Linux x86_64" ]]; then
    echo "mergiraf: no pinned asset for $(uname -s)/$(uname -m) — this checkout keeps git's line merge" >&2
    return 0
  fi

  local bindir="$HOME/.local/bin"
  mkdir -p "$bindir" # bare-mkdir-ok: the post-condition is checked on the next line
  [[ -d "$bindir" ]] || {
    warn "mergiraf: $bindir is not a directory — merges use git's line merge"
    return 0
  }

  # A warn, not an exit: every other tool here is optional, and a session with no
  # mergiraf must still start. It merges as it did before the attributes existed.
  # The bound is on the whole install because curl's --connect-timeout does not
  # cap an established transfer, so a stalled download would hang session start.
  local rc=0
  (cd "$PROJECT_DIR" && timeout --kill-after=10 300 bash "$installer" "$bindir") >/dev/null || rc=$?
  # --local because that is the only scope install-mergiraf.sh writes: a global
  # driver, which mergiraf's own setup docs tell users to register, would
  # otherwise answer here and silence both warns.
  local bound
  bound="$(git -C "$PROJECT_DIR" config --local --get merge.mergiraf.driver)" || bound=""

  if [[ "$rc" -eq 0 ]]; then
    # The post-condition, not the exit status: install-mergiraf.sh exits 0 after
    # installing the binary when git refuses the checkout (dubious ownership),
    # which leaves every merge=mergiraf attribute inert and says nothing.
    [[ -n "$bound" ]] ||
      warn "mergiraf installed but merge.mergiraf.driver is unset — merges use git's line merge"
  elif [[ -n "$bound" ]]; then
    # A download or digest refusal aborts BEFORE the binary is replaced, so an
    # earlier run's driver is still bound and still merging — through a version
    # this run did not verify. Saying "line merge" here would name the one
    # outcome that is not happening.
    warn "Failed to install mergiraf — merges keep using the already-bound driver, not git's line merge"
  else
    warn "Failed to install mergiraf — merges in this checkout use git's line merge"
  fi
}

install_mergiraf

#######################################
# GitHub CLI auth
#######################################

if ! command -v gh &>/dev/null; then
  warn "gh CLI not found"
elif [ -z "${GH_TOKEN:-}" ]; then
  warn "GH_TOKEN is not set — GitHub CLI requires authentication"
fi

#######################################
# GitHub repo detection for proxy environments
#######################################

# In Claude Code web sessions, git remotes use a local proxy URL like:
#   http://local_proxy@127.0.0.1:18393/git/owner/repo
# The gh CLI can't detect the GitHub repo from this, so we extract
# owner/repo and export GH_REPO to make all gh commands work.

if [ -z "${GH_REPO:-}" ]; then
  remote_url=$(git -C "$PROJECT_DIR" remote get-url origin 2>/dev/null)
  # Anchor to the real local-proxy host authority — the same predicate the
  # web-session permission grant below uses. A bare /git/owner/repo suffix on a
  # hostile origin (e.g. https://attacker.example/git/evil/repo) must not be
  # allowed to redirect every subsequent gh command at an attacker's repo.
  # BASH_REMATCH[1] is the optional port group; owner/repo is [2].
  if [[ "$remote_url" =~ ^https?://[^/@]*@127\.0\.0\.1(:[0-9]+)?/git/([^/]+/[^/]+)$ ]]; then
    GH_REPO="${BASH_REMATCH[2]}"
    GH_REPO="${GH_REPO%.git}"
    export GH_REPO
    if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
      echo "export GH_REPO=\"$GH_REPO\"" >>"$CLAUDE_ENV_FILE"
    fi
  fi
fi

#######################################
# Web-session permissions
#######################################

# In web sessions (detected by proxy remote URL), grant Claude Code
# permission to modify its own .claude/ folder without prompting.
remote_url="${remote_url:-$(git -C "$PROJECT_DIR" remote get-url origin 2>/dev/null)}"
if [[ "$remote_url" =~ ^https?://[^/@]*@127\.0\.0\.1(:[0-9]+)?/git/ ]]; then
  local_settings="$PROJECT_DIR/.claude/settings.local.json"
  if [ ! -f "$local_settings" ]; then
    # Grant self-edit only over non-executable Claude assets (skills), and
    # explicitly DENY the paths that become code the next session executes:
    # the hooks and the settings files themselves. A blanket Edit/Write(.claude/**)
    # would let a prompt-injected session rewrite its own PreToolUse/SessionStart
    # hooks — silent escalation to arbitrary code execution on the next launch.
    # deny wins over allow, so the deny entries below are the hard boundary.
    cat >"$local_settings" <<'SETTINGS'
{
  "permissions": {
    "allow": [
      "Edit(.claude/skills/**)",
      "Write(.claude/skills/**)",
      "Read(.claude/**)",
      "Bash(pnpm build)",
      "Bash(pnpm check:*)",
      "Bash(pnpm format)",
      "Bash(pnpm install)",
      "Bash(pnpm lint:*)",
      "Bash(pnpm test:*)",
      "Bash(pre-commit run:*)",
      "Bash(uv run pytest:*)"
    ],
    "deny": [
      "Edit(.claude/hooks/**)",
      "Write(.claude/hooks/**)",
      "Edit(.claude/settings*.json)",
      "Write(.claude/settings*.json)"
    ]
  }
}
SETTINGS
  fi
fi

#######################################
# Project dependencies
#######################################

if [ -f "$PROJECT_DIR/package.json" ]; then
  # Always run install (git hooks are configured in package.json postinstall)
  if command -v pnpm &>/dev/null; then
    pnpm install --silent || warn "Failed to install Node dependencies"
  elif command -v npm &>/dev/null; then
    npm install --silent || warn "Failed to install Node dependencies"
  fi
fi

if [ -f "$PROJECT_DIR/uv.lock" ] && command -v uv &>/dev/null; then
  uv sync --quiet || warn "Failed to sync Python dependencies"
  # Add .venv/bin to PATH so Python tools are available to hooks
  if [ -d "$PROJECT_DIR/.venv/bin" ]; then
    export PATH="$PROJECT_DIR/.venv/bin:$PATH"
    if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
      echo "export PATH=\"$PROJECT_DIR/.venv/bin:\$PATH\"" >>"$CLAUDE_ENV_FILE"
    fi
  fi
fi

#######################################
# Verify the END STATE, through the consumer's own resolution
#######################################

# Every install above warns when the INSTALL fails, and nothing checked whether
# the tool ended up reachable by the thing that needs it. Those are different
# questions, and the gap between them is silent: `shfmt` installed fine into the
# Go bin directory, which git hooks — a bare shell, no CLAUDE_ENV_FILE — could
# not see, so the first symptom was `Task failed to spawn: shfmt … ENOENT` from
# lint-staged in the middle of a commit. Resolve exactly as .hooks/lib-gate.sh
# does rather than testing this shell's PATH, so what is verified is what the
# hooks will actually find.
if [ -f "$PROJECT_DIR/.hooks/lib-gate.sh" ]; then
  (
    # shellcheck source=.hooks/lib-gate.sh
    source "$PROJECT_DIR/.hooks/lib-gate.sh"
    gate_tool_path "$PROJECT_DIR"
    missing=""
    for tool in shfmt shellcheck pytest node; do
      command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
    done
    if [ -n "$missing" ]; then
      echo "WARNING: the git hooks will not find:$missing" >&2
      echo "  A commit that needs one fails with a bare ENOENT from the tool that ran it," >&2
      echo "  which names the symptom and not the cause. Re-run this script, or install the" >&2
      echo "  tool by hand — see the install helpers at the top of .claude/hooks/session-setup.sh." >&2
      exit 1
    fi
  ) || SETUP_WARNINGS=$((SETUP_WARNINGS + 1))
fi

if [ "$SETUP_WARNINGS" -gt 0 ]; then
  echo "Setup done with $SETUP_WARNINGS warning(s) — see above" >&2
fi
