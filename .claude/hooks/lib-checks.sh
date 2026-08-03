#!/bin/bash
# Shared helpers for Claude Code hook scripts

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
cd "$PROJECT_DIR" || exit 1

exists() { command -v "$1" &>/dev/null; }

# has_script parses package.json with jq. Without jq it would return "no such
# script" for everything, silently skipping every configured check (fail open).
# Require jq up front so a missing dependency fails the gate closed instead.
if [[ -f package.json ]] && ! command -v jq &>/dev/null; then
  echo "lib-checks: jq is required to read package.json scripts but is not installed" >&2
  exit 1
fi

has_script() {
  [[ -f package.json ]] || return 1
  local val
  # A jq parse failure means package.json is malformed, not that the script is
  # simply unconfigured — fail loudly instead of silently skipping checks.
  # Exit 2, matching .github/scripts/script-configured.sh's contract: >=2 means
  # "could not classify", distinct from 1 = "not configured".
  if ! val=$(jq -r --arg name "$1" '.scripts[$name] // empty' package.json 2>&1); then
    echo "ERROR: package.json is not valid JSON, cannot check for script \"$1\": $val" >&2
    exit 2
  fi
  [[ -n "$val" && "$val" != *"ERROR: Configure"* ]]
}
