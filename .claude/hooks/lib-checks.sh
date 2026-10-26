#!/bin/bash
# Shared helpers for Claude Code hook scripts

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
cd "$PROJECT_DIR" || exit 1

exists() { command -v "$1" &>/dev/null; }

<<<<<<< local
# has_script's delegate (script-configured.sh) parses package.json with jq.
# Without jq every lookup would abort mid-hook with an obscure exit code;
# require jq up front so the missing dependency fails the gate closed with a
# clear message instead.
if [[ -f package.json ]] && ! command -v jq &>/dev/null; then
  echo "lib-checks: jq is required to read package.json scripts but is not installed" >&2
  exit 1
fi

# has_script delegates to .github/scripts/script-configured.sh — the one
# definition of "is this package.json script configured (present and not the
# template's ERROR: Configure placeholder)". Its exit contract passes through:
# 0 = configured, 1 = not configured; >=2 means "could not classify" (malformed
# package.json, jq failure, or the script itself missing) and aborts the hook
# loudly instead of silently skipping checks (fail closed).
||||||| base
=======
# Resolved beside this library, not under the project root: template-sync ships
# .claude/ and .github/scripts/ together. Parameter expansion, not `dirname`, so
# a caller with a bare PATH can still source this file.
_SCRIPT_CONFIGURED="${BASH_SOURCE[0]%/*}/../../.github/scripts/script-configured.sh"

# has_script NAME — is the package.json script NAME configured? Asks
# script-configured.sh, the one definition of that predicate. A status of 2 or
# more means "could not classify", so it EXITS 2 rather than returning: read as
# "not configured", it would skip real pre-push checks in silence.
>>>>>>> template
has_script() {
<<<<<<< local
  local sc="$PROJECT_DIR/.github/scripts/script-configured.sh" rc=0
  if [[ ! -f "$sc" ]]; then
    echo "lib-checks: $sc is missing; cannot check package.json scripts (failing closed)" >&2
||||||| base
  [[ -f package.json ]] || return 1
  local val
  # A jq parse failure means package.json is malformed, not that the script is
  # simply unconfigured — fail loudly instead of silently skipping checks.
  # Exit 2, matching .github/scripts/script-configured.sh's contract: >=2 means
  # "could not classify", distinct from 1 = "not configured".
  if ! val=$(jq -r --arg name "$1" '.scripts[$name] // empty' package.json 2>&1); then
    echo "ERROR: package.json is not valid JSON, cannot check for script \"$1\": $val" >&2
=======
  if [[ ! -f "$_SCRIPT_CONFIGURED" ]]; then
    echo "ERROR: lib-checks.sh: has_script needs $_SCRIPT_CONFIGURED, which is missing" >&2
>>>>>>> template
    exit 2
  fi
<<<<<<< local
  bash "$sc" "$1" || rc=$?
  if ((rc >= 2)); then
    echo "lib-checks: script-configured.sh could not classify script \"$1\" (exit $rc); aborting instead of skipping checks" >&2
    exit "$rc"
  fi
  return "$rc"
||||||| base
  [[ -n "$val" && "$val" != *"ERROR: Configure"* ]]
=======
  local rc=0
  # $BASH, not `bash`: the interpreter already running, so no PATH lookup.
  "$BASH" "$_SCRIPT_CONFIGURED" "$1" || rc=$?
  ((rc >= 2)) && exit 2
  return "$rc"
>>>>>>> template
}
