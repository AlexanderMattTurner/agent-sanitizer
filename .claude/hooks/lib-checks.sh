#!/bin/bash
# Shared helpers for Claude Code hook scripts

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
cd "$PROJECT_DIR" || exit 1

exists() { command -v "$1" &>/dev/null; }

# has_script's delegate (script-configured.sh) parses package.json with jq.
# Without jq every lookup would abort mid-hook with an obscure exit code;
# require jq up front so the missing dependency fails the gate closed with a
# clear message instead.
if [[ -f package.json ]] && ! command -v jq &>/dev/null; then
  echo "lib-checks: jq is required to read package.json scripts but is not installed" >&2
  exit 1
fi

# Resolved beside this library, not under the project root: template-sync ships
# .claude/ and .github/scripts/ together. Parameter expansion, not `dirname`, so
# a caller with a bare PATH can still source this file.
_SCRIPT_CONFIGURED="${BASH_SOURCE[0]%/*}/../../.github/scripts/script-configured.sh"

# has_script NAME — is the package.json script NAME configured (present and not
# the template's ERROR: Configure placeholder)? Asks script-configured.sh, the
# one definition of that predicate, and passes its exit contract through:
# 0 = configured, 1 = not configured. A status of 2 or more means "could not
# classify" (malformed package.json, a jq failure, or the delegate itself
# missing), so it EXITS rather than returning: read as "not configured", it
# would skip real pre-push checks in silence (fail closed).
has_script() {
  local rc=0
  if [[ ! -f "$_SCRIPT_CONFIGURED" ]]; then
    echo "ERROR: lib-checks.sh: has_script needs $_SCRIPT_CONFIGURED, which is missing (failing closed)" >&2
    exit 2
  fi
  local rc=0
  # $BASH, not `bash`: the interpreter already running, so no PATH lookup.
  "$BASH" "$_SCRIPT_CONFIGURED" "$1" || rc=$?
  if ((rc >= 2)); then
    echo "lib-checks: script-configured.sh could not classify script \"$1\" (exit $rc); aborting instead of skipping checks" >&2
    exit 2
  fi
  return "$rc"
}
