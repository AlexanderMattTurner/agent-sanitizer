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

# has_script delegates to .github/scripts/script-configured.sh — the one
# definition of "is this package.json script configured (present and not the
# template's ERROR: Configure placeholder)". Its exit contract passes through:
# 0 = configured, 1 = not configured; >=2 means "could not classify" (malformed
# package.json, jq failure, or the script itself missing) and aborts the hook
# loudly instead of silently skipping checks (fail closed).
has_script() {
  local sc="$PROJECT_DIR/.github/scripts/script-configured.sh" rc=0
  if [[ ! -f "$sc" ]]; then
    echo "lib-checks: $sc is missing; cannot check package.json scripts (failing closed)" >&2
    exit 2
  fi
  bash "$sc" "$1" || rc=$?
  if ((rc >= 2)); then
    echo "lib-checks: script-configured.sh could not classify script \"$1\" (exit $rc); aborting instead of skipping checks" >&2
    exit "$rc"
  fi
  return "$rc"
}
