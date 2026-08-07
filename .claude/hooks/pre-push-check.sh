#!/bin/bash
# Pre-push/PR hook: Runs configured checks before pushing or creating PRs.
# Only runs scripts that exist and are properly configured in package.json.
#
# Registered in .claude/settings.json as a PreToolUse hook on the "Bash" tool.
# Claude Code hook matchers filter on the tool NAME only — they do not match
# command patterns — so settings.json narrows to `git push` / `gh pr create`
# via each handler's `if` field. This in-script gate stays as defense in depth
# for Claude Code versions that ignore an unrecognized `if` key and fire the
# hook on every Bash call: we read the PreToolUse payload from stdin and gate
# on the command ourselves. Fail closed: if the command cannot be positively
# identified as something other than a push/PR-create, the checks run anyway.

set -uo pipefail

HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"

#######################################
# Command gate
#######################################

# stdin carries the PreToolUse payload, already fully buffered by Claude Code
# (so this read cannot stall). Extract .tool_input.command.
payload=$(cat)
command_str=""
if [[ -n "$payload" ]]; then
  if command -v jq >/dev/null 2>&1; then
    command_str=$(printf '%s' "$payload" | jq -r '.tool_input.command // empty' 2>/dev/null)
  elif command -v python3 >/dev/null 2>&1; then
    command_str=$(printf '%s' "$payload" |
      python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("tool_input", {}).get("command", ""))
except Exception:
    pass' 2>/dev/null)
  fi
fi

# A non-empty command that is neither a push nor a PR-create needs no checks.
# An empty command_str means we could not parse it — fall through and run the
# checks (fail closed).
if [[ -n "$command_str" ]]; then
  case "$command_str" in
  *"git push"* | *"gh pr create"*) : ;;
  *) exit 0 ;;
  esac
fi

#######################################
# Checks
#######################################

# shellcheck source=lib-checks.sh
source "$HOOK_DIR/lib-checks.sh"

FAILED=0

run_check() {
  local name="$1"
  shift
  local output
  if ! output=$("$@" 2>&1); then
    echo "=== $name FAILED ===" >&2
    echo "$output" >&2
    FAILED=1
  fi
}

# Node.js checks
if [[ -f package.json ]] && ! exists jq; then
  echo "=== node scripts FAILED ===" >&2
  echo "jq is required to detect which package.json scripts are configured, but is not installed." >&2
  FAILED=1
else
  has_script build && run_check "build" pnpm build
  has_script lint && run_check "lint" pnpm lint
  has_script check && run_check "typecheck" pnpm check
  has_script test && run_check "tests" pnpm test
fi

# Python checks. Fail closed: if the project is Python but no runner is
# available, that is a broken environment, not a reason to silently skip lint.
if [[ -f pyproject.toml ]] || [[ -f uv.lock ]]; then
  if [[ -f uv.lock ]] && exists uv; then
    run_check "ruff" uv run ruff check .
  elif exists ruff; then
    run_check "ruff" ruff check .
  else
    echo "=== ruff FAILED ===" >&2
    echo "Neither ruff nor uv (with uv.lock) is available to run Python checks." >&2
    FAILED=1
  fi
fi

exit $FAILED
