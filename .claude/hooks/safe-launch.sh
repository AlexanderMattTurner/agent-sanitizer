#!/bin/bash
# Resilient launcher for PreToolUse hooks.
#
# Usage:  safe-launch.sh <hook-script> [args...]
#
# Wrap any PreToolUse hook with this script in settings.json so that a syntax
# error in the underlying hook (e.g. an unresolved merge conflict marker)
# can never lock the session.
#
# Behavior:
#   * Fast path — if <hook-script> parses cleanly, run it as a child with the
#     PreToolUse stdin payload forwarded transparently and its stdout (JSON
#     verdicts included) passed through verbatim. A runtime exit 2 from the
#     target — bash abort, argparse/grep/jq usage error, `set -e` propagation —
#     is Claude Code's hard-block signal and would lock the guarded tool, so it
#     is converted into a permissionDecision="ask" verdict instead. Contract:
#     a wrapped hook signals denial via JSON permissionDecision, NEVER exit 2;
#     any exit 2 that reaches this shim is treated as a fault, and the worst
#     case the user sees is a manual-approval prompt, not a lockout.
#   * Degraded path — if <hook-script> fails `bash -n`, fall back to a
#     fail-safe policy instead of exiting non-zero (which Claude Code would
#     treat as a tool block):
#       - Edit/Write/MultiEdit/NotebookEdit targeting .claude/hooks/ or
#         .hooks/ are allowed so the broken hook can be repaired in-session.
#       - Everything else returns permissionDecision="ask", forcing a
#         conscious user override on a tool-by-tool basis.
#
# This shim is itself guarded: .claude/settings.json invokes it through an
# inline bootstrap (`bash -n … && exec bash … ; printf <ask-verdict>`) so a
# parse error in THIS file also degrades to "ask" instead of a lockout.
# .github/scripts/validate-config.sh enforces that bootstrap shape.
#
# This mirrors the launcher shim from
# alexander-turner/secure-claude-code-defaults#109.

set -uo pipefail

target="${1:-}"
# Drop the target arg only when present; `|| true` would also swallow an
# unexpected shift failure (CLAUDE.md: branch on the condition instead).
[[ $# -gt 0 ]] && shift

# Emit a fail-closed PreToolUse "ask" verdict and print nothing else. A non-zero
# exit OR empty stdout is NON-blocking in Claude Code, so a missing/corrupt hook
# must still PRINT a verdict and exit 0 or the guarded tool sails through
# UNGUARDED (fail OPEN) — the whole reason this shim exists. The reason is
# JSON-escaped so a future non-literal reason can't break the JSON into a
# fail-open.
emit_ask() {
  local esc="${1//\\/\\\\}"
  esc="${esc//\"/\\\"}"
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"%s"}}\n' "$esc"
}

if [[ -z "$target" ]] || [[ ! -f "$target" ]]; then
  # Misconfigured hook path: no verdict source at all. Fail closed with an "ask"
  # instead of the non-blocking `exit 1` that would let the guarded tool run
  # unchecked (fail OPEN).
  echo "safe-launch: missing target hook: $target" >&2
  emit_ask "safe-launch: hook is missing; verdict unavailable — failing closed."
  exit 0
fi

# Language-aware syntax check + interpreter-explicit exec. Bash for shell hooks,
# node for JS. Running the target THROUGH its interpreter (not a bare
# `exec "$target"`) is a fail-closed guard: a target that lost its +x bit makes
# `exec "$target"` fail with 126, which Claude Code treats as NON-blocking, so the
# guarded tool would run unchecked (fail OPEN). `exec bash|node "$target"` ignores
# the mode bit and always runs the check.
case "$target" in
*.mjs | *.cjs | *.js)
  syntax_check=(node --check "$target")
  interp=node
  ;;
*)
  syntax_check=(bash -n "$target")
  interp=bash
  ;;
esac

# Fast path: target parses — run it via its interpreter as a CHILD, not an
# exec: an exec'd target that later dies with status 2 (bash abort, argparse/
# grep/jq usage error, `set -e` propagating an inner exit 2) becomes the hook's
# own exit code, which Claude Code treats as a HARD BLOCK — the lockout this
# shim exists to prevent. Stdout is buffered and replayed verbatim on any exit
# other than 2, so JSON verdicts (including a deliberate "deny") pass through
# untouched; stderr is captured for the ask reason and replayed to our stderr.
if "${syntax_check[@]}" 2>/dev/null; then
  err_snippet=""
  if stderr_file=$(mktemp 2>/dev/null) && [[ -n "$stderr_file" ]]; then
    out=$("$interp" "$target" "$@" 2>"$stderr_file")
    rc=$?
    cat "$stderr_file" >&2
    # JSON strings cannot carry raw control characters, and a byte-truncated
    # multibyte sequence would make the verdict invalid UTF-8 — keep printable
    # ASCII only, replaced in a single pass so nothing re-touches an escape.
    err_snippet=$(head -c 300 "$stderr_file" | tr -c '\40-\176' ' ' | tr -s ' ')
    rm -f "$stderr_file"
  else
    # mktemp unavailable: still guard the exit code, just without a captured
    # stderr snippet (the target's stderr streams through directly).
    out=$("$interp" "$target" "$@")
    rc=$?
  fi
  if [[ "$rc" -eq 2 ]]; then
    # Partial stdout from a crashed hook is not a trustworthy verdict — drop
    # it and emit the fail-soft "ask" instead of letting exit 2 hard-block.
    echo "safe-launch: target hook exited 2 at runtime — degrading hard block to ask: $target" >&2
    emit_ask "safe-launch: hook '$(basename "$target")' failed with exit 2 (${err_snippet:-no stderr}); manual override required."
    exit 0
  fi
  [[ -n "$out" ]] && printf '%s\n' "$out"
  exit "$rc"
fi

# Degraded path. Read the PreToolUse payload before we touch stdin again.
parse_error=$("${syntax_check[@]}" 2>&1)
echo "safe-launch: target hook failed to parse — degrading closed: $target" >&2
[[ -n "$parse_error" ]] && echo "$parse_error" >&2

# Cap the read at 10 MiB so a pathological payload can't OOM the degraded path.
# (No timeout: stdin is the in-flight PreToolUse payload, already fully buffered
# by Claude Code before the hook runs, so the read can't stall.)
payload=$(head -c 10485760)
project_dir="${CLAUDE_PROJECT_DIR:-$(pwd)}"

tool_name=""
tool_path=""
parser="$(dirname "$0")/safe-launch-parse.py"
if command -v python3 &>/dev/null && [[ -f "$parser" ]]; then
  parsed=$(printf '%s' "$payload" | python3 "$parser" "$project_dir" 2>/dev/null)
  tool_name=$(printf '%s\n' "$parsed" | sed -n '1p')
  tool_path=$(printf '%s\n' "$parsed" | sed -n '2p')
fi

# Lexical + symlink-resolving containment check. Fails closed: any error
# (missing parent dir, cd failure, unset args) returns non-zero so the
# caller falls through to the "ask" default.
is_under() {
  local candidate="$1" parent="$2" parent_dir resolved
  [[ -n "$candidate" ]] && [[ -n "$parent" ]] || return 1
  # Filter — a candidate with no ".." segment correctly falls through to the
  # containment check below; only a traversal-shaped path short-circuits here.
  # case-default-ok: no-match is the intended no-op, not a missed case.
  case "$candidate" in *..*) return 1 ;; esac
  # The parent dir is resolved with `pwd -P`, but the leaf is not: a symlinked
  # leaf (e.g. .claude/hooks/evil -> /etc/cron.d/x) would pass containment while
  # writes land outside. Reject a symlinked leaf outright.
  [[ -L "$candidate" ]] && return 1
  parent_dir=$(cd "$(dirname "$candidate")" 2>/dev/null && pwd -P) || return 1
  [[ -n "$parent_dir" ]] || return 1
  resolved="$parent_dir/$(basename "$candidate")"
  # A symlink at the final component could point outside the resolved parent
  # even though its own path lives under it. Fail closed rather than follow it.
  [[ -L "$resolved" ]] && return 1
  case "$resolved" in
  "$parent"/*) return 0 ;;
  *) return 1 ;;
  esac
}

# Filter — only edit-shaped tools get the self-repair containment check;
# every other tool name correctly falls through to the "ask" default below.
# case-default-ok: no-match is the intended fall-through, not a missed case.
case "$tool_name" in
Edit | Write | MultiEdit | NotebookEdit)
  for safe in "$project_dir/.claude/hooks" "$project_dir/.hooks"; do
    [[ -d "$safe" ]] || continue
    safe_resolved=$(cd "$safe" && pwd -P)
    if is_under "$tool_path" "$safe_resolved"; then
      echo "safe-launch: allowing self-repair edit under ${safe#"$project_dir/"}" >&2
      exit 0
    fi
  done
  ;;
esac

# Default: surface the failure as an "ask" decision so the user can choose.
emit_ask "safe-launch: PreToolUse hook failed to parse; manual override required."
exit 0
