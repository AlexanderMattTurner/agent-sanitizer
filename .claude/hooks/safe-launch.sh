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
#     is degraded per the posture knob instead. Contract: a wrapped hook signals
#     denial via JSON permissionDecision, NEVER exit 2; any exit 2 that reaches
#     this shim is treated as a fault, never as policy.
#   * Degraded path — if <hook-script> fails `bash -n`, fall back to a policy
#     instead of exiting non-zero (which Claude Code would treat as a block):
#       - Edit/Write/MultiEdit/NotebookEdit targeting .claude/hooks/ or
#         .hooks/ are allowed so the broken hook can be repaired in-session.
#       - Everything else goes through emit_degraded (below).
#
# Failure posture (AGENT_SANITIZER_FAIL_OPEN), mirroring
# plugin/scripts/safe-launch.sh and failOpenEnabled() in
# claude-hooks/lib/hook-io.mjs so the three cannot drift:
#   * Default (unset, or anything other than the two literals below) — fail
#     OPEN. The guarded tool runs; the shim prints a non-empty
#     `additionalContext` warning so the transcript records that the call went
#     UNGUARDED, and warns on stderr. No permissionDecision, so nothing halts
#     for a human: the session never stalls on the hook's own breakage.
#   * AGENT_SANITIZER_FAIL_OPEN=0 (or false) — fail CLOSED, restoring the
#     permissionDecision="ask" verdict. A host that must not run an unguarded
#     tool call (agent-glovebox pins this closed) keeps the strict posture.
# The knob covers this shim's OWN failures only. A verdict a healthy wrapped
# hook decided is passed through byte-identical either way.
#
# This shim is itself guarded: .claude/settings.json invokes it through an
# inline bootstrap that `bash -n` checks it first and applies the same posture
# knob, so a parse error in THIS file degrades the same way instead of locking
# the session. .github/scripts/validate-config.sh enforces that bootstrap shape.
#
# This mirrors the launcher shim from
# alexander-turner/secure-claude-code-defaults#109.

set -uo pipefail

target="${1:-}"
# Drop the target arg only when present; `|| true` would also swallow an
# unexpected shift failure (CLAUDE.md: branch on the condition instead).
[[ $# -gt 0 ]] && shift

# JSON-escape $1 (backslashes before quotes, so nothing re-touches an inserted
# escape). A non-literal reason that broke the JSON would leave stdout
# unparseable, which Claude Code reads as NO verdict — an unintended fail-open
# even under the closed posture.
json_escape() {
  local esc="${1//\\/\\\\}"
  printf '%s' "${esc//\"/\\\"}"
}

# Emit the degraded PreToolUse response and exit 0. A non-zero exit OR empty
# stdout is a NON-blocking hook error in Claude Code — the guarded tool runs
# with no trace at all — so every fault path must PRINT something and exit 0,
# whichever posture is in force.
emit_degraded() {
  local reason
  reason="$(json_escape "$1")"
  # The two literals failOpenEnabled() matches, in the same order as its
  # FAIL_CLOSED_VALUES set; every other value (including unset) is fail-open.
  case "${AGENT_SANITIZER_FAIL_OPEN:-}" in
  0 | false)
    # Fail CLOSED: halt for a conscious, per-tool user override.
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"%s"}}\n' "$reason"
    ;;
  *)
    echo "safe-launch: failing open — this tool call runs UNGUARDED (set AGENT_SANITIZER_FAIL_OPEN=0 to fail closed)" >&2
    # No permissionDecision: nothing is blocked and nothing prompts. The
    # context is all that is left, and it is why stdout is still non-empty —
    # an empty one reads as a clean run, not a degraded one.
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"%s The PreToolUse guard is failing open, so this tool call ran UNCHECKED. Set AGENT_SANITIZER_FAIL_OPEN=0 to fail closed on hook failures."}}\n' "$reason"
    ;;
  esac
  exit 0
}

if [[ -z "$target" ]] || [[ ! -f "$target" ]]; then
  # Misconfigured hook path: no verdict source at all.
  echo "safe-launch: missing target hook: $target" >&2
  emit_degraded "safe-launch: hook is missing; verdict unavailable."
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
# shim exists to prevent. Stdout/stderr go through temp files (not command
# substitution, which would strip trailing newlines) and are replayed with
# `cat` on any exit other than 2, so JSON verdicts — including a deliberate
# "deny" — pass through byte-identical. On exit 2, partial stdout is dropped
# and the captured stderr feeds the ask reason. `${@+"$@"}` instead of a bare
# "$@": zero positional params under `set -u` abort bash 3.2 (macOS) with
# exit 1, a NON-blocking error that would let the guarded tool run unchecked.
if "${syntax_check[@]}" 2>/dev/null; then
  err_snippet=""
  stdout_file=""
  stderr_file=""
  trap '[[ -n "$stdout_file" ]] && rm -f "$stdout_file"; [[ -n "$stderr_file" ]] && rm -f "$stderr_file"' EXIT
  if stdout_file=$(mktemp 2>/dev/null) && stderr_file=$(mktemp 2>/dev/null) && [[ -n "$stdout_file" ]] && [[ -n "$stderr_file" ]]; then
    rc=0
    "$interp" "$target" ${@+"$@"} >"$stdout_file" 2>"$stderr_file" || rc=$?
    cat "$stderr_file" >&2
    # JSON strings cannot carry raw control characters, and a byte-truncated
    # multibyte sequence would make the verdict invalid UTF-8 — keep printable
    # ASCII only, replaced in a single pass so nothing re-touches an escape.
    err_snippet=$(head -c 300 "$stderr_file" | tr -c '\40-\176' ' ' | tr -s ' ')
  else
    # mktemp unavailable (e.g. broken TMPDIR): still guard the exit code, at
    # the cost of trailing-newline normalization and no stderr snippet (the
    # target's stderr streams through directly).
    stdout_file=""
    rc=0
    out=$("$interp" "$target" ${@+"$@"}) || rc=$?
  fi
  if [[ "$rc" -eq 2 ]]; then
    # Partial stdout from a crashed hook is not a trustworthy verdict — drop
    # it and degrade per the posture knob instead of letting exit 2 hard-block.
    echo "safe-launch: target hook exited 2 at runtime — not honoring it as a block: $target" >&2
    emit_degraded "safe-launch: hook '$(basename "$target")' failed with exit 2 (${err_snippet:-no stderr})."
  fi
  if [[ -n "$stdout_file" ]]; then
    cat "$stdout_file"
  elif [[ -n "${out:-}" ]]; then
    printf '%s\n' "$out"
  fi
  exit "$rc"
fi

# Degraded path. Read the PreToolUse payload before we touch stdin again.
parse_error=$("${syntax_check[@]}" 2>&1)
echo "safe-launch: target hook failed to parse — degrading: $target" >&2
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
# caller falls through to emit_degraded.
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
# every other tool name correctly falls through to emit_degraded below.
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

# Default: surface the parse failure per the posture knob.
emit_degraded "safe-launch: PreToolUse hook failed to parse."
