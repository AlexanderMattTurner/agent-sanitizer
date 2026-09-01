# shellcheck shell=bash
# The shell port of claude-hooks/lib/hook-timing.mjs, for the entry points that
# never reach node: scripts/safe-launch.sh (whose preflight — a PATH probe and
# the redactor-daemon resolution — runs before the hook it launches can time
# anything), and the two SessionStart provisioners, which are a python install
# and a download rather than node processes and reach this through
# lib/provision-common.sh.
#
# Sourced, so the shell answer is written once rather than three times; that
# node module is still the SSOT for the thresholds and the prose, and
# test/hook-timing-shell-parity.test.mjs runs both implementations over the same
# inputs and asserts byte-identical output, so a reworded notice or a moved
# threshold on either side fails CI rather than drifting quietly.

# Mirrors SLOW_HOOK_THRESHOLD_MS / SLOW_PROVISION_THRESHOLD_MS in the node
# module (see the parity test above for what keeps them equal — it runs with the
# overrides unset, so the DEFAULTS are what is pinned).
#
# The overrides exist so a test can drive the reporting path in milliseconds
# instead of waiting out a real overrun; underscore-prefixed like every other
# test-only knob in this package (_AGENT_SANITIZER_*), because a user who lowers
# these gets a performance complaint on every healthy session.
SLOW_HOOK_THRESHOLD_MS="${_AGENT_SANITIZER_SLOW_HOOK_MS:-1000}"
SLOW_PROVISION_THRESHOLD_MS="${_AGENT_SANITIZER_SLOW_PROVISION_MS:-60000}"
HOOK_TIMING_ISSUE_URL="https://github.com/AlexanderMattTurner/agent-sanitizer/issues/new"

# This build's version, for the report line the notices end with — the number a
# maintainer needs first and the one an operator is least likely to include by
# hand. Empty when it cannot be read, which the notices word as "your
# agent-sanitizer version" rather than naming a number nothing confirmed.
#
# Read from the nearest `.claude-plugin/plugin.json` at or above this file: this
# port only ever ships inside the plugin, whose manifest version is the one
# version string committed to the repo (the node module reads package.json first
# because its own artifact is the npm package — see readVersion there). Parsed
# with bash builtins for the same reason provision-hook-binary.sh does it that
# way: no JSON-capable tool is guaranteed on a bare PATH.
hook_timing_version() {
  local dir parent version line
  dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
  [[ -n "$dir" ]] || return 0
  while :; do
    version=""
    if [[ -r "$dir/.claude-plugin/plugin.json" ]]; then
      while IFS= read -r line; do
        case "$line" in
        *'"version"'*)
          version="${line#*\"version\"*:*\"}"
          version="${version%%\"*}"
          break
          ;;
        *) ;;
        esac
      done <"$dir/.claude-plugin/plugin.json"
      if [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        printf '%s' "$version"
        return 0
      fi
    fi
    parent="$(dirname "$dir")"
    [[ "$parent" == "$dir" ]] && return 0
    dir="$parent"
  done
}

# The clause naming the version a report should carry: this build's when it
# knows it, an instruction to look it up when it does not. $1 version (may be
# empty). Mirrors versionClause in the node module.
hook_timing_version_clause() {
  if [[ -z "$1" ]]; then
    printf '%s' "your agent-sanitizer version"
  else
    printf '%s' "agent-sanitizer $1"
  fi
}

# Epoch milliseconds.
#
# $EPOCHREALTIME (bash 5+) is read as a string and stripped of its decimal
# separator — which is locale-dependent, hence the [.,] class — giving exact
# integer microseconds with no external process. bash 3.2 (what macOS ships) has
# no such variable and no sub-second `date` format that is portable, so it
# degrades to whole seconds there: a gross overrun still reports, a marginal one
# rounds away. Reporting nothing at all on those hosts would be the worse trade —
# the 30-second session start this measurement exists to catch is exactly the
# kind that survives second-granularity.
hook_timing_now_ms() {
  local micros
  if [[ -n "${EPOCHREALTIME:-}" ]]; then
    micros="${EPOCHREALTIME/[.,]/}"
    printf '%s' "$((10#${micros} / 1000))"
    return 0
  fi
  printf '%s' "$(($(date +%s) * 1000))"
}

# Milliseconds since $1 (a hook_timing_now_ms reading), floored at 0 so a clock
# that steps backwards mid-hook reports "fast", never a negative duration.
hook_timing_elapsed_ms() {
  local start="$1" elapsed
  elapsed=$(($(hook_timing_now_ms) - start))
  ((elapsed < 0)) && elapsed=0
  printf '%s' "$elapsed"
}

# Milliseconds as the seconds string the notices print, rounding tenths half-up
# from an exact count of hundredths — the integer spelling of the node module's
# formatSeconds, which is written that way precisely so this one can match it.
hook_timing_format_seconds() {
  local tenths=$((($1 + 50) / 100))
  printf '%s.%s' "$((tenths / 10))" "$((tenths % 10))"
}

# The line for a hook that overran its budget, or nothing when it did not.
# $1 hook name, $2 elapsed ms, $3 threshold ms (optional), $4 version
# (optional; PASSED EMPTY means "unknown" and is worded as such, while OMITTED
# resolves hook_timing_version — the two ports resolve their own artifact's
# version, so the parity test passes this one explicitly on both sides).
#
# This is the node module's NO-CPU wording, and it is the honest one here. The
# node timer splits the wait with process.cpuUsage(); bash's nearest equivalent
# is `times`, and reading it the obvious way — inside a command substitution —
# forks first and so reports the child's zero. A silently-zero CPU figure is
# worse than none, so this port says it cannot attribute the wait.
slow_hook_notice() {
  local name="$1" elapsed="$2" threshold="${3:-$SLOW_HOOK_THRESHOLD_MS}"
  ((elapsed > threshold)) || return 0
  # Resolved only past the guard: a healthy run must not pay the manifest walk.
  local version="${4-$(hook_timing_version)}"
  printf '%s' "agent-sanitizer PERFORMANCE: the ${name} hook took $(hook_timing_format_seconds "$elapsed")s, over its $(hook_timing_format_seconds "$threshold")s budget. Wall-clock alone cannot separate the sanitizer's own work from a busy machine. Tell the user, and suggest they report it at ${HOOK_TIMING_ISSUE_URL} with $(hook_timing_version_clause "$version"), the hook name and timing."
}

# The line for a ONE-TIME provisioning step that overran its (much larger)
# budget, or nothing when it did not. $1 step name, $2 elapsed ms, $3 threshold
# ms (optional), $4 step-specific speedup advice (optional — the default fits
# the engine install, not a download), $5 version (optional, as above).
slow_provision_notice() {
  local name="$1" elapsed="$2" threshold="${3:-$SLOW_PROVISION_THRESHOLD_MS}"
  local advice="${4:-Installing uv makes it faster}"
  ((elapsed > threshold)) || return 0
  local version="${5-$(hook_timing_version)}"
  printf '%s' "agent-sanitizer PERFORMANCE: one-time setup (${name}) took $(hook_timing_format_seconds "$elapsed")s, over its $(hook_timing_format_seconds "$threshold")s budget — this is paid once per install, not per tool call, so the session is not slow from here on. ${advice}; if it happens on EVERY new session, report it at ${HOOK_TIMING_ISSUE_URL} with $(hook_timing_version_clause "$version")."
}

# Report an overrun on stderr, or say nothing. stderr and not stdout: a hook's
# stdout is its VERDICT, parsed as JSON by the harness, and an unparsable line
# there is read as a non-blocking hook error — a fail open. $1 hook name, $2 the
# hook_timing_now_ms reading the run started at.
report_slow_hook() {
  local notice
  notice="$(slow_hook_notice "$1" "$(hook_timing_elapsed_ms "$2")")"
  [[ -n "$notice" ]] && printf '%s\n' "$notice" >&2
  return 0
}

# report_slow_hook for a one-time provisioning step. $1 step name, $2 start,
# $3 step-specific speedup advice (optional).
report_slow_provision() {
  local notice
  notice="$(slow_provision_notice "$1" "$(hook_timing_elapsed_ms "$2")" "" "${3:-}")"
  [[ -n "$notice" ]] && printf '%s\n' "$notice" >&2
  return 0
}
