# shellcheck shell=bash
# phase-timer.bash — wall-clock timing for a multi-phase setup run.
#
# Why: GitHub already times each *step*, but a setup that spans several scripts
# inside one step (session-setup -> pre-commit -> pre-push) reports as a single
# opaque duration, and the end-to-end number a session actually pays — the span
# across every phase — appears nowhere. This records both: a Mermaid waterfall
# and a table, one row per phase plus the total, in the job log and the step
# summary.
#
# Contract: sourced into strict-mode (set -euo pipefail) callers; do not re-set
# shell options. Timing is advisory — nothing here fails a job on a slow run,
# because hosted-runner variance is far wider than any regression worth gating.
#
# Usage:
#   source .github/scripts/lib/phase-timer.bash
#   timer_start
#   timed_phase "session-setup" .claude/hooks/session-setup.sh
#   timer_report "Hook lifecycle"
#
# Set TIMER_JSON_OUT to also drop a machine-readable record of the run there —
# that file is what the over-time trend chart is built from.

# Milliseconds since the epoch. `date` (not $EPOCHREALTIME) because that
# variable's decimal separator follows LC_NUMERIC, so a comma locale would
# silently corrupt the arithmetic. GNU date has %N; BSD/macOS date does not and
# emits a literal "N", so fall back to whole seconds there rather than parsing
# garbage — a developer running this by hand gets second granularity, CI (where
# the numbers are actually read) gets milliseconds.
if [[ "$(date +%s%N)" =~ ^[0-9]+$ ]]; then
  _timer_now_ms() { echo $(($(date +%s%N) / 1000000)); }
else
  _timer_now_ms() { echo $(($(date +%s) * 1000)); }
fi

# Render a duration in the largest unit that keeps it readable — never
# scientific notation, never a raw count of some other unit's thousandths.
_timer_fmt() {
  local ms="$1" tenths seconds
  if ((ms < 1000)); then
    printf '%dms' "$ms"
    return 0
  fi
  if ((ms < 60000)); then
    tenths=$(((ms + 50) / 100))
    printf '%d.%ds' "$((tenths / 10))" "$((tenths % 10))"
    return 0
  fi
  seconds=$(((ms + 500) / 1000))
  ((seconds < 3600)) && {
    printf '%dm%02ds' "$((seconds / 60))" "$((seconds % 60))"
    return 0
  }
  printf '%dh%02dm%02ds' "$((seconds / 3600))" "$((seconds % 3600 / 60))" "$((seconds % 60))"
}

# Mermaid gantt task titles are terminated by ':', and '#' opens an entity
# escape — fold both (in a single pass, so neither can re-touch the other's
# replacement) rather than emitting a diagram that fails to parse.
_timer_mermaid_label() { printf '%s' "${1//[:#]/-}"; }

# Parallel arrays: phase label, start offset from timer_start (ms), and elapsed
# (ms), in completion order.
_TIMER_LABELS=()
_TIMER_OFFSETS_MS=()
_TIMER_ELAPSED_MS=()
_TIMER_T0_MS=""

timer_start() {
  _TIMER_LABELS=()
  _TIMER_OFFSETS_MS=()
  _TIMER_ELAPSED_MS=()
  _TIMER_T0_MS="$(_timer_now_ms)"
}

# timed_phase LABEL COMMAND...
# Runs COMMAND inside a collapsed log group, records its wall clock, and
# propagates its exit status — a phase that fails still gets a row, so the
# report shows how far the run got before dying.
timed_phase() {
  local label="$1" start end rc=0
  shift
  [ -n "${_TIMER_T0_MS}" ] || {
    printf 'timed_phase: call timer_start first\n' >&2
    return 2
  }
  printf '::group::%s\n' "$label"
  start="$(_timer_now_ms)"
  "$@" || rc=$?
  end="$(_timer_now_ms)"
  printf '::endgroup::\n'
  _TIMER_LABELS+=("$label")
  _TIMER_OFFSETS_MS+=("$((start - _TIMER_T0_MS))")
  _TIMER_ELAPSED_MS+=("$((end - start))")
  printf '%s took %s\n' "$label" "$(_timer_fmt "$((end - start))")"
  return "$rc"
}

# Total wall clock since timer_start, in ms, including anything between phases.
timer_total_ms() {
  [ -n "${_TIMER_T0_MS}" ] || {
    printf '0'
    return 0
  }
  printf '%d' "$(($(_timer_now_ms) - _TIMER_T0_MS))"
}

# The waterfall: one bar per phase at its real start offset, so the gaps
# between phases — the time no phase accounts for — are visible, and a Total
# section whose bar spans the whole run. `dateFormat x` reads the numbers as
# epoch milliseconds; anchoring at 0 makes the axis read as time-since-start.
_timer_gantt() {
  local title="$1" total="$2" i start end
  printf '```mermaid\ngantt\n'
  printf '    title %s (end-to-end %s)\n' "$(_timer_mermaid_label "$title")" "$(_timer_fmt "$total")"
  printf '    dateFormat x\n    axisFormat %%M:%%S\n'
  printf '    section Phases\n'
  for ((i = 0; i < ${#_TIMER_LABELS[@]}; i++)); do
    start="${_TIMER_OFFSETS_MS[$i]}"
    end="$((start + _TIMER_ELAPSED_MS[i]))"
    # Mermaid drops a zero-width bar; give a sub-millisecond phase 1ms so it
    # still appears (the table carries the exact number).
    ((end > start)) || end=$((start + 1))
    printf '    %s (%s) :%d, %d\n' \
      "$(_timer_mermaid_label "${_TIMER_LABELS[$i]}")" "$(_timer_fmt "${_TIMER_ELAPSED_MS[$i]}")" "$start" "$end"
  done
  printf '    section Total\n'
  printf '    end-to-end (%s) :crit, 0, %d\n' "$(_timer_fmt "$total")" "$((total > 0 ? total : 1))"
  printf '```\n\n'
}

# JSON string escaping: backslashes first, then quotes — the quote pass inserts
# backslashes the (already finished) backslash pass can no longer re-touch, so
# no escape gets double-escaped.
_timer_json_string() {
  local s="${1//\\/\\\\}"
  printf '"%s"' "${s//\"/\\\"}"
}

# The machine-readable record, written to $TIMER_JSON_OUT when that is set.
# Durations stay in integer milliseconds here — formatting for humans is the
# report's job, and a chart needs the raw number.
_timer_write_json() {
  local title="$1" total="$2" i sep=""
  {
    printf '{"title":%s,"total_ms":%d,"phases":[' "$(_timer_json_string "$title")" "$total"
    for ((i = 0; i < ${#_TIMER_LABELS[@]}; i++)); do
      printf '%s{"label":%s,"offset_ms":%d,"ms":%d}' \
        "$sep" "$(_timer_json_string "${_TIMER_LABELS[$i]}")" \
        "${_TIMER_OFFSETS_MS[$i]}" "${_TIMER_ELAPSED_MS[$i]}"
      sep=","
    done
    printf ']}\n'
  } >"$TIMER_JSON_OUT"
}

# timer_report TITLE
# Prints the phase table to stderr and, when running under Actions, appends the
# waterfall and the table to the step summary. Safe to call from an EXIT trap:
# a report over a partial run is exactly what a crashed setup needs.
timer_report() {
  local title="$1" i total
  # Nothing to report if the run died before the timer was armed; stay silent
  # rather than publishing a fabricated 0ms end-to-end.
  [ -n "${_TIMER_T0_MS}" ] || return 0
  total="$(timer_total_ms)"
  [ -z "${TIMER_JSON_OUT:-}" ] || _timer_write_json "$title" "$total"

  # A zero-phase report is still worth printing (it carries the total), but
  # `${!arr[@]}` on an empty array trips `set -u` on older bash — so index it
  # by count instead of expanding the (possibly empty) subscript list.
  {
    printf '\n%s timing (end-to-end %s)\n' "$title" "$(_timer_fmt "$total")"
    for ((i = 0; i < ${#_TIMER_LABELS[@]}; i++)); do
      printf '  %-28s %10s\n' "${_TIMER_LABELS[$i]}" "$(_timer_fmt "${_TIMER_ELAPSED_MS[$i]}")"
    done
  } >&2

  [ -n "${GITHUB_STEP_SUMMARY:-}" ] || return 0
  {
    printf '### %s timing\n\n' "$title"
    ((${#_TIMER_LABELS[@]} > 0)) && _timer_gantt "$title" "$total"
    printf '| Phase | Duration |\n| --- | ---: |\n'
    for ((i = 0; i < ${#_TIMER_LABELS[@]}; i++)); do
      printf '| %s | %s |\n' "${_TIMER_LABELS[$i]}" "$(_timer_fmt "${_TIMER_ELAPSED_MS[$i]}")"
    done
    printf '| **End-to-end** | **%s** |\n\n' "$(_timer_fmt "$total")"
  } >>"$GITHUB_STEP_SUMMARY"
}
