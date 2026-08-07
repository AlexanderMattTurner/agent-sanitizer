# shellcheck shell=bash
# phase-timer.bash — wall-clock timing for a multi-phase setup run.
#
# Why: GitHub already times each *step*, but a setup that spans several scripts
# inside one step (session-setup -> pre-commit -> pre-push) reports as a single
# opaque duration, and the end-to-end number a session actually pays — the sum
# across every phase — appears nowhere. This records both: one row per phase
# plus the total, printed to the job log and appended to the step summary.
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

# Seconds since the epoch. `date +%s` (not $SECONDS) so the total survives being
# read in a subshell, and not %s%N because macOS `date` has no %N.
_timer_now() { date +%s; }

# Parallel arrays: phase label -> elapsed seconds, in completion order.
_TIMER_LABELS=()
_TIMER_SECONDS=()
_TIMER_T0=""

timer_start() {
  _TIMER_LABELS=()
  _TIMER_SECONDS=()
  _TIMER_T0="$(_timer_now)"
}

# timed_phase LABEL COMMAND...
# Runs COMMAND inside a collapsed log group, records its wall clock, and
# propagates its exit status — a phase that fails still gets a row, so the
# report shows how far the run got before dying.
timed_phase() {
  local label="$1" start end rc=0
  shift
  [ -n "${_TIMER_T0}" ] || {
    printf 'timed_phase: call timer_start first\n' >&2
    return 2
  }
  printf '::group::%s\n' "$label"
  start="$(_timer_now)"
  "$@" || rc=$?
  end="$(_timer_now)"
  printf '::endgroup::\n'
  _TIMER_LABELS+=("$label")
  _TIMER_SECONDS+=("$((end - start))")
  printf '%s took %ds\n' "$label" "$((end - start))"
  return "$rc"
}

# Total wall clock since timer_start, including anything between phases.
# Reports 0 before timer_start: an EXIT-trap report can fire on a run that died
# before the timer was armed, and an empty $_TIMER_T0 in `$(( ))` is a syntax
# error that would replace the real failure with a confusing one.
timer_total() {
  [ -n "${_TIMER_T0}" ] || {
    printf '0'
    return 0
  }
  printf '%d' "$(($(_timer_now) - _TIMER_T0))"
}

# timer_report TITLE
# Prints the phase table to stdout and, when running under Actions, appends the
# same table to the step summary. Safe to call from an EXIT trap: a report over
# a partial run is exactly what a crashed setup needs.
timer_report() {
  local title="$1" i total
  # Nothing to report if the run died before the timer was armed; stay silent
  # rather than publishing a fabricated 0s end-to-end.
  [ -n "${_TIMER_T0}" ] || return 0
  total="$(timer_total)"
  # A zero-phase report is still worth printing (it carries the total), but
  # `${!arr[@]}` on an empty array trips `set -u` on older bash — so index it
  # by count instead of expanding the (possibly empty) subscript list.
  {
    printf '\n%s timing (total %ds)\n' "$title" "$total"
    for ((i = 0; i < ${#_TIMER_LABELS[@]}; i++)); do
      printf '  %-28s %6ds\n' "${_TIMER_LABELS[$i]}" "${_TIMER_SECONDS[$i]}"
    done
  } >&2

  [ -n "${GITHUB_STEP_SUMMARY:-}" ] || return 0
  {
    printf '### %s timing\n\n' "$title"
    printf '| Phase | Seconds |\n| --- | ---: |\n'
    for ((i = 0; i < ${#_TIMER_LABELS[@]}; i++)); do
      printf '| %s | %d |\n' "${_TIMER_LABELS[$i]}" "${_TIMER_SECONDS[$i]}"
    done
    printf '| **End-to-end** | **%d** |\n\n' "$total"
  } >>"$GITHUB_STEP_SUMMARY"
}
