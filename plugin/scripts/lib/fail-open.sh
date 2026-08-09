#!/usr/bin/env bash
# GENERATED from FAIL_CLOSED_VALUES in claude-hooks/lib/hook-io.mjs — do not
# edit by hand. Regenerate with:
#
#   node -e 'import("./claude-hooks/lib/hook-io.mjs").then((m) => process.stdout.write(m.failOpenShellLib()))' \
#     > plugin/scripts/lib/fail-open.sh
#
# The posture knob (AGENT_SANITIZER_FAIL_OPEN) has to be read by shell shims that
# cannot import the JS. Rather than restate the closed set in each of them, they
# source this one function. plugin/test/fail-open-parity.test.mjs asserts these
# bytes are what the generator still produces, and tests/test_safe_launch.py
# asserts every remaining hand-written implementation agrees with it.
#
# Returns 0 to fail OPEN (the default: the guarded action runs, loudly), 1 to
# fail CLOSED (block/ask/suppress). Sourced, never executed.
agent_sanitizer_fail_open() {
  case "${AGENT_SANITIZER_FAIL_OPEN:-}" in
  0 | false) return 1 ;;
  *) return 0 ;;
  esac
}
