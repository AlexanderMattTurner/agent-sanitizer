# shellcheck shell=bash
# GENERATED from FAIL_CLOSED_VALUES in claude-hooks/lib/hook-io.mjs by
# scripts/gen-fail-open-lib.mjs — do not edit by hand. Rebuild with:
#
#   pnpm build:plugin
#
# The posture knob (AGENT_SANITIZER_FAIL_OPEN) has to be read by shell shims that
# cannot import the JS. Rather than restate the closed set in each of them, they
# source this one function. plugin/test/fail-open-parity.test.mjs asserts it
# decides exactly as failOpenEnabled() does, and tests/test_safe_launch.py
# asserts every remaining hand-written implementation agrees with it.
#
# Returns 0 to fail OPEN (the default: the guarded action runs, loudly), 1 to
# fail CLOSED (block/ask/suppress). Sourced, never executed — hence no shebang
# and no +x bit.
agent_sanitizer_fail_open() {
  case "${AGENT_SANITIZER_FAIL_OPEN:-}" in
  0 | false) return 1 ;;
  *) return 0 ;;
  esac
}
