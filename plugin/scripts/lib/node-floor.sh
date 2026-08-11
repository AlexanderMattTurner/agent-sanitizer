# shellcheck shell=bash
# GENERATED from engines.node in package.json by scripts/gen-node-floor-lib.mjs
# — do not edit by hand. Regenerate with:
#
#   pnpm gen:node-floor-lib
#
# The plugin launcher runs inside an INSTALLED plugin, where package.json is not
# on disk, so it cannot read the floor at runtime. Rather than re-type the
# number there (where it would drift the day engines.node moves),
# scripts/safe-launch.sh sources this. plugin/test/node-floor-parity.test.mjs
# asserts these bytes are what the generator still produces AND that the shell
# comparison agrees with the declared range.
#
# Sourced, never executed — hence no shebang and no +x bit (the repo's
# shebang/executable pre-commit hook pairs the two).
AGENT_SANITIZER_NODE_MAJOR_FLOOR=22

# The major version `$1` (a node binary) reports, or nothing when it cannot be
# asked or answered something unrecognizable. Empty means UNKNOWN, and every
# caller treats unknown as "do not claim a version fault" — a wrong version
# diagnosis sends an operator to reinstall a runtime that was fine.
agent_sanitizer_node_major() {
  local reported major
  reported="$("$1" --version 2>/dev/null)" || return 0
  # `v22.14.0` -> `22`; anything without that shape yields nothing.
  case "$reported" in
  v[0-9]*)
    major="${reported#v}"
    major="${major%%.*}"
    case "$major" in
    *[!0-9]*) return 0 ;;
    esac
    printf '%s' "$major"
    ;;
  esac
}

# Returns 0 when `$1` (a node binary) is at or above the floor, or when its
# version could not be determined; 1 only when it is DEFINITELY too old.
agent_sanitizer_node_meets_floor() {
  local major
  major="$(agent_sanitizer_node_major "$1")"
  [[ -z "$major" ]] && return 0
  ((major >= AGENT_SANITIZER_NODE_MAJOR_FLOOR))
}
