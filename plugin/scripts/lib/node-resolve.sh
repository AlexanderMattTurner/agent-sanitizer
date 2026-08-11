# shellcheck shell=bash
# Find the node the plugin's hooks should run on, for hosts where `command -v
# node` answers nothing.
#
# `command -v node` alone assumes the hook inherits an environment an
# INTERACTIVE shell built. Claude Code sessions that do not — a launchd- or
# cron-scheduled run, a CI job, a GUI-launched app on macOS — inherit a PATH of
# roughly `/usr/bin:/bin`, and every version manager (fnm, nvm, mise, volta,
# asdf, nodenv) puts node on PATH from a shell rc file, never there. Homebrew's
# `/opt/homebrew/bin` is missing from that PATH too. So the sanitizer's own
# launcher found no node, degraded, and every hook in the session failed open —
# on a machine where node was installed the whole time.
#
# This is a best-effort search of where those installs actually live, and its
# posture is deliberate: when it finds nothing, the caller still degrades
# loudly. It never silently substitutes a runtime for a broken install.
#
# Sourced, never executed — hence no shebang and no +x bit (the repo's
# shebang/executable pre-commit hook pairs the two).

# A sortable integer for a `major.minor.patch` string, so the newest install
# among several wins without shelling out to `sort -V` (BSD/macOS coreutils do
# not reliably have it) and without lexicographic ordering (which ranks v9 above
# v10). Non-numeric components — a `-rc.1` suffix, an `iojs` prefix — are
# stripped rather than rejected, since they only need to ORDER, not round-trip.
agent_sanitizer_node_version_key() {
  local raw="${1#v}" major minor patch
  IFS=. read -r major minor patch <<<"$raw"
  major="${major//[!0-9]/}"
  minor="${minor//[!0-9]/}"
  patch="${patch//[!0-9]/}"
  printf '%s' "$((10#${major:-0} * 1000000 + 10#${minor:-0} * 1000 + 10#${patch:-0}))"
}

# Print the path to a usable node, or nothing. Resolution order, first hit wins:
#
#   1. $AGENT_SANITIZER_NODE — the operator's explicit answer, honored verbatim
#      (including a non-existent path: a wrong pin must fail loudly at the
#      degraded arm, not be silently replaced by a different runtime).
#   2. PATH — the normal case, and the only one that costs nothing.
#   3. Version-manager installs, highest version across ALL managers. Whoever
#      installed a version manager meant its node to be the one, so these are
#      preferred over a system package.
#   4. Single-install layouts (volta, n, mise's shim) and the system prefixes an
#      rc-less PATH misses, in that order.
#
# The version-directory arm picks the newest install rather than the manager's
# "default" alias: reading each manager's alias format is four more parsers, and
# a too-old default would land on the floor diagnosis anyway.
agent_sanitizer_resolve_node() {
  if [[ -n "${AGENT_SANITIZER_NODE:-}" ]]; then
    printf '%s' "$AGENT_SANITIZER_NODE"
    return 0
  fi

  local from_path
  from_path="$(command -v node 2>/dev/null)"
  if [[ -n "$from_path" ]]; then
    printf '%s' "$from_path"
    return 0
  fi

  # Test-only ($_-prefixed like every other internal knob): the suites that
  # model a host with NO node must not find the runner's own installation
  # through the search below.
  [[ "${_AGENT_SANITIZER_NODE_SEARCH:-1}" == "0" ]] && return 1

  local home="${HOME:-}"
  # A glob against an empty prefix would search `/`, so an unset HOME (launchd
  # jobs can have one) drops the HOME-relative entries instead of walking the
  # filesystem root.
  local -a versioned=() fixed=()
  if [[ -n "$home" ]]; then
    versioned+=(
      "${NVM_DIR:-$home/.nvm}/versions/node"
      "${FNM_DIR:-$home/.local/share/fnm}/node-versions"
      "$home/Library/Application Support/fnm/node-versions"
      "${MISE_DATA_DIR:-${XDG_DATA_HOME:-$home/.local/share}/mise}/installs/node"
      "${ASDF_DATA_DIR:-$home/.asdf}/installs/nodejs"
      "$home/.nodenv/versions"
    )
    fixed+=(
      "${VOLTA_HOME:-$home/.volta}/bin/node"
      "${N_PREFIX:-$home/n}/bin/node"
      "${MISE_DATA_DIR:-${XDG_DATA_HOME:-$home/.local/share}/mise}/shims/node"
    )
  else
    versioned+=("${NVM_DIR:-}" "${FNM_DIR:-}" "${ASDF_DATA_DIR:-}")
  fi
  # Prefixes an rc-less PATH does not carry: Homebrew (both architectures),
  # /usr/local, MacPorts. /usr/bin is deliberately absent — it is on every PATH
  # this function only runs without.
  fixed+=(
    /opt/homebrew/bin/node
    /usr/local/bin/node
    /opt/local/bin/node
  )

  local best="" best_key=0 root dir candidate key
  for root in "${versioned[@]}"; do
    [[ -n "$root" && -d "$root" ]] || continue
    # Both layouts, since the managers disagree: nvm/nodenv put bin/ directly
    # under the version dir, fnm nests it under installation/.
    for dir in "$root"/*; do
      for candidate in "$dir/bin/node" "$dir/installation/bin/node"; do
        # -f as well as -x: a DIRECTORY named node is executable too, and
        # handing one to the launcher would surface as a corrupt-install verdict.
        [[ -f "$candidate" && -x "$candidate" ]] || continue
        key="$(agent_sanitizer_node_version_key "${dir##*/}")"
        ((key > best_key)) || continue
        best_key="$key"
        best="$candidate"
      done
    done
  done
  if [[ -n "$best" ]]; then
    printf '%s' "$best"
    return 0
  fi

  for candidate in "${fixed[@]}"; do
    if [[ -f "$candidate" && -x "$candidate" ]]; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}
