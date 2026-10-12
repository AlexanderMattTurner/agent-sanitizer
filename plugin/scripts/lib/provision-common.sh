# shellcheck shell=bash
# `source=` paths below are relative to this file, not to shellcheck's cwd.
# shellcheck source-path=SCRIPTDIR
# The shared scaffolding of the SessionStart provisioners (provision-redactor.sh
# and provision-hook-binary.sh). Both resolve the same plugin root and the same
# data dir, both must report their wall-clock against the provisioning budget
# rather than the per-hook one, and both owe the operator a loud line when the
# artifact they just installed is not actually runnable — answers that are the
# same for reasons that have nothing to do with what either one installs.
#
# A caller resolves its own directory (it cannot source a file whose path it has
# not resolved yet) and sources this; everything after that line is shared.

_provision_lib_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# The plugin root and the plugin's persistent data dir, for the caller — the two
# variables this file publishes rather than keeps to itself, hence the disables.
# shellcheck disable=SC2034
plugin_root="$(cd -- "$_provision_lib_dir/../.." && pwd)"
# Read from the environment, exactly as safe-launch.sh reads it, so the hook command in
# hooks.json names no variable beyond CLAUDE_PLUGIN_ROOT. A sandbox that re-runs plugin
# hooks from its own root-owned tier (a glovebox microVM) resolves that one and sets
# nothing else, so each caller checks this for emptiness and exits 0: there is nowhere
# to install into, and a red SessionStart hook would say something untrue about a
# session that still works.
# shellcheck disable=SC2034
plugin_data="${CLAUDE_PLUGIN_DATA:-}"

_provision_step=""
_provision_started_ms=""
_provision_lock_dir=""
_provision_lock_owner=""

# How long the lock-directory fallback waits for a LIVE holder before giving up
# for the session. Generous: it must outlast a real cold install (a venv build,
# a ~100 MB download). A live holder is never broken.
_provision_lock_timeout_s=900

# How long a lock directory may carry no owner record before it counts as
# abandoned: only a holder killed between its mkdir and writing the record.
_provision_lock_ownerless_s=10

# Start measuring a one-time provisioning step named $1.
#
# A provisioning step blocks session start under the same 1800s harness timeout
# as every hook, and nothing downstream can attribute that wait to it: the hooks
# it provisions FOR deliberately exclude one-time provisioning from their own
# budgets.
provision_begin() {
  _provision_step="${1:?provision_begin needs a step name}"
  _provision_started_ms=""
  if [[ ! -r "$_provision_lib_dir/hook-timing.sh" ]]; then
    # Degraded, not fatal: an install missing the timer can still provision.
    echo "agent-sanitizer: $_provision_lib_dir/hook-timing.sh is missing — provisioning timing disabled (reinstall the plugin)" >&2
    return 0
  fi
  # shellcheck source=hook-timing.sh
  . "$_provision_lib_dir/hook-timing.sh"
  _provision_started_ms="$(hook_timing_now_ms)"
}

# Report the elapsed time of the step `provision_begin` named, appending $1 as
# step-specific advice. Silent when it was fast, and silent when the timer was
# unavailable — so a caller can arm this from an EXIT trap unconditionally,
# which is the only placement that also covers its failure arms.
provision_report_elapsed() {
  [[ -n "$_provision_started_ms" ]] || return 0
  report_slow_provision "$_provision_step" "$_provision_started_ms" "${1:-}"
}

# Return when $1 is executable; otherwise say $2 and exit 1, aborting the
# caller. Never call it as `$(…)` — the exit would die with the subshell.
#
# The post-condition, not the exit status of whatever wrote it: an install whose
# every command returned 0 and left nothing runnable is exactly the failure a
# provisioner must not report as done, because the launcher then finds no
# artifact and the operator has been told there is one.
provision_require_executable() {
  local path="${1:?provision_require_executable needs a path}"
  [[ -x "$path" ]] && return 0
  echo "${2:?provision_require_executable needs a message}" >&2
  exit 1
}

# Serialize the caller against another session's provisioner, using a lock at
# $1, until this process exits.
#
# Both provisioners are check-then-act — "is the artifact already the pinned
# one? no, install it" — and two sessions starting together interleave those
# halves: one recreates the venv (or removes and refetches the binary) under a
# path the other's daemon is already running from. The lock makes the pair
# atomic. Only the provisioners take it; nothing on a hook's exec path waits on
# it, so a session start blocked here never blocks a tool call.
provision_hold_lock() {
  local lock_path="${1:?provision_hold_lock needs a lock path}"
  local lock_dir
  lock_dir="$(dirname -- "$lock_path")"
  mkdir -p -- "$lock_dir"
  [[ -d "$lock_dir" ]] || {
    echo "agent-sanitizer: cannot create $lock_dir for the provisioning lock" >&2
    return 1
  }
  if command -v flock >/dev/null 2>&1; then
    # Held for the life of the process: the kernel releases it when this fd
    # closes, so a killed provisioner cannot leave the lock stuck.
    exec 9>"$lock_path"
    flock 9
    return 0
  fi
  # flock(1) is util-linux and absent on a stock macOS, where `mkdir` is the
  # portable atomic primitive. It has no kernel-backed release, so the holder
  # records "<pid> <token>" inside: a waiter breaks the lock only when that pid
  # is gone (or no record ever appeared), and a holder releases it only while
  # the record is still its own token.
  local dir="$lock_path.d"
  local me="$$ $RANDOM$RANDOM$RANDOM"
  local holder waited=0 ownerless=0
  # retry-loop-ok: a mutex-acquisition spin, not a retry of a failing command
  # — lib-ci-retry.sh's `retry` re-runs one argv and has no analog for
  # "keep polling for a directory another process may remove".
  until mkdir -- "$dir" 2>/dev/null; do
    _provision_lock_holder "$dir"
    holder="$_provision_lock_read"
    if [[ -z "$holder" ]]; then
      ownerless=$((ownerless + 1))
      if [[ "$ownerless" -gt "$_provision_lock_ownerless_s" ]]; then
        _provision_break_lock "$dir" ""
        continue
      fi
    elif [[ ! "${holder%% *}" =~ ^[0-9]+$ ]] || ! kill -0 "${holder%% *}" 2>/dev/null; then
      _provision_break_lock "$dir" "$holder"
      continue
    else
      ownerless=0
    fi
    # Breaking a LIVE holder would run two installs into one path at once.
    if [[ "$waited" -ge "$_provision_lock_timeout_s" ]]; then
      echo "agent-sanitizer: the provisioning lock $dir is still held by live pid ${holder%% *} after ${_provision_lock_timeout_s}s — not provisioning this session (delete $dir if that process is not a provisioner)" >&2
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
  printf '%s\n' "$me" >"$dir/owner"
  _provision_lock_dir="$dir"
  _provision_lock_owner="$me"
}

# Set _provision_lock_read to the owner record in lock dir $1, or to "" when
# there is none (not yet written, or the holder released it meanwhile).
_provision_lock_read=""
_provision_lock_holder() {
  _provision_lock_read=""
  [[ -f "$1/owner" ]] || return 0
  IFS= read -r _provision_lock_read <"$1/owner" 2>/dev/null || _provision_lock_read=""
}

# Remove the abandoned lock dir $1 whose owner record read $2 ("" for none).
# Re-read first: another waiter may have broken it and taken it since, and its
# fresh record differs from the one this waiter judged dead.
_provision_break_lock() {
  _provision_lock_holder "$1"
  [[ "$_provision_lock_read" == "$2" ]] || return 0
  if [[ -n "$2" ]]; then
    echo "agent-sanitizer: breaking the provisioning lock $1 — its holder, pid ${2%% *}, is gone" >&2
  else
    echo "agent-sanitizer: breaking the provisioning lock $1 — no holder recorded itself in it for ${_provision_lock_ownerless_s}s" >&2
  fi
  rm -rf -- "$1"
}

# Release a lock-directory taken by provision_hold_lock (a no-op under flock),
# only while the record is still this holder's token: a lock broken and re-taken
# by another provisioner is that one's to release. Armed from the EXIT trap.
provision_release_lock() {
  [[ -n "$_provision_lock_dir" ]] || return 0
  _provision_lock_holder "$_provision_lock_dir"
  if [[ "$_provision_lock_read" == "$_provision_lock_owner" ]]; then
    rm -rf -- "$_provision_lock_dir"
  else
    echo "agent-sanitizer: the provisioning lock $_provision_lock_dir no longer names this provisioner — leaving it to its current holder" >&2
  fi
  _provision_lock_dir=""
}
