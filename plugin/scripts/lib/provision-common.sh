# shellcheck shell=bash
# `source=` paths below are relative to this file, not to shellcheck's cwd.
# shellcheck source-path=SCRIPTDIR
# The shared scaffolding of the SessionStart provisioners (provision-redactor.sh
# and provision-hook-binary.sh). Both resolve the same plugin root, both must
# report their wall-clock against the provisioning budget rather than the
# per-hook one, and both owe the operator a loud line when the artifact they
# just installed is not actually runnable — three answers that are the same for
# reasons that have nothing to do with what either one installs.
#
# A caller resolves its own directory (it cannot source a file whose path it has
# not resolved yet) and sources this; everything after that line is shared.

_provision_lib_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# The plugin root, for the caller — the one variable this file publishes rather
# than keeps to itself, hence the disable.
# shellcheck disable=SC2034
plugin_root="$(cd -- "$_provision_lib_dir/../.." && pwd)"

_provision_step=""
_provision_started_ms=""
_provision_lock_dir=""

# How long the lock-directory fallback waits for another provisioner before it
# declares the lock abandoned. Generous: it must outlast a real cold install
# (a venv build, a ~100 MB download) so a slow-but-live holder is never broken.
_provision_lock_timeout_s=900

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
  # portable atomic primitive. It has no kernel-backed release, so a holder
  # killed mid-install leaves the directory behind and every later session
  # would block on it forever — hence the timeout below, which degrades to the
  # unserialized behaviour this lock replaces rather than to a wedged install.
  local dir="$lock_path.d"
  local waited=0
  # retry-loop-ok: a mutex-acquisition spin, not a retry of a failing command
  # — lib-ci-retry.sh's `retry` re-runs one argv and has no analog for
  # "keep polling for a directory another process may remove".
  until mkdir -- "$dir" 2>/dev/null; do
    if [[ "$waited" -ge "$_provision_lock_timeout_s" ]]; then
      echo "agent-sanitizer: the provisioning lock $dir has been held for over ${_provision_lock_timeout_s}s; treating it as abandoned and provisioning anyway" >&2
      rm -rf -- "$dir"
      mkdir -p -- "$dir"
      [[ -d "$dir" ]] || {
        echo "agent-sanitizer: cannot recreate the provisioning lock dir $dir" >&2
        return 1
      }
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done
  _provision_lock_dir="$dir"
}

# Release a lock-directory taken by provision_hold_lock. A no-op under flock,
# whose release is the kernel's. Armed from the caller's EXIT trap so it covers
# the failure arms too.
provision_release_lock() {
  [[ -n "$_provision_lock_dir" ]] || return 0
  rm -rf -- "$_provision_lock_dir"
  _provision_lock_dir=""
}
