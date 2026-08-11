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

# The plugin root, for the caller — the one variable this file publishes rather
# than keeps to itself, hence the disable.
# shellcheck disable=SC2034
plugin_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

_provision_lib_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
_provision_step=""
_provision_started_ms=""

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

# Refuse to claim success unless $1 is executable, saying $2 if it is not.
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
