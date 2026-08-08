#!/usr/bin/env bash
# `source=` paths below are relative to this script, not to shellcheck's cwd.
# shellcheck source-path=SCRIPTDIR
# SessionStart: provision the Layer-4 secret-redaction engine (the Python
# agent-secret-redactor-daemon from agent-sanitizer[secrets]) into the
# plugin's persistent data dir. Idempotent: a venv already carrying the shipped
# pin is left untouched. Failure here is advisory — the sanitize hooks fail
# closed per secret-shaped payload at runtime until the engine exists, so a
# missing Python degrades loudly, never silently open.
set -euo pipefail

data_dir="${1:?usage: provision-redactor.sh <plugin-data-dir>}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
plugin_root="$(cd -- "$script_dir/.." && pwd)"

# This install blocks session start with a 1800s harness timeout above it, and
# nothing downstream can attribute the wait to it: the hooks it provisions FOR
# deliberately exclude one-time provisioning from their own budgets, so a
# pathological install was, until now, wall-clock nobody reported. Budgeted as
# provisioning, not as a hook — see lib/hook-timing.sh for why that is a
# different threshold and a different message. The trap covers every exit,
# including the idempotent early return (which is fast, so it prints nothing)
# and the failure arms.
if [[ -r "$script_dir/lib/hook-timing.sh" ]]; then
  # shellcheck source=lib/hook-timing.sh
  . "$script_dir/lib/hook-timing.sh"
  provision_started_ms="$(hook_timing_now_ms)"
  trap 'report_slow_provision "secret-redaction engine install" "$provision_started_ms"' EXIT
else
  echo "agent-sanitizer: $script_dir/lib/hook-timing.sh is missing — provisioning timing disabled (reinstall the plugin)" >&2
fi
req="$plugin_root/requirements.txt"
venv="$data_dir/venv"
stamp="$venv/.requirements-installed"

# The stamp is a copy of the requirements file made after a successful install,
# so a version bump in a plugin update (new requirements.txt) reprovisions.
if [[ -x "$venv/bin/agent-secret-redactor-daemon" ]] && cmp -s "$req" "$stamp"; then
  exit 0
fi

if command -v uv >/dev/null 2>&1; then
  uv venv --quiet "$venv"
  uv pip install --quiet --python "$venv/bin/python" -r "$req"
elif command -v python3 >/dev/null 2>&1; then
  python3 -m venv "$venv"
  "$venv/bin/pip" install --quiet -r "$req"
else
  echo "agent-sanitizer: python3 not found — the secret-redaction engine (Layer 4)" \
    "cannot be provisioned. Tool output will reach the model UNREDACTED (the hooks" \
    "fail open; set AGENT_SANITIZER_FAIL_OPEN=0 to have it suppressed instead)" \
    "until Python 3.10+ or uv is installed and a new session starts." >&2
  exit 1
fi

[[ -x "$venv/bin/agent-secret-redactor-daemon" ]] || {
  echo "agent-sanitizer: install finished but $venv/bin/agent-secret-redactor-daemon is missing" >&2
  exit 1
}
cp -- "$req" "$stamp"
echo "agent-sanitizer: secret-redaction engine provisioned into $venv" >&2
