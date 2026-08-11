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

# The secret layer is opt-in (see AGENT_SANITIZER_SECRETS_ENABLED in
# plugin/README.md): without the knob no hook ever calls the daemon, so
# provisioning a Python venv for it would be pure session-start cost.
if [[ "${AGENT_SANITIZER_SECRETS_ENABLED:-}" != "1" ]]; then
  exit 0
fi

data_dir="${1:?usage: provision-redactor.sh <plugin-data-dir>}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -r "$script_dir/lib/provision-common.sh" ]]; then
  echo "agent-sanitizer: $script_dir/lib/provision-common.sh is missing — the secret-redaction engine (Layer 4) cannot be provisioned (reinstall the plugin)" >&2
  exit 1
fi
# shellcheck source=lib/provision-common.sh
. "$script_dir/lib/provision-common.sh"

# The trap covers every exit, including the idempotent early return (which is
# fast, so it prints nothing) and the failure arms.
provision_begin "secret-redaction engine install"
trap provision_report_elapsed EXIT

req="$plugin_root/requirements.txt"
# The engine itself ships as a wheel beside the zipapp rather than being resolved
# from PyPI: the venv and the committed daemon.pyz are then the SAME build, so
# the fast path and the floor cannot be two different versions.
wheel="$plugin_root/dist/redactor/agent_sanitizer-0.0.0-py3-none-any.whl"
venv="$data_dir/venv"
stamp="$venv/.requirements-installed"
wheel_stamp="$venv/.engine-wheel-installed"

if [[ ! -f "$wheel" ]]; then
  echo "agent-sanitizer: $wheel is missing — the secret-redaction engine (Layer 4) cannot be provisioned (reinstall the plugin)" >&2
  exit 1
fi

# Both inputs are stamped as copies compared with `cmp`, so a plugin update that
# moves either the third-party lock or the engine wheel reprovisions. Copies
# rather than digests because this fast path must clear with NOTHING on PATH —
# no python, no uv, and no sha256sum/shasum either.
if [[ -x "$venv/bin/agent-secret-redactor-daemon" ]] && cmp -s "$req" "$stamp" && cmp -s "$wheel" "$wheel_stamp"; then
  exit 0
fi

if command -v uv >/dev/null 2>&1; then
  uv venv --quiet "$venv"
  uv pip install --quiet --python "$venv/bin/python" -r "$req"
  # --no-deps: the wheel's dependencies just came from the hashed lock, and
  # letting it re-resolve them would pull unpinned versions in beside them.
  uv pip install --quiet --python "$venv/bin/python" --no-deps -- "$wheel"
elif command -v python3 >/dev/null 2>&1; then
  python3 -m venv "$venv"
  "$venv/bin/pip" install --quiet -r "$req"
  "$venv/bin/pip" install --quiet --no-deps -- "$wheel"
else
  echo "agent-sanitizer: python3 not found — the secret-redaction engine (Layer 4)" \
    "cannot be provisioned. Tool output will reach the model UNREDACTED (the hooks" \
    "fail open; set AGENT_SANITIZER_FAIL_OPEN=0 to have it suppressed instead)" \
    "until Python 3.10+ or uv is installed and a new session starts." >&2
  exit 1
fi

provision_require_executable "$venv/bin/agent-secret-redactor-daemon" \
  "agent-sanitizer: install finished but $venv/bin/agent-secret-redactor-daemon is not an executable file"
cp -- "$req" "$stamp"
cp -- "$wheel" "$wheel_stamp"
echo "agent-sanitizer: secret-redaction engine provisioned into $venv" >&2
