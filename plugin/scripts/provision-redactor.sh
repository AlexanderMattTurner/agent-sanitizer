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

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -r "$script_dir/lib/provision-common.sh" ]]; then
  echo "agent-sanitizer: $script_dir/lib/provision-common.sh is missing — the secret-redaction engine (Layer 4) cannot be provisioned (reinstall the plugin)" >&2
  exit 1
fi
# shellcheck source=lib/provision-common.sh
. "$script_dir/lib/provision-common.sh"

# Loud, because the operator asked for this layer: without the venv the client
# falls back to the committed dist/redactor/daemon.pyz, so secrets are still
# redacted, one zipapp self-extract slower on the first call of each session.
if [[ -z "$plugin_data" ]]; then
  echo "agent-sanitizer: CLAUDE_PLUGIN_DATA is unset — the secret-redaction engine (Layer 4) keeps no venv in this session and runs from the committed zipapp instead" >&2
  exit 0
fi

# The trap covers every exit, including the idempotent early return (which is
# fast, so it prints nothing) and the failure arms.
provision_begin "secret-redaction engine install"
# $build names a venv under construction until the swap below hands it over, so
# a failed install leaves the live venv untouched and no half-built one behind.
build=""
trap '[[ -z "$build" ]] || rm -rf -- "$build"; provision_release_lock; provision_report_elapsed' EXIT

# Held across the up-to-date CHECK and the install below, not just the install:
# without it a second session that reads the check before this one finishes goes
# on to build and swap in a second venv, replacing the first under a daemon
# already running out of it.
provision_hold_lock "$plugin_data/.redactor-provision.lock"

req="$plugin_root/requirements.txt"
# The engine itself ships as a wheel beside the zipapp rather than being resolved
# from PyPI: the venv and the committed daemon.pyz are then the SAME build, so
# the fast path and the floor cannot be two different versions.
wheel="$plugin_root/dist/redactor/agent_sanitizer-0.0.0-py3-none-any.whl"
venv="$plugin_data/venv"
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

# Built beside the live venv and swapped in only once it is installed, verified
# and stamped: `uv venv` refuses a path that already holds a venv, and building
# in place would hand the launcher a half-installed daemon mid-build. Leftovers
# of a provisioner killed mid-build are ours to clear: the lock is held.
for leftover in "$plugin_data"/venv.new.* "$plugin_data"/venv.old.*; do
  if [[ -e "$leftover" || -L "$leftover" ]]; then
    rm -rf -- "$leftover"
  fi
done
build="$plugin_data/venv.new.$$"
retired="$plugin_data/venv.old.$$"

# --require-hashes is explicit, as in build-redactor-pyz.mjs, so an unhashed
# line in the lock fails the install rather than turning hash checking off.
# Unlike that build, prebuilt wheels are accepted: this venv only ever runs on
# the host that built it, so a platform wheel is correct here and needs no
# compiler, while the committed zipapp must stay platform-independent.
if command -v uv >/dev/null 2>&1; then
  uv venv --quiet "$build"
  uv pip install --quiet --python "$build/bin/python" --require-hashes -r "$req"
  # --no-deps: the wheel's dependencies just came from the hashed lock, and
  # letting it re-resolve them would pull unpinned versions in beside them.
  uv pip install --quiet --python "$build/bin/python" --no-deps -- "$wheel"
elif command -v python3 >/dev/null 2>&1; then
  python3 -m venv "$build"
  "$build/bin/pip" install --quiet --require-hashes -r "$req"
  "$build/bin/pip" install --quiet --no-deps -- "$wheel"
else
  echo "agent-sanitizer: python3 not found — the secret-redaction engine (Layer 4)" \
    "cannot be provisioned. Tool output will reach the model UNREDACTED (the hooks" \
    "fail open; set AGENT_SANITIZER_FAIL_OPEN=0 to have it suppressed instead)" \
    "until Python 3.10+ or uv is installed and a new session starts." >&2
  exit 1
fi

daemon="$build/bin/agent-secret-redactor-daemon"
provision_require_executable "$daemon" \
  "agent-sanitizer: install finished but $daemon is not an executable file"

# The installer wrote the daemon's interpreter as an absolute path inside
# $build, which stops existing at the swap. Every occurrence is re-pointed at
# $venv, where that same interpreter lives once the rename lands. Prefix/suffix
# removal with a quoted pattern is literal in every bash, which a ${x//a/b}
# replacement is not (bash 5.2 expands `&` in it).
script="$(cat -- "$daemon" && printf x)"
script="${script%x}"
relocated=""
while [[ "$script" == *"$build/"* ]]; do
  relocated+="${script%%"$build/"*}$venv/"
  script="${script#*"$build/"}"
done
relocated+="$script"
printf '%s' "$relocated" >"$daemon.relocated"
chmod 755 -- "$daemon.relocated"
mv -f -- "$daemon.relocated" "$daemon"

# The launcher refuses a venv another uid could write into (see trusted_dir in
# safe-launch.sh), so a group-writable umask must not leave one it will refuse.
chmod go-w -- "$build" "$build/bin"
cp -- "$req" "$build/.requirements-installed"
cp -- "$wheel" "$build/.engine-wheel-installed"

# Two renames, not one: a rename cannot replace a non-empty directory. Between
# them the launcher finds no venv and the client redacts through the zipapp.
if [[ -e "$venv" || -L "$venv" ]]; then
  mv -- "$venv" "$retired"
fi
if ! mv -- "$build" "$venv"; then
  if [[ -e "$retired" ]]; then
    mv -- "$retired" "$venv"
  fi
  echo "agent-sanitizer: could not move the new secret-redaction engine into $venv — the previous one stays in place" >&2
  exit 1
fi
build=""
if [[ -e "$retired" ]]; then
  rm -rf -- "$retired"
fi
echo "agent-sanitizer: secret-redaction engine provisioned into $venv" >&2
