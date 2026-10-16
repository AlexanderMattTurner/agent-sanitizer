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
# $build names a venv under construction until the swap below hands it over.
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

# Built beside the live venv and swapped in once installed, verified and
# stamped: `uv venv` refuses an existing venv, and building in place would hand
# the launcher a half-installed daemon. Leftovers of a killed provisioner are
# ours to clear: the lock is held.
for leftover in "$plugin_data"/venv.new.* "$plugin_data"/venv.old.*; do
  if [[ -e "$leftover" || -L "$leftover" ]]; then
    rm -rf -- "$leftover"
  fi
done
build="$plugin_data/venv.new.$$"
retired="$plugin_data/venv.old.$$"

unredacted_note="(the hooks fail open; set AGENT_SANITIZER_FAIL_OPEN=0 to have it suppressed instead)"

# The installer's own error names neither this plugin nor the step: uv's is a
# bare "Request failed after 3 retries".
install_failed() {
  local serving
  if [[ -x "$venv/bin/agent-secret-redactor-daemon" ]]; then
    serving="the previously provisioned engine in $venv keeps serving"
  elif command -v python3 >/dev/null 2>&1; then
    serving="this session redacts through the committed zipapp instead"
  else
    serving="with no python3 for the committed zipapp either, tool output reaches the model UNREDACTED $unredacted_note"
  fi
  echo "agent-sanitizer: $1 failed (exit $2) — the secret-redaction engine (Layer 4) was not provisioned; $serving until a later session's retry succeeds.${3:+ $3}" >&2
  exit 1
}
index_hint="If that was a network error, the package index was unreachable: check this host's network and proxy access to pypi.org, or to the index"

# --require-hashes is explicit, as in build-redactor-pyz.mjs, so an unhashed
# lock line fails the install rather than turning hash checking off. Unlike
# that build, prebuilt platform wheels are fine: this venv runs only on the host
# that built it.
if command -v uv >/dev/null 2>&1; then
  venv_hint=""
  if ! command -v python3 >/dev/null 2>&1; then
    venv_hint="With no python3 on PATH, uv downloads a managed Python from GitHub first: if that was a network error, install Python 3.10+ or allow that download."
  fi
  uv venv --quiet "$build" || install_failed "uv venv" "$?" "$venv_hint"
  uv pip install --quiet --python "$build/bin/python" --require-hashes -r "$req" ||
    install_failed "installing the engine's dependencies (uv pip install -r)" "$?" \
      "$index_hint UV_INDEX_URL names (uv honours HTTPS_PROXY; behind a TLS-intercepting proxy, set UV_SYSTEM_CERTS=1, or UV_NATIVE_TLS=1 on an older uv)."
  # --no-deps: the wheel's dependencies just came from the hashed lock, and
  # letting it re-resolve them would pull unpinned versions in beside them.
  uv pip install --quiet --python "$build/bin/python" --no-deps -- "$wheel" ||
    install_failed "installing the engine wheel (uv pip install --no-deps)" "$?"
elif command -v python3 >/dev/null 2>&1; then
  python3 -m venv "$build" ||
    install_failed "python3 -m venv" "$?" "On Debian/Ubuntu, install the python3-venv package."
  "$build/bin/pip" install --quiet --require-hashes -r "$req" ||
    install_failed "installing the engine's dependencies (pip install -r)" "$?" \
      "$index_hint PIP_INDEX_URL names (pip honours HTTPS_PROXY and PIP_CERT)."
  "$build/bin/pip" install --quiet --no-deps -- "$wheel" ||
    install_failed "installing the engine wheel (pip install --no-deps)" "$?"
else
  echo "agent-sanitizer: python3 not found — the secret-redaction engine (Layer 4)" \
    "cannot be provisioned. Tool output will reach the model UNREDACTED" \
    "$unredacted_note" \
    "until Python 3.10+ or uv is installed and a new session starts." >&2
  exit 1
fi

daemon="$build/bin/agent-secret-redactor-daemon"
provision_require_executable "$daemon" \
  "agent-sanitizer: install finished but $daemon is not an executable file"

# The daemon's interpreter path points inside $build, which stops existing at
# the swap: re-point every occurrence at $venv. Prefix/suffix removal with a
# quoted pattern is literal in every bash; ${x//a/b} is not (5.2 expands `&`).
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

# The launcher refuses a venv another uid could write into (trusted_dir in
# safe-launch.sh). Recursive: it vets only the root and bin/, but the daemon
# imports from site-packages, where a group-editable module runs with every
# secret-bearing payload. Done after the last write into $build.
chmod -R go-w -- "$build"
cp -- "$req" "$build/.requirements-installed"
cp -- "$wheel" "$build/.engine-wheel-installed"

# Two renames: a rename cannot replace a non-empty directory. Between them the
# client redacts through the zipapp.
if [[ -e "$venv" || -L "$venv" ]]; then
  mv -- "$venv" "$retired"
fi
if ! mv -- "$build" "$venv"; then
  # Every arm sits in a condition: a bare `mv` would abort under `set -e`
  # before the message naming where the only surviving copy lives.
  if [[ ! -e "$retired" ]]; then
    echo "agent-sanitizer: could not move the newly built secret-redaction engine into $venv — this session redacts through the committed zipapp" >&2
  elif mv -- "$retired" "$venv"; then
    echo "agent-sanitizer: could not move the new secret-redaction engine into $venv — the previous one stays in place" >&2
  else
    echo "agent-sanitizer: could not move the new secret-redaction engine into $venv, and the previous one could not be restored from $retired — this session redacts through the committed zipapp; move $retired back by hand, or start a new session to re-provision" >&2
  fi
  exit 1
fi
build=""
if [[ -e "$retired" ]]; then
  rm -rf -- "$retired"
fi
echo "agent-sanitizer: secret-redaction engine provisioned into $venv" >&2
