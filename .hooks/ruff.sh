#!/bin/bash
# Run ruff at the version .pre-commit-config.yaml pins, the one CI enforces.
#
# PROBLEM CLASS — a local gate running whichever ruff is on PATH. A newer ruff
# enables more default rules, so it rejects a commit or a push of a tree CI
# passes. lint-staged and .claude/hooks/pre-push-check.sh both call this file.
# With no pin or no uvx: the locked `uv run ruff`, then the PATH ruff, then a
# loud failure. No pin also prints a warning.
#
# Usage: ruff.sh <ruff arguments>
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
pin=""
config="$root/.pre-commit-config.yaml"
runner="$root/.github/scripts/run-with-pyyaml.sh"
if [[ -f "$config" && -f "$runner" ]] && command -v uv >/dev/null 2>&1; then
  # A runner failure (uv offline) leaves the pin empty, so the fallback chain still runs.
  if ! pin="$(bash "$runner" "$root/.github/scripts/ruff_pin.py" "$config")"; then
    pin=""
  fi
fi
if [[ -z "$pin" ]]; then
  echo "WARNING: ruff.sh found no ruff pin in .pre-commit-config.yaml; the ruff it runs may differ from CI." >&2
fi

if [[ -n "$pin" ]] && command -v uvx >/dev/null 2>&1; then
  exec uvx "ruff@${pin}" "$@"
elif [[ -f "$root/uv.lock" ]] && command -v uv >/dev/null 2>&1; then
  exec uv run ruff "$@"
elif command -v ruff >/dev/null 2>&1; then
  exec ruff "$@"
fi
echo "Neither ruff nor uv (with uv.lock) is available to run Python checks." >&2
exit 1
