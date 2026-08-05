#!/usr/bin/env bash
# The committed plugin bundle may only move when one of its BUILD INPUTS moves.
#
# The reproducibility test already refuses a bundle that differs from a fresh
# build, which stops a hand-edited artifact. This closes the other direction: an
# artifact change riding a PR that touches none of the things the artifact is
# built from. Since the lockfile is committed, every dependency-driven change to
# the bundle shows up as a pnpm-lock.yaml change in the same diff — so a dist
# diff with no input diff has no legitimate cause, and the check cannot fire on
# an honest PR.
set -euo pipefail

base_ref="${1:?usage: check-dist-provenance.sh <base-ref>}"

changed="$(git diff --name-only "$base_ref"...HEAD)"

dist_changed=false
input_changed=false
while IFS= read -r file; do
  [[ -n "$file" ]] || continue
  case "$file" in
  # The zipapp is the one artifact whose inputs are NOT all committed: only
  # `agent-sanitizer[secrets]==X.Y.Z` is pinned, its transitive Python deps
  # float, so a new dep release moves the bytes with no diff in this repo at
  # all. That drift is legitimate and is caught the strong way instead — the
  # live-engine job (ungated, every PR) rebuilds the zipapp from PyPI and
  # `git diff --exit-code`s it, which refuses a hand-edited artifact outright.
  # Counting it here only ever fires on the honest rebuild.
  plugin/dist/redactor/*) ;;
  plugin/dist/*) dist_changed=true ;;
  package.json | pnpm-lock.yaml | claude-hooks/* | plugin/scripts/* | plugin/requirements.txt)
    input_changed=true
    ;;
  esac
done <<<"$changed"

if [[ "$dist_changed" == true && "$input_changed" == false ]]; then
  echo "::error::plugin/dist changed but no build input did." >&2
  echo "The bundle is generated from package.json + pnpm-lock.yaml + claude-hooks/ +" >&2
  echo "plugin/scripts/. A dist-only diff means the artifact was edited by hand or" >&2
  echo "carried over from another branch. Rebuild with:" >&2
  echo "  node plugin/scripts/build-plugin.mjs" >&2
  git diff --stat "$base_ref"...HEAD -- plugin/dist >&2
  exit 1
fi

if [[ "$dist_changed" == true ]]; then
  echo "plugin/dist changed alongside a build input — expected."
else
  echo "plugin/dist unchanged."
fi
