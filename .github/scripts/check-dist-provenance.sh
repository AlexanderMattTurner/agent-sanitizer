#!/usr/bin/env bash
# The committed plugin bundle may only move when one of its BUILD INPUTS moves.
# The first-party inputs are the source trees the artifacts compile from — src/
# for the JS bundle, python/ for the wheel and zipapp — plus the locked
# dependency inputs below. Omitting src/ or python/ makes the check fire on every
# honest source-only change, which regenerates the artifact with no lockfile diff.
#
# The reproducibility test already refuses a bundle that differs from a fresh
# build, which stops a hand-edited artifact. This closes the other direction: an
# artifact change riding a PR that touches none of the things the artifact is
# built from. BOTH dependency trees are locked and committed — pnpm-lock.yaml for
# the JS bundle, plugin/requirements.txt (hash-pinned) for the zipapp — so every
# dependency-driven change to either artifact shows up as a lockfile change in
# the same diff. A dist diff with no input diff therefore has no legitimate
# cause on an honest PR — with one residual gap: the zipapp installs its sdists
# under PEP 517 build isolation, so the build BACKENDS (setuptools/hatchling and
# their own build-system.requires) are resolved from PyPI per build and are not
# in plugin/requirements.txt. A backend release that changes the generated
# METADATA — the one dist-info file the zipapp keeps — can still move its bytes
# with no diff here. If that ever fires, pin the backend; do not re-exempt the
# artifact. (An earlier exemption existed for exactly that shape of drift one
# layer up, when the Python tree itself was unlocked.)
set -euo pipefail

base_ref="${1:?usage: check-dist-provenance.sh <base-ref>}"

changed="$(git diff --name-only "$base_ref"...HEAD)"

dist_changed=false
input_changed=false
while IFS= read -r file; do
  [[ -n "$file" ]] || continue
  case "$file" in
  plugin/dist/*) dist_changed=true ;;
  src/* | python/* | package.json | pnpm-lock.yaml | claude-hooks/* | plugin/scripts/* | plugin/requirements.in | plugin/requirements.txt)
    input_changed=true
    ;;
  esac
done <<<"$changed"

if [[ "$dist_changed" == true && "$input_changed" == false ]]; then
  echo "::error::plugin/dist changed but no build input did." >&2
  echo "The artifacts are generated from src/ + python/ + package.json + pnpm-lock.yaml +" >&2
  echo "claude-hooks/ + plugin/scripts/ + plugin/requirements.{in,txt}. A dist-only diff" >&2
  echo "means the artifact was edited by hand or carried over from another branch. Rebuild with:" >&2
  echo "  node plugin/scripts/build-plugin.mjs        # JS bundle + requirements.in" >&2
  echo "  node plugin/scripts/build-redactor-pyz.mjs  # zipapp, from the committed lock" >&2
  echo "  node plugin/scripts/build-hook-binaries.mjs # hook-binary digest manifest" >&2
  git diff --stat "$base_ref"...HEAD -- plugin/dist >&2
  exit 1
fi

if [[ "$dist_changed" == true ]]; then
  echo "plugin/dist changed alongside a build input — expected."
else
  echo "plugin/dist unchanged."
fi
