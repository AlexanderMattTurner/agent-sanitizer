#!/usr/bin/env bash
# Rebuild the bun-compiled hook binaries and attach them to the GitHub release
# for the version just published. `--check` recompiles all four platform
# executables from this tree and fails loudly unless their digests reproduce
# the committed manifest byte-for-byte — a mismatch means the release would
# ship binaries the SessionStart provisioner's digest verification rejects, so
# nothing is uploaded and the step's failure is the alert (via the
# build-publish-notify workflow_run listener).
#
# Inputs: $VERSION — the released X.Y.Z; the tag "v$VERSION" is already pushed
# by version-bump.sh before this runs. $GH_TOKEN — the workflow's github.token.
# Idempotent on re-runs: when the release already exists, the assets are
# re-uploaded with `--clobber` instead of failing on the duplicate create.
set -euo pipefail

log() { echo "$@" >&2; }

VERSION="${VERSION:?VERSION (the released X.Y.Z version) must be set}"
TAG="v$VERSION"

OUTDIR=$(mktemp -d)
trap 'rm -rf "$OUTDIR"' EXIT

# --outdir keeps the digest-verified binaries around for the upload below.
node plugin/scripts/build-hook-binaries.mjs --check --outdir="$OUTDIR"

ASSETS=("$OUTDIR"/agent-sanitizer-hooks-*)
if [[ "${#ASSETS[@]}" -ne 4 ]]; then
  log "Error: expected 4 hook binaries in $OUTDIR, found ${#ASSETS[@]}: ${ASSETS[*]}"
  exit 1
fi

# Notes stay minimal: the CHANGELOG's matching "## [$VERSION]" section is the
# release-notes source of truth (promoted by version-bump.sh), so the release
# just points there instead of duplicating prose that would drift.
CREATE_RC=0
CREATE_OUTPUT=$(gh release create "$TAG" "${ASSETS[@]}" \
  --title "$TAG" --notes "See CHANGELOG.md." 2>&1) || CREATE_RC=$?
if [[ "$CREATE_RC" -ne 0 ]]; then
  # Only an already-existing release (a re-run, or an out-of-band release for
  # this tag) downgrades to an asset upload — asked via `gh release view`, not
  # parsed from error text. Any other create failure is real and propagates.
  if ! gh release view "$TAG" >/dev/null 2>&1; then
    log "$CREATE_OUTPUT"
    log "Error: could not create release $TAG (and it does not already exist)."
    exit "$CREATE_RC"
  fi
  log "Release $TAG already exists; uploading the binaries with --clobber."
  gh release upload "$TAG" "${ASSETS[@]}" --clobber
else
  log "$CREATE_OUTPUT"
fi
log "✅ Hook binaries attached to release $TAG."
