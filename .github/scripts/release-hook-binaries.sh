#!/usr/bin/env bash
# Attach the bun-compiled hook binaries to the GitHub release for $TAG. The
# binaries were compiled by build-plugin-dist.sh in the same run that rendered
# the hook-binary manifest baked onto `plugin-dist`, so their digests are the
# manifest's by construction; this re-checks every one against that manifest
# with `sha256sum -c` before uploading, so an artifact corrupted in transit is
# never published as the asset the SessionStart provisioner downloads.
#
# Usage: release-hook-binaries.sh <bin-dir> <manifest>
# Env:   $TAG — the release tag (vX.Y.Z); $GH_TOKEN — a token with
#        `contents: write` on this repo.
# Idempotent on re-runs: when the release already exists, the assets are
# re-uploaded with `--clobber` instead of failing on the duplicate create.
set -euo pipefail

log() { echo "$@" >&2; }

BIN_DIR="${1:?usage: release-hook-binaries.sh <bin-dir> <manifest>}"
MANIFEST="${2:?usage: release-hook-binaries.sh <bin-dir> <manifest>}"
TAG="${TAG:?TAG (the release tag, vX.Y.Z) must be set}"
MANIFEST_ABS="$(cd "$(dirname "$MANIFEST")" && pwd)/$(basename "$MANIFEST")"

NAMES="$(awk '/^[0-9a-f]{64}  / { print $2 }' "$MANIFEST_ABS")"
ASSETS=()
while IFS= read -r asset; do
  if [[ -n "$asset" ]]; then
    ASSETS+=("$BIN_DIR/$asset")
  fi
done <<<"$NAMES"
if [[ "${#ASSETS[@]}" -eq 0 ]]; then
  log "Error: $MANIFEST names no hook binaries."
  exit 1
fi
# sha256sum skips the `# key=value` header lines as comments and fails on a
# missing or mismatched binary; --strict also fails on a malformed line.
(cd "$BIN_DIR" && sha256sum --check --strict "$MANIFEST_ABS")

# Notes stay minimal: the CHANGELOG's matching section is the release-notes
# source of truth (promoted by version-bump.sh), so the release just points
# there instead of duplicating prose that would drift.
CREATE_RC=0
CREATE_OUTPUT=$(gh release create "$TAG" "${ASSETS[@]}" \
  --verify-tag --title "$TAG" --notes "See CHANGELOG.md." 2>&1) || CREATE_RC=$?
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
