#!/usr/bin/env bash
# Build every file an installed plugin needs from the checked-out release tag,
# and stage them for commit-plugin-dist.sh: the baked artifacts
# (plugin/scripts/baked-artifacts.mjs lists them) plus plugin.json stamped with
# the release version, laid out at their repo-relative paths under <stage-dir>.
# The four hook binaries are left in <bin-dir> for release-hook-binaries.sh.
#
# plugin.json is restamped because version-bump.sh writes the released version
# into the `docs: release` commit AFTER the tagged one, so the tagged tree still
# names the previous release — and the baked copy is the one Claude Code reads.
#
# Usage: build-plugin-dist.sh <tag> <stage-dir> <bin-dir>
# Needs the network (PyPI for the zipapp, bun's cross-target runtimes) and a
# `pnpm install`ed checkout.
set -euo pipefail

log() { echo "$@" >&2; }

TAG="${1:?usage: build-plugin-dist.sh <tag> <stage-dir> <bin-dir>}"
STAGE="${2:?usage: build-plugin-dist.sh <tag> <stage-dir> <bin-dir>}"
BIN_DIR="${3:?usage: build-plugin-dist.sh <tag> <stage-dir> <bin-dir>}"
if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  log "Error: '$TAG' is not a release tag (vX.Y.Z)."
  exit 1
fi
VERSION="${TAG#v}"
PLUGIN_JSON=plugin/.claude-plugin/plugin.json
BUNDLE=plugin/dist/hooks/plugin-hooks.bundle.mjs
MANIFEST=plugin/dist/hooks/hook-binaries.sha256

NEW_VERSION="$VERSION" node .github/scripts/set-plugin-version.mjs
node plugin/scripts/build-plugin.mjs
node plugin/scripts/build-redactor-pyz.mjs
node plugin/scripts/build-hook-binaries.mjs --outdir="$BIN_DIR"

# The provisioner refuses a hook binary whose manifest pins a different bundle
# than the one installed beside it, so a bake that breaks this pairing would
# ship a plugin that never provisions its fast path.
BUNDLE_SHA="$(sha256sum "$BUNDLE")"
BUNDLE_SHA="${BUNDLE_SHA%% *}"
if ! grep -qxF "# bundle=$BUNDLE_SHA" "$MANIFEST"; then
  log "Error: $MANIFEST does not pin the bundle it was built beside ($BUNDLE_SHA)."
  exit 1
fi
STAMPED="$(jq -er .version "$PLUGIN_JSON")"
if [[ "$STAMPED" != "$VERSION" ]]; then
  log "Error: $PLUGIN_JSON reads $STAMPED after stamping $VERSION."
  exit 1
fi

# Captured first: a failure inside `< <(…)` would be silently dropped, staging
# plugin.json alone.
BAKED="$(node plugin/scripts/baked-artifacts.mjs)"
FILES=("$PLUGIN_JSON")
while IFS= read -r path; do
  FILES+=("$path")
done <<<"$BAKED"
for path in "${FILES[@]}"; do
  if [[ ! -s "$path" ]]; then
    log "Error: the build left $path missing or empty."
    exit 1
  fi
  dest_dir="$STAGE/$(dirname "$path")"
  mkdir -p "$dest_dir"
  [[ -d "$dest_dir" ]] || {
    log "Error: could not create $dest_dir."
    exit 1
  }
  cp -- "$path" "$STAGE/$path"
done
log "Staged ${#FILES[@]} files for $TAG in $STAGE."
