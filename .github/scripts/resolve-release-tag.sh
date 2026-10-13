#!/usr/bin/env bash
# Write `tag=<vX.Y.Z>` to $GITHUB_OUTPUT for the release tag on HEAD, or `tag=`
# when HEAD carries none.
#
# version-bump.sh tags the exact SHA it published, which is the SHA the
# triggering push checked out — so a run that released leaves its tag on HEAD,
# and a run that did not (nothing to release, or a failure before tagging)
# leaves none and there is nothing to bake.
#
# Usage: resolve-release-tag.sh [<wanted-tag>]
#   With <wanted-tag> (a manual dispatch), HEAD must carry exactly that tag;
#   anything else fails loudly rather than baking a tree under the wrong name.
set -euo pipefail

log() { echo "$@" >&2; }

WANTED="${1:-}"
OUTPUT="${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set}"

# Template-sync delivers this workflow to repos that ship no plugin. There is
# nothing to bake there, and build-plugin-dist.sh would die on the missing build
# script, so resolve to "no tag" before looking at tags at all.
ROOT="$(git rev-parse --show-toplevel)"
if [[ ! -f "$ROOT/plugin/scripts/build-plugin.mjs" ]]; then
  log "No plugin/scripts/build-plugin.mjs in this repo: no plugin to bake."
  echo "tag=" >>"$OUTPUT"
  exit 0
fi

# Captured first so a failing `git tag` aborts here instead of reading as "no
# tag" and silently skipping the bake.
ON_HEAD="$(git tag --points-at HEAD --list 'v*')"
HEAD_SHA="$(git rev-parse HEAD)"
TAGS=()
while IFS= read -r tag; do
  if [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    TAGS+=("$tag")
  fi
done <<<"$ON_HEAD"

if [[ -n "$WANTED" ]]; then
  for tag in "${TAGS[@]}"; do
    if [[ "$tag" == "$WANTED" ]]; then
      echo "tag=$WANTED" >>"$OUTPUT"
      exit 0
    fi
  done
  log "Error: HEAD ($HEAD_SHA) is not tagged $WANTED; it carries: ${TAGS[*]:-no release tag}."
  exit 1
fi

case "${#TAGS[@]}" in
0)
  log "HEAD ($HEAD_SHA) carries no release tag: this push released nothing, so there is nothing to bake."
  echo "tag=" >>"$OUTPUT"
  ;;
1)
  echo "tag=${TAGS[0]}" >>"$OUTPUT"
  ;;
*)
  log "Error: HEAD carries several release tags (${TAGS[*]}); bake one explicitly via workflow_dispatch."
  exit 1
  ;;
esac
