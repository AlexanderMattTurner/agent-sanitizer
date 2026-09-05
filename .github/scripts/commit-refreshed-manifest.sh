#!/usr/bin/env bash
# Commit and push a refreshed plugin/dist/hooks/hook-binaries.sha256 to the
# default branch. Run right after `build-hook-binaries.mjs --if-stale`, which is
# what may have rewritten it; this script owns only the git half, so the
# 4-target bun compile stays out of the unit test that drives it.
#
# The manifest is the SessionStart provisioner's trust anchor: it pins the
# bundle the release binaries were compiled from, and the provisioner refuses to
# install a binary when that pin does not match the bundle the install ships. So
# the default branch must carry a manifest describing ITS bundle, and this is
# the single writer that keeps it that way — PR branches never touch the file,
# which is what makes it unable to conflict.
#
# Ordered BEFORE the release in auto-version.yaml so the published tree and the
# vX.Y.Z tag on it carry the refreshed manifest rather than the previous
# release's. Pushed here rather than left for version-bump.sh's release-docs
# commit because most pushes to the default branch cut no release at all, and
# the commit would then be dropped with the runner.
#
# Inputs: $GITHUB_REF_NAME — the branch to push to (Actions sets it; a local run
# falls back to the current branch, which detached HEAD makes an error rather
# than a bogus "HEAD:HEAD" push).
set -euo pipefail

MANIFEST="plugin/dist/hooks/hook-binaries.sha256"

log() { echo "$@" >&2; }

branch="${GITHUB_REF_NAME:-$(git rev-parse --abbrev-ref HEAD)}"
if [[ "$branch" == "HEAD" ]]; then
  log "Error: cannot push from a detached HEAD without GITHUB_REF_NAME naming the branch."
  exit 1
fi

if git diff --quiet -- "$MANIFEST"; then
  log "$MANIFEST already describes this tree; nothing to refresh."
  exit 0
fi

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git add -- "$MANIFEST"
# [skip ci]: the manifest is emitted by its own generator, so re-running the
# suite over it proves nothing, and the default branch is protected by required
# checks this bot commit could never satisfy.
git commit -m "chore(plugin): refresh the hook-binary digest manifest [skip ci]"

# Retried for a network blip only — deliberately NOT rebased onto a racing tip.
# A merge that lands mid-run moves the bundle too, so replaying this commit onto
# it would push a manifest describing neither tree; that merge's own push runs
# this same refresh and gets it right. Failing here is therefore self-healing,
# and loud is the point: it aborts the release step below rather than tagging a
# tree whose manifest the provisioner will reject.
# shellcheck source=.github/scripts/lib-ci-retry.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib-ci-retry.sh"
if ! RETRY_MAX="${RETRY_MAX:-4}" RETRY_BASE_DELAY="${RETRY_BASE_DELAY:-2}" \
  retry timeout --kill-after=10 60 git push origin "HEAD:$branch"; then
  log "Error: failed to push the refreshed $MANIFEST to $branch."
  log "       Until it lands, $branch pins binaries compiled from an older bundle and"
  log "       the SessionStart provisioner refuses to install one. The next push to"
  log "       $branch re-runs this refresh."
  exit 1
fi
log "Pushed the refreshed $MANIFEST to $branch."
