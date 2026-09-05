#!/usr/bin/env bash
# Regenerate plugin/dist/hooks/hook-binaries.sha256 against the default branch's
# CURRENT tip and land it there.
#
# Usage: commit-refreshed-manifest.sh <generator-argv…>
#   e.g. commit-refreshed-manifest.sh node plugin/scripts/build-hook-binaries.mjs --if-stale
#
# The generator is passed in rather than called by name so this script can be
# driven end to end in a test: the real one compiles four bun targets (~100 MB
# each, downloaded on a cold cache), which no unit test can run. Everything else
# here — the tip sync, the change detection, the commit, the push — is real.
#
# The manifest is the SessionStart provisioner's trust anchor: it pins the bundle
# the release binaries were compiled from, and the provisioner refuses to install
# a binary when that pin does not match the bundle the install ships. So the
# default branch must carry a manifest describing ITS bundle, and this is the
# single writer that keeps it that way — PR branches never touch the file, which
# is what makes it unable to conflict.
#
# Ordered BEFORE the release in auto-version.yaml so the published tree and the
# vX.Y.Z tag on it carry the refreshed manifest rather than the previous
# release's. Pushed here rather than left for version-bump.sh's release-docs
# commit because most pushes to the default branch cut no release at all, and the
# commit would then be dropped with the runner.
#
# Inputs: $GITHUB_REF_NAME — the branch to refresh (Actions sets it; a local run
# falls back to the current branch, which detached HEAD makes an error rather
# than a bogus "HEAD:HEAD" push).
set -euo pipefail

MANIFEST="plugin/dist/hooks/hook-binaries.sha256"

log() { echo "$@" >&2; }

[[ $# -ge 1 ]] || {
  log "usage: commit-refreshed-manifest.sh <generator-argv…>"
  exit 1
}

branch="${GITHUB_REF_NAME:-$(git rev-parse --abbrev-ref HEAD)}"
if [[ "$branch" == "HEAD" ]]; then
  log "Error: cannot push from a detached HEAD without GITHUB_REF_NAME naming the branch."
  exit 1
fi

# shellcheck source=.github/scripts/lib-ci-retry.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib-ci-retry.sh"

# Regenerate against the branch TIP, not the SHA that triggered this run. The
# auto-version concurrency group queues runs, so by the time this one starts the
# branch can already carry a later merge — and a manifest compiled from the
# triggering SHA would then describe a bundle that is no longer on the branch,
# on a commit whose push is rejected non-fast-forward. Both wrongs come from the
# same stale checkout, so both are fixed by moving to the tip first.
retry timeout --kill-after=10 60 git fetch origin "$branch"
git reset --hard "origin/$branch"

"$@"

if git diff --quiet -- "$MANIFEST"; then
  log "$MANIFEST already describes the tip of $branch; nothing to refresh."
  exit 0
fi

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git add -- "$MANIFEST"
# [skip ci]: the manifest is emitted by its own generator, so re-running the
# suite over it proves nothing, and the default branch is protected by required
# checks this bot commit could never satisfy.
git commit -m "chore(plugin): refresh the hook-binary digest manifest [skip ci]"

# Retried for a network blip only — deliberately NOT rebased onto a tip that
# moved during the compile itself. A merge landing in that window moves the
# bundle too, so replaying this commit onto it would push a manifest describing
# neither tree; that merge's own push runs this refresh from the new tip and
# gets it right. Failing here is loud on purpose: it aborts the release step
# below rather than tagging a tree whose manifest the provisioner will reject.
if ! RETRY_MAX="${RETRY_MAX:-4}" RETRY_BASE_DELAY="${RETRY_BASE_DELAY:-2}" \
  retry timeout --kill-after=10 60 git push origin "HEAD:$branch"; then
  log "Error: failed to push the refreshed $MANIFEST to $branch."
  log "       Until it lands, $branch pins binaries compiled from an older bundle and"
  log "       the SessionStart provisioner refuses to install one. The next push to"
  log "       $branch re-runs this refresh from the new tip."
  exit 1
fi
log "Pushed the refreshed $MANIFEST to $branch."
