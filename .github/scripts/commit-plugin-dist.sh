#!/usr/bin/env bash
# Commit a release's baked plugin onto the branch the marketplace installs from,
# and push it — fast-forward only, never forced.
#
# The commit's tree is the tagged tree with <stage-dir>'s files laid over it, and
# its parents are the branch's previous tip and the tagged commit. So the branch
# only ever moves forward, every release on it is reachable from the tag it was
# built from, and "is this tag already baked?" is plain ancestry — which is what
# makes a re-run, or a dispatch of an older tag, a no-op instead of a rollback.
# A missing branch is bootstrapped with the tagged commit as the only parent.
#
# Usage: commit-plugin-dist.sh <tag> <stage-dir>
# Runs in a checkout of the tag with full history and push credentials, and
# nothing else: no dependency install, so no repo hook and no third-party code
# runs beside the credential.
set -euo pipefail

log() { echo "$@" >&2; }

# shellcheck source=.github/scripts/lib-ci-retry.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib-ci-retry.sh"

TAG="${1:?usage: commit-plugin-dist.sh <tag> <stage-dir>}"
STAGE="${2:?usage: commit-plugin-dist.sh <tag> <stage-dir>}"
TAG_COMMIT="$(git rev-parse --verify "refs/tags/$TAG^{commit}")"

# The branch name is read from the marketplace this tag ships, so the bake
# writes exactly the ref the published marketplace tells Claude Code to read.
BRANCH="$(git show "$TAG_COMMIT:.claude-plugin/marketplace.json" |
  jq -er '[.plugins[].source.ref] | unique | if length == 1 and (.[0] | type) == "string" then .[0] else error("marketplace plugins name \(.) as their ref; expected one branch") end')"

REMOTE_RC=0
timeout --kill-after=10 120 git ls-remote --exit-code --heads origin "refs/heads/$BRANCH" >/dev/null || REMOTE_RC=$?
PARENTS=()
case "$REMOTE_RC" in
0)
  timeout --kill-after=10 300 git fetch --no-tags origin "+refs/heads/$BRANCH:refs/remotes/origin/$BRANCH"
  TIP="$(git rev-parse --verify "refs/remotes/origin/$BRANCH^{commit}")"
  if git merge-base --is-ancestor "$TAG_COMMIT" "$TIP"; then
    log "$BRANCH ($TIP) already contains $TAG ($TAG_COMMIT); nothing to bake."
    exit 0
  fi
  PARENTS+=(-p "$TIP")
  ;;
2)
  log "$BRANCH does not exist on origin yet; bootstrapping it from $TAG."
  ;;
*)
  log "Error: git ls-remote for $BRANCH failed (exit $REMOTE_RC)."
  exit "$REMOTE_RC"
  ;;
esac
PARENTS+=(-p "$TAG_COMMIT")

# Captured first: a failing `find` inside `< <(…)` would be silently dropped,
# committing the bare tagged tree as if it were baked.
STAGED="$(cd "$STAGE" && find . -type f -printf '%P\n' | LC_ALL=C sort)"
if [[ -z "$STAGED" ]]; then
  log "Error: $STAGE holds no files to bake."
  exit 1
fi

# A private index, so the checkout's own index and working tree are never
# touched. Every baked file is a plain 100644 blob, as the sources are.
GIT_INDEX_FILE="$(mktemp)"
export GIT_INDEX_FILE
trap 'rm -f "$GIT_INDEX_FILE"' EXIT
git read-tree "$TAG_COMMIT"
while IFS= read -r path; do
  blob="$(git hash-object -w -- "$STAGE/$path")"
  git update-index --add --cacheinfo "100644,$blob,$path"
done <<<"$STAGED"
TREE="$(git write-tree)"

COMMIT="$(GIT_AUTHOR_NAME="github-actions[bot]" \
  GIT_AUTHOR_EMAIL="41898282+github-actions[bot]@users.noreply.github.com" \
  GIT_COMMITTER_NAME="github-actions[bot]" \
  GIT_COMMITTER_EMAIL="41898282+github-actions[bot]@users.noreply.github.com" \
  git commit-tree "$TREE" "${PARENTS[@]}" -m "build(plugin-dist): bake $TAG")"

# No force: a concurrent writer makes this a non-fast-forward rejection, which
# fails the run loudly rather than discarding the other writer's commit.
RETRY_MAX=4 RETRY_BASE_DELAY=2 retry timeout --kill-after=10 300 git push origin "$COMMIT:refs/heads/$BRANCH"
log "✅ Baked $TAG onto $BRANCH as $COMMIT."
