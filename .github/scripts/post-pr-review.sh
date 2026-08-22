#!/usr/bin/env bash
# Post the review agent's structured findings as ONE GitHub PR review with
# inline, line-anchored comments and (where offered) one-click suggested edits.
# post-pr-review.mjs builds the reviews-API payload from review.json; this posts
# it via the shared retry-as-COMMENT helper (lib-post-review-with-retry.sh) —
# see that file for why the retry exists.
#
# Requires: gh authenticated (GH_TOKEN), GH_REPO, PR, PR_INPUT_DIR; node with the
# scripts on the module path. HEAD_SHA (the PR head sha) is optional but pins the
# review to the reviewed commit.
set -euo pipefail

# shellcheck source=.github/scripts/lib-post-review-with-retry.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib-post-review-with-retry.sh"

: "${PR:?PR number required}"
: "${GH_REPO:?GH_REPO required}"
: "${PR_INPUT_DIR:?PR_INPUT_DIR required}"

# A non-zero exit from the reader means the reviewer produced no valid
# review.json — it crashed before writing its verdict. Surface that as a RED step
# (fail loud) rather than the reader's old silent green, so a broken reviewer
# can't masquerade as a clean pass. `if !` suspends set -e for the substitution so
# we can react to the failure instead of dying on it.
if ! status="$(node .github/scripts/post-pr-review.mjs)"; then
  echo "::error::the reviewer wrote no valid review.json — it likely crashed; see the reader's diagnostics above" >&2
  exit 1
fi
if [[ "$status" != "PAYLOAD" ]]; then
  echo "no structured review to post" >&2
  exit 0
fi

post_review_with_retry "$PR" "${PR_INPUT_DIR}/review-payload.json" "${PR_INPUT_DIR}/review-summary.txt"
