# shellcheck shell=bash
# Contract: sourced into strict-mode (set -euo pipefail) callers; do not re-set shell options.
#
# The GraphQL review read behind the merge gate: the document plus the reviewer
# filter that answer "what has the automated reviewer posted on this PR?". Kept in
# a lib rather than inline so the pagination cannot be dropped — a
# `reviews(first: 100)` with no cursor returns the OLDEST 100 reviews and reports
# a stale state as the live one.
#
# Consumer: review-findings-gate.sh. (decide-pr-review-trigger.sh answers a
# different question — the latest review's STATE, over the REST endpoint — and
# does not share this document.)

# retry_stdout: sourced here rather than assumed, so a consumer gets the retry
# ladder by sourcing this file alone. lib-ci-retry.sh guards against double-source.
# shellcheck source=.github/scripts/lib-ci-retry.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib-ci-retry.sh"

# $endCursor + pageInfo are what make `gh api graphql --paginate` able to walk:
# gh feeds the previous page's endCursor back in and stops on hasNextPage=false.
# Drop either and gh has no cursor to advance, so it returns page one forever —
# and page one of `reviews` is the OLDEST page, so an unpaginated query on a
# long-lived PR reports a superseded review as the current state.
REVIEWS_QUERY=$(
  cat <<'GRAPHQL'
query($owner: String!, $name: String!, $pr: Int!, $endCursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $pr) {
      reviews(first: 100, after: $endCursor) {
        pageInfo { hasNextPage endCursor }
        nodes { author { login } state body submittedAt }
      }
    }
  }
}
GRAPHQL
)

# reviewer_reviews_ndjson <owner> <name> <pr>
#
# Every one of the reviewer's REAL reviews as NDJSON objects
# {state, body, submittedAt}.
#
# Empty-body reviews are excluded HERE, in the one shared read: GitHub
# synthesizes a body-less COMMENTED review by the same bot around every
# standalone review-comment POST (the thread resolver's audit replies), and
# counting one as "the reviewer's review" satisfies the review-findings gate's
# reviewed-at-all condition vacuously. The real reviewer never posts an empty
# body (post-pr-review.mjs falls back to "Automated review."), so body-non-empty
# is exactly the real-review discriminator.
#
# Requires the caller to have EXPORTED REVIEWER_LOGIN_BARE: the jq reads it out of
# `env`, and GraphQL returns an app bot's login WITHOUT the REST `[bot]` suffix
# (`github-actions`, not `github-actions[bot]`), so the node's login is stripped
# the same way before comparing and either spelling matches.
reviewer_reviews_ndjson() {
  local owner="$1" name="$2" pr="$3"
  retry_stdout gh api graphql --paginate \
    -f query="$REVIEWS_QUERY" -f owner="$owner" -f name="$name" -F pr="$pr" \
    --jq '.data.repository.pullRequest.reviews.nodes[]
          | select((.author.login // "" | sub("\\[bot\\]$"; "")) == env.REVIEWER_LOGIN_BARE)
          | select((.body // "") != "")
          | {state, body, submittedAt}'
}
