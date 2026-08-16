# shellcheck shell=bash
# Contract: sourced into strict-mode (set -euo pipefail) callers; do not re-set shell options.
#
# The GraphQL review read behind the merge gate: the document plus the reviewer
# filter that answer "what has the automated reviewer posted on this PR?". Kept in
# a lib rather than inline so the pagination cannot be dropped — a
# `reviews(first: 100)` with no cursor returns the OLDEST 100 reviews and reports
# a stale state as the live one.
#
# Consumers: review-findings-gate.sh, approve-if-reviewer-hold-clear.sh.
# (decide-pr-review-trigger.sh answers a different question — the latest review's
# STATE, over the REST endpoint — and does not share this document.)

# retry_stdout and the reviewer predicate: sourced here rather than assumed, so a
# consumer gets both by sourcing this file alone. Each is idempotent under a
# second source.
# shellcheck source=.github/scripts/lib-ci-retry.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib-ci-retry.sh"
# shellcheck source=.github/scripts/lib/reviewer-identity.bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/reviewer-identity.bash"

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
        nodes { databaseId author { login } state body submittedAt }
      }
    }
  }
}
GRAPHQL
)

# reviewer_reviews_ndjson <owner> <name> <pr>
#
# Every one of the reviewer's REAL reviews as NDJSON objects
# {databaseId, state, body, submittedAt}. `is_reviewer_review` — the shared
# predicate in lib/reviewer-identity.bash — decides both halves of "the
# reviewer's real review": who authored it, and that it carries a body at all.
reviewer_reviews_ndjson() {
  local owner="$1" name="$2" pr="$3"
  retry_stdout gh api graphql --paginate \
    -f query="$REVIEWS_QUERY" -f owner="$owner" -f name="$name" -F pr="$pr" \
    --jq "$REVIEWER_JQ"'.data.repository.pullRequest.reviews.nodes[]
          | select(is_reviewer_review)
          | {databaseId, state, body, submittedAt}'
}
