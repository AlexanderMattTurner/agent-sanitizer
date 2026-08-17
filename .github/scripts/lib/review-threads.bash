# shellcheck shell=bash
# Contract: sourced into strict-mode (set -euo pipefail) callers; do not re-set shell options.
#
# The PR review-thread read, in ONE place: the GraphQL document plus the
# `gh api graphql --paginate` call that walks it. Every step that needs a PR's
# review threads goes through fetch_review_threads, so no caller can ship a
# `reviewThreads(first: 100)` with no cursor — a query that silently drops every
# thread past the first page and reports the truncated slice as the whole set.
# Callers differ only in the jq they project each page's nodes through.
#
# Consumers: review-findings-gate.sh, approve-if-reviewer-hold-clear.sh.

# retry_stdout and the reviewer predicate: sourced here rather than assumed, so a
# consumer gets both by sourcing this file alone. Each is idempotent under a
# second source.
# shellcheck source=.github/scripts/lib-ci-retry.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib-ci-retry.sh"
# shellcheck source=.github/scripts/lib/reviewer-identity.bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/reviewer-identity.bash"

# $endCursor + pageInfo are what make `gh api graphql --paginate` able to walk:
# gh feeds the previous page's endCursor back in and stops on hasNextPage=false.
# Drop either and gh has no cursor to advance, so it returns page one forever.
#
# The node selection is the UNION of what the consumers project, because one
# shared document is the point — a few scalars a given caller ignores are far
# cheaper than a second copy of the query. The comment page is the one field with
# a per-page cost proportional to its size, so it is a variable: a caller keying on
# who OPENED each thread takes the root comment alone (the default), and one
# rendering the whole conversation for a model asks for more.
REVIEW_THREADS_QUERY=$(
  cat <<'GRAPHQL'
query($owner: String!, $name: String!, $pr: Int!, $comments: Int!, $endCursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $pr) {
      reviewThreads(first: 100, after: $endCursor) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id
          isResolved
          path
          line
          comments(first: $comments) { nodes { author { login } body } }
        }
      }
    }
  }
}
GRAPHQL
)

# jq predicate over ONE thread node: its ROOT comment was authored by the
# automated reviewer. The authorship question itself belongs to `is_reviewer` in
# lib/reviewer-identity.bash; a thread root is just another authored node, so
# this only says WHICH node to ask about. fetch_review_threads prepends the
# definitions, so a projection using this needs no prelude of its own.
# shellcheck disable=SC2034 # spliced into the sourcing scripts' projections
REVIEW_THREAD_ROOT_IS_REVIEWER='select(.comments.nodes[0] | is_reviewer)'

# fetch_review_threads <owner> <name> <pr> <jq> [comments-per-thread]
#
# Walk EVERY page of the PR's review threads, applying <jq> to each page's nodes
# ARRAY (`.[]` to stream nodes, `[.[] | …] | …` to aggregate) — the response path
# is prefixed here so no caller restates it. gh emits one page's jq output after
# another, so a per-node projection yields a flat stream while a per-page
# aggregate leaves the caller to fold the pages (`jq -s`). Non-zero only once the
# retry ladder is exhausted.
fetch_review_threads() {
  local owner="$1" name="$2" pr="$3" projection="$4" comments="${5:-1}"
  retry_stdout gh api graphql --paginate \
    -f query="$REVIEW_THREADS_QUERY" \
    -f owner="$owner" -f name="$name" -F pr="$pr" -F comments="$comments" \
    --jq "$REVIEWER_JQ .data.repository.pullRequest.reviewThreads.nodes | $projection"
}
