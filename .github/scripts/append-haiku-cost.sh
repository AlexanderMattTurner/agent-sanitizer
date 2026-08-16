#!/usr/bin/env bash
# Fold this Haiku thread-resolution run's cost into the reviewer's original cost
# footnote — runs on EVERY Haiku pass (whether or not it resolved a thread), so
# the footnote's running Haiku tally and the "how many PRs fit a Max 20x plan"
# final line stay current.
#
# Finds the reviewer's costed review (authored by the reviewer
# lib/reviewer-identity.bash defines, carrying the hidden "review-cost" marker
# post-pr-review.mjs writes into the cost footer),
# rewrites its body via compute-haiku-cost-footer.mjs
# (which maintains the tally markers), and PUTs it back. No costed reviewer review
# (e.g. the cost log was missing when it posted) -> nothing to annotate, exit 0.
#
# Env: GH_TOKEN, GH_REPO (owner/name), PR, EXECUTION_FILE; REVIEWER_LOGIN optional.
set -euo pipefail

: "${GH_REPO:?GH_REPO required}"
: "${PR:?PR number required}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=.github/scripts/lib/reviewer-identity.bash
source "$SCRIPT_DIR/lib/reviewer-identity.bash"

# The reviewer's most recent costed review. Paginated so a PR with >100 reviews
# still finds the newest match: the per-page --jq emits each matching review as
# NDJSON, the slurp picks the last (newest — the API returns reviews oldest-first).
target="$(gh api --paginate "repos/${GH_REPO}/pulls/${PR}/reviews" \
  --jq "$REVIEWER_JQ"'.[] | select(is_reviewer_review and (.body | test("<!-- review-cost usd="))) | {id, body}' |
  jq -s 'last // empty')"

if [[ -z "$target" ]]; then
  echo "no costed reviewer review to annotate; skipping" >&2
  exit 0
fi

review_id="$(jq -r '.id' <<<"$target")"
old_body="$(jq -r '.body' <<<"$target")"

new_body="$(printf '%s' "$old_body" |
  EXECUTION_FILE="${EXECUTION_FILE:-}" node .github/scripts/compute-haiku-cost-footer.mjs)"

gh api -X PUT "repos/${GH_REPO}/pulls/${PR}/reviews/${review_id}" -f body="$new_body" >/dev/null
echo "folded Haiku cost into review ${review_id}'s footnote" >&2
