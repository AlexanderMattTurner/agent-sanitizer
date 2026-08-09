#!/usr/bin/env bash
# Resolve the reviewer threads Haiku judged addressed. Resolving ONLY — what
# clears the merge is the review-findings gate, whose predicate is re-derived from
# the PR's unresolved threads by review-findings-gate.sh; the resolver workflow
# re-posts that verdict in a separate always-on step so it lands no matter WHO
# resolved the last thread (this run, a human, or a prior race).
#
# Flow:
#   1. select-resolvable-threads.mjs turns (threads.json, verdicts.json) into
#      resolve-list.jsonl: the {id, path, line, reason} of each thread to close.
#   2. For each, RESOLVE the thread first and confirm it actually took, THEN post
#      the short in-thread reply that records WHY it was auto-resolved — resolve
#      before reply so a failed resolve never leaves a lying "Auto-resolved"
#      comment on a still-open thread.
#
# Two tokens, on purpose:
#   * The Actions GITHUB_TOKEN can REPLY to a review thread but NOT resolve one —
#     resolveReviewThread returns "Resource not accessible by integration" for the
#     app installation token even with pull-requests:write, so a resolve needs a
#     PAT acting as a user (GH_RESOLVE_TOKEN).
#   * The audit reply is posted with the ambient GH_TOKEN (the GITHUB_TOKEN) so it
#     keeps the github-actions[bot] identity the rest of the reviewer machinery
#     keys on.
#
# Env: GH_TOKEN (reply, GITHUB_TOKEN), the GH_TOKEN_* ladder rungs the resolve
# credential is picked from (see lib/github-token-ladder.bash), PR_INPUT_DIR.
# (select-resolvable-threads.mjs reads the threads/verdicts under PR_INPUT_DIR;
# the reply+resolve mutations act on thread ids alone, so no owner/name/PR number
# is needed here.)
set -euo pipefail

: "${PR_INPUT_DIR:?PR_INPUT_DIR required}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/github-token-ladder.bash disable=SC1091
source "$SCRIPT_DIR/lib/github-token-ladder.bash"
# shellcheck source=.github/scripts/lib-ci-retry.sh
source "$SCRIPT_DIR/lib-ci-retry.sh"

# The resolve PAT is a USER credential, so its API budget is shared with every
# other job and session acting as that user — an exhausted budget answers this
# mutation with "API rate limit already exceeded", not a permission error. Back
# off far enough to outlast a secondary limit (5+10+20+40s) before going red; a
# primary limit resets hourly and correctly stays red rather than silently
# skipping the resolve. A hard permission error burns the same cap before going
# red, which is the accepted cost of not parsing gh's error text: that state is a
# broken credential config, and it has to go red either way.
RETRY_MAX=5
RETRY_BASE_DELAY=5

die() {
  echo "$*" >&2
  exit 1
}

GH_RESOLVE_TOKEN="$(github_token_with_quota)" ||
  die "every configured GitHub credential is out of API quota; cannot resolve threads. Re-run once quota resets, or provision another TEMPLATE_SYNC_TOKEN."

count="$(node .github/scripts/select-resolvable-threads.mjs)"
if [[ "$count" -eq 0 ]]; then
  echo "no threads judged addressed; nothing to resolve" >&2
  exit 0
fi

# SC2016: the `$id`/`$body` are GraphQL variables the query passes to `gh api`,
# NOT shell expansions — single quotes keep them literal on purpose.
# shellcheck disable=SC2016
reply_mutation='mutation($id: ID!, $body: String!) {
  addPullRequestReviewThreadReply(input: {pullRequestReviewThreadId: $id, body: $body}) { comment { id } }
}'
# shellcheck disable=SC2016
resolve_mutation='mutation($id: ID!) {
  resolveReviewThread(input: {threadId: $id}) { thread { id isResolved } }
}'

# One thread's resolve, as a function so retry_stdout can re-run it: gh writes
# the HTTP error body to stdout, which only retry_stdout (not plain retry) keeps
# out of the captured response.
gh_resolve_thread() {
  GH_TOKEN="$GH_RESOLVE_TOKEN" gh api graphql -f query="$resolve_mutation" -f id="$1"
}

resolved=0
while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  id="$(jq -r '.id' <<<"$line")"
  where="$(jq -r 'if .path then .path + (if .line then ":" + (.line|tostring) else "" end) else "(general)" end' <<<"$line")"
  reason="$(jq -r '.reason // ""' <<<"$line")"

  # Resolve FIRST (via the PAT) and prove the post-condition — that the thread is
  # actually resolved — before anything claims it was. Trusting the command's exit
  # status alone is not enough: a 200 that failed to resolve (or a swallowed
  # error) would otherwise read as success, so assert isResolved on the response.
  resp="$(retry_stdout gh_resolve_thread "$id")" ||
    die "resolveReviewThread failed for ${where} (thread ${id}) after ${RETRY_MAX} attempts — see gh's error above. Two causes look identical from here: GH_RESOLVE_TOKEN's user is over its API rate limit, or GH_RESOLVE_TOKEN is not a PAT with pull-request write (the Actions GITHUB_TOKEN cannot resolve threads, only reply)."
  jq -e '.data.resolveReviewThread.thread.isResolved == true' <<<"$resp" >/dev/null ||
    die "resolveReviewThread returned without resolving ${where} (thread ${id}); response: ${resp}"

  # Only now — the thread is provably resolved — post the audit reply that says so.
  body="✅ Auto-resolved: a later commit appears to address this. ${reason}

<sub>Resolved by the automated review-thread resolver (Claude Haiku judged \`${where}\` addressed). Re-open the thread if this is wrong.</sub>"
  # Same rate-limit exposure as the resolve, and worse consequences if it is
  # dropped: the thread is already closed, so a lost reply leaves it resolved
  # with no record of why.
  retry gh api graphql -f query="$reply_mutation" -f id="$id" -f body="$body" >/dev/null

  resolved=$((resolved + 1))
  echo "resolved thread for ${where}" >&2
done <"${PR_INPUT_DIR}/resolve-list.jsonl"

echo "resolved ${resolved} thread(s)" >&2
