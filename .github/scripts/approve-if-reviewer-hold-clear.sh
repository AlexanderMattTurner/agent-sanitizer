#!/usr/bin/env bash
# Approve the PR when the automated reviewer's hold is fully cleared, regardless
# of WHO cleared the last thread. This is the single source of truth for "the
# reviewer requested changes (or commented), every one of its threads is now
# resolved, so post the APPROVE that supersedes the hold and satisfies a
# review-required ruleset."
#
# It is deliberately state-based and idempotent: it reads the CURRENT thread and
# review state via the API and decides from that alone, never from who resolved
# what. Whoever addressed a finding resolves its thread — the author, an agent, a
# human clicking Resolve — and a resolve fires no workflow event, so the periodic
# sweep over open PRs (claude-reviewer-hold-clear.yaml) is what turns the last
# resolution into a cleared hold.
#
# Approves ONLY when the reviewer's LATEST review is a live hold or comment —
# CHANGES_REQUESTED or COMMENTED (any other latest state means nothing to clear:
# APPROVED already through, DISMISSED, or "" the reviewer never reviewed this PR —
# so an unrelated sweep mints no approval; this allowlist is stricter than
# "!= APPROVED" on purpose) — AND the reviewer opened at least one thread (root
# comment authored by REVIEWER_LOGIN) with none still unresolved. A hold whose
# concern lived only in the review BODY has no thread to resolve and is therefore
# never auto-cleared; it waits for a human or a re-review.
#
# Env: the GH_TOKEN_* ladder rungs (see lib/github-token-ladder.bash), GH_REPO
# (owner/name), PR; REVIEWER_LOGIN optional.
set -euo pipefail

: "${GH_REPO:?GH_REPO required}"
: "${PR:?PR number required}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/github-token-ladder.bash disable=SC1091
source "$SCRIPT_DIR/lib/github-token-ladder.bash"
# shellcheck source=.github/scripts/lib/review-threads.bash
source "$SCRIPT_DIR/lib/review-threads.bash"
# shellcheck source=.github/scripts/lib/pr-reviews.bash
source "$SCRIPT_DIR/lib/pr-reviews.bash"

# Every call below spends API quota, so pick a credential that has some before
# the first one rather than discovering it mid-flight. Reddening only once EVERY
# rung is spent is the point: a spent top rung is not a reason to fail a step
# whose posture is to degrade, but nothing left to spend anywhere is a real
# blocker a human has to clear, so it is not swallowed either.
GH_TOKEN="$(github_token_with_quota)" || {
  echo "every configured GitHub credential is out of API quota; cannot read this PR's review state, so the reviewer's hold is left in place. Re-run once quota resets, or provision another TEMPLATE_SYNC_TOKEN." >&2
  exit 1
}
export GH_TOKEN

owner="${GH_REPO%%/*}"
name="${GH_REPO##*/}"

# Count the reviewer's threads two ways, over the shared paginated read — a PR
# can accrue >100 threads, and an unpaginated first:100 would miss a later page.
# The per-page projection emits one {total, unresolved} object; the trailing
# reduce sums them.
#
# A thread hold is "demonstrably cleared" only when the reviewer opened at least
# one thread AND none remain unresolved. A CHANGES_REQUESTED / COMMENTED review
# that opened ZERO threads carries no resolution signal at all — clearing it on
# "unresolved == 0" (trivially true with no threads) would merge the reviewer's
# concern unaddressed.
counts="$(fetch_review_threads "$owner" "$name" "$PR" \
  "[.[] | $REVIEW_THREAD_ROOT_IS_REVIEWER]
   | {total: length, unresolved: (map(select(.isResolved == false)) | length)}" |
  jq -s 'reduce .[] as $p ({total: 0, unresolved: 0};
           {total: (.total + $p.total), unresolved: (.unresolved + $p.unresolved)})')"
unresolved="$(jq -r '.unresolved' <<<"$counts")"
total="$(jq -r '.total' <<<"$counts")"

if [[ "${unresolved:-0}" -ne 0 ]]; then
  echo "${unresolved} reviewer thread(s) still open; not approving" >&2
  exit 0
fi

if [[ "${total:-0}" -eq 0 ]]; then
  echo "reviewer opened no thread, so nothing here can demonstrate its concern was addressed; a thread-less hold is not auto-cleared (defer to re-review / human)" >&2
  exit 0
fi

# What is the reviewer's latest review state? reviewer_reviews_ndjson owns the
# paginated read (a long-lived PR can accrue >100 reviews, and an unpaginated
# first:100 returns the OLDEST 100 and would pick a stale state) and the reviewer
# predicate; the slurp picks the globally latest by submittedAt.
reviews_ndjson="$(reviewer_reviews_ndjson "$owner" "$name" "$PR")"
latest_state="$(jq -rs 'if length == 0 then "" else (sort_by(.submittedAt) | last | .state) end' <<<"$reviews_ndjson")"

if [[ "$latest_state" != "CHANGES_REQUESTED" && "$latest_state" != "COMMENTED" ]]; then
  echo "reviewer's latest review is '${latest_state:-<none>}' — no live hold to clear; nothing to do" >&2
  exit 0
fi

cleared_by="every review conversation from the automated reviewer has been resolved"

# Dismiss the REVIEWER'S OWN stale CHANGES_REQUESTED. Reached only when the hold
# is already proven clear above and the approval was structurally refused, so it
# is the fallback lever for a hold nothing else can clear.
#
# Dismissal is not approval: it needs write access rather than a different actor,
# so it succeeds exactly where the approval cannot — including for GITHUB_TOKEN,
# which GitHub bars from approving at all, so the periodic sweep gains it too.
#
# The candidate set is what makes this safe: reviews_ndjson holds the reviewer's
# own reviews and no others, so a HUMAN's CHANGES_REQUESTED is never a candidate.
# A human hold still blocks and still needs that human. Dismissing is also
# idempotent — a dismissed review's state stops being CHANGES_REQUESTED, so a
# re-run finds nothing and says so.
dismiss_stale_hold() {
  local reason="$1" review_id dismiss_err
  # The most recent CHANGES_REQUESTED specifically, NOT the latest review: a
  # CHANGES_REQUESTED keeps blocking until dismissed or superseded by an APPROVED
  # from the same reviewer, and a later COMMENTED review does not clear it. So the
  # blocking review is routinely not the latest one.
  review_id="$(jq -rs '[.[] | select(.state == "CHANGES_REQUESTED")]
    | if length == 0 then "" else (sort_by(.submittedAt) | last | .databaseId) end' <<<"$reviews_ndjson")"

  if [[ -z "$review_id" ]]; then
    echo "no active CHANGES_REQUESTED from ${REVIEWER_LOGIN} to dismiss — its hold was a COMMENTED review, which does not block a merge." >&2
    return 0
  fi

  # Unlike the approval refusals above, a failed dismissal is NOT structural:
  # nothing about this PR makes it permanently impossible, so it is a real error
  # and must be seen rather than logged past.
  if ! dismiss_err="$(gh api --method PUT \
    "repos/${GH_REPO}/pulls/${PR}/reviews/${review_id}/dismissals" \
    -f message="$reason" -f event=DISMISS 2>&1)"; then
    echo "failed to dismiss the reviewer's stale hold (review ${review_id}): ${dismiss_err}" >&2
    return 1
  fi
  echo "dismissed the reviewer's stale CHANGES_REQUESTED (review ${review_id}) — ${reason}" >&2
}
# Two refusals here are STRUCTURAL — no permission, retry or configuration on
# this PR makes them succeed, so failing the job on either would red every PR
# whose hold clears, forever, and a check that can only fail teaches nothing.
# GitHub refuses `addPullRequestReview` for an Actions token regardless of
# permissions ("GitHub Actions is not permitted to approve pull requests"), and
# it refuses any approval of a PR the token's own actor authored. Stand down
# LOUDLY on both, naming the remedy. Any OTHER failure is real and exits
# non-zero.
# Every write below is a REVIEW made with GITHUB_TOKEN, and GitHub emits no
# pull_request_review event for one — so the review-keyed gate would keep a
# verdict that predates it: pending after an approve, or GREEN after a dismissal
# that left nothing standing. The second is fail-open on a required merge gate,
# so the re-derivation lives here beside the writes rather than in each caller
# (the same reason the verdict itself lives in this one script).
#
# Safe for every PR this script ACTS on, and it acts on no others: it reaches a
# write only when the reviewer's latest review is a live hold or comment, so the
# deliberately-skipped class — never reviewed, its gate cleared by hand — is
# never reached and never overwritten.
rederive_review_gate() {
  local head_sha
  head_sha="$(gh api "repos/${GH_REPO}/pulls/${PR}" --jq '.head.sha')"
  # Report mode, so a red VERDICT is not a failure here — only an inability to
  # post one is, and that reaches the caller as a non-zero exit.
  REPORT_SHA="$head_sha" bash "$SCRIPT_DIR/review-findings-gate.sh"
}

approve_err=""
if ! approve_err="$(gh pr review "$PR" --repo "$GH_REPO" --approve --body \
  "Automated approval: ${cleared_by}, so this satisfies the review-required ruleset. Re-request review if a human should take a closer look." 2>&1)"; then
  if [[ "$approve_err" == *"not permitted to approve pull requests"* ]]; then
    echo "hold is clear, but this token cannot approve: GitHub blocks approvals from GitHub Actions." >&2
    dismiss_stale_hold "${cleared_by}, so this hold no longer reflects the pull request's state." || exit 1
    rederive_review_gate
    exit 0
  fi
  if [[ "$approve_err" == *"Can not approve your own pull request"* ]]; then
    echo "hold is clear, but this token's actor authored PR #${PR}, and GitHub refuses a self-approval." >&2
    dismiss_stale_hold "${cleared_by}, so this hold no longer reflects the pull request's state." || exit 1
    rederive_review_gate
    exit 0
  fi
  echo "failed to post the clearing approval: ${approve_err}" >&2
  exit 1
fi
echo "${cleared_by} and reviewer was holding (${latest_state}); approved to satisfy the review gate" >&2
rederive_review_gate
