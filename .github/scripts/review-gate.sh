#!/usr/bin/env bash
# Post the automated-review gate's verdict as a COMMIT STATUS on the PR head.
#
# PROBLEM CLASS — auto-merge landing a pull request before the reviewer has
# spoken. The cheap checks finish in about ninety seconds while an LLM review
# takes minutes, so a PR whose ruleset lists only the cheap checks merges first
# and the reviewer's REQUEST_CHANGES arrives on a merged PR. Nothing is red; the
# review simply was not part of the merge gate.
#
# The predicate is one line and stateless: a pull request is clear when at least
# one review of it BY THE AUTOMATED REVIEWER stands undismissed. It needs no
# memory of which reviews have been seen, and it re-derives the same answer on
# every event.
#
# PR-SCOPED, NOT HEAD-SCOPED, and that is load-bearing. Requiring a review OF THE
# CURRENT HEAD looks stricter and strands the pull request instead:
# decide-pr-review-trigger.sh answers run=false for a plain `synchronize`, so
# once the reviewer has approved, the next push produces a head nothing will ever
# review, and a head-scoped gate would hold that pull request at `pending`
# forever with no event able to clear it. Whether a later push still satisfies
# the reviewer is a question the reviewer already owns: a non-approving verdict
# makes every push re-run the cheap recheck, and the review-required ruleset
# holds the merge meanwhile. This gate answers only the question nothing else
# did — has the reviewer spoken about this pull request at all?
#
# A COMMIT STATUS, not this job's own check run. Under `pull_request_target` the
# job's check run is reported against the BASE commit, so it never satisfies a
# requirement evaluated on the pull request's head. A status posted explicitly on
# `HEAD_SHA` does.
#
# Can't-verify is RED, never green: an API failure propagates through `set -e`,
# because a gate that fails open lets a PR merge past a review nobody read.
#
# Env: GH_TOKEN, GH_REPO (owner/name), PR, HEAD_SHA, RUN_URL.
set -euo pipefail

: "${GH_REPO:?GH_REPO required}"
: "${PR:?PR number required}"
: "${HEAD_SHA:?HEAD_SHA required}"
: "${GH_TOKEN:?GH_TOKEN required}"

# MUST stay byte-identical to the `name:` of the job in review-gate.yaml: that
# job name is what sync-required-checks registers as the ruleset's required
# context, and the status posted here has to carry the same context or the head
# never satisfies it.
GATE_CONTEXT="Automated review posted"

# WHOSE review clears this gate, and the reason the answer is not "anyone's": a
# review is something the PR author can post on their own pull request, so an
# any-actor gate is cleared by the author writing a one-word COMMENT review and
# the required context then asserts an automated review that never ran.
#
# The reviewer posts with the workflow GITHUB_TOKEN, so its reviews are authored
# by this bot — as is the approval auto-approve-skipped posts for a PR the
# reviewer skips by title or author, which is what still clears this gate for
# that class without re-deriving decide-pr-review-trigger.sh's skip rules here.
#
# DUPLICATED, deliberately: review-findings-gate.sh sets the same login and both
# gates must mean the same reviewer. Neither can source it from a lib, because
# five workflows fetch this script ALONE via `sparse-checkout:
# .github/scripts/review-gate.sh`, and a lib absent from those checkouts would
# kill the gate at runtime under `set -e`. The drift is guarded by a test.
REVIEWER_LOGIN_BARE="github-actions"
export REVIEWER_LOGIN_BARE

# Every review that still stands, paginated: a long-lived PR accumulates more
# than one page. A DISMISSED review is dropped here, which is what makes the
# workflow's `dismissed` trigger do something — dismissing the only review
# returns the PR to `pending`.
#
# The filter is per-element (`.[] | select(…)`), never a reducer: `gh api
# --paginate --jq` applies the filter to EACH page, so a `first`/`max_by` would
# silently run once per page and answer from the last one.
#
# Only the reviewer's own reviews count (see REVIEWER_LOGIN_BARE above). The
# REST endpoint spells an app bot's login WITH the `[bot]` suffix while GraphQL
# spells it without, so the login is stripped before comparing and either
# spelling matches — the same normalization lib/pr-reviews.bash applies.
#
# The body-non-empty test asks WHETHER THIS IS A REVIEW, which the author test
# does not. GitHub synthesizes a body-less COMMENTED review by the same bot
# around every standalone review-comment POST, and resolve-addressed-threads.sh
# posts its audit replies under that identity. Counting one satisfies this gate
# vacuously on exactly the PRs that carry threads — the ones
# approve-if-reviewer-hold-clear.sh dismisses a CHANGES_REQUESTED on, where a
# standing synthesized review holds the status green and strips the workflow's
# `dismissed` trigger of meaning. Every bot writer passes a non-empty body
# (post-pr-review.mjs falls back to "Automated review."), so the test costs
# nothing. lib/pr-reviews.bash applies the same one for the sibling gate.
reviewers="$(gh api --paginate "repos/${GH_REPO}/pulls/${PR}/reviews" \
  --jq '.[] | select(.state != "DISMISSED")
      | select((.body // "") != "")
      | select((.user.login // "" | sub("\\[bot\\]$"; "")) == env.REVIEWER_LOGIN_BARE)
      | .user.login // ""')"
reviewer="$(head -n 1 <<<"$reviewers")"

if [[ -n "$reviewer" ]]; then
  state=success
  description="Reviewed by ${reviewer}"
else
  state=pending
  description="Waiting for the automated review of this pull request"
fi

# `pending`, not `failure`, for the not-yet-reviewed case: the review is coming,
# and a red would tell a reader to go diagnose something. Both hold the merge.
gh api -X POST "repos/${GH_REPO}/statuses/${HEAD_SHA}" \
  -f "state=${state}" \
  -f "context=${GATE_CONTEXT}" \
  -f "description=${description}" \
  -f "target_url=${RUN_URL:-}" >/dev/null

echo "posted ${state} status '${GATE_CONTEXT}' on ${HEAD_SHA}: ${description}" >&2
