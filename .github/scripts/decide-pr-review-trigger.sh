#!/usr/bin/env bash
# Decide whether the PR reviewer (claude-pr-review.yaml) should run for this
# pull_request_target event, emitting run=true/false AND the model to use to
# GITHUB_OUTPUT.
#
#   opened / ready_for_review — always review, on Opus: the first, thorough look
#     at a newly reviewable PR (a normal open, or a draft marked ready).
#   labeled — review on demand, on Opus, when the "needs-auto-review" label is
#     applied. The escape hatch the auto-approve message points at: a PR the
#     reviewer skipped by title/author (chore/style, or a bot) gets a real
#     read when a human adds the label. Any other label is a no-op (run=false).
#   synchronize — a push. Two INDEPENDENT re-review triggers:
#       1. "[opus-review]" in the head commit TITLE — a full, on-demand Opus
#          re-read. Head-scoped (once-per-tag): the re-review fires for the
#          commit that carries the tag and NOT again on later untagged pushes
#          (re-tag to run again).
#       2. The reviewer has NEVER reviewed this PR — the first whole-diff pass,
#          on the cheap tier, for a PR whose earlier events all skipped. A push is never a
#          RE-read: the reviewer reads a PR once, and later pushes make progress
#          by the thread resolver closing findings out, which is what the
#          review-findings gate reads. This automatic pass NEVER spends Opus —
#          the expensive model is only ever the explicit [opus-review] opt-in.
#
# Read under pull_request_target, so the untrusted PR head is NEVER checked out
# or executed here: the head commit's message and the PR's reviews are fetched as
# DATA via the API and matched as FIXED strings (grep -F / exact compare, never
# eval). A transient API failure yields run=false (no review, no red) rather than
# a spurious re-review.
#
# Env: GH_TOKEN, ACTION, REPO, HEAD_SHA, PR, LABEL (LABEL set only on `labeled`).
set -euo pipefail

KEYWORD="[opus-review]"
REVIEW_LABEL="needs-auto-review"
# The reviewer posts with GITHUB_TOKEN, so its reviews are authored by this bot.
REVIEWER="github-actions[bot]"
OPUS_MODEL="claude-opus-5"
CHEAP_MODEL="claude-sonnet-5"

emit() {
  # $1 run, $2 reason, $3 model (defaults to Opus — the thorough first-look model)
  local run="$1" reason="$2" model="${3:-$OPUS_MODEL}"
  {
    echo "run=$run"
    echo "model=$model"
  } >>"$GITHUB_OUTPUT"
  echo "decision: run=$run model=$model ($reason)"
}

case "$ACTION" in
opened | ready_for_review)
  emit true "first review on $ACTION"
  exit 0
  ;;
labeled)
  if [[ "${LABEL:-}" == "$REVIEW_LABEL" ]]; then
    emit true "on-demand review requested via '$REVIEW_LABEL' label"
  else
    emit false "labeled with '${LABEL:-}', not '$REVIEW_LABEL'"
  fi
  exit 0
  ;;
synchronize) ;;
*)
  emit false "no automatic review on '$ACTION'"
  exit 0
  ;;
esac

# synchronize, trigger 1: full Opus re-read on the [opus-review] opt-in in the
# head commit title. Fetch the head commit DIRECTLY by SHA — not the PR-commits
# list, which the API caps at 250 even with --paginate, so on a heavily-revised
# PR (exactly what this re-trigger serves) the head would fall off the list and
# the opt-in would silently fail. Capture into a variable (never `gh … | grep`,
# whose early-exit SIGPIPEs the still-writing gh under pipefail), then match the
# subject line.
message="$(gh api "repos/$REPO/commits/$HEAD_SHA" --jq '.commit.message' 2>/dev/null || true)"
subject="${message%%$'\n'*}"
if grep -qiF "$KEYWORD" <<<"$subject"; then
  emit true "$KEYWORD in head commit title" "$OPUS_MODEL"
  exit 0
fi

# synchronize, trigger 2: the FIRST whole-diff pass, when this PR has never had
# one. A push is never a re-read — the reviewer reviews a PR once, and what makes
# progress on later pushes is the thread resolver closing the findings out (which
# is what the review-findings gate reads). Only the $KEYWORD opt-in above buys
# another whole-diff pass.
#
# Do NOT key this on the latest review's STATE being non-approving: every review
# posts as COMMENTED (the merge consequence lives in the review-findings gate), so
# that condition is always true and would fire a Haiku re-read on every push to
# every reviewed PR.
#
# Empty-bodied reviews are filtered out because GitHub synthesizes one, authored
# by this same bot, around every standalone review-comment POST the thread
# resolver makes — counting one as "already reviewed" would permanently suppress
# the first real pass on the PR. Non-empty body is the real-review discriminator
# (post-pr-review.mjs always posts prose, falling back to "Automated review.").
#
# `--paginate --slurp` returns an array with ONE element PER PAGE (each element is
# that page's reviews array), so the filter must flatten BOTH levels (`.[][]`) to
# walk every review across every page. A single `.[]` iterates PAGES, so
# `.user.login`/`.state` index a page ARRAY — jq errors and the recheck silently
# misbehaves. The filter runs in a SEPARATE `jq`, not gh's `--jq`: gh rejects
# `--slurp` together with `--jq`/`--template` outright ("the `--slurp` option is
# not supported with `--jq`"), and it exits 1 before issuing the request, so the
# fail-closed branch below would swallow that as a transient API error and this
# trigger would never fire.
#
# The exit STATUS is captured separately from the state, because the two empty
# results mean opposite things: a successful query returning "" means nobody ever
# looked at this PR (the strongest reason to review), while a FAILED query also
# yields "" and must not be read that way — folding them together would review on
# every push forever whenever the API is flaky or the filter is malformed.
reviews_rc=0
state=""
pages="$(gh api "repos/$REPO/pulls/${PR:-}/reviews" --paginate --slurp 2>/dev/null)" || reviews_rc=$?
if [[ "$reviews_rc" -eq 0 ]]; then
  state="$(jq -r "[.[][] | select(.user.login == \"$REVIEWER\") | select((.body // \"\") != \"\")] | last | .state // empty" <<<"$pages")" || reviews_rc=$?
fi
if [[ "$reviews_rc" -ne 0 ]]; then
  emit false "could not read $REPO#${PR:-} reviews (rc=$reviews_rc) — not reviewing rather than guessing"
elif [[ -z "$state" ]]; then
  emit true "$REVIEWER has never reviewed this PR — running the first pass this push" "$CHEAP_MODEL"
else
  emit false "$REVIEWER already reviewed this PR (latest: $state) — a push is not re-read; put $KEYWORD in a commit title for a full re-read"
fi
