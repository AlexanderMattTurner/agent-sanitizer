#!/usr/bin/env bash
# Decide whether the PR reviewer (claude-pr-review.yaml) should run for this
# pull_request_target event, emitting run=true/false AND the model to use to
# GITHUB_OUTPUT.
#
#   opened / ready_for_review — always review, on Opus: the one thorough read of
#     a newly reviewable PR (a normal open, or a draft marked ready).
#   labeled — review on demand, on Opus, when the "needs-auto-review" label is
#     applied. The escape hatch the auto-approve message points at: a PR the
#     reviewer skipped by title/author (chore/style, or a bot), or one whose
#     first read never posted, gets a real read when a human adds the label. Any
#     other label is a no-op (run=false).
#   synchronize — a push. Reviews only on the "[opus-review]" opt-in in the head
#     commit TITLE: a full, on-demand Opus re-read. Head-scoped (once-per-tag),
#     so it fires for the commit that carries the tag and NOT again on later
#     untagged pushes (re-tag to run again). A push is otherwise never a read:
#     the reviewer reads a PR once, and later pushes make progress by the author
#     resolving the findings, which is what the review-findings gate reads.
#
# There is deliberately NO catch-up trigger that starts a first pass on a push.
# One existed for PRs whose earlier events all skipped, and it could not tell
# "never reviewed" from "being reviewed right now": the first pass posts its
# review in its LAST step, so the reviews list reads empty for that whole run. On
# #340 a bot's push read it three seconds before the Opus review landed, bought a
# second whole-diff pass on the cheap tier, and that pass's concurrency group
# then cancelled the Opus run. The label above serves the same PRs with no race
# to lose and no second model spend.
#
# Read under pull_request_target, so the untrusted PR head is NEVER checked out
# or executed here: the head commit's message is fetched as DATA via the API and
# matched as a FIXED string (grep -F, never eval). A transient API failure yields
# run=false (no review, no red) rather than a spurious re-review.
#
# Env: GH_TOKEN, ACTION, REPO, HEAD_SHA, LABEL (LABEL set only on `labeled`).
set -euo pipefail

KEYWORD="[opus-review]"
REVIEW_LABEL="needs-auto-review"
OPUS_MODEL="claude-opus-5"

emit() {
  # $1 run, $2 reason, $3 model (defaults to Opus — the only model this reviewer
  # ever runs; every trigger here is a full whole-diff read)
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

# synchronize: full Opus re-read on the [opus-review] opt-in in the head commit
# title. Fetch the head commit DIRECTLY by SHA — not the PR-commits list, which
# the API caps at 250 even with --paginate, so on a heavily-revised PR (exactly
# what this re-trigger serves) the head would fall off the list and the opt-in
# would silently fail. Capture into a variable (never `gh … | grep`, whose
# early-exit SIGPIPEs the still-writing gh under pipefail), then match the
# subject line.
message="$(gh api "repos/$REPO/commits/$HEAD_SHA" --jq '.commit.message' 2>/dev/null || true)"
subject="${message%%$'\n'*}"
if grep -qiF "$KEYWORD" <<<"$subject"; then
  emit true "$KEYWORD in head commit title"
else
  emit false "ordinary push — a push is not a re-read; put $KEYWORD in a commit title, or add the '$REVIEW_LABEL' label, for a full read"
fi
