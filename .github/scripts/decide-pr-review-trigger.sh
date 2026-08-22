#!/usr/bin/env bash
# Decide whether the PR reviewer (claude-pr-review.yaml) should run for this
# pull_request_target event, emitting run=true/false AND the model to use to
# GITHUB_OUTPUT.
#
#   opened / ready_for_review — always review, on Opus: the one thorough read of
#     a newly reviewable PR (a normal open, or a draft marked ready).
#   labeled — review on demand, on Opus, when the "needs-auto-review" label is
#     applied. The escape hatch the auto-approve message points at: a PR the
<<<<<<< local
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
||||||| base
#     reviewer skipped by title/author (chore/style, or a bot) gets a real
#     read when a human adds the label. Any other label is a no-op (run=false).
#   synchronize — a push. Two INDEPENDENT re-review triggers:
#       1. "[opus-review]" in the head commit TITLE — a full, on-demand Opus
#          re-read. Head-scoped (once-per-tag): the re-review fires for the
#          commit that carries the tag and NOT again on later untagged pushes
#          (re-tag to run again).
#       2. The reviewer's latest verdict is a non-approving review that still
#          blocks the merge — CHANGES_REQUESTED (an explicit hold) OR COMMENTED
#          (a review the reviewer left without approving). Under a review-required
#          ruleset both leave the PR at zero approvals, so both must clear the
#          same way: EVERY push gets a cheap HAIKU re-check, so a push that
#          addresses the concerns is re-evaluated and can flip the verdict to
#          APPROVE (clearing the block) instead of the stale hold gating the PR
#          until someone re-tags it by hand. Self-terminating: once the re-check
#          approves, the latest verdict is no longer a non-approving review and
#          later pushes stop re-running. This automatic recheck NEVER spends
#          Opus — the expensive model is only ever the explicit [opus-review]
#          opt-in.
=======
#     reviewer skipped by title/author (chore/style, or a bot) gets a real
#     read when a human adds the label. Any other label is a no-op (run=false).
#   synchronize — a push. Two INDEPENDENT re-review triggers:
#       1. "[opus-review]" in the head commit TITLE — a full, on-demand Opus
#          re-read. Head-scoped (once-per-tag): the re-review fires for the
#          commit that carries the tag and NOT again on later untagged pushes
#          (re-tag to run again).
#       2. The reviewer's latest verdict is a non-approving review that still
#          blocks the merge — CHANGES_REQUESTED (an explicit hold) OR COMMENTED
#          (a review the reviewer left without approving). Under a review-required
#          ruleset both leave the PR at zero approvals, so both must clear the
#          same way: EVERY push gets a re-check, so a push that addresses the
#          concerns is re-evaluated and can flip the verdict to APPROVE
#          (clearing the block) instead of the stale hold gating the PR until
#          someone re-tags it by hand. Self-terminating: once the re-check
#          approves, the latest verdict is no longer a non-approving review and
#          later pushes stop re-running.
>>>>>>> template
#
# Read under pull_request_target, so the untrusted PR head is NEVER checked out
# or executed here: the head commit's message is fetched as DATA via the API and
# matched as a FIXED string (grep -F, never eval). A transient API failure yields
# run=false (no review, no red) rather than a spurious re-review.
#
<<<<<<< local
# Env: GH_TOKEN, ACTION, REPO, HEAD_SHA, LABEL (LABEL set only on `labeled`).
||||||| base
# Env: GH_TOKEN, ACTION, REPO, HEAD_SHA, PR, LABEL (LABEL set only on `labeled`).
=======
# Env: GH_TOKEN, ACTION, REPO, HEAD_SHA, PR, LABEL (LABEL set only on `labeled`);
# REVIEWER_LOGIN optional.
>>>>>>> template
set -euo pipefail

KEYWORD="[opus-review]"
REVIEW_LABEL="needs-auto-review"
<<<<<<< local
OPUS_MODEL="claude-opus-5"
||||||| base
# The reviewer posts with GITHUB_TOKEN, so its reviews are authored by this bot;
# the latest review it left is the effective verdict that gates the PR.
REVIEWER="github-actions[bot]"
OPUS_MODEL="claude-opus-4-8"
HAIKU_MODEL="claude-haiku-4-5"
=======
# The reviewer posts with GITHUB_TOKEN, so its reviews are authored by this bot;
# the latest review it left is the effective verdict that gates the PR.
# reviewer_login_init owns that identity for every reviewer script, including the
# REST/GraphQL `[bot]`-suffix mismatch (lib/reviewer-login.bash).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/reviewer-login.bash disable=SC1091
source "$SCRIPT_DIR/lib/reviewer-login.bash"
reviewer_login_init
# The one model behind every verdict that gates or clears a PR's merge — the
# first read and the re-check alike. Not a place to economize: a cheaper model
# that flips a hold to APPROVE clears the merge on its own judgement.
REVIEW_MODEL="claude-opus-5"
>>>>>>> template

emit() {
<<<<<<< local
  # $1 run, $2 reason, $3 model (defaults to Opus — the only model this reviewer
  # ever runs; every trigger here is a full whole-diff read)
  local run="$1" reason="$2" model="${3:-$OPUS_MODEL}"
||||||| base
  # $1 run, $2 reason, $3 model (defaults to Opus — the thorough first-look model)
  local run="$1" reason="$2" model="${3:-$OPUS_MODEL}"
=======
  # $1 run, $2 reason
  local run="$1" reason="$2"
>>>>>>> template
  {
    echo "run=$run"
    echo "model=$REVIEW_MODEL"
  } >>"$GITHUB_OUTPUT"
  echo "decision: run=$run model=$REVIEW_MODEL ($reason)"
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
<<<<<<< local
  emit true "$KEYWORD in head commit title"
||||||| base
  emit true "$KEYWORD in head commit title" "$OPUS_MODEL"
  exit 0
fi

# synchronize, trigger 2: a cheap Haiku re-check on every push while the
# reviewer's latest verdict is a non-approving review it can supersede —
# CHANGES_REQUESTED or COMMENTED. The latest review authored by the reviewer bot
# is the effective verdict; both of these leave the PR at zero approvals under a
# review-required ruleset, so the push gets the re-check that can flip it to
# APPROVE. The other states are deliberately NOT re-checked, mirroring
# approve-if-reviewer-hold-clear.sh's allowlist: APPROVED is already through, and
# DISMISSED / "" (the reviewer never reviewed this PR) are not a reviewer hold to
# clear. `--paginate --slurp` returns an array with ONE element PER PAGE (each
# element is that page's reviews array), so the filter must flatten BOTH levels
# (`.[][]`) to walk every review across every page, then `last` picks the most
# recent. A single `.[]` iterates PAGES, so `.user.login`/`.state` index a page
# ARRAY — jq errors, the `2>/dev/null` swallows it to empty, and the recheck
# silently never fires (the bug that stranded every held PR). `--slurp` keeps the
# whole result in one document so `--jq` runs ONCE and emits a single line; bare
# `--paginate` would run the filter per page and concatenate. A transient API
# failure yields empty -> no re-review.
state="$(gh api "repos/$REPO/pulls/${PR:-}/reviews" --paginate --slurp \
  --jq "[.[][] | select(.user.login == \"$REVIEWER\")] | last | .state // empty" 2>/dev/null || true)"
if [[ "$state" == "CHANGES_REQUESTED" || "$state" == "COMMENTED" ]]; then
  emit true "outstanding $REVIEWER hold ($state) — re-checking on Haiku" "$HAIKU_MODEL"
=======
  emit true "$KEYWORD in head commit title"
  exit 0
fi

# synchronize, trigger 2: a re-check on every push while the
# reviewer's latest verdict is a non-approving review it can supersede —
# CHANGES_REQUESTED or COMMENTED. The latest review authored by the reviewer bot
# is the effective verdict; both of these leave the PR at zero approvals under a
# review-required ruleset, so the push gets the re-check that can flip it to
# APPROVE. The other states are deliberately NOT re-checked, mirroring
# approve-if-reviewer-hold-clear.sh's allowlist: APPROVED is already through, and
# DISMISSED / "" (the reviewer never reviewed this PR) are not a reviewer hold to
# clear. `--paginate --slurp` returns an array with ONE element PER PAGE (each
# element is that page's reviews array), so the filter must flatten BOTH levels
# (`.[][]`) to walk every review across every page, then `last` picks the most
# recent. A single `.[]` iterates PAGES, so `.user.login`/`.state` index a page
# ARRAY — jq errors, the `2>/dev/null` swallows it to empty, and the recheck
# silently never fires (the bug that stranded every held PR). `--slurp` keeps the
# whole result in one document so `--jq` runs ONCE and emits a single line; bare
# `--paginate` would run the filter per page and concatenate. A transient API
# failure yields empty -> no re-review.
state="$(gh api "repos/$REPO/pulls/${PR:-}/reviews" --paginate --slurp \
  --jq "[.[][] | ${REVIEWER_MATCH_USER}] | last | .state // empty" 2>/dev/null || true)"
if [[ "$state" == "CHANGES_REQUESTED" || "$state" == "COMMENTED" ]]; then
  emit true "outstanding $REVIEWER_LOGIN hold ($state) — re-checking"
>>>>>>> template
else
  emit false "ordinary push — a push is not a re-read; put $KEYWORD in a commit title, or add the '$REVIEW_LABEL' label, for a full read"
fi
