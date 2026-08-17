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
#       2. The reviewer has NEVER reviewed this PR and none is UNDERWAY — the
#          first whole-diff pass, on the cheap tier, for a PR whose earlier
#          events all skipped. A push is never a RE-read: the reviewer reads a
#          PR once, and later pushes make progress by the thread resolver
#          closing findings out, which is what the review-findings gate reads.
#          This automatic pass NEVER spends Opus — the expensive model is only
#          ever the explicit [opus-review] opt-in.
#
# Read under pull_request_target, so the untrusted PR head is NEVER checked out
# or executed here: the head commit's message and the PR's reviews are fetched as
# DATA via the API and matched as FIXED strings (grep -F / exact compare, never
# eval). A transient API failure yields run=false (no review, no red) rather than
# a spurious re-review.
#
# Env: GH_TOKEN, ACTION, REPO, HEAD_SHA, PR, LABEL (LABEL set only on `labeled`),
# plus the GITHUB_WORKFLOW_REF / GITHUB_RUN_ID the runner always sets.
set -euo pipefail

KEYWORD="[opus-review]"
REVIEW_LABEL="needs-auto-review"
# The reviewer posts with GITHUB_TOKEN, so its reviews are authored by this bot.
REVIEWER="github-actions[bot]"
OPUS_MODEL="claude-opus-5"
CHEAP_MODEL="claude-sonnet-5"
# The `review` job's `name:` in claude-pr-review.yaml, which is what marks a
# sibling run as one that will post rather than one still deciding.
REVIEW_JOB="Claude PR review"
# This workflow's own file, so a rename cannot leave a stale literal here.
# GITHUB_WORKFLOW_REF is "owner/repo/.github/workflows/file.yaml@refs/…", and the
# ref half carries slashes, so the "@" must go before the last path segment.
# Both vars are runner-provided; unset means this is not running where it thinks
# it is, which is a bug to crash on rather than to degrade around.
: "${GITHUB_WORKFLOW_REF:?GITHUB_WORKFLOW_REF is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
WORKFLOW_FILE="${GITHUB_WORKFLOW_REF%%@*}"
WORKFLOW_FILE="${WORKFLOW_FILE##*/}"

# Whether another run of this workflow is ALREADY REVIEWING this PR: 0 yes,
# 1 no, 2 the API could not say.
#
# The reviews list this script reads below cannot show a first pass that is still
# running, because that job posts its review in its last step. On #340 this step
# decided at 22:20:43 and the opened-event review landed at 22:20:46, so the
# trigger read "never reviewed", bought a second whole-diff pass, and the review
# job's concurrency group then cancelled the Opus run three seconds from posting.
#
# Only a sibling whose REVIEW JOB already exists counts. A sibling still inside
# its decide job may yet decide not to review, and if it does review, the
# concurrency group cancels this run's review job — so no duplicate can post, and
# suppressing on an undecided sibling would drop pushes for nothing.
#
# Bounded at the newest 100 runs of this workflow (the API's page maximum): a
# sibling that is still running started seconds ago and cannot have fallen off.
# A fork PR whose run carries no `pull_requests` matches nothing here and keeps
# the unguarded behaviour — under-suppressing, never over-suppressing.
review_in_flight() {
  local runs run pending
  runs="$(gh api "repos/$REPO/actions/workflows/$WORKFLOW_FILE/runs?per_page=100" \
    --jq ".workflow_runs[]
          | select(.status != \"completed\")
          | select(.id != $GITHUB_RUN_ID)
          | select([.pull_requests[]?.number] | index($PR))
          | .id" 2>/dev/null)" || return 2
  while IFS= read -r run; do
    [[ -n "$run" ]] || continue
    pending="$(gh api "repos/$REPO/actions/runs/$run/jobs" \
      --jq "[.jobs[] | select(.name == \"$REVIEW_JOB\") | select(.status != \"completed\")] | length" 2>/dev/null)" || return 2
    if [[ "$pending" -gt 0 ]]; then return 0; fi
  done <<<"$runs"
  return 1
}

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
#
# The in-flight query runs BEFORE the reviews query, and the order is what makes
# the pair gap-free: a sibling that posts between the two reads is caught by the
# LATER one, and a sibling that has not posted yet was still running at the
# EARLIER one. Reading reviews first leaves a window between them where a sibling
# both posts and finishes, so neither read sees it.
in_flight_rc=0
review_in_flight || in_flight_rc=$?

reviews_rc=0
state=""
pages="$(gh api "repos/$REPO/pulls/${PR:-}/reviews" --paginate --slurp 2>/dev/null)" || reviews_rc=$?
if [[ "$reviews_rc" -eq 0 ]]; then
  state="$(jq -r "[.[][] | select(.user.login == \"$REVIEWER\") | select((.body // \"\") != \"\")] | last | .state // empty" <<<"$pages")" || reviews_rc=$?
fi
if [[ "$reviews_rc" -ne 0 ]]; then
  emit false "could not read $REPO#${PR:-} reviews (rc=$reviews_rc) — not reviewing rather than guessing"
  exit 0
fi
if [[ -n "$state" ]]; then
  emit false "$REVIEWER already reviewed this PR (latest: $state) — a push is not re-read; put $KEYWORD in a commit title for a full re-read"
  exit 0
fi

# No review is VISIBLE, which is not the same as none being under way.
case "$in_flight_rc" in
0) emit false "another $WORKFLOW_FILE run is already reviewing $REPO#${PR:-} — one first pass per PR, not two" ;;
1) emit true "$REVIEWER has never reviewed this PR — running the first pass this push" "$CHEAP_MODEL" ;;
*) emit false "could not read in-flight $WORKFLOW_FILE runs (rc=$in_flight_rc) — not reviewing rather than risking a duplicate" ;;
esac
