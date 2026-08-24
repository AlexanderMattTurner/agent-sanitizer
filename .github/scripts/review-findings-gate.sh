#!/usr/bin/env bash
# The review merge gate, as ONE stateless predicate: a PR is clear to merge when
# (a) at least one review of it BY THE AUTOMATED REVIEWER stands undismissed AND
# (b) no unresolved reviewer-rooted review thread still carries a merge-gating
# finding (🔴 blocking / 🟡 warning). Resolving the last gating thread is what
# flips the gate — there is no approval to mint, no sticky verdict to supersede,
# and no state beyond what the PR itself shows.
#
# Clause (a) is the whole reason a merge cannot outrun the reviewer: the cheap
# checks finish in about ninety seconds while an LLM review takes minutes, so a
# PR gated only on those merges first and the reviewer's findings arrive on a
# merged PR. It is PR-SCOPED, not head-scoped, and that is load-bearing:
# decide-pr-review-trigger.sh answers run=false for a plain `synchronize`, so a
# head-scoped clause would hold a reviewed PR at unreviewed forever the moment a
# push produced a head nothing will review.
#
# The severity of a thread is read from the root comment the reviewer posted:
# the hidden `<!-- severity: … -->` marker post-pr-review.mjs stamps on every
# finding, with the finding's leading 🔴/🟡 icon as a fallback for threads
# posted before the marker existed. Which severities gate — and which icon each
# renders as — comes from config/review-severities.json, the same SSOT
# post-pr-review.mjs stamps from, so the writer and this reader cannot drift.
#
# Two modes, one predicate:
#   * REPORT_SHA set — post the verdict as a COMMIT STATUS under the context
#     "$GATE_CONTEXT" on that sha (the PR head), so the ruleset's required check
#     is satisfied, pending or red there. Exit 0 once the status is posted,
#     whatever the verdict; a failure to POST it is a hard red (a gate that
#     cannot report is a gate that hangs the PR at "Expected").
#   * REPORT_SHA unset — exit 0 when the gate is green, 1 otherwise. This is the
#     merge_group mode: the calling job is itself the check on the queue sha,
#     so its exit status is the report, and a queue has no way to say `pending`.
#
# Three verdicts, two of which hold the merge. An unreviewed PR posts `pending`
# rather than `failure`: the review is coming, and a red there would send a
# reader off to diagnose a gate that is merely waiting. Unresolved findings post
# `failure`, because that one IS something to act on.
#
# A STATUS, not a check run, and that distinction is load-bearing: a check run
# POSTed for a bare sha lands in a check suite of the app's own making, whose
# `pull_requests` array is empty, and the PR-scoped merge box counts only the
# suites tied to the pull request. Such a run shows green on the commit and in
# the Checks tab while the required context sits at "Expected — Waiting for
# status to be reported" forever. A status carries no suite and is read on the
# sha itself.
#
# GATE_UNREPORTED set skips the predicate entirely and posts a RED verdict on
# REPORT_SHA — the caller's `always()` arm for a run that died before it could
# evaluate, so a required check is never left unreported.
#
# Can't-verify is RED, never green: an API failure exhausting the retry ladder
# propagates as a non-zero exit (set -e), because a gate that fails open lets a
# PR merge past findings nobody read.
#
# Env: GH_TOKEN, GH_REPO (owner/name), PR; REPORT_SHA, RUN_URL and
# GATE_UNREPORTED optional.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=.github/scripts/lib/review-threads.bash
source "$SCRIPT_DIR/lib/review-threads.bash"
# shellcheck source=.github/scripts/lib/pr-reviews.bash
source "$SCRIPT_DIR/lib/pr-reviews.bash"

: "${GH_REPO:?GH_REPO required}"
: "${PR:?PR number required}"
: "${GH_TOKEN:?GH_TOKEN required}"

# MUST stay byte-identical to the `name:` of the merge_gate job in
# review-findings-merge-gate.yaml: the ruleset's required-check context is
# derived from that job name (sync-required-checks), and the status posted
# here has to carry the same context or the PR head never satisfies the gate.
GATE_CONTEXT="Review findings resolved"

# GitHub caps a status description at 140 characters, so the reason a reader
# acts on lives in this run's log and behind target_url; the merge box gets as
# much of its head as fits.
post_verdict() {
  local state="$1" description="$2"
  if ((${#description} > 140)); then
    description="${description:0:137}..."
  fi
  retry gh api --method POST "repos/${GH_REPO}/statuses/${REPORT_SHA}" \
    -f "state=${state}" \
    -f "context=${GATE_CONTEXT}" \
    -f "description=${description}" \
    -f "target_url=${RUN_URL:-}" >/dev/null
}

# GATE_UNREPORTED mode: the evaluation below never reached its POST, so report
# red here instead of leaving the head with no verdict at all. An unposted
# REQUIRED context reads as "Expected — Waiting for status to be reported", which
# blocks the merge on a check that never arrives: thread resolution fires no
# workflow event, so nothing re-derives this gate until the next push or a
# `recheck-review-gate` label, and the merge box offers nothing to act on
# meanwhile. Red is the same state said out loud, and it keeps the retry path.
if [[ -n "${GATE_UNREPORTED:-}" ]]; then
  : "${REPORT_SHA:?REPORT_SHA required to report an unevaluated gate}"
  post_verdict failure \
    "the gate evaluation did not complete — re-run it by removing and re-adding the recheck-review-gate label"
  echo "posted failure status '${GATE_CONTEXT}' on ${REPORT_SHA}: evaluation did not complete" >&2
  exit 0
fi

owner="${GH_REPO%%/*}"
name="${GH_REPO##*/}"

# The gating predicate, derived from the SSOT at runtime: a root body gates when
# a line equals a gating severity's hidden marker (whole-line match, so a
# finding that merely QUOTES a marker in prose or a suggestion block does not
# gate), or — the pre-marker fallback — when the body starts with a gating
# severity's icon.
SEVERITY_CONFIG="$SCRIPT_DIR/../../config/review-severities.json"
[[ -f "$SEVERITY_CONFIG" ]] || {
  echo "missing $SEVERITY_CONFIG — the gate cannot know which severities gate; failing closed" >&2
  exit 1
}
# Captured before iterating so a jq failure (malformed config, a gating
# severity with no icon) fails the gate loudly instead of dissolving into an
# empty loop.
severity_rows="$(jq -r '.gating[] as $s | [$s, (.icons[$s] // error("no icon for gating severity \($s)"))] | @tsv' "$SEVERITY_CONFIG")"
gating_predicate=""
while IFS=$'\t' read -r sev sev_icon; do
  # An empty `gating` list makes the herestring yield ONE blank line, and a blank
  # row would append `startswith("")` — true of every body — so the gate would
  # red every thread while the can-never-gate guard below stayed satisfied.
  # Skipping blanks is what lets that guard actually see an empty predicate.
  [[ -n "$sev" && -n "$sev_icon" ]] || continue
  [[ -n "$gating_predicate" ]] && gating_predicate+=" or "
  gating_predicate+="(\$body | split(\"\\n\") | any(. == \"<!-- severity: ${sev} -->\"))"
  gating_predicate+=" or (\$body | startswith(\"${sev_icon}\"))"
done <<<"$severity_rows"
[[ -n "$gating_predicate" ]] || {
  echo "no gating severities in $SEVERITY_CONFIG — refusing to run a gate that can never gate" >&2
  exit 1
}

# (a) At least one reviewer review still standing. A PR nothing has read must
# not merge on "zero unresolved findings" — zero findings from zero reviews is
# vacuous, so the gate waits until the reviewer's first pass lands.
#
# DISMISSED reviews are dropped, which is what makes a dismissal mean something:
# the hold sweeper dismisses the reviewer's stale hold routinely (GitHub refuses
# approvals from an Actions token), and a PR whose only review was dismissed has
# nothing standing that read it.
reviews="$(reviewer_reviews_ndjson "$owner" "$name" "$PR" | jq -c 'select(.state != "DISMISSED")')"
if [[ -z "$reviews" ]]; then
  verdict=pending
  reason="waiting for the automated review of this pull request"
else
  # (b) Unresolved reviewer-rooted threads carrying a gating severity, per the
  # SSOT-derived predicate built above — 🔵 nits are advisory and never gate.
  gating="$(fetch_review_threads "$owner" "$name" "$PR" \
    "[.[] | select(.isResolved == false)
          | $REVIEW_THREAD_ROOT_IS_REVIEWER
          | (.comments.nodes[0].body // \"\") as \$body
          | select(${gating_predicate})
          | {path, line}]" |
    jq -s 'add // []')"
  count="$(jq 'length' <<<"$gating")"
  if [[ "$count" -eq 0 ]]; then
    verdict=green
    reason="the reviewer has reviewed this PR and no unresolved thread carries a 🔴/🟡 finding"
  else
    verdict=red
    where="$(jq -r '[.[] | (.path // "(general)") + (if .line then ":" + (.line|tostring) else "" end)] | join(", ")' <<<"$gating")"
    reason="${count} unresolved reviewer finding(s) still gate the merge: ${where} — resolve each thread (fix and let the resolver judge it, or resolve it with a reply) to clear"
  fi
fi

echo "review-findings gate on ${GH_REPO}#${PR}: ${verdict} — ${reason}" >&2

if [[ -z "${REPORT_SHA:-}" ]]; then
  [[ "$verdict" == "green" ]] || exit 1
  exit 0
fi

case "$verdict" in
green) state=success ;;
pending) state=pending ;;
*) state=failure ;;
esac
# No `|| true`: a verdict that cannot be reported leaves the required check
# hanging at "Expected", so a failed POST must red this run loudly.
post_verdict "$state" "$reason"
echo "posted ${state} status '${GATE_CONTEXT}' on ${REPORT_SHA}" >&2
