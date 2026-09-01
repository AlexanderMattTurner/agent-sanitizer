#!/usr/bin/env bash
# Keep the `merge-conflict` label on every open PR whose GitHub-computed
# mergeability is CONFLICTING, and clear it once the PR merges cleanly again.
# Conflict cost scales with how long a branch sits behind a fast-moving base,
# so surfacing the transition the moment it happens (instead of at merge time,
# hundreds of commits later) is what keeps resolutions small enough to review
# honestly. Event-driven with a cron backstop; API-only — it never pushes to a
# PR branch and never triggers a CI run on one.
#
# Scope: with PR_NUMBER set (a PR event) it syncs that one PR; unset (a base
# push / schedule) it scans every open PR. A single-PR sync is what clears the
# label seconds after a conflict is resolved.
#
# GitHub computes mergeability lazily: querying a PR triggers the computation,
# so a PR reporting UNKNOWN on the first pass usually resolves by a later one.
# PRs still UNKNOWN after MAX_PASSES are named in a workflow warning — never
# silently skipped — and the next event or scheduled run retries them anyway.
# Env: GH_TOKEN, REPO; PR_NUMBER scopes to one PR; MAX_PASSES (default 2) caps
# the retry loop; RETRY_DELAY_SECS overrides the between-pass wait; SWEEP_LIMIT
# (default 100) caps how many open PRs one full-repo sweep lists.
set -euo pipefail

: "${GH_TOKEN:?}" "${REPO:?}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/shared-names.bash disable=SC1091
source "$SCRIPT_DIR/lib/shared-names.bash"

# The label name comes from the cross-language SSOT (lib/shared-names.json):
# this script WRITES the label that discover.py and workflow gates read.
export LABEL="$_LABEL_MERGE_CONFLICT"

gh label create "$LABEL" --repo "$REPO" --color d93f0b --force \
  --description "This PR has merge conflicts with its base branch"

SWEEP_LIMIT="${SWEEP_LIMIT:-100}"
# Set once the cap warning has fired, so a multi-pass retry (MAX_PASSES) that
# keeps re-fetching the same capped page reports it once, not once per pass.
# Must be set from the main loop, never from inside a command substitution —
# a subshell's assignment never reaches back to this variable's parent shell.
sweep_capped_warned=""

# Raw JSON: a single PR wrapped in an array (`pr view`), or an open-PR page
# (`pr list`) — a uniform shape so the caller never special-cases PR_NUMBER.
fetch_page() {
  if [[ -n "${PR_NUMBER:-}" ]]; then
    gh pr view "$PR_NUMBER" --repo "$REPO" --json number,mergeable,labels --jq '[.]'
    return
  fi
  gh pr list --repo "$REPO" --state open --limit "$SWEEP_LIMIT" \
    --json number,mergeable,labels
}

# TSV rows from a fetch_page JSON blob: number, mergeable, whether LABEL is
# already applied.
list_prs() {
  local jq_row='[.number, .mergeable, any(.labels[]; .name == env.LABEL)] | @tsv'
  jq -r ".[] | $jq_row" <<<"$1"
}

unknown=""
<<<<<<< local
# retry-loop-ok: each pass re-lists and re-labels every open PR, not one
# failing command — lib-ci-retry.sh's `retry` re-runs a single argv and has
# no equivalent for "re-sync a whole label pass".
||||||| base
=======
# retry-loop-ok: not a retry-until-success loop — each pass labels every PR
# whose state IS known this pass and only carries the still-UNKNOWN subset
# forward, so the repo's single-command retry_cmd has no body to wrap here.
>>>>>>> template
for ((pass = 1; pass <= ${MAX_PASSES:-2}; pass++)); do
  [[ "$pass" == "1" ]] || sleep "${RETRY_DELAY_SECS:-10}"
  unknown=""
  page="$(fetch_page)"
  # A full page means more open PRs may exist past the limit; say so rather
  # than silently under-sweeping them. jq's own array length, not a line count
  # of the rendered rows — a zero-PR page renders as one blank TSV line.
  if [[ -z "${PR_NUMBER:-}" && -z "$sweep_capped_warned" &&
    "$(jq 'length' <<<"$page")" -ge "$SWEEP_LIMIT" ]]; then
    echo "::warning::open-PR sweep hit its $SWEEP_LIMIT-PR limit; some PRs may not have been checked this run." >&2
    sweep_capped_warned=1
  fi
  while IFS=$'\t' read -r num state labeled; do
    [[ -n "$num" ]] || continue
    case "$state" in
    CONFLICTING)
      [[ "$labeled" == "true" ]] || gh pr edit "$num" --repo "$REPO" --add-label "$LABEL"
      ;;
    MERGEABLE)
      [[ "$labeled" == "false" ]] || gh pr edit "$num" --repo "$REPO" --remove-label "$LABEL"
      ;;
    *)
      unknown="$unknown #$num"
      ;;
    esac
  done <<<"$(list_prs "$page")"
  [[ -n "$unknown" ]] || break
done

if [[ -n "$unknown" ]]; then
  echo "::warning::mergeability still UNKNOWN for$unknown after ${MAX_PASSES:-2} passes; the next PR event or scheduled run will retry them."
fi
