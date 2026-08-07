#!/usr/bin/env bash
# Append one timed run to the timing-history branch, then render the trend.
#
# The history is an append-only JSONL file on an orphan branch: it must not
# live on main, where every run would add a commit to the branch under review
# and turn `git log` into a timing feed. One line per run, oldest first:
#   {"title":…,"total_ms":…,"phases":[…],"commit":…,"at":…,"run_id":…}
#
# Only a push to the default branch may write: a PR's numbers are measured on a
# commit that may never land, and mixing those into the series makes the trend
# meaningless. The workflow gates on that too — this re-checks rather than
# trusting a condition that a later edit could quietly widen.
#
# Env: TIMING_JSON (the record written via TIMER_JSON_OUT), GITHUB_SHA,
#      GITHUB_RUN_ID, GITHUB_REF_NAME, DEFAULT_BRANCH, HISTORY_BRANCH,
#      HISTORY_FILE, TREND_SERIES (newline separated), TREND_TITLE.

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

# shellcheck source=.github/scripts/lib/retry.bash
source "$repo_root/.github/scripts/lib/retry.bash"

: "${TIMING_JSON:?TIMING_JSON required}"
: "${GITHUB_SHA:?GITHUB_SHA required}"
: "${GITHUB_REF_NAME:?GITHUB_REF_NAME required}"
: "${DEFAULT_BRANCH:?DEFAULT_BRANCH required}"
branch="${HISTORY_BRANCH:-ci-timings}"
history_file="${HISTORY_FILE:-hook-lifecycle.jsonl}"
title="${TREND_TITLE:-Session setup}"

[ "$GITHUB_REF_NAME" = "$DEFAULT_BRANCH" ] || {
  echo "refusing to record timings from '$GITHUB_REF_NAME': the series tracks $DEFAULT_BRANCH only" >&2
  exit 1
}
command -v jq >/dev/null || {
  echo "jq is required to stamp the timing record" >&2
  exit 1
}
[ -s "$TIMING_JSON" ] || {
  echo "no timing record at $TIMING_JSON — the timed job did not produce one" >&2
  exit 1
}

# The stamped line. `--sort-keys` keeps field order stable, so a diff of the
# history branch shows the numbers that changed rather than a reshuffle.
record=$(jq -c --sort-keys \
  --arg commit "$GITHUB_SHA" \
  --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg run_id "${GITHUB_RUN_ID:-}" \
  '. + {commit: $commit, at: $at, run_id: $run_id}' "$TIMING_JSON")

# A worktree, not a fresh `git init` + clone: it inherits this checkout's
# credential config, so the push authenticates with the job's token.
work="${RUNNER_TEMP:-/tmp}/timing-history.$$"

cleanup() {
  [ -e "$work" ] || return 0
  local rc=0
  git worktree remove --force "$work" >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 0 ] || echo "warning: could not remove the temporary worktree at $work (exit $rc)" >&2
}
trap cleanup EXIT

# `git ls-remote --exit-code` separates the three cases a bare fetch conflates:
# 0 = the branch exists, 2 = the repo is reachable but has no such branch (the
# first-ever run), anything else = a real error worth dying on.
set +e
git ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1
branch_exists=$?
set -e
[ "$branch_exists" -eq 0 ] || [ "$branch_exists" -eq 2 ] || {
  echo "git ls-remote origin $branch failed (exit $branch_exists)" >&2
  exit "$branch_exists"
}

# (Re)build the worktree from the remote tip, or from nothing the first time.
# Called again after a rejected push, so it has to be idempotent.
checkout_history() {
  cleanup
  if [ "$branch_exists" -eq 0 ]; then
    retry_cmd 4 2 git fetch --depth=1 origin "$branch"
    git worktree add --detach "$work" FETCH_HEAD >/dev/null
    return 0
  fi
  # No branch yet. Start from an empty tree so the history branch never carries
  # a copy of the source tree.
  git worktree add --detach --no-checkout "$work" HEAD >/dev/null
  git -C "$work" checkout --orphan "$branch" >/dev/null
  [ -z "$(git -C "$work" ls-files)" ] || git -C "$work" rm -rq --cached .
  : >"$work/$history_file"
}

commit_and_push() {
  printf '%s\n' "$record" >>"$work/$history_file"
  git -C "$work" add "$history_file"
  git -C "$work" \
    -c user.name="github-actions[bot]" \
    -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    commit -qm "chore(timing): record ${GITHUB_SHA:0:7} [skip ci]"
  git -C "$work" push origin "HEAD:$branch"
}

# Concurrent runs can both try to land a record; the loser re-reads the
# advanced tip and re-appends. A rebase would work too, but re-appending is
# exact for an append-only file and cannot conflict.
attempt=1
delay=2
while :; do
  checkout_history
  commit_and_push && break
  [ "$attempt" -lt 4 ] || {
    echo "could not push the timing record to $branch after $attempt attempts" >&2
    exit 1
  }
  echo "push to $branch rejected (attempt $attempt/4); re-reading the tip in ${delay}s..." >&2
  sleep "$delay"
  delay=$((delay * 2))
  attempt=$((attempt + 1))
  branch_exists=0 # whoever won the race created it
done

series_args=()
while IFS= read -r series; do
  if [ -n "$series" ]; then series_args+=(--series "$series"); fi
done <<<"${TREND_SERIES:-total}"

node "$repo_root/.github/scripts/render-timing-trend.mjs" \
  --history "$work/$history_file" \
  --title "$title" \
  "${series_args[@]}"
