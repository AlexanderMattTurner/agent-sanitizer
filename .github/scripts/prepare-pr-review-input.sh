#!/usr/bin/env bash
# Fetch the untrusted PR diff + metadata and run them through the
# agent-sanitizer (sanitize-pr-input.mjs) BEFORE the review agent sees
# them. The agent reads only the sanitized files this writes — never the raw
# diff — so an injection payload hidden in it (zero-width control text, ANSI
# escapes, exfil beacons) cannot reach the agent intact.
#
# Generated-file filter: a path whose regen rule sets `reviewOmit` is stripped
# from the diff before it is counted or sanitized. That flag asserts a REQUIRED
# check re-derives the artifact and reds on any difference, so its bytes cannot
# disagree with their sources and a reviewer reading them learns nothing. Being
# generated is NOT enough on its own — a lockfile has a generator but no such
# check, so nothing regenerates it and the reviewer is the only reader it has.
# This repo commits a ~29k-line hook bundle, which pushed ordinary source edits
# over the size guard below.
#
# Oversized-diff guard: the base-only checkout means diff.txt is the ONLY source
# of the PR's changes — the agent cannot reconstruct them from the trusted base
# tree, so an enormous diff (a mega-merge, a vendored dump) would be ingested
# whole into an Opus read that is slow, costly, and low-signal. Above
# MAX_DIFF_LINES lines this skips the review, emitting oversized=true so the
# caller posts a "please review manually" notice instead of spending the read.
#
# Requires: GH_TOKEN/GH_REPO (the diff fetch calls the API directly with these;
# `gh pr view` below still expects them as gh's own auth env vars), node +
# `pnpm install` done (agent-sanitizer on the module path). Emits to GITHUB_OUTPUT:
#   oversized=true|false       — whether the review was skipped for size
#   diff_lines=<n>             — the diff's line count (only when oversized)
# Writes into $PR_INPUT_DIR (only when NOT oversized):
#   diff.txt / meta.txt        — sanitized diff and PR metadata
#   sanitizer-report.txt       — what was flagged (never empty; says so)
# and, only when oversized:
#   oversized-notice.txt       — the human-review notice body for the caller
set -euo pipefail

# shellcheck source=.github/scripts/lib-ci-retry.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib-ci-retry.sh"

: "${PR:?PR number required}"
: "${PR_INPUT_DIR:?PR_INPUT_DIR required}"
: "${GH_TOKEN:?GH_TOKEN required}"
: "${GH_REPO:?GH_REPO required}"

MAX_DIFF_LINES="${MAX_DIFF_LINES:-20000}"

mkdir -p "$PR_INPUT_DIR"

emit_output() {
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf '%s\n' "$1" >>"$GITHUB_OUTPUT"
  fi
}

# Materialize the raw diff OUTSIDE the agent-readable input dir (the review step
# grants the agent read over PR_INPUT_DIR via --add-dir), so only the SANITIZED
# diff.txt ever reaches the reviewer.
raw_diff="$(mktemp)"
review_diff="$(mktemp)"
omit_list="$(mktemp)"
trap 'rm -f "$raw_diff" "$review_diff" "$omit_list"' EXIT
# curl for the diff media type, not `gh api`/`gh pr diff`: gh's own
# client-side safety guard (pkg/iostreams content sanitization) refuses to
# print ANY response holding a raw terminal escape sequence unless
# --allow-escape-sequences is passed, and that guard fires identically whether
# the request is made through `gh pr diff` or `gh api` — it is not a `pr diff`
# quirk, so switching gh subcommands cannot clear it. curl has no such guard,
# and only the sanitizer below ever reads these bytes.
#
# retry_stdout via a command substitution: a transient blip re-fetches the whole
# diff and only the succeeding attempt's bytes land in raw_diff. A plain `retry
# … >"$raw_diff"` would leak a failing attempt's error body into the file.
api_url="${GITHUB_API_URL:-https://api.github.com}"
raw_diff_content="$(retry_stdout curl -fsS \
  -H "Authorization: Bearer ${GH_TOKEN}" \
  -H "Accept: application/vnd.github.v3.diff" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "${api_url}/repos/${GH_REPO}/pulls/${PR}")"
printf '%s\n' "$raw_diff_content" >"$raw_diff"

# resolve-generated.mjs owns the decision; nothing classifies a path here. The
# filter must run BEFORE the line count and before sanitize, so both see the
# diff a reviewer will actually read.
node .github/scripts/resolve-generated.mjs --owned --rederived-only >"$omit_list"
node .github/scripts/strip-generated-diff.mjs "$omit_list" \
  <"$raw_diff" >"$review_diff"

diff_lines="$(wc -l <"$review_diff" | tr -d '[:space:]')"
if ((diff_lines > MAX_DIFF_LINES)); then
  emit_output "oversized=true"
  emit_output "diff_lines=$diff_lines"
  printf '%s\n' \
    "Automated Opus review skipped: this PR's diff is ${diff_lines} lines, over the ${MAX_DIFF_LINES}-line limit for automated review. A change this large should get a human review — please review it manually." \
    >"${PR_INPUT_DIR}/oversized-notice.txt"
  echo "diff ${diff_lines} lines exceeds MAX_DIFF_LINES=${MAX_DIFF_LINES}; skipping review" >&2
  exit 0
fi
emit_output "oversized=false"

sanitize() { node .github/scripts/sanitize-pr-input.mjs; }

sanitize <"$review_diff" >"${PR_INPUT_DIR}/diff.txt" 2>"${PR_INPUT_DIR}/diff.report.txt"
# Capture the metadata JSON with retry_stdout, THEN pipe the clean result into
# the sanitizer — retrying gh directly inside the `| sanitize` pipe is unsafe (a
# failing attempt would stream partial JSON into the sanitizer, and a SIGPIPE if
# it exited early would trip pipefail).
meta_json="$(retry_stdout gh pr view "$PR" --json title,body,author,files)"
printf '%s' "$meta_json" |
  sanitize >"${PR_INPUT_DIR}/meta.txt" 2>"${PR_INPUT_DIR}/meta.report.txt"

report="${PR_INPUT_DIR}/sanitizer-report.txt"
{
  if [[ -s "${PR_INPUT_DIR}/diff.report.txt" ]]; then
    echo "## Diff"
    cat "${PR_INPUT_DIR}/diff.report.txt"
  fi
  if [[ -s "${PR_INPUT_DIR}/meta.report.txt" ]]; then
    echo "## Metadata"
    cat "${PR_INPUT_DIR}/meta.report.txt"
  fi
} >"$report"

if [[ -s "$report" ]]; then
  echo "sanitizer flagged injection-shaped content; see ${report}" >&2
else
  echo "(sanitizer found no injection-shaped content in the diff or metadata)" >"$report"
fi
