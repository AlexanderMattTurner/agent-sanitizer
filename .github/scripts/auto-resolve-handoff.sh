#!/usr/bin/env bash
# Auto-resolve merge conflicts — HANDOFF step. Runs when PREPARE found
# conflicted paths that cannot be merged textually AND that no owning tool can
# regenerate: a binary, or a lockfile whose tool is not a known/available one
# (known lockfiles — pnpm-lock.yaml, package-lock.json, uv.lock — are deferred
# to owning-tool regeneration instead and never land here). No LLM edit can
# produce a correct resolution, so comment and fail loud BEFORE any LLM cost.
#
# The PR is also labeled `auto-resolve-blocked` (which discover excludes):
# nothing about a later push to the base branch changes an unmergeable
# conflict, so retrying on every base push would only re-spend on the same
# refusal and re-post the same comment. A human resolves by hand and removes
# the label to re-enable auto-resolve for this PR.
set -euo pipefail

: "${PR:?PR required}"
: "${BASE_REF:?BASE_REF required}"
: "${UNRESOLVABLE:?UNRESOLVABLE required}"

read -ra paths <<<"$UNRESOLVABLE"
bullets=""
for f in "${paths[@]}"; do
  bullets+="- \`${f}\`"$'\n'
done

gh label create auto-resolve-blocked --color e4e669 --force \
  --description "Auto-resolve cannot push to this PR; remove the label to let it retry" || echo "[auto-resolve] gh label create failed" >&2
gh pr edit "$PR" --add-label auto-resolve-blocked || echo "[auto-resolve] failed to add auto-resolve-blocked label to PR #${PR}" >&2

gh pr comment "$PR" --body "⚠️ **Cannot auto-resolve the merge conflict with \`${BASE_REF}\`** — these files cannot be merged textually and no available tool can regenerate them (binary, or an unsupported lockfile):

${bullets}
Resolve by hand: merge \`${BASE_REF}\` locally and re-run the tool that owns each file (or re-export the asset), then push the merge commit. This PR is now labeled \`auto-resolve-blocked\` and auto-resolve will skip it — remove the label to re-enable." || echo "[auto-resolve] failed to post handoff comment on PR #${PR}" >&2

echo "::error::unmergeable conflict(s) with ${BASE_REF}: ${UNRESOLVABLE} — no textual resolution and no owning tool to rerun; a human must resolve and push the merge."
exit 1
