#!/usr/bin/env bash
# Fail unless an active ruleset restricts updates to every branch the plugin
# marketplace installs from.
#
# .claude-plugin/marketplace.json points installs at a machine-written branch
# (plugin-dist), so whoever can push that branch ships code to every installed
# user. The restriction is a repository ruleset, not code in this tree, so
# nothing else goes red when it is missing or deleted; this check is what does.
# It reads the rules GitHub actually enforces on the branch
# (GET /repos/{repo}/rules/branches/{branch}), which already folds in every
# active repository and organization ruleset, and requires an `update` rule —
# the one that confines pushes to the ruleset's bypass actors.
#
# A repo with no marketplace, or whose plugins name no `source.ref`, has no
# such branch and passes.
#
# Usage: check-plugin-dist-ruleset.sh   (env: GITHUB_REPOSITORY, GH_TOKEN)
set -euo pipefail

log() { echo "$@" >&2; }

REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
MARKETPLACE=.claude-plugin/marketplace.json

if [[ ! -f "$MARKETPLACE" ]]; then
  log "No $MARKETPLACE in this repo; no install branch to protect."
  exit 0
fi
REFS="$(jq -r '[.plugins[].source | objects | .ref | strings] | unique | .[]' "$MARKETPLACE")"
if [[ -z "$REFS" ]]; then
  log "$MARKETPLACE names no source.ref; no install branch to protect."
  exit 0
fi

# Listed for the log only: when the check fails, the reader needs to see which
# rulesets exist to tell "missing" from "present but not covering the branch".
RULESETS="$(gh api "repos/$REPO/rulesets?includes_parents=true" --jq '.[] | "\(.id) \(.name) (\(.source_type), \(.enforcement))"')"
log "Rulesets on $REPO:"
log "${RULESETS:-  (none)}"

failed=0
while IFS= read -r branch; do
  RULES="$(gh api "repos/$REPO/rules/branches/$branch" --jq '[.[].type] | unique | join(" ")')"
  log "Active rules on refs/heads/$branch: ${RULES:-(none)}"
  if [[ " $RULES " != *" update "* ]]; then
    log "::error::No active ruleset restricts updates to refs/heads/$branch, which $MARKETPLACE installs from — anyone with write access can push it and ship code to every installed user. A repository admin must add a branch ruleset on refs/heads/$branch with the update, creation, deletion and non_fast_forward rules, bypassed only by the identity plugin-dist.yaml pushes with."
    failed=1
  fi
done <<<"$REFS"
exit "$failed"
