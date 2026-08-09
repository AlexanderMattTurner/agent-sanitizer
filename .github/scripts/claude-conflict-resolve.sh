#!/usr/bin/env bash
# Resolves a PR's merge conflicts: install the pinned Claude CLI from the trusted
# base worktree, then walk the configured credentials, running the per-file
# fan-out (auto-resolve/fanout.sh) under each until one produces a resolution.
#
# A rung advances only when the one before it produced NO usable run at all —
# no execution log, or a log reporting is_error. A run that reached the model and
# judged a conflict too hard is an ANSWER, and re-asking it on a different
# credential would only buy the same answer at twice the price.
#
# This is a base-staged SCRIPT on purpose — never convert it back into a local
# `uses: ./…` composite action: the runner reads a local action's manifest out of
# the WORKSPACE at step time, and the resolve job's workspace is the untrusted PR
# head left mid-merge, so the manifest itself can be one of the conflicted files
# — a manifest carrying conflict markers is not YAML, and every rung of the
# credential ladder then dies before the resolver starts. A script staged into
# $RUNNER_TEMP from the base ref is out of reach of both the PR's content and the
# merge state.
#
# Env: at least one of CLAUDE_CODE_OAUTH_TOKEN and its _FALLBACK /
# _FALLBACK_2 … _FALLBACK_6 rungs; the rest is auto-resolve/fanout.sh's own
# contract — see its header. Needs node/npm on PATH for the CLI install, and must
# run with the mid-merge working tree as the current directory, like every
# resolver entrypoint.
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=.github/scripts/lib/claude-oauth-ladder.bash
source "${SCRIPTS_DIR}/lib/claude-oauth-ladder.bash"

# The one ordered rung list every resolver caller walks, so a credential this
# job can resolve on is never one the pre-push review then cannot verify on.
ladder=()
while IFS= read -r token; do
  [[ -n "$token" ]] && ladder+=("$token")
done < <(claude_oauth_ladder)

# Refuse on an EMPTY ladder, not on an empty first rung. Demanding
# CLAUDE_CODE_OAUTH_TOKEN specifically is the short-copy failure the ladder
# library's header warns about: a repo that provisions only the fallbacks — the
# ordinary shape when rung 1 is rotated out — has every conflict resolve die
# here before the model is ever reached, and the workflow's execution-log gate
# then reports it as "no execution log … action config or credential plumbing"
# rather than naming the missing credential. Refuse before the CLI install, not
# after: with no credential at all every shard fails anyway, and the fan-out's
# own guard only fires once the install is paid.
if [[ "${#ladder[@]}" -eq 0 ]]; then
  echo "::error::no Claude credential configured — set at least one of ${CLAUDE_OAUTH_LADDER_VARS[*]}; no shard can authenticate without one." >&2
  exit 1
fi

# The installer resolves its version pin relative to itself, so it reads the
# base-staged pin rather than whatever the untrusted PR head carries.
bash "${SCRIPTS_DIR}/install-claude-cli.sh"

# The fan-out writes its aggregate log here every rung, overwriting the previous
# rung's — so the rung that finally answers is the one the caller reads.
fanout_dir="${FANOUT_DIR:-${RUNNER_TEMP:-/tmp}/conflict-fanout}"
export FANOUT_DIR="$fanout_dir"

rung=0
for token in "${ladder[@]}"; do
  rung=$((rung + 1))
  echo "Conflict resolution: credential ${rung} of ${#ladder[@]}."
  rc=0
  CLAUDE_CODE_OAUTH_TOKEN="$token" bash "${SCRIPTS_DIR}/auto-resolve/fanout.sh" || rc=$?
  log="${fanout_dir}/execution.json"
  if [[ "$rc" -eq 0 && -s "$log" ]] && ! jq -e '.is_error == true' "$log" >/dev/null; then
    exit 0
  fi
  echo "::warning::credential ${rung} produced no usable resolution (exit ${rc}); trying the next rung if one is configured."
done

# Every rung is spent. Exiting non-zero is the honest report, and the workflow's
# execution-log gate turns it into a message naming the real cause.
echo "::error::every configured Claude credential failed to resolve the conflicts."
exit 1
