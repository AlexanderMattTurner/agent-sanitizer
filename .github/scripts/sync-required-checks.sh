#!/usr/bin/env bash
# Apply (or, with CHECK_ONLY=true, only diff) the branch-protection ruleset's
# required-status-checks to the `# required-check:` annotations in
# .github/workflows. Invoked solely by sync-required-checks.yaml; reads REPO,
# DEFAULT_BRANCH, CHECK_ONLY, and GH_TOKEN from the environment.
#
# The ci-truth-serum rev is read from .pre-commit-config.yaml — its single
# source — so this apply step and the check-required-reporter lint can never run
# different parser versions (the drift that would let the gate and the lint read
# the same YAML two ways).
#
# The module path below is tied to that rev: at the pinned revision
# ci-truth-serum's package is `ci_truth_serum`. If a future rev bump lands
# past another package rename, this line needs updating in the same commit;
# nothing else here does.
set -euo pipefail

ref="$(awk '/repo:.*ci-truth-serum$/{f=1; next} f && /^[[:space:]]*rev:/{print $2; exit}' .pre-commit-config.yaml)"
if [[ ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Could not read a 40-char ci-truth-serum rev from .pre-commit-config.yaml (got: '${ref}')" >&2
  exit 1
fi

: "${REPO:?REPO required}"
: "${DEFAULT_BRANCH:?DEFAULT_BRANCH required}"

# ci-truth-serum's own discovery refuses when several repo-owned branch rulesets
# exist, so name the one that carries the required checks on the default branch.
ids="$(gh api --paginate "repos/${REPO}/rules/branches/${DEFAULT_BRANCH}" \
  --jq '.[] | select(.ruleset_source_type == "Repository" and .type == "required_status_checks") | .ruleset_id' |
  sort -u)"
if [[ -z "$ids" || "$ids" == *$'\n'* ]]; then
  echo "Expected exactly one repo-owned ruleset requiring status checks on ${DEFAULT_BRANCH} of ${REPO}; found: ${ids:-none}" >&2
  exit 1
fi

args=(--repo "$REPO" --ruleset-id "$ids")
if [[ "${CHECK_ONLY:-false}" == "true" ]]; then
  args+=(--check)
fi

uv run --no-project \
  --with "ci-truth-serum @ git+https://github.com/AlexanderMattTurner/ci-truth-serum@${ref}" \
  python -m ci_truth_serum.sync_required_checks "${args[@]}"
