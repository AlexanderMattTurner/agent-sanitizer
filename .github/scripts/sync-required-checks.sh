#!/usr/bin/env bash
# Apply (or, with CHECK_ONLY=true, only diff) the branch-protection ruleset's
# required-status-checks to the `# required-check:` annotations in
# .github/workflows. Invoked solely by sync-required-checks.yaml; reads REPO,
# CHECK_ONLY, and GH_TOKEN from the environment.
#
# The ci-truth-serum rev is read from .pre-commit-config.yaml — its single
# source — so this apply step and the check-required-reporter lint can never run
# different parser versions (the drift that would let the gate and the lint read
# the same YAML two ways).
#
# The module path below is tied to that rev: ci-truth-serum's package was
# `hooks` at the pinned revision and was later renamed to `ci_truth_serum`, so
# bumping the rev in .pre-commit-config.yaml past that rename means changing
# this line in the same commit. Nothing else here needs touching.
set -euo pipefail

ref="$(awk '/repo:.*ci-truth-serum$/{f=1; next} f && /^[[:space:]]*rev:/{print $2; exit}' .pre-commit-config.yaml)"
if [[ ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Could not read a 40-char ci-truth-serum rev from .pre-commit-config.yaml (got: '${ref}')" >&2
  exit 1
fi

args=(--repo "$REPO")
if [[ "${CHECK_ONLY:-false}" == "true" ]]; then
  args+=(--check)
fi

uv run --no-project \
  --with "ci-truth-serum @ git+https://github.com/alexander-turner/ci-truth-serum@${ref}" \
  python -m hooks.sync_required_checks "${args[@]}"
