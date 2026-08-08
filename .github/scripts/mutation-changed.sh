#!/usr/bin/env bash
# Exit 0 iff the diff between $BASE_SHA and $HEAD_SHA touches a file mutation
# testing depends on (the mutated sources — every SHIPPED .mjs, not just src/ —
# the tests that kill mutants, the Stryker config and the scripts that compute
# the mutate spec, package.json, or this workflow). Exit 1 means "nothing
# mutation-relevant changed, skip the expensive run".
#
# On a push to main (or any event without a usable base) we cannot cheaply diff,
# so we fail OPEN (exit 0) and let the full run decide — never skip a real gate
# on a missing base.

set -euo pipefail

base="${BASE_SHA:-}"
head="${HEAD_SHA:-}"

if [[ -z "$base" || -z "$head" ]]; then
  echo "No base/head SHA provided; running mutation testing (fail open)."
  exit 0
fi

# The workflow checks out with fetch-depth: 0, so the base commit is present for
# any PR/push diff. If it somehow isn't, fail OPEN rather than skip a real gate.
if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
  echo "Base commit $base not present; running mutation testing (fail open)."
  exit 0
fi

changed=$(git diff --name-only "$base" "$head" --)

printf '%s\n' "$changed" | grep -qE \
  '^(src/.*\.mjs|claude-hooks/.*\.mjs|bin/.*\.mjs|test/.*\.mjs|scripts/(shipped-sources|mutate)\.mjs|stryker\.conf\.json|package\.json|pnpm-lock\.yaml|\.github/mutation-shards\.json|\.github/workflows/mutation\.yaml|\.github/scripts/(mutation-changed|run-mutation-shard)\.sh|\.github/scripts/(aggregate-mutation|expand-shards)\.mjs)$'
