#!/usr/bin/env bash
# Run one mutation-testing shard over the slice named in $MUTATE (a --mutate
# spec: comma-separated files, each optionally postfixed with a :start-end line
# range). Derives its Stryker config from the committed stryker.conf.json: only
# the break threshold (the aggregator gates on the global score, not
# per-shard) and the reporter set are overridden.
set -euo pipefail

: "${MUTATE:?MUTATE must be set to a Stryker --mutate spec}"

jq '.thresholds.break = null | .reporters = ["json", "clear-text"]' \
  stryker.conf.json >stryker.shard.json

pnpm exec stryker run stryker.shard.json --mutate "$MUTATE" --incremental
