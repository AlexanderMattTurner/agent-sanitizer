#!/usr/bin/env bash
# Stryker DRY RUN only, over every shipped source: instrument the tree, run the
# suite once, exit. No mutants are executed.
#
# WHY THIS EXISTS. Stryker does not run the suite against the checkout — it
# copies the project to .stryker-tmp/sandbox-XXXXXX/ and rewrites every file in
# the --mutate set, so `const X = {` arrives as
# `const X = stryMutAct_9fa48("0") ? {} : ({…})` before a single mutant is
# activated. A test that asserts on the syntactic FORM of a file it reads from
# disk therefore fails in that dry run while passing on a healthy tree, and
# because Stryker aborts a shard whose dry run is red, one such test takes every
# 25-minute shard down at once. That is how PR #279 went red.
#
# The eliminator is the real oracle rather than a static approximation of it: no
# lint can tell a source-shape assertion that survives instrumentation from one
# that does not, but a dry run answers by construction. It costs one suite run,
# so the answer arrives in minutes instead of after the whole matrix has died.
set -euo pipefail

# The mutate scope is derived, never spelled out here: scripts/shipped-sources.mjs
# is the same SSOT the coverage floor and the shard list read, so a new shipped
# module is instrumented by this oracle with no config to remember.
sources=()
while IFS= read -r line; do
  sources+=("$line")
done < <(node scripts/shipped-sources.mjs)

if [[ ${#sources[@]} -eq 0 ]]; then
  echo "run-mutation-dry-run: shipped-sources.mjs listed no files. The dry run" >&2
  echo "  would instrument nothing and pass vacuously, which is worse than not" >&2
  echo "  running it at all. Fix the source list before trusting this gate." >&2
  exit 2
fi

mutate="$(
  IFS=,
  printf '%s' "${sources[*]}"
)"

# Derived from the committed config so the two cannot drift, exactly as
# run-mutation-shard.sh does. Only what a dry run makes meaningless is
# overridden: there is no score to threshold, no per-mutant JSON to aggregate,
# and no incremental verdict to carry forward.
#
# dryRunTimeoutMinutes is raised from Stryker's default of 5 because this job IS
# the dry run: it instruments every shipped source and then runs the WHOLE suite
# once, including the rehydrate property test that drives the real Python
# redactor. Measured here: a warm run finishes in ~2 minutes, a cold one hit the
# 5-minute default as a TIMEOUT rather than a result — the failure mode that
# margin exists to prevent, since a timed-out oracle reports nothing about the
# thing it was asked. A shard hides the same cost inside its 25-minute budget;
# here it is the whole job, so the limit is stated instead of inherited. The
# job's own timeout-minutes remains the outer bound.
jq '.thresholds.break = null
    | .reporters = ["clear-text"]
    | .incremental = false
    | .dryRunTimeoutMinutes = 15' \
  stryker.conf.json >stryker.dryrun.json

pnpm exec stryker run stryker.dryrun.json --mutate "$mutate" --dryRunOnly
