#!/usr/bin/env bash
# Assert the npm tarball's file set, given an `npm pack --dry-run` listing on
# stdin. Split out of pack-smoke.sh so the assertions are unit-testable: the
# listing is the only input, and a wrong pattern here is a false RED on every PR
# (which is how the `types/src/...` substring bug below was found) or, worse, a
# silent green while the `files` allowlist ships something it should not.
#
# Three properties, each a real regression class:
#   * no Python egg-info build artifacts,
#   * every file shipped under src/ is an .mjs module,
#   * the plugin tree stays out (it is distributed from the repo, not npm).
set -euo pipefail

listing="$(cat)"

# Only npm's `npm notice <size> <path>` lines name a packed file. `npm pack`
# also echoes the lifecycle scripts it runs — `prepare` prints
# `node plugin/scripts/build-plugin.mjs` and the src/ tables it writes — and
# reading those as packed paths reported the plugin tree as shipped. Matching
# the whole line, path included, also keeps a nested `types/src/...` declaration
# from reading as a file under src/.
paths="$(sed -nE 's/^npm notice [0-9.]+[kMG]?B (.+)$/\1/p' <<<"$listing")"
if [ -z "$paths" ]; then
  echo "ERROR: the listing names no packed file (no \`npm notice <size> <path>\` line)" >&2
  exit 1
fi

if grep -q 'egg-info' <<<"$paths"; then
  echo "ERROR: tarball ships Python egg-info build artifacts" >&2
  exit 1
fi

# A stray .py/.d.ts/.map under src/ means the `files` allowlist widened by
# accident. `grep` exits 1 when there is simply nothing to report, which must
# not abort the job; exit >=2 is a real grep failure. Branch on the code:
# tolerate <=1, propagate anything higher. Separate steps rather than a pipeline:
# `pipefail` reports the RIGHTMOST failing stage, which would hide a stage-1
# exit 2 behind a stage-2 exit 1.
rc=0
src_paths="$(grep -E '^src/' <<<"$paths")" || rc=$?
if [ "$rc" -gt 1 ]; then
  echo "ERROR: pack-listing scan failed (grep exit $rc)" >&2
  exit "$rc"
fi
rc=0
src_nonmjs="$(grep -vE '\.mjs$' <<<"$src_paths")" || rc=$?
if [ "$rc" -gt 1 ]; then
  echo "ERROR: pack-listing scan failed (grep exit $rc)" >&2
  exit "$rc"
fi
if [ -n "$src_nonmjs" ]; then
  echo "ERROR: tarball ships a non-.mjs file under src/:" >&2
  echo "$src_nonmjs" >&2
  exit 1
fi

if grep -q '^plugin/' <<<"$paths"; then
  echo "ERROR: tarball ships the plugin tree (bundle + packaging); it is distributed from the repo, not npm" >&2
  exit 1
fi
