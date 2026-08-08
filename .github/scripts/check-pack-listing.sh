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

if grep -q 'egg-info' <<<"$listing"; then
  echo "ERROR: tarball ships Python egg-info build artifacts" >&2
  exit 1
fi

# Pull the src/ path tokens out of the listing and assert each ends in .mjs — a
# stray .py/.d.ts/.map under src/ means the `files` allowlist widened by
# accident. The `(^|[[:space:]])` anchor is load-bearing: an unanchored `src/`
# also matches INSIDE `types/src/claude-context.d.mts`, the declaration the
# hooks build legitimately emits for the relatively-imported context module, and
# reported it as a non-.mjs file under src/.
#
# `grep` exits 1 when there is simply nothing to report (no src/ path at all),
# which must not abort the job; but exit >=2 is a real grep failure that
# `|| true` would silently swallow (masking a broken scan as "all clean").
# Branch on the code: tolerate <=1, propagate anything higher. Kept as separate
# steps rather than a pipeline because `pipefail` reports the RIGHTMOST failing
# stage, which would hide a stage-1 exit 2 behind a stage-2 exit 1.
rc=0
src_paths="$(grep -oE '(^|[[:space:]])src/[^[:space:]]+' <<<"$listing")" || rc=$?
if [ "$rc" -gt 1 ]; then
  echo "ERROR: pack-listing scan failed (grep exit $rc)" >&2
  exit "$rc"
fi
if [ -n "$src_paths" ]; then
  # The matches carry the anchor's leading blank; paths never contain one.
  src_paths="$(tr -d '[:blank:]' <<<"$src_paths")"
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
fi

if grep -qE '(^|[[:space:]])plugin/' <<<"$listing"; then
  echo "ERROR: tarball ships the plugin tree (bundle + packaging); it is distributed from the repo, not npm" >&2
  exit 1
fi
