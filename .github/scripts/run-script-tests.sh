#!/usr/bin/env bash
# Run EVERY `*.test.mjs` under .github/scripts, discovered rather than listed.
#
# `node --test`'s default discovery skips dot-directories, so nothing here runs
# via `pnpm test`. The workflow used to name the suites by hand, and the naming
# rotted in both directions at once: the glob `auto-resolve-*.test.mjs` needs a
# literal hyphen and does not cross `/`, so it matched only the four FLAT suites
# — whose scripts nothing invoked any more — while the nine live suites under
# auto-resolve/ ran in no job at all, and seven further suites were simply never
# added to the list. Discovery removes the whole class: a suite added anywhere
# under .github/scripts runs from the moment it is committed.
#
# git ls-files, not a filesystem walk: an untracked scratch test in a working
# tree must not silently join a required check.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

suites=()
while IFS= read -r suite; do
  suites+=("$suite")
done < <(git ls-files -- '.github/scripts/**.test.mjs')

# Fail loud rather than pass an empty run: a glob that stops matching is exactly
# how this step went decorative before, and `node --test` with no files exits 0.
if [[ ${#suites[@]} -eq 0 ]]; then
  echo "::error::run-script-tests: no .github/scripts test suites discovered." >&2
  exit 1
fi

printf 'Running %d discovered suite(s):\n' "${#suites[@]}"
printf '  %s\n' "${suites[@]}"
node --test "${suites[@]}"
