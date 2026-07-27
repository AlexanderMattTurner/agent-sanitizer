#!/usr/bin/env bash
# Build the npm tarball exactly as it would be published, install it into a
# throwaway directory that is NOT a git repo, and exercise the published surface:
# every documented `exports` subpath plus the `sanitize-cli` bin. This catches
# the class of bug that the in-repo `node --test` cannot — a `files` allowlist
# that drops a shipped module, a `prepack` that fails to emit types, or an
# install lifecycle script (`postinstall`/`prepare`) that assumes a git repo and
# crashes the consumer's `npm install`. We deliberately do NOT pass
# --ignore-scripts so a broken install hook fails the job here, not in the wild.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# 1. The published tarball must not carry Python build artifacts or any
#    non-.mjs source under src/. `npm pack --dry-run` lists the file set without
#    writing the tarball, so we can assert on it before building for real.
echo "::group::npm pack --dry-run file listing"
pack_listing="$(npm pack --dry-run 2>&1)"
echo "$pack_listing"
echo "::endgroup::"

if grep -q 'egg-info' <<<"$pack_listing"; then
  echo "ERROR: tarball ships Python egg-info build artifacts" >&2
  exit 1
fi
# Every file shipped under src/ must be an .mjs module — a stray .py/.d.ts/.map
# under src/ means the `files` allowlist widened by accident. Pull the src/ path
# tokens out of the listing and assert each ends in .mjs.
# `grep` exits 1 when there is simply nothing to report (no non-.mjs file — the
# healthy case), which must not abort the job; but exit >=2 is a real grep
# failure that `|| true` would silently swallow (masking a broken scan as "all
# clean"). Branch on the code: tolerate <=1, propagate anything higher.
src_nonmjs=""
rc=0
src_nonmjs="$(grep -oE 'src/[^[:space:]]+' <<<"$pack_listing" | grep -vE '\.mjs$')" || rc=$?
if [ "$rc" -gt 1 ]; then
  echo "ERROR: pack-listing scan failed (grep exit $rc)" >&2
  exit "$rc"
fi
if [ -n "$src_nonmjs" ]; then
  echo "ERROR: tarball ships a non-.mjs file under src/:" >&2
  echo "$src_nonmjs" >&2
  exit 1
fi

# 2. Build the real tarball.
echo "::group::npm pack"
tarball="$(npm pack 2>/dev/null | tail -n 1)"
echo "Built $tarball"
echo "::endgroup::"
tarball_abs="$REPO_ROOT/$tarball"
trap 'rm -f "$tarball_abs"' EXIT

# 3. Install into a fresh temp dir that is NOT a git repo. A consumer install is
#    never inside this project's working tree, so the install lifecycle script
#    must not assume one.
workdir="$(mktemp -d)"
trap 'rm -f "$tarball_abs"; rm -rf "$workdir"' EXIT
cd "$workdir"
echo '{"name":"smoke-consumer","version":"1.0.0","private":true}' >package.json

echo "::group::npm install (lifecycle scripts ENABLED)"
# No --ignore-scripts: a postinstall/prepare that crashes outside a git repo
# must fail here.
npm install "$tarball_abs"
echo "::endgroup::"

# 4. Import the root and every documented subpath through Node's package
#    resolver, so a dropped file or a broken `exports` map is caught.
echo "::group::import every documented entry point"
node --input-type=module -e '
import "agent-sanitizer";
import "agent-sanitizer/invisible";
import "agent-sanitizer/html";
import "agent-sanitizer/confusables";
import "agent-sanitizer/instructions";
import "agent-sanitizer/prompt";
import "agent-sanitizer/output";
import "agent-sanitizer/view-map";
import "agent-sanitizer/rehydrate";
console.log("all entry points imported");
'
echo "::endgroup::"

# 5. Invoke the installed bin over its JSON stdin/stdout protocol.
echo "::group::invoke sanitize-cli bin"
bin_path="$workdir/node_modules/.bin/sanitize-cli"
[ -x "$bin_path" ] || {
  echo "ERROR: installed bin not found or not executable at $bin_path" >&2
  exit 1
}
out="$(printf '%s' '{"text":"x"}' | node "$bin_path")"
echo "CLI output: $out"
grep -q '"cleaned"' <<<"$out" || {
  echo "ERROR: sanitize-cli did not return a cleaned field" >&2
  exit 1
}
echo "::endgroup::"

echo "pack-smoke: OK"
