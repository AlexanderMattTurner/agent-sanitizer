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

# 1. Assert the published file set before building for real: no Python build
#    artifacts, no non-.mjs source under src/, no plugin tree. `npm pack
#    --dry-run` lists the files without writing the tarball; the assertions live
#    in check-pack-listing.sh, which reads that listing on stdin and is
#    unit-tested against fixtures (a wrong pattern there is a false RED on every
#    PR, or a silent green while the `files` allowlist ships something it should
#    not).
echo "::group::npm pack --dry-run file listing"
pack_listing="$(npm pack --dry-run 2>&1)"
echo "$pack_listing"
echo "::endgroup::"

bash "$REPO_ROOT/.github/scripts/check-pack-listing.sh" <<<"$pack_listing"

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

# 6. Drive the published hook entry the way a consumer's settings.json does:
#    `node <resolved path> --hook=<mode>` from a cwd that is not this project,
#    with no node_modules of its own beside the hooks. The in-repo suite spawns
#    the BUNDLE; only this leg proves the un-bundled sources resolve their own
#    imports (the engine self-reference, agent-control-plane-core,
#    namespace-guard) and their JSON configs out of the installed tree.
echo "::group::drive the published claude-hooks entry"
hook_entry="$(node --input-type=module -e '
  import { createRequire } from "node:module";
  const require = createRequire(process.cwd() + "/");
  process.stdout.write(
    require.resolve("agent-sanitizer/claude-hooks"),
  );
')"
echo "resolved entry: $hook_entry"

# A bare import must be inert: a consumer who imports the module (rather than
# spawning it) must not get a process that consumes stdin and exits.
node --input-type=module -e '
  const m = await import("agent-sanitizer/claude-hooks");
  if (typeof m.main !== "function") throw new Error("no main export");
  process.stdout.write("import is a no-op\n");
'

# Each wired mode reaches its verdict. Run from / so nothing resolves relatively.
# The posture is pinned rather than inherited: a runner that exported the knob
# either way would be asserting something other than what this file states.
unset AGENT_SANITIZER_FAIL_OPEN
cd /
prompt_payload='{"hook_event_name":"UserPromptSubmit","prompt":"plain text"}'
printf '%s' "$prompt_payload" | node "$hook_entry" --hook=sanitize-user-prompt >/dev/null

pre_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"}}'
printf '%s' "$pre_payload" | node "$hook_entry" --hook=pretooluse-sanitize >/dev/null

scan_payload='{"hook_event_name":"SessionStart","source":"startup"}'
printf '%s' "$scan_payload" | node "$hook_entry" --hook=scan-invisible-chars >/dev/null

# Layer 4 with the redactor unreachable, under the fail-closed opt-out, must
# SUPPRESS the secret rather than pass it through: that posture is what a
# deployment gets by setting AGENT_SANITIZER_FAIL_OPEN=0, so a published package
# whose opt-out stopped working would be shipping a knob that does nothing.
secret_payload='{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{},"tool_response":{"stdout":"key=AKIAIOSFODNN7EXAMPLE"}}'
closed_out="$(printf '%s' "$secret_payload" |
  AGENT_SANITIZER_FAIL_OPEN=0 \
    _AGENT_SANITIZER_REDACTOR_SOCKET=/nonexistent/redactor.sock \
    _AGENT_SANITIZER_REDACTOR_DAEMON=/nonexistent/agent-secret-redactor-daemon \
    _AGENT_SANITIZER_REDACTOR_WAIT_MS=300 \
    _AGENT_SANITIZER_REDACTOR_REQUEST_MS=300 \
    _AGENT_SANITIZER_SANITIZE_BUDGET_MS=3000 \
    node "$hook_entry" --hook=sanitize-output)"
grep -q 'SANITIZATION FAILED' <<<"$closed_out" || {
  echo "ERROR: unreachable redactor did not fail closed: $closed_out" >&2
  exit 1
}
grep -q 'AKIAIOSFODNN7EXAMPLE' <<<"$closed_out" && {
  echo "ERROR: the secret survived into the model's view: $closed_out" >&2
  exit 1
}

# An unknown mode is a wiring typo in someone's settings.json; it must fail loud
# with the blocking exit code rather than silently doing nothing.
unknown_rc=0
printf '{}' | node "$hook_entry" --hook=no-such-hook >/dev/null 2>&1 || unknown_rc=$?
[ "$unknown_rc" -eq 2 ] || {
  echo "ERROR: unknown --hook exited $unknown_rc, expected 2" >&2
  exit 1
}
cd "$workdir"
echo "::endgroup::"

echo "pack-smoke: OK"
