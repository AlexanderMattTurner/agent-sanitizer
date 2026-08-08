/**
 * The credential ladder carries subscription OAuth tokens ONLY.
 *
 * A metered `ANTHROPIC_API_KEY` rung used to sit at the bottom of
 * `anthropic-ladder.bash`, and `security-vulnerability-scan.yaml` handed the
 * same key straight to `claude-code-action`. Both were removed so that no CI
 * path can fall through from an exhausted subscription token to spending real
 * credits — the failure mode is meant to be a degraded changelog, not a bill.
 *
 * Every negative assertion here is paired with a positive marker proving the
 * assertion is reading the live artifact (CLAUDE.md: "don't let guard tests pass
 * vacuously"). Asserting only "the string ANTHROPIC_API_KEY is absent" would
 * keep passing if this test were pointed at the wrong file, if the ladder were
 * renamed, or if the workflow glob matched nothing at all.
 */
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const REPO_ROOT = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
  cwd: dirname(fileURLToPath(import.meta.url)),
}).trim();

const LIB = join(REPO_ROOT, ".github", "scripts", "lib");

/** Print a bash array's elements, one per line, after sourcing the ladder libs.
 * Reading the arrays back out of bash rather than re-parsing the source is what
 * makes this a test of the ladder the scripts actually walk.
 * @param {string} arrayName @returns {string[]} */
const ladderVars = (arrayName) =>
  execFileSync(
    "bash",
    [
      "-c",
      `set -euo pipefail
       source "$1/claude-oauth-ladder.bash"
       source "$1/anthropic-ladder.bash"
       printf '%s\\n' "\${${arrayName}[@]}"`,
      "_",
      LIB,
    ],
    { encoding: "utf8" },
  )
    .split("\n")
    .filter(Boolean);

test("the direct-API ladder is exactly the OAuth ladder — no metered rung", () => {
  const oauth = ladderVars("CLAUDE_OAUTH_LADDER_VARS");
  const anthropic = ladderVars("_ANTHROPIC_LADDER_VARS");

  // Positive markers: we really read a populated ladder of OAuth secrets, so
  // the absence check below cannot pass by matching nothing.
  assert.ok(oauth.length > 0, "the OAuth ladder must not be empty");
  assert.ok(
    oauth.every((v) => v.startsWith("CLAUDE_CODE_OAUTH_TOKEN")),
    `every OAuth rung should be a CLAUDE_CODE_OAUTH_TOKEN* secret, got ${oauth.join(", ")}`,
  );

  // The derivation itself: the direct-API caller appends nothing.
  assert.deepEqual(
    anthropic,
    oauth,
    "the direct-API ladder must be the OAuth ladder verbatim — a rung appended here is a credential nobody else walks",
  );
  assert.ok(
    !anthropic.includes("ANTHROPIC_API_KEY"),
    "ANTHROPIC_API_KEY must not be a ladder rung: an exhausted subscription token must degrade, not bill",
  );
});

/** Run `anthropic_auth_headers CRED` and report how it exited. spawnSync, not
 * execFileSync: a refused credential returns non-zero BY DESIGN here, and
 * execFileSync would throw that away as a spawn error. The `|| exit 1` is what
 * surfaces the refusal as the subprocess's status — without it the trailing
 * printfs would mask it.
 * @param {string} cred */
const authHeaders = (cred) =>
  spawnSync(
    "bash",
    [
      "-c",
      `source "$1/anthropic-ladder.bash"
       anthropic_auth_headers "$2" || exit 1
       printf 'MODE=%s\\n' "$AUTH_MODE"
       printf '%s\\n' "\${AUTH_HEADERS[@]}"`,
      "_",
      LIB,
      cred,
    ],
    { encoding: "utf8" },
  );

test("only subscription OAuth tokens authenticate; an API-key shape is refused", () => {
  // Positive marker: the accepted shape really does produce Bearer + oauth beta
  // headers, so the rejection below is about the SHAPE, not a broken function.
  const good = authHeaders("sk-ant-oat-example");
  assert.equal(good.status, 0, good.stderr);
  assert.match(good.stdout, /MODE=Bearer \+ oauth beta/);
  assert.match(good.stdout, /authorization: Bearer sk-ant-oat-example/);
  assert.match(good.stdout, /anthropic-beta: oauth-2025-04-20/);
  assert.ok(
    !/x-api-key/.test(good.stdout),
    "an OAuth token must never be sent as x-api-key",
  );

  // An Anthropic API key is the exact shape that used to authenticate here.
  const keyed = authHeaders("sk-ant-api-example");
  assert.equal(
    keyed.status,
    1,
    "a metered sk-ant-api… key must be refused, not silently sent as x-api-key",
  );
  assert.equal(keyed.stdout, "", "a refused credential must emit no headers");
});

test("a wrong-shaped rung is stepped over, not fatal to the whole walk", () => {
  // The misconfiguration this PR exists to prevent is an operator pasting a
  // metered key into CLAUDE_CODE_OAUTH_TOKEN while a later rung holds a good
  // subscription token. Refusing the bad shape must not strand the good one —
  // the ladder's contract is that walking it changes WHO answers, not WHETHER.
  const res = spawnSync(
    "bash",
    [
      "-c",
      `set -uo pipefail
       source "$1/claude-oauth-ladder.bash"
       source "$1/anthropic-ladder.bash"
       for cred in sk-ant-api-bad sk-ant-oat-good; do
         if anthropic_auth_headers "$cred"; then
           printf 'USED=%s\\n' "$cred"
         else
           printf 'SKIPPED=%s\\n' "$cred"
         fi
       done`,
      "_",
      LIB,
    ],
    { encoding: "utf8" },
  );
  assert.equal(res.status, 0, res.stderr);
  // Positive marker: the good rung really was reached and used. Asserting only
  // "did not exit" would pass if the loop never ran at all.
  assert.match(res.stdout, /SKIPPED=sk-ant-api-bad/);
  assert.match(res.stdout, /USED=sk-ant-oat-good/);
});

test("no workflow or composite action hands Claude an API key", () => {
  const roots = [
    join(REPO_ROOT, ".github", "workflows"),
    join(REPO_ROOT, ".github", "actions"),
  ];
  /** @type {{path: string, body: string}[]} */
  const files = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (/\.ya?ml$/.test(entry.name))
        files.push({ path, body: readFileSync(path, "utf8") });
    }
  };
  for (const root of roots) walk(root);

  // Positive markers: the walk found real workflow YAML that really does wire
  // up Claude credentials. Without these, a glob that matched nothing — a
  // renamed directory, a walk that silently skipped subdirectories — would
  // report "no API key anywhere" and be believed.
  assert.ok(files.length > 0, "found no workflow/action YAML to scan");
  assert.ok(
    files.some((f) => f.body.includes("CLAUDE_CODE_OAUTH_TOKEN")),
    "no scanned file references CLAUDE_CODE_OAUTH_TOKEN — the scan is not reading the Claude workflows",
  );

  const offenders = files
    .filter((f) => /ANTHROPIC_API_KEY|anthropic_api_key/.test(f.body))
    .map((f) => f.path.slice(REPO_ROOT.length + 1));
  assert.deepEqual(
    offenders,
    [],
    `these workflows still provide a metered Anthropic API key: ${offenders.join(", ")}`,
  );
});
