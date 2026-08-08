// Behavioral tests for the tarball file-set gate: the real script runs against
// a staged `npm pack --dry-run` listing and every assertion reads an observable
// — its exit status and the stderr a human would read in the step log.
//
// Regression: the src/ scan matched an unanchored `src/`, so the declaration
// the hooks build emits for the relatively-imported context module,
// `types/src/claude-context.d.mts`, was reported as a non-.mjs file shipped
// under src/ and reddened pack-smoke on every PR.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = join(
  dirname(fileURLToPath(import.meta.url)),
  "check-pack-listing.sh",
);

/** Run the gate over a listing (an array of lines). */
function gate(lines) {
  const res = spawnSync("bash", [SCRIPT], {
    encoding: "utf8",
    input: lines.join("\n") + "\n",
  });
  return { status: res.status, stderr: res.stderr };
}

// The healthy shape of a real listing: npm's `notice <size> <path>` lines,
// including the nested `types/src/...` declaration that is legitimately shipped.
const HEALTHY = [
  "npm notice === Tarball Contents ===",
  "npm notice 4.4kB bin/sanitize-cli.mjs",
  "npm notice 12.1kB src/index.mjs",
  "npm notice 3.9kB src/warnings.mjs",
  "npm notice 5.1kB types/claude-context.d.mts",
  "npm notice 5.1kB types/src/claude-context.d.mts",
  "npm notice 18.7kB types/claude-hooks/sanitize-output.d.mts",
  "npm notice total files: 87",
];

test("a healthy listing passes, nested types/src declarations and all", () => {
  const res = gate(HEALTHY);
  assert.equal(res.status, 0, res.stderr);
  assert.equal(res.stderr, "");
});

// Non-vacuity for the case above: the very same listing plus one genuinely
// misplaced src/ file must fail, so the pass is the anchor working rather than
// the scan having quietly stopped looking.
test("a non-.mjs file actually under src/ fails", () => {
  const res = gate([...HEALTHY, "npm notice 900B src/leaked.d.mts"]);
  assert.equal(res.status, 1);
  assert.match(res.stderr, /non-\.mjs file under src\//);
  assert.match(res.stderr, /src\/leaked\.d\.mts/);
  // The legitimately-nested declaration is not among the reported offenders.
  assert.doesNotMatch(res.stderr, /types\/src/);
});

test("a src/ path at the start of a line is still caught", () => {
  const res = gate(["src/oops.py"]);
  assert.equal(res.status, 1);
  assert.match(res.stderr, /src\/oops\.py/);
});

test("python egg-info build artifacts fail", () => {
  const res = gate([
    ...HEALTHY,
    "npm notice 1.2kB agent_sanitizer.egg-info/PKG-INFO",
  ]);
  assert.equal(res.status, 1);
  assert.match(res.stderr, /egg-info/);
});

test("the plugin tree fails", () => {
  const res = gate([...HEALTHY, "npm notice 1.8MB plugin/dist/bundle.mjs"]);
  assert.equal(res.status, 1);
  assert.match(res.stderr, /plugin tree/);
});

test("a listing with no src/ paths at all passes", () => {
  const res = gate([
    "npm notice === Tarball Contents ===",
    "npm notice 1kB README.md",
  ]);
  assert.equal(res.status, 0, res.stderr);
});
