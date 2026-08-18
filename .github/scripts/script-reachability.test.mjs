// Reachability guard: every file under .github/scripts must be reachable from
// something that actually runs it.
//
// Regression: install-input-sanitizer.sh pinned agent-input-sanitizer@1.38.0 —
// the PRE-RENAME package — while the live install-sanitizer.sh pinned
// agent-sanitizer@2.0.0. Nothing referenced the orphan, so grepping for the
// version pin found TWO files and editing the wrong one landed nowhere. The
// same sweep turned up a superseded flat auto-resolve entrypoint set (whose
// four test suites were the only thing CI still ran there), a Prettier autofix
// script the workflow had inlined and hardened past, a reviewer-body-hold
// detector with no consumer, and a markdownlint rule for a markdownlint runner
// this repo does not have. An unreferenced script is not inert: it is a live
// grep hit that reads as the real thing.
//
// The roots are the things that can start execution — workflows, composite
// actions, and .pre-commit-config.yaml — and reachability is the transitive
// closure over references from there. A test suite joins the closure once it
// references something already reachable, which is what keeps a test-only
// helper (auto-resolve/fixtures.mjs) live while denying an orphan the ability
// to certify itself by having a test. A structural guard like this one joins the
// closure through the live paths its own assertions name, so don't replace those
// literals with computed paths — the names are load-bearing twice over.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const REPO_ROOT = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();

/** Tracked paths matching `patterns`, relative to the repo root. */
function tracked(...patterns) {
  return execFileSync("git", ["ls-files", "--", ...patterns], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  })
    .split("\n")
    .filter(Boolean);
}

// Consumed by the node runtime itself (it is the package-scope marker that
// makes .mjs/.cjs resolution behave under .github/scripts), so no file names
// it and none should have to.
const IMPLICIT = new Set([".github/scripts/package.json"]);

const SCRIPTS = tracked(".github/scripts").filter((p) => !IMPLICIT.has(p));
const SUITES = SCRIPTS.filter((p) => p.endsWith(".test.mjs"));
const ROOTS = [
  ...tracked(".github/workflows"),
  ...tracked(".github/actions"),
  ".pre-commit-config.yaml",
];

/**
 * Whether `text` names `script`. Basename match covers every invocation form
 * (`bash .github/scripts/x.sh`, `source "$dir/lib/x.bash"`, `import "./x.mjs"`).
 * Python imports drop the extension, so the bare stem counts too — but only as
 * a whole word, and only for .py, so `lib.sh` is not "referenced" by the word
 * `lib` in prose.
 */
function references(text, script) {
  const base = script.slice(script.lastIndexOf("/") + 1);
  if (text.includes(base)) return true;
  if (!base.endsWith(".py")) return false;
  const stem = base.slice(0, -3);
  return new RegExp(`\\b(?:import|from)\\s+${stem}\\b`).test(text);
}

/** The transitive closure of scripts reachable from ROOTS. */
function reachable() {
  const text = new Map(
    [...ROOTS, ...SCRIPTS].map((path) => [
      path,
      readFileSync(join(REPO_ROOT, path), "utf8"),
    ]),
  );
  const live = new Set(ROOTS);
  for (;;) {
    const before = live.size;
    for (const script of SCRIPTS) {
      if (live.has(script)) continue;
      const isLive = SUITES.includes(script)
        ? // A suite earns its place by testing something that runs.
          [...live].some((path) => references(text.get(script), path))
        : [...live].some((path) => references(text.get(path), script));
      if (isLive) live.add(script);
    }
    if (live.size === before) return live;
  }
}

test("every .github/scripts file is reachable from a workflow, action or hook", () => {
  const live = reachable();
  // Suites are held to the same bar: one that references nothing reachable is
  // testing dead code, which is how four suites for a superseded auto-resolve
  // entrypoint set stayed the only .github/scripts tests CI ran.
  const orphans = SCRIPTS.filter((path) => !live.has(path));
  assert.deepEqual(orphans, []);
});

test("the reachability sweep is non-empty and reaches known-live scripts", () => {
  const live = reachable();
  assert.ok(SCRIPTS.length > 50, `only ${SCRIPTS.length} scripts enumerated`);
  assert.ok(ROOTS.length > 20, `only ${ROOTS.length} roots enumerated`);
  assert.ok(SUITES.length > 10, `only ${SUITES.length} suites enumerated`);

  // One per hop the closure has to make: named straight from a workflow;
  // sourced by another script; python-imported without its extension by a
  // script named straight from .pre-commit-config.yaml; and a suite that is
  // itself only reachable through what it tests.
  for (const path of [
    ".github/scripts/claude-run-errored.sh",
    ".github/scripts/lib/claude-oauth-ladder.bash",
    ".github/scripts/_linecheck.py",
    ".github/scripts/resolve-generated.test.mjs",
  ]) {
    assert.ok(SCRIPTS.includes(path), `${path} vanished — update this test`);
    assert.ok(live.has(path), `${path} should be reachable`);
  }
});

test("an unreferenced script is NOT reachable", () => {
  // Non-vacuity for the guard itself: the closure must be able to say no. A
  // name no file mentions stands in for the orphan this test exists to catch.
  const live = reachable();
  const phantom = ".github/scripts/no-such-orphan-xyzzy.sh";
  assert.ok(!SCRIPTS.includes(phantom), "fixture name is in use — rename it");
  assert.ok(!live.has(phantom));

  // And the reference test must be able to say yes for the same shapes the
  // closure relies on, so a `references` that always returned false could not
  // pass the assertions above by coincidence.
  assert.ok(references("bash .github/scripts/x.sh", ".github/scripts/x.sh"));
  assert.ok(references('source "$d/lib/x.bash"', ".github/scripts/lib/x.bash"));
  assert.ok(
    references("from _ci_retry import x", ".github/scripts/_ci_retry.py"),
  );
  assert.ok(!references("the lib holds x", ".github/scripts/lib.sh"));
});
