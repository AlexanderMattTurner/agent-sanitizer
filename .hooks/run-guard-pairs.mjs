#!/usr/bin/env node
/**
 * Guard-test pairing: run the cheap check(s) that cover each staged source and
 * exit non-zero if any fails — so "edited the data, forgot its guard test" is
 * caught at commit time instead of as a red main. Invoked by .hooks/pre-commit
 * with the staged paths as argv.
 *
 * The pairs are DERIVED, not listed. `.hooks/lib/guarded-data-scan.mjs` parses
 * every suite in the repo and reports which files each one reads — by import,
 * by resolved path, by `git ls-files` glob, and (through its Python half) by
 * `REPO_ROOT / "…"`. The hook used to read a hand-written cache of that scan
 * instead, and the cache is what went stale: two branches that were each green
 * on their own base went red together on main because a new file's pair could
 * not exist until both had landed. A derived map cannot have that gap.
 *
 * `.hooks/guard-pairs.json` still exists, holding only what the scan cannot
 * reach (a generator's input data, whose chain to a test runs through generated
 * code) and the guard tests too slow to run at commit time. Both lists are
 * checked by test/guard-pairs.test.mjs, so an excuse cannot outlive its reason.
 *
 * A pair is a GUARD, not an SSOT: it says "run this check when that file
 * changes". It derives no content, so naming it otherwise would launder the
 * very smell a drift guard exists to expose.
 *
 * A guard test is either a `node --test` file (`*.test.mjs`) or a pytest module
 * (`test_*.py`), dispatched by extension. Both are supported because the map
 * guards data of any language, and this repo's data is not all read from JS.
 */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const { pairs, tooSlowForCommit } = JSON.parse(
  readFileSync(join(repoRoot, ".hooks", "guard-pairs.json"), "utf8"),
);

// acorn is what parses the suites. It is a devDependency of this repo and the
// scan is useless without it, so a missing one FAILS the commit with something
// an operator can act on — never a silent pass, and never a bare ESM stack.
const scan = await import("./lib/guarded-data-scan.mjs").catch((error) => {
  if (error?.code !== "ERR_MODULE_NOT_FOUND") throw error;
  console.error(
    `pre-commit: cannot derive the guard-pair map — ${error.message}\n` +
      `Run 'pnpm install' to provision it, then retry the commit. Refusing to ` +
      `pass a commit whose guard tests were never selected.`,
  );
  process.exit(1);
});

const staged = new Set(process.argv.slice(2));
const isGuardTest = (path) =>
  path.endsWith(".test.mjs") || /(?:^|\/)test_[^/]+\.py$/.test(path);

// A staged DELETION is still a staged path, and the scan sees the working
// tree — so a deleted file is absent from the walk, resolves to no suites, and
// the commit that removes it runs nothing. That is the silent no-op this
// mechanism exists to close, and the hand-written map it replaces did not have
// it: keying on the path alone, a deletion scheduled its guard. Seeding the
// staged set back into the scan restores that, because the suites still NAME
// the path — only the tracked-file filter was dropping it.
scan.includePaths(staged);

// The derivation runs once per commit regardless of how many files are staged
// (~1.3s), which is cheaper than the per-source model it replaces as soon as a
// commit touches more than one guarded file.
let derived;
try {
  derived = scan.scanGuardedData();
} catch (error) {
  if (error?.code !== scan.MISSING_TOOL) throw error;
  console.error(
    `pre-commit: cannot derive the guard-pair map — ${error.message}\n` +
      `Refusing to pass a commit whose guard tests were never selected.`,
  );
  process.exit(1);
}

const testsToRun = new Set();
// A staged suite is its own guard: nothing else covers an edit to it, and it is
// by definition the cheap check for that file. A DELETED suite is skipped —
// `node --test` on a file that no longer exists would fail the very commit that
// removes it.
for (const path of staged)
  if (isGuardTest(path) && existsSync(join(repoRoot, path)))
    testsToRun.add(path);

for (const path of staged) {
  for (const test of derived.get(path) ?? []) testsToRun.add(test);
  for (const test of pairs[path] ?? []) {
    // A curated pair naming a test that is not there cannot guard anything, and
    // `node --test` on it would fail with a path error that blames the wrong
    // thing. Say what is actually wrong. (The derived side cannot hit this: it
    // only ever names suites the scan just parsed.)
    if (!existsSync(join(repoRoot, test))) {
      console.error(
        `pre-commit: .hooks/guard-pairs.json pairs ${path} with ${test}, which does ` +
          `not exist — repair the pair (or drop it) in this commit.`,
      );
      process.exit(1);
    }
    testsToRun.add(test);
  }
}

// Excluded LAST, so a test cannot sneak in through a second source that reaches
// it. Each exclusion is a cost decision with a reason, checked by
// test/guard-pairs.test.mjs against the scan.
const skipped = [...testsToRun].filter((test) => test in tooSlowForCommit);
for (const test of skipped) testsToRun.delete(test);
if (skipped.length > 0)
  console.error(
    `pre-commit: not running ${skipped.join(", ")} at commit time — too slow ` +
      `for the hook's budget (see tooSlowForCommit in .hooks/guard-pairs.json). CI runs it.`,
  );

if (testsToRun.size === 0) process.exit(0);

const files = [...testsToRun].sort();
console.error(
  `pre-commit: staged guarded source(s) — running paired guard test(s): ${files.join(", ")}`,
);

// One runner invocation per language, each over all of its files, so a commit
// touching both a JS-guarded and a Python-guarded source pays two process starts
// rather than one per test.
const RUNNERS = [
  {
    match: (file) => file.endsWith(".test.mjs"),
    command: "node",
    leading: ["--test"],
    install: "install Node",
  },
  {
    match: (file) => file.endsWith(".py"),
    command: "pytest",
    leading: ["-q"],
    install:
      "provision the Python dev env (`uv sync --extra dev`, or activate .venv)",
  },
];

// The runners must PARTITION the guard tests. A path matching none of them
// would otherwise fall through the loop below and the hook would exit 0 having
// run nothing — a silent no-op for exactly the source the pair was added to
// protect. test/guard-pairs.test.mjs pins the value domain, but it only runs in
// CI and when the map or the scan is staged, so the hook checks here too.
const unclaimed = files.filter(
  (file) => !RUNNERS.some((runner) => runner.match(file)),
);
if (unclaimed.length > 0) {
  console.error(
    `pre-commit: no runner knows how to execute ${unclaimed.join(", ")} — a guard ` +
      `test must be a node --test file (*.test.mjs) or a pytest module ` +
      `(test_*.py). Refusing to pass a commit whose guard never ran.`,
  );
  process.exit(1);
}

// Git's repository-location overrides, which a git hook exports into every
// child it starts. With GIT_DIR set, a `cwd:` no longer decides which repository
// git answers for — so a guard suite that builds a throwaway repo in a tmpdir and
// commits into it writes those commits onto the DEVELOPER'S branch instead, and
// one that checks out a fixture ref rewinds the working tree mid-commit. Both
// happened. Stripping them here fixes every suite at once, rather than each
// module remembering.
const GIT_LOCATION_VARS = [
  "GIT_DIR",
  "GIT_WORK_TREE",
  "GIT_COMMON_DIR",
  "GIT_INDEX_FILE",
  "GIT_OBJECT_DIRECTORY",
  "GIT_PREFIX",
];
const runnerEnv = Object.fromEntries(
  Object.entries(process.env).filter(
    ([key]) => !GIT_LOCATION_VARS.includes(key),
  ),
);

for (const runner of RUNNERS) {
  const forRunner = files.filter(runner.match);
  if (forRunner.length === 0) continue;
  const result = spawnSync(runner.command, [...runner.leading, ...forRunner], {
    cwd: repoRoot,
    env: runnerEnv,
    stdio: ["ignore", "inherit", "inherit"],
  });
  // A missing runner is NOT a pass: the guard did not run, so the commit it was
  // meant to gate must not go through unchecked.
  if (result.error?.code === "ENOENT") {
    console.error(
      `pre-commit: cannot run the paired guard test(s) ${forRunner.join(", ")} — ` +
        `\`${runner.command}\` is not on PATH. ${runner.install}, then retry the commit.`,
    );
    process.exit(1);
  }
  if (result.error) throw result.error;
  if (result.status !== 0) {
    console.error(
      "pre-commit: a paired guard test failed — update the guard test in the SAME commit as its data (see CLAUDE.md, Testing).",
    );
    process.exit(result.status ?? 1);
  }
}
