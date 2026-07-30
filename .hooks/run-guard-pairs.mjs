#!/usr/bin/env node
/**
 * SSOT guard-test pairing: run the cheap contract test(s) paired with each
 * staged SSOT source (pairs live in .hooks/guard-pairs.json) and exit
 * non-zero if any fails — so "edited the data, forgot its guard test" is
 * caught at commit time instead of as a red main. Invoked by .hooks/pre-commit
 * with the staged paths as argv; only tests whose paired source is staged run,
 * keeping the added latency to ~1s per touched SSOT.
 */
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const { pairs } = JSON.parse(
  readFileSync(join(repoRoot, ".hooks", "guard-pairs.json"), "utf8"),
);

const staged = new Set(process.argv.slice(2));
const testsToRun = new Set();
for (const [source, tests] of Object.entries(pairs)) {
  if (!staged.has(source)) continue;
  for (const t of tests) testsToRun.add(t);
}

if (testsToRun.size === 0) process.exit(0);

const files = [...testsToRun].sort();
console.error(
  `pre-commit: staged SSOT source(s) — running paired guard test(s): ${files.join(", ")}`,
);
const result = spawnSync("node", ["--test", ...files], {
  cwd: repoRoot,
  stdio: ["ignore", "inherit", "inherit"],
});
if (result.error) throw result.error;
if (result.status !== 0) {
  console.error(
    "pre-commit: a paired SSOT guard test failed — update the guard test in the SAME commit as its data (see CLAUDE.md, Testing).",
  );
  process.exit(result.status ?? 1);
}
