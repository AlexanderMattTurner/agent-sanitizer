#!/usr/bin/env node
/**
 * SSOT guard-test pairing: run the cheap contract test(s) paired with each
 * staged SSOT source (pairs live in .hooks/guard-pairs.json) and exit
 * non-zero if any fails — so "edited the data, forgot its guard test" is
 * caught at commit time instead of as a red main. Invoked by .hooks/pre-commit
 * with the staged paths as argv; only tests whose paired source is staged run,
 * keeping the added latency to ~1s per touched SSOT.
 *
 * A guard test is either a `node --test` file (`*.test.mjs`) or a pytest module
 * (`test_*.py`), dispatched by extension. Both are supported because the map
 * guards DATA, and this repo's data is not all read from JS: JSON that only a
 * Python contract test mirrors was unpairable while the map's value domain was
 * `.test.mjs`, so the one guard it had ran in full CI and never at commit time —
 * the exact gap the map exists to close.
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

// One runner invocation per language, each over all of its files, so a commit
// touching both a JS-guarded and a Python-guarded SSOT pays two process starts
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

for (const runner of RUNNERS) {
  const forRunner = files.filter(runner.match);
  if (forRunner.length === 0) continue;
  const result = spawnSync(runner.command, [...runner.leading, ...forRunner], {
    cwd: repoRoot,
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
      "pre-commit: a paired SSOT guard test failed — update the guard test in the SAME commit as its data (see CLAUDE.md, Testing).",
    );
    process.exit(result.status ?? 1);
  }
}
