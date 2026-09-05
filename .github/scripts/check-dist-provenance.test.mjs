// check-dist-provenance.sh against real git history — the script reads a diff
// range, so a scratch repo with real commits is the subject, not a stub.
//
// Two properties: a dist artifact may not move without one of its build inputs
// moving, and the hook-binary digest manifest may not move on a PR branch at all
// (it has one writer, on the default branch — see auto-version.yaml).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = join(
  dirname(fileURLToPath(import.meta.url)),
  "check-dist-provenance.sh",
);
const MANIFEST = "plugin/dist/hooks/hook-binaries.sha256";
const BUNDLE = "plugin/dist/hooks/plugin-hooks.bundle.mjs";

const scratched = [];
process.on("exit", () => {
  for (const dir of scratched) rmSync(dir, { recursive: true, force: true });
});

const git = (cwd, ...args) => {
  const run = spawnSync("git", args, { cwd, encoding: "utf8" });
  assert.equal(run.status, 0, `git ${args.join(" ")}: ${run.stderr}`);
  return run.stdout.trim();
};

const write = (repo, path, contents) => {
  mkdirSync(join(repo, dirname(path)), { recursive: true });
  writeFileSync(join(repo, path), contents);
};

/**
 * A repo whose `base` carries the artifacts, plus a branch committing `changes`
 * on top of it.
 * @param {Record<string, string>} changes path → new contents
 * @returns {import("node:child_process").SpawnSyncReturns<string>}
 */
const checkBranchWith = (changes) => {
  const repo = mkdtempSync(join(tmpdir(), "dist-provenance-"));
  scratched.push(repo);
  git(repo, "init", "--initial-branch=base", ".");
  git(repo, "config", "user.name", "seed");
  git(repo, "config", "user.email", "seed@example.invalid");
  for (const path of [MANIFEST, BUNDLE, "src/output.mjs"])
    write(repo, path, "base\n");
  git(repo, "add", "-A");
  git(repo, "commit", "-m", "seed");

  git(repo, "checkout", "-b", "pr");
  for (const [path, contents] of Object.entries(changes))
    write(repo, path, contents);
  git(repo, "add", "-A");
  git(repo, "commit", "-m", "pr");

  return spawnSync("bash", [SCRIPT, "base"], { cwd: repo, encoding: "utf8" });
};

test("accepts a dist change that rides a build-input change", () => {
  const run = checkBranchWith({
    [BUNDLE]: "rebuilt\n",
    "src/output.mjs": "edited\n",
  });
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /alongside a build input/);
});

test("rejects a dist change with no build-input change", () => {
  const run = checkBranchWith({ [BUNDLE]: "hand-edited\n" });
  assert.equal(run.status, 1);
  assert.match(run.stderr, /no build input did/);
});

// The manifest is the case a build-input change would otherwise wave through:
// its bundle and bun headers can be preserved while the digests are arbitrary,
// and nothing downstream re-derives it until the release is already published.
test("rejects a manifest change even beside a build-input change", () => {
  const run = checkBranchWith({
    [MANIFEST]: "regenerated on a PR branch\n",
    [BUNDLE]: "rebuilt\n",
    "src/output.mjs": "edited\n",
  });
  assert.equal(run.status, 1);
  assert.match(run.stderr, new RegExp(`${MANIFEST} changed on a PR branch`));
  assert.match(run.stderr, /refreshed only on the default branch/);
});

test("accepts a branch that touches no dist artifact at all", () => {
  const run = checkBranchWith({ "src/output.mjs": "edited\n" });
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /plugin\/dist unchanged/);
});
