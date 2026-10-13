// The plugin-dist bake's git half, driven for real: resolve-release-tag.sh and
// commit-plugin-dist.sh run against real repos and a real bare remote. Only the
// build is stood in for (a staged directory of fixture files), because the real
// one compiles four ~100 MB bun binaries and installs from PyPI.
//
// The branch is what every installed plugin reads, so each case pins a way it
// could end up wrong: rolled back, force-moved, missing a baked file, or
// carrying a tree that is not the tag's.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { parse as parseYaml } from "yaml";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..");
const COMMIT = join(HERE, "commit-plugin-dist.sh");
const RESOLVE = join(HERE, "resolve-release-tag.sh");
const BRANCH = "plugin-dist";
const BUNDLE = "plugin/dist/hooks/plugin-hooks.bundle.mjs";

/** Git state from an enclosing hook (GIT_DIR, GIT_INDEX_FILE) must not leak in. */
const ENV = Object.fromEntries(
  Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")),
);

const scratched = [];
process.on("exit", () => {
  for (const dir of scratched) rmSync(dir, { recursive: true, force: true });
});
const scratchDir = (prefix) => {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  scratched.push(dir);
  return dir;
};

const git = (cwd, ...args) => {
  const run = spawnSync("git", args, { cwd, encoding: "utf8", env: ENV });
  assert.equal(run.status, 0, `git ${args.join(" ")}: ${run.stderr}`);
  return run.stdout.trim();
};

const writeFile = (root, path, contents) => {
  mkdirSync(join(root, dirname(path)), { recursive: true });
  writeFileSync(join(root, path), contents);
};

const MARKETPLACE = JSON.stringify({
  name: "fixture",
  plugins: [
    {
      name: "fixture",
      source: {
        source: "git-subdir",
        url: "https://example.invalid/fixture.git",
        path: "plugin",
        ref: BRANCH,
      },
    },
  ],
});

/**
 * A checkout of a bare remote whose main carries a marketplace naming
 * plugin-dist, standing in for the publish job's checkout of the tag.
 */
const scratchRelease = (marketplace = MARKETPLACE) => {
  const remote = scratchDir("plugin-dist-remote-");
  git(remote, "init", "--bare", "--initial-branch=main", ".");
  const repo = scratchDir("plugin-dist-repo-");
  git(repo, "init", "--initial-branch=main", ".");
  git(repo, "config", "user.name", "seed");
  git(repo, "config", "user.email", "seed@example.invalid");
  writeFile(repo, ".claude-plugin/marketplace.json", marketplace);
  writeFile(repo, "plugin/.claude-plugin/plugin.json", '{"version":"0.0.0"}\n');
  writeFile(repo, "src/a.mjs", "export const a = 1;\n");
  git(repo, "add", "-A");
  git(repo, "commit", "-m", "feat: seed");
  git(repo, "remote", "add", "origin", remote);
  git(repo, "push", "origin", "main");
  return { repo, remote };
};

/** Land a source commit on main and tag it, as a release does. */
const release = (repo, tag, contents) => {
  writeFile(repo, "src/a.mjs", contents);
  git(repo, "add", "-A");
  git(repo, "commit", "-m", `feat: ${tag}`);
  git(repo, "tag", tag);
  git(repo, "push", "origin", "main", tag);
  return git(repo, "rev-parse", "HEAD");
};

/** A build's staged output for `tag`. */
const stage = (tag, bundle = `bundle for ${tag}\n`) => {
  const dir = scratchDir("plugin-dist-stage-");
  writeFile(dir, BUNDLE, bundle);
  writeFile(
    dir,
    "plugin/.claude-plugin/plugin.json",
    `{"version":"${tag.slice(1)}"}\n`,
  );
  return dir;
};

const bake = (repo, tag, stageDir) =>
  spawnSync("bash", [COMMIT, tag, stageDir], {
    cwd: repo,
    encoding: "utf8",
    env: ENV,
  });

const remoteTip = (remote) =>
  spawnSync("git", ["rev-parse", "--verify", "-q", `refs/heads/${BRANCH}`], {
    cwd: remote,
    encoding: "utf8",
    env: ENV,
  }).stdout.trim();

test("a missing branch is bootstrapped from the tag with the baked files laid over its tree", () => {
  const { repo, remote } = scratchRelease();
  const tagged = release(repo, "v1.0.0", "export const a = 2;\n");
  const run = bake(repo, "v1.0.0", stage("v1.0.0"));
  assert.equal(run.status, 0, run.stderr);
  const tip = remoteTip(remote);
  assert.equal(git(remote, "log", "-1", "--format=%P", tip), tagged);
  assert.equal(git(remote, "show", `${tip}:${BUNDLE}`), "bundle for v1.0.0");
  assert.equal(
    git(remote, "show", `${tip}:plugin/.claude-plugin/plugin.json`),
    '{"version":"1.0.0"}',
  );
  assert.equal(
    git(remote, "show", `${tip}:src/a.mjs`),
    "export const a = 2;",
    "the rest of the tree is the tag's",
  );
  assert.equal(
    git(remote, "log", "-1", "--format=%s", tip),
    "build(plugin-dist): bake v1.0.0",
  );
  assert.equal(
    git(repo, "status", "--porcelain"),
    "",
    "the checkout's own index and worktree are untouched",
  );
});

test("the next release fast-forwards the branch, parented on the old tip and the tag", () => {
  const { repo, remote } = scratchRelease();
  release(repo, "v1.0.0", "export const a = 2;\n");
  assert.equal(bake(repo, "v1.0.0", stage("v1.0.0")).status, 0);
  const first = remoteTip(remote);
  const tagged = release(repo, "v1.1.0", "export const a = 3;\n");
  const run = bake(repo, "v1.1.0", stage("v1.1.0"));
  assert.equal(run.status, 0, run.stderr);
  const second = remoteTip(remote);
  assert.equal(
    git(remote, "log", "-1", "--format=%P", second),
    `${first} ${tagged}`,
  );
  assert.equal(git(remote, "show", `${second}:${BUNDLE}`), "bundle for v1.1.0");
  assert.equal(
    git(remote, "show", `${second}:src/a.mjs`),
    "export const a = 3;",
  );
});

test("re-baking a contained tag, or an older one, leaves the branch where it is", () => {
  const { repo, remote } = scratchRelease();
  release(repo, "v1.0.0", "export const a = 2;\n");
  release(repo, "v1.1.0", "export const a = 3;\n");
  assert.equal(bake(repo, "v1.1.0", stage("v1.1.0")).status, 0);
  const tip = remoteTip(remote);
  for (const tag of ["v1.1.0", "v1.0.0"]) {
    const run = bake(repo, tag, stage(tag, "a different build\n"));
    assert.equal(run.status, 0, run.stderr);
    assert.match(run.stderr, /nothing to bake/);
    assert.equal(remoteTip(remote), tip, `re-baking ${tag} moved the branch`);
  }
});

test("a branch another writer moved is built on, never overwritten", () => {
  const { repo, remote } = scratchRelease();
  release(repo, "v1.0.0", "export const a = 2;\n");
  assert.equal(bake(repo, "v1.0.0", stage("v1.0.0")).status, 0);
  // Another writer replaces the branch with an unrelated commit.
  const other = scratchDir("plugin-dist-other-");
  git(other, "init", "--initial-branch=x", ".");
  git(other, "config", "user.name", "other");
  git(other, "config", "user.email", "other@example.invalid");
  writeFile(other, "x", "x\n");
  git(other, "add", "-A");
  git(other, "commit", "-m", "chore: other");
  git(other, "push", "--force", remote, `HEAD:refs/heads/${BRANCH}`);
  const theirs = remoteTip(remote);
  release(repo, "v1.1.0", "export const a = 3;\n");
  const run = bake(repo, "v1.1.0", stage("v1.1.0"));
  assert.equal(run.status, 0, run.stderr);
  const tip = remoteTip(remote);
  assert.equal(
    git(remote, "log", "-1", "--format=%P", tip).split(" ")[0],
    theirs,
    "the bake must fast-forward from the tip it fetched",
  );
});

test("an empty stage fails loudly and pushes nothing", () => {
  const { repo, remote } = scratchRelease();
  release(repo, "v1.0.0", "export const a = 2;\n");
  const run = bake(repo, "v1.0.0", scratchDir("plugin-dist-empty-"));
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /holds no files to bake/);
  assert.equal(remoteTip(remote), "");
});

test("a marketplace that names no single branch fails loudly and pushes nothing", () => {
  const { repo, remote } = scratchRelease(
    JSON.stringify({ plugins: [{ name: "fixture", source: "./plugin" }] }),
  );
  release(repo, "v1.0.0", "export const a = 2;\n");
  const run = bake(repo, "v1.0.0", stage("v1.0.0"));
  assert.notEqual(run.status, 0);
  assert.equal(remoteTip(remote), "");
});

/** Run resolve-release-tag.sh at HEAD of `repo`; returns [status, output, stderr]. */
const resolveTag = (repo, ...args) => {
  const output = join(scratchDir("plugin-dist-output-"), "out");
  writeFileSync(output, "");
  const run = spawnSync("bash", [RESOLVE, ...args], {
    cwd: repo,
    encoding: "utf8",
    env: { ...ENV, GITHUB_OUTPUT: output },
  });
  return [run.status, readFileSync(output, "utf8"), run.stderr];
};

test("resolve-release-tag names the release tag on HEAD, and nothing when there is none", () => {
  const { repo } = scratchRelease();
  assert.deepEqual(resolveTag(repo).slice(0, 2), [0, "tag=\n"]);
  git(repo, "tag", "not-a-release");
  git(repo, "tag", "v1.2.3");
  assert.deepEqual(resolveTag(repo).slice(0, 2), [0, "tag=v1.2.3\n"]);
  assert.deepEqual(resolveTag(repo, "v1.2.3").slice(0, 2), [0, "tag=v1.2.3\n"]);
});

test("resolve-release-tag refuses a dispatch for a tag HEAD does not carry, and an ambiguous HEAD", () => {
  const { repo } = scratchRelease();
  git(repo, "tag", "v1.2.3");
  const [status, output, stderr] = resolveTag(repo, "v9.9.9");
  assert.notEqual(status, 0);
  assert.equal(output, "");
  assert.match(stderr, /not tagged v9\.9\.9/);
  git(repo, "tag", "v1.2.4");
  const [ambiguous, , why] = resolveTag(repo);
  assert.notEqual(ambiguous, 0);
  assert.match(why, /several release tags/);
});

test("the bake listens to the release workflow by its real name", () => {
  // workflow_run binds by NAME; renaming the release workflow without this
  // would leave every release unbaked, with nothing red anywhere.
  const read = (file) =>
    parseYaml(readFileSync(join(REPO_ROOT, ".github/workflows", file), "utf8"));
  const bake = read("plugin-dist.yaml");
  assert.deepEqual(bake.on.workflow_run.workflows, [
    read("auto-version.yaml").name,
  ]);
  const notify = read("build-publish-notify.yaml");
  assert.ok(
    notify.on.workflow_run.workflows.includes(bake.name),
    "a failed bake must page someone",
  );
});

test("the bake writes the branch the marketplace installs from", () => {
  const marketplace = JSON.parse(
    readFileSync(join(REPO_ROOT, ".claude-plugin/marketplace.json"), "utf8"),
  );
  assert.deepEqual(
    marketplace.plugins.map((plugin) => plugin.source.ref),
    [BRANCH],
  );
});
