// Integration tests for the timing-history recorder: the real script runs
// against a real local remote, and every assertion reads what actually landed
// on the history branch.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync, cpSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const HAS_JQ = spawnSync("jq", ["--version"]).status === 0;

const TIMING = {
  title: "Session setup",
  total_ms: 30_000,
  phases: [{ label: "session-setup (cold cache)", offset_ms: 0, ms: 20_000 }],
};

function git(cwd, ...args) {
  const res = spawnSync("git", args, { cwd, encoding: "utf8" });
  assert.equal(res.status, 0, `git ${args.join(" ")}: ${res.stderr}`);
  return res.stdout.trim();
}

// A work repo whose `origin` is a real (bare) repository on disk, carrying the
// scripts under test — the recorder resolves everything from the repo root.
function makeRepo() {
  const root = mkdtempSync(join(tmpdir(), "timing-history-"));
  const remote = join(root, "remote.git");
  const work = join(root, "work");
  spawnSync("git", ["init", "--bare", "-b", "main", remote]);
  spawnSync("git", ["init", "-b", "main", work]);
  mkdirSync(join(work, ".github/scripts/lib"), { recursive: true });
  for (const f of [
    "append-timing-history.sh",
    "render-timing-trend.mjs",
    "lib/retry.bash",
  ])
    cpSync(join(HERE, f), join(work, ".github/scripts", f));
  writeFileSync(join(work, "README.md"), "source tree\n");
  git(work, "add", "-A");
  git(
    work,
    "-c",
    "user.name=t",
    "-c",
    "user.email=t@t",
    "commit",
    "-qm",
    "init",
  );
  git(work, "remote", "add", "origin", remote);
  git(work, "push", "-q", "origin", "main");
  writeFileSync(join(root, "timing.json"), JSON.stringify(TIMING));
  return { root, work, remote, timing: join(root, "timing.json") };
}

function record(repo, env = {}) {
  return spawnSync("bash", [".github/scripts/append-timing-history.sh"], {
    cwd: repo.work,
    encoding: "utf8",
    env: {
      ...process.env,
      TIMING_JSON: repo.timing,
      GITHUB_SHA: "0123456789abcdef0123456789abcdef01234567",
      GITHUB_RUN_ID: "42",
      GITHUB_REF_NAME: "main",
      DEFAULT_BRANCH: "main",
      RUNNER_TEMP: repo.root,
      ...env,
    },
  });
}

// The JSONL that landed on the history branch of the remote.
function historyLines(repo) {
  const raw = git(repo.work, "show", `origin/ci-timings:hook-lifecycle.jsonl`);
  return raw.split("\n").filter(Boolean).map(JSON.parse);
}

test(
  "the first run creates the history branch with one stamped record",
  { skip: !HAS_JQ },
  () => {
    const repo = makeRepo();
    const res = record(repo);
    assert.equal(res.status, 0, res.stderr);
    git(repo.work, "fetch", "origin", "ci-timings");
    const lines = historyLines(repo);
    assert.equal(lines.length, 1);
    assert.equal(lines[0].total_ms, 30_000);
    assert.equal(lines[0].commit, "0123456789abcdef0123456789abcdef01234567");
    assert.equal(lines[0].run_id, "42");
    assert.match(lines[0].at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    assert.deepEqual(lines[0].phases, TIMING.phases);
  },
);

test(
  "the history branch carries only the history, not a copy of the tree",
  { skip: !HAS_JQ },
  () => {
    const repo = makeRepo();
    assert.equal(record(repo).status, 0);
    git(repo.work, "fetch", "origin", "ci-timings");
    const files = git(
      repo.work,
      "ls-tree",
      "-r",
      "--name-only",
      "origin/ci-timings",
    );
    assert.equal(files, "hook-lifecycle.jsonl");
  },
);

test("a later run appends rather than replacing", { skip: !HAS_JQ }, () => {
  const repo = makeRepo();
  assert.equal(record(repo).status, 0);
  const second = record(repo, {
    GITHUB_SHA: "f".repeat(40),
    GITHUB_RUN_ID: "43",
  });
  assert.equal(second.status, 0, second.stderr);
  git(repo.work, "fetch", "origin", "ci-timings");
  const lines = historyLines(repo);
  assert.equal(lines.length, 2);
  assert.deepEqual(
    lines.map((l) => l.run_id),
    ["42", "43"],
  );
  // Two runs is a trend, so the recorder now renders the chart.
  assert.match(second.stdout, /xychart-beta/);
});

test(
  "a run off the default branch is refused, leaving no history",
  { skip: !HAS_JQ },
  () => {
    const repo = makeRepo();
    const res = record(repo, { GITHUB_REF_NAME: "some-pr-branch" });
    assert.notEqual(res.status, 0);
    assert.match(
      res.stderr,
      /refusing to record timings from 'some-pr-branch'/,
    );
    const branches = git(repo.work, "ls-remote", "--heads", "origin");
    assert.doesNotMatch(branches, /ci-timings/);
  },
);

test(
  "a missing timing record fails loudly instead of recording nothing",
  { skip: !HAS_JQ },
  () => {
    const repo = makeRepo();
    const res = record(repo, { TIMING_JSON: join(repo.root, "absent.json") });
    assert.notEqual(res.status, 0);
    assert.match(res.stderr, /no timing record at/);
  },
);
