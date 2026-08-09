/**
 * Contract test for the merged-history guard in `.hooks/pre-push`.
 *
 * The rule it enforces used to live only in prose: a branch whose pull request
 * merged is finished, and follow-up work belongs on a branch restarted from the
 * current default. A stale local ref makes that rule easy to break by accident —
 * the push looks ordinary and re-lands history the remote already has.
 *
 * The hook is DRIVEN here, not read: each case feeds it a real ref line on stdin
 * in a throwaway repository and asserts the exit status and the message. A test
 * that grepped the script for `rev-list` would keep passing if the check moved
 * behind the pre-commit tool gate, which is exactly the regression that would
 * make it silent on a machine without pre-commit.
 */
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";

import { repoRoot } from "./lib/repo-root.mjs";

const HOOK = join(repoRoot, ".hooks", "pre-push");
const ZERO = "0".repeat(40);

let scratch;
let origin;
let clone;

// Git's own environment must not leak in from whatever invoked this suite:
// under the pre-commit hook `GIT_INDEX_FILE` names the OUTER repo's temporary
// index, and every git call in this throwaway repo would use it.
const cleanEnv = Object.fromEntries(
  Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")),
);

const git = (args, cwd) =>
  execFileSync("git", args, { cwd, encoding: "utf8", env: cleanEnv }).trim();

/**
 * Run the hook against `clone` with one ref line on stdin.
 *
 * PATH and HOME are stripped down on purpose: with neither `uvx` nor
 * `pre-commit` reachable the hook skips its pushed-range lint, which leaves the
 * merged-history check as the only thing under test. HOME must move too — the
 * hook prepends `$HOME/.local/bin`, where uv normally lives.
 */
function runHook(refLine) {
  const result = spawnSync("bash", [HOOK], {
    cwd: clone,
    input: `${refLine}\n`,
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin", HOME: join(scratch, "home") },
  });
  return { status: result.status, stderr: result.stderr };
}

const headOf = (ref) => git(["rev-parse", ref], clone);

before(() => {
  scratch = mkdtempSync(join(tmpdir(), "pre-push-guard-"));
  origin = join(scratch, "origin");
  clone = join(scratch, "clone");

  git(["init", "-q", "-b", "main", origin], scratch);
  git(["config", "user.email", "t@example.invalid"], origin);
  git(["config", "user.name", "Test"], origin);
  writeFileSync(join(origin, "seed.txt"), "seed\n");
  git(["add", "-A"], origin);
  git(["commit", "-qm", "seed"], origin);
  // A non-bare origin refuses a push to its checked-out branch; nothing here
  // pushes, but detaching keeps the fixture honest if a case ever does.
  git(["checkout", "-q", "--detach"], origin);

  git(["clone", "-q", origin, clone], scratch);
  git(["config", "user.email", "t@example.invalid"], clone);
  git(["config", "user.name", "Test"], clone);
});

after(() => rmSync(scratch, { recursive: true, force: true }));

describe("pre-push merged-history guard", () => {
  it("refuses a branch whose commits are all already in the default branch", () => {
    git(["checkout", "-q", "-B", "stale", "origin/main"], clone);
    const sha = headOf("HEAD");
    const { status, stderr } = runHook(
      `refs/heads/stale ${sha} refs/heads/stale ${ZERO}`,
    );
    assert.equal(status, 1, `expected a blocked push, got ${status}`);
    assert.match(stderr, /every commit in it is already contained/);
    // The message has to say what to do instead, or the block is a dead end.
    assert.match(stderr, /git checkout -B/);
    assert.match(stderr, /--no-verify/);
  });

  it("allows a branch carrying one unmerged commit", () => {
    git(["checkout", "-q", "-B", "live", "origin/main"], clone);
    writeFileSync(join(clone, "new.txt"), "work\n");
    git(["add", "-A"], clone);
    git(["commit", "-qm", "feat: real work"], clone);
    const sha = headOf("HEAD");
    const { status, stderr } = runHook(
      `refs/heads/live ${sha} refs/heads/live ${ZERO}`,
    );
    assert.equal(status, 0, `expected the push to pass, stderr: ${stderr}`);
    assert.doesNotMatch(stderr, /already contained/);
  });

  it("skips a tag push, which introduces no commits", () => {
    const sha = git(["rev-parse", "origin/main"], clone);
    const { status, stderr } = runHook(
      `refs/tags/v1.0.0 ${sha} refs/tags/v1.0.0 ${ZERO}`,
    );
    assert.equal(status, 0);
    assert.doesNotMatch(stderr, /already contained/);
  });

  it("skips a branch deletion", () => {
    const { status } = runHook(
      `(delete) ${ZERO} refs/heads/gone ${headOf("origin/main")}`,
    );
    assert.equal(status, 0);
  });

  it("skips loudly, not silently, when the default branch is absent locally", () => {
    git(["checkout", "-q", "-B", "orphan-probe", "origin/main"], clone);
    const sha = headOf("HEAD");
    // Remove the remote-tracking ref the check resolves against. A guard that
    // failed CLOSED here would block every push in a fresh shallow checkout;
    // one that failed silently would leave the operator thinking it ran.
    git(["update-ref", "-d", "refs/remotes/origin/main"], clone);
    git(["symbolic-ref", "-d", "refs/remotes/origin/HEAD"], clone);
    try {
      const { status, stderr } = runHook(
        `refs/heads/orphan-probe ${sha} refs/heads/orphan-probe ${ZERO}`,
      );
      assert.equal(status, 0);
      assert.match(stderr, /SKIPPING the merged-history check/);
      assert.match(stderr, /git fetch origin/);
    } finally {
      git(["fetch", "-q", "origin"], clone);
      git(["remote", "set-head", "origin", "-a"], clone);
    }
  });
});
