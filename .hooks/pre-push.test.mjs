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
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";

import { repoRoot } from "../test/helpers/repo-root.mjs";
import { cleanGitEnv } from "../test/helpers/git-env.mjs";

const HOOK = join(repoRoot, ".hooks", "pre-push");
const ZERO = "0".repeat(40);

let scratch;
let origin;
let clone;

const git = (args, cwd) =>
  execFileSync("git", args, { cwd, encoding: "utf8", env: cleanGitEnv }).trim();

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

/**
 * Run the hook with a recording `pre-commit` stub first on PATH.
 *
 * `failing` names a hook id the stub should fail, so a test can prove one
 * concurrent hook's failure still aborts the push. Every invocation appends its
 * `SKIP` value and its argv to a log, which is what the fan-out assertions read.
 */
function runHookWithStub(
  refLine,
  { failing = null, unprovisioned = null } = {},
) {
  const binDir = join(scratch, "stubbin");
  const log = join(scratch, "precommit-calls");
  mkdirSync(binDir, { recursive: true });
  writeFileSync(log, "");
  const stub = join(binDir, "pre-commit");
  writeFileSync(
    stub,
    `#!/usr/bin/env bash\nprintf 'SKIP=%s ARGV=%s\\n' "\${SKIP:-}" "$*" >>${JSON.stringify(log)}\n` +
      (failing
        ? `[[ "\${2:-}" == ${JSON.stringify(failing)} ]] && { echo "stub: ${failing} failed"; exit 1; }\n`
        : "") +
      (unprovisioned
        ? `[[ "\${2:-}" == ${JSON.stringify(unprovisioned)} ]] && exit 3\n`
        : "") +
      "exit 0\n",
  );
  chmodSync(stub, 0o755);
  const result = spawnSync("bash", [HOOK], {
    cwd: clone,
    input: `${refLine}\n`,
    encoding: "utf8",
    env: {
      PATH: `${binDir}:/usr/bin:/bin`,
      HOME: join(scratch, "home"),
    },
  });
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
    calls: readFileSync(log, "utf8").split("\n").filter(Boolean),
  };
}

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

  it("still refuses a force-push to the default branch that adds nothing, with rollback-aware wording", () => {
    // A ref pushed AT origin/main only reaches "ahead == 0" via a force push —
    // an ordinary push adding nothing is rejected by git before the hook runs.
    // The hook cannot tell a deliberate rollback from an accidental stale
    // force-push, so it still refuses; only the message changes, so the
    // rollback case doesn't get told to "restart the branch" against itself.
    git(["checkout", "-q", "-B", "ahead", "origin/main"], clone);
    writeFileSync(join(clone, "later.txt"), "later\n");
    git(["add", "-A"], clone);
    git(["commit", "-qm", "feat: later work"], clone);
    const rollbackTo = git(["rev-parse", "origin/main"], clone);
    const current = headOf("HEAD");
    const { status, stderr } = runHook(
      `refs/heads/ahead ${rollbackTo} refs/heads/main ${current}`,
    );
    assert.equal(status, 1, `expected the refusal, stderr: ${stderr}`);
    assert.doesNotMatch(stderr, /already contained/);
    assert.doesNotMatch(stderr, /restart the branch/i);
    assert.match(stderr, /deliberate rollback/);
    assert.match(stderr, /--no-verify/);
    // Non-vacuity: the SAME sha aimed at a feature branch gets the ordinary
    // feature-branch wording instead, so the message above is keyed on the
    // ref being the default branch and nothing else.
    const feature = runHook(
      `refs/heads/ahead ${rollbackTo} refs/heads/other ${current}`,
    );
    assert.equal(feature.status, 1);
    assert.match(feature.stderr, /every commit in it is already contained/);
    assert.doesNotMatch(feature.stderr, /deliberate rollback/);
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

/**
 * The pushed-range lint is the expensive half of this hook, and the hooks that
 * only READ the tree are fanned out concurrently to pay for it. What that
 * partition must never do is drop a hook: every id the serial pass is told to
 * SKIP has to reappear as its own invocation, or a check silently stops running
 * on push while still reading as "pre-commit ran".
 */
describe("pre-push pushed-range fan-out", () => {
  let sha;

  before(() => {
    // The hook reads the real config to intersect its allowlist against the
    // hooks that actually exist, so the throwaway clone needs one.
    writeFileSync(
      join(clone, ".pre-commit-config.yaml"),
      [
        "repos:",
        "  - repo: local",
        "    hooks:",
        "      - id: trailing-whitespace",
        "      - id: check-yaml",
        "      - id: check-tier1",
        "      - id: retired-hook-not-in-config",
        "",
      ].join("\n"),
    );
    git(["checkout", "-q", "-B", "fanout", "origin/main"], clone);
    git(["add", "-A"], clone);
    git(["commit", "-qm", "chore: seed a pre-commit config"], clone);
    sha = headOf("HEAD");
  });

  const refLine = () => `refs/heads/fanout ${sha} refs/heads/fanout ${ZERO}`;

  it("skips the read-only hooks serially and runs each of them on its own", () => {
    const { status, calls } = runHookWithStub(refLine());
    assert.equal(status, 0);

    const serial = calls.filter((c) => /ARGV=run --from-ref/.test(c));
    assert.equal(serial.length, 1, `expected one serial pass, got: ${calls}`);
    const skipped = /SKIP=(\S*) /.exec(serial[0])[1].split(",").filter(Boolean);
    // The mutating hook must NOT be skipped — it is why the serial pass exists.
    assert.ok(!skipped.includes("trailing-whitespace"));
    assert.deepEqual(skipped.slice().sort(), ["check-tier1", "check-yaml"]);

    // Every skipped hook comes back as its own run. Deriving the expectation
    // from `skipped` is what makes this a partition check rather than a list
    // of names that can drift away from the hook's allowlist.
    for (const hook of skipped) {
      assert.equal(
        calls.filter((c) => c.includes(`ARGV=run ${hook} --from-ref`)).length,
        1,
        `${hook} was skipped in the serial pass and never run on its own`,
      );
    }
  });

  it("does not invoke a hook the config no longer declares", () => {
    // A stale allowlist entry would otherwise reach `pre-commit run <unknown>`,
    // which dies and blocks every push.
    const { calls } = runHookWithStub(refLine());
    assert.ok(!calls.join("\n").includes("retired-hook-not-in-config"));
  });

  it("fails the push when one concurrently-run hook fails", () => {
    const { status, stdout } = runHookWithStub(refLine(), {
      failing: "check-tier1",
    });
    assert.equal(status, 1, "a failing read-only hook must abort the push");
    assert.match(stdout, /stub: check-tier1 failed/);
  });

  it("lets a real failure outrank another hook's provisioning skip", () => {
    // Exit 3 is "could not install a hook environment", which the caller
    // degrades to a loud skip. If it won over a hook that genuinely failed, a
    // sandbox that cannot reach an index would wave every lint error through.
    const { status, stderr } = runHookWithStub(refLine(), {
      failing: "check-tier1",
      // check-yaml, not some hook absent from the fixture config: an id the
      // config never declares is never run, and the case would prove nothing.
      unprovisioned: "check-yaml",
    });
    assert.equal(status, 1, "a lint failure was masked by a provisioning skip");
    assert.doesNotMatch(stderr, /could not PROVISION/);
  });

  it("falls back to ONE serial run when the working tree is dirty", () => {
    // Concurrent pre-commit processes stash and restore unstaged changes over
    // each other, which corrupts the tree mid-run. Nothing to stash is what
    // makes the fan-out safe, so a dirty tree must not take it.
    writeFileSync(join(clone, "seed.txt"), "dirtied, unstaged\n");
    try {
      const { status, calls } = runHookWithStub(refLine());
      assert.equal(status, 0);
      assert.equal(calls.length, 1, `expected one run, got: ${calls}`);
      assert.match(calls[0], /^SKIP= ARGV=run --from-ref/);
    } finally {
      git(["checkout", "--", "seed.txt"], clone);
    }
  });
});
