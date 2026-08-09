/**
 * Contract test for the `git worktree remove` PreToolUse guard.
 *
 * The failure it exists to prevent is a silent one: staged-but-uncommitted work
 * deleted along with a worktree, invisible to `git diff`. So the assertions here
 * are about what the guard CONSULTS as much as what it answers — a version that
 * asked `git diff` instead of `git status --porcelain` would satisfy a
 * "returns a decision" test and still lose the work.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  dirtyWorktrees,
  judgeTeardown,
  linkedWorktrees,
} from "./worktree-teardown-check.mjs";

/** Payload shape Claude Code hands a PreToolUse hook. */
const bash = (command) => ({ tool_name: "Bash", tool_input: { command } });

/**
 * A recorded fake git: returns canned stdout per `git <subcommand>` and remembers
 * every argv it was handed, so a test can assert which QUESTION was asked.
 */
function fakeGit(responses) {
  const calls = [];
  const run = (file, args, cwd) => {
    calls.push({ file, args, cwd });
    const key = args.slice(0, 2).join(" ");
    if (!(key in responses)) throw new Error(`unexpected git call: ${key}`);
    const value = responses[key];
    return typeof value === "function" ? value(cwd) : value;
  };
  return { run, calls };
}

const WORKTREE_LIST = [
  "worktree /repo\nHEAD abc\nbranch refs/heads/main\n",
  "worktree /repo/.worktrees/feature\nHEAD def\nbranch refs/heads/feature\n",
  "worktree /repo/.worktrees/spike\nHEAD 012\ndetached\n",
].join("\n");

describe("linkedWorktrees", () => {
  it("lists the removable worktrees and excludes the main one", () => {
    const { run } = fakeGit({ "worktree list": WORKTREE_LIST });
    assert.deepEqual(linkedWorktrees("/repo", run), [
      "/repo/.worktrees/feature",
      "/repo/.worktrees/spike",
    ]);
  });

  it("excludes a bare repo's record", () => {
    const { run } = fakeGit({
      "worktree list": "worktree /repo\nbare\n\nworktree /repo/wt\nbare\n",
    });
    assert.deepEqual(linkedWorktrees("/repo", run), []);
  });
});

describe("dirtyWorktrees", () => {
  it("counts the entries at stake, per worktree", () => {
    const { run } = fakeGit({
      "status --porcelain": (cwd) =>
        cwd === "/a" ? "A  one.txt\n M two.txt\n" : "",
    });
    assert.deepEqual(dirtyWorktrees(["/a", "/b"], run), [
      { path: "/a", entries: 2 },
    ]);
  });
});

describe("judgeTeardown", () => {
  const io = (responses) => ({ cwd: "/repo", ...fakeGit(responses) });

  it("stays silent on a command that is not a worktree removal", () => {
    // No git responses registered: a fake that answered would throw, which is
    // the assertion — an unrelated command must not even ask.
    const seen = io({});
    assert.equal(judgeTeardown(bash("git worktree list"), seen), null);
    assert.equal(judgeTeardown(bash("rm -rf build"), seen), null);
    assert.deepEqual(seen.calls, []);
  });

  it("stays silent when every linked worktree is clean", () => {
    const seen = io({
      "worktree list": WORKTREE_LIST,
      "status --porcelain": "",
    });
    assert.equal(
      judgeTeardown(
        bash("git worktree remove --force /repo/.worktrees/spike"),
        seen,
      ),
      null,
    );
  });

  it("asks, naming the worktree and the count, when work would be lost", () => {
    const seen = io({
      "worktree list": WORKTREE_LIST,
      "status --porcelain": (cwd) =>
        cwd === "/repo/.worktrees/feature" ? "A  staged.mjs\n" : "",
    });
    const out = judgeTeardown(
      bash("git worktree remove --force /repo/.worktrees/feature"),
      seen,
    );
    assert.equal(out.hookSpecificOutput.permissionDecision, "ask");
    const reason = out.hookSpecificOutput.permissionDecisionReason;
    assert.match(
      reason,
      /\/repo\/\.worktrees\/feature \(1 uncommitted entry\)/,
    );
    // The `git diff` blind spot is the whole reason the guard exists; a reason
    // that omits it leaves the reader with no way to check the claim.
    assert.match(reason, /git status --porcelain/);
    assert.match(reason, /git diff/);
  });

  it("consults status --porcelain, never git diff", () => {
    const seen = io({
      "worktree list": WORKTREE_LIST,
      "status --porcelain": "A  staged.mjs\n",
    });
    judgeTeardown(
      bash("git worktree remove --force /repo/.worktrees/feature"),
      seen,
    );
    const subcommands = seen.calls.map((c) => c.args[0]);
    assert.ok(
      subcommands.includes("status"),
      "the guard never asked git for status",
    );
    assert.ok(
      !subcommands.includes("diff"),
      "`git diff` reports nothing for staged work — the exact blind spot this guard closes",
    );
  });

  it("fires on a removal reached through a shell chain, not only a bare command", () => {
    const seen = io({
      "worktree list": WORKTREE_LIST,
      "status --porcelain": "?? scratch.mjs\n",
    });
    const out = judgeTeardown(
      bash("cd /repo && git worktree remove --force .worktrees/feature"),
      seen,
    );
    assert.equal(out.hookSpecificOutput.permissionDecision, "ask");
  });

  it("tolerates a payload with no command at all", () => {
    const seen = io({});
    assert.equal(judgeTeardown({ tool_name: "Bash" }, seen), null);
    assert.equal(judgeTeardown({}, seen), null);
    assert.equal(judgeTeardown(null, seen), null);
  });
});

describe("against a real repository", () => {
  it("sees work that git diff does not: staged changes in a live worktree", () => {
    const root = mkdtempSync(join(tmpdir(), "worktree-teardown-"));
    const git = (args, cwd) =>
      execFileSync("git", args, { cwd, encoding: "utf8" });
    try {
      git(["init", "-q", "-b", "main", "."], root);
      git(["config", "user.email", "t@example.invalid"], root);
      git(["config", "user.name", "Test"], root);
      writeFileSync(join(root, "seed.txt"), "seed\n");
      git(["add", "-A"], root);
      git(["commit", "-qm", "seed"], root);

      const linked = join(root, "wt");
      git(["worktree", "add", "-q", "-b", "side", linked], root);
      writeFileSync(join(linked, "work.txt"), "unsaved\n");
      git(["add", "-A"], linked);

      // The incident in one assertion: the command the agent trusted reports
      // nothing, while the one the guard asks reports the work.
      assert.equal(git(["diff"], linked), "");
      assert.notEqual(git(["status", "--porcelain"], linked).trim(), "");

      const out = judgeTeardown(bash(`git worktree remove --force ${linked}`), {
        cwd: root,
        run: (file, args, cwd) => git(args, cwd),
      });
      assert.equal(out.hookSpecificOutput.permissionDecision, "ask");
      assert.match(out.hookSpecificOutput.permissionDecisionReason, /wt/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
