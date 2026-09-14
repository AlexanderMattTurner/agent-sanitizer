/**
 * WHAT a context scan refuses to walk once git has been asked, driven against a
 * real repository rather than a canned `ls-files` dump: the prune set IS git's
 * answer, so a stubbed one would only test the stub.
 *
 * Three directions, and all three have to hold together. A gitignored DIRECTORY
 * and a nested worktree are not this checkout's source and are pruned from the
 * whole-tree walk. A gitignored FILE is still scanned, because `CLAUDE.local.md`
 * is gitignored by convention and loads as model context at launch. And the
 * launch walk keeps every gitignored directory, because `.gitignore` is
 * repo-controlled and that walk is the only thing covering launch-time ingress.
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, sep } from "node:path";

import {
  CLAUDE_INSTRUCTION_GLOBS,
  excludeFromContextScan,
} from "../src/claude-context.mjs";
import { findInstructionFiles } from "../src/instructions.mjs";
import {
  contextScanExclude,
  parseWorktreeList,
  repoPrunedDirs,
} from "../src/repo-scope.mjs";
import { launchInstructionFiles } from "../claude-hooks/lib/invisible-alert.mjs";
import { cleanGitEnv } from "./helpers/git-env.mjs";

const root = mkdtempSync(join(tmpdir(), "sanitizer-repo-scope-"));
const plain = mkdtempSync(join(tmpdir(), "sanitizer-repo-scope-nogit-"));

after(() => {
  for (const path of [root, plain])
    rmSync(path, { recursive: true, force: true });
});

/** A directory name git always C-quotes without `-z`, whatever `core.quotePath` says. */
const QUOTED_DIR = 'weird dir"q';

const git = (args, cwd = root) =>
  execFileSync("git", args, { cwd, encoding: "utf8", env: cleanGitEnv });

/** Create `rel` (a `/`-separated path) under `dir` with clean prose in it. */
function write(dir, rel) {
  const abs = join(dir, ...rel.split("/"));
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, "clean prose\n");
  return rel;
}

before(() => {
  git(["init", "--quiet", "--initial-branch=main"]);
  git(["config", "user.email", "test@example.invalid"]);
  git(["config", "user.name", "Test"]);
  writeFileSync(
    join(root, ".gitignore"),
    `build/\nCLAUDE.local.md\n${QUOTED_DIR}/\n.claude/skills/hidden/\n`,
  );
  write(root, "CLAUDE.md");
  git(["add", "-A"]);
  git(["commit", "--quiet", "-m", "seed"]);

  // Untracked and ignored, each holding a file the globs would otherwise match.
  write(root, "CLAUDE.local.md");
  write(root, "build/CLAUDE.md");
  write(root, `${QUOTED_DIR}/CLAUDE.md`);
  write(root, ".claude/skills/hidden/SKILL.md");
  write(root, ".claude/skills/visible/SKILL.md");

  // Two more checkouts of the same repo, nested and NOT gitignored: nothing but
  // git's own registry can tell either from an ordinary subdirectory. The second
  // sits inside a whitelisted `.claude/` subdirectory, which is the only place
  // the shallow LAUNCH walk could ever reach one.
  git(["worktree", "add", "--quiet", "-b", "other", join("worktrees", "wt")]);
  git([
    "worktree",
    "add",
    "--quiet",
    "-b",
    "scoped",
    join(".claude", "skills", "wt"),
  ]);
});

/** Whole-tree matches under `root`, as `/`-separated relative paths. */
function wholeTree(exclude) {
  return new Set(
    findInstructionFiles([...CLAUDE_INSTRUCTION_GLOBS], {
      cwd: root,
      exclude,
    }).map((abs) => relative(root, abs).split(sep).join("/")),
  );
}

/** Launch-time targets under `root`, as `/`-separated relative paths. */
const launchSet = () =>
  new Set(
    launchInstructionFiles(root)
      .filter((abs) => abs.startsWith(root + sep))
      .map((abs) => relative(root, abs).split(sep).join("/")),
  );

describe("repoPrunedDirs", () => {
  it("names the ignored directories and the nested worktree, and no ignored file", () => {
    assert.deepEqual(
      [...repoPrunedDirs(root)].sort(),
      [
        ".claude/skills/hidden",
        ".claude/skills/wt",
        QUOTED_DIR,
        "build",
        "worktrees/wt",
        // `.git` is not listed: git never reports its own directory as ignored.
      ].sort(),
    );
  });

  it("keeps every gitignored FILE out of the prune set", () => {
    assert.equal(repoPrunedDirs(root).has("CLAUDE.local.md"), false);
  });

  it("prunes only the worktree when ignored directories are off", () => {
    assert.deepEqual(
      [...repoPrunedDirs(root, { ignoredDirs: false })].sort(),
      [".claude/skills/wt", "worktrees/wt"].sort(),
    );
  });

  it("prunes nothing outside a repository", () => {
    assert.deepEqual([...repoPrunedDirs(plain)], []);
  });

  it("prunes nothing when git cannot be spawned", () => {
    const enoent = () => {
      const err = new Error("spawn git ENOENT");
      /** @type {NodeJS.ErrnoException} */ (err).code = "ENOENT";
      throw err;
    };
    assert.deepEqual([...repoPrunedDirs(root, { run: enoent })], []);
  });

  it("propagates a throw that is not git refusing", () => {
    const bug = () => {
      throw new TypeError("run is not a function");
    };
    assert.throws(() => repoPrunedDirs(root, { run: bug }), TypeError);
  });
});

describe("whole-tree context scan", () => {
  it("scans the checkout's own instruction files, ignored FILES included", () => {
    const scanned = wholeTree(contextScanExclude(root));
    assert.deepEqual(
      [...scanned].sort(),
      [
        "CLAUDE.md",
        "CLAUDE.local.md",
        ".claude/skills/visible/SKILL.md",
      ].sort(),
    );
  });

  it("prunes what git says is not this checkout's source", () => {
    const scanned = wholeTree(contextScanExclude(root));
    for (const rel of [
      "build/CLAUDE.md",
      `${QUOTED_DIR}/CLAUDE.md`,
      "worktrees/wt/CLAUDE.md",
    ])
      assert.equal(scanned.has(rel), false, `${rel} should not be scanned`);
  });

  // Non-vacuity: the static prune alone — the scope before git was asked —
  // reaches every file the case above says is pruned. Without this the two
  // assertions above would pass just as happily against a prune that never ran.
  it("reaches those same files under the static prune alone", () => {
    const scanned = wholeTree(excludeFromContextScan);
    for (const rel of [
      "build/CLAUDE.md",
      `${QUOTED_DIR}/CLAUDE.md`,
      "worktrees/wt/CLAUDE.md",
    ])
      assert.equal(scanned.has(rel), true, `${rel} should be reachable`);
  });
});

describe("launch scan", () => {
  // The evasion this refuses: a payload planted in a skill, with that skill's
  // directory added to `.gitignore`. Honouring the ignore here would hide it
  // from the one scan that runs before the first tool call.
  it("scans a gitignored directory's launch-time context", () => {
    const rel = ".claude/skills/hidden/SKILL.md";
    assert.equal(launchSet().has(rel), true);
    // The contrast is the point: the whole-tree walk drops the same file, and
    // only scan-loaded-instructions covers it there. Asserting both halves is
    // what makes the difference between the two scopes deliberate.
    assert.equal(wholeTree(contextScanExclude(root)).has(rel), false);
  });

  it("prunes a worktree nested inside a context directory it does walk", () => {
    const scanned = launchSet();
    assert.equal(scanned.has(".claude/skills/wt/CLAUDE.md"), false);
    // Non-vacuity, twice over: the walk reaches that directory's sibling, and
    // the pre-prune scope reached the worktree's own copy.
    assert.equal(scanned.has(".claude/skills/visible/SKILL.md"), true);
    assert.equal(
      wholeTree(excludeFromContextScan).has(".claude/skills/wt/CLAUDE.md"),
      true,
    );
  });
});

describe("parseWorktreeList", () => {
  it("drops the main worktree, bare repos and prunable registrations", () => {
    assert.deepEqual(
      parseWorktreeList(
        [
          "worktree /repo\nHEAD abc\nbranch refs/heads/main",
          "worktree /repo/wt\nHEAD def\nbranch refs/heads/other",
          "worktree /gone\nHEAD ghi\nprunable gitdir file points to non-existent location",
          "worktree /bare\nbare",
        ].join("\n\n"),
      ),
      ["/repo/wt"],
    );
  });
});
