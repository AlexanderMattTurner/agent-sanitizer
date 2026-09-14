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
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, sep } from "node:path";

import {
  CLAUDE_INSTRUCTION_GLOBS,
  excludeFromContextScan,
} from "../src/claude-context.mjs";
import { findInstructionFiles } from "../src/instructions.mjs";
import {
  contextScanExclude,
  linkedWorktrees,
  parseWorktreeList,
  repoPrunedDirs,
} from "../src/repo-scope.mjs";
import { launchInstructionFiles } from "../claude-hooks/lib/invisible-alert.mjs";
import { cleanGitEnv } from "./helpers/git-env.mjs";
import { worktreePorcelainZ } from "./helpers/worktree-porcelain.mjs";

const root = mkdtempSync(join(tmpdir(), "sanitizer-repo-scope-"));
const plain = mkdtempSync(join(tmpdir(), "sanitizer-repo-scope-nogit-"));
// A second spelling of `root`, outside its tree: git answers about the checkout
// in PHYSICAL paths whatever spelling the scan root was reached through.
const linkParent = mkdtempSync(join(tmpdir(), "sanitizer-repo-scope-link-"));
const linked = join(linkParent, "checkout");

after(() => {
  for (const path of [root, plain, linkParent])
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
  // `/build/` is ANCHORED, so `src/build/` below is tracked source that merely
  // shares a basename with the ignored directory — the case a prune matching
  // bare entry names silently swallows.
  writeFileSync(
    join(root, ".gitignore"),
    `/build/\nCLAUDE.local.md\n${QUOTED_DIR}/\n.claude/skills/hidden/\n`,
  );
  write(root, "CLAUDE.md");
  write(root, "src/build/CLAUDE.md");
  git(["add", "-A"]);
  git(["commit", "--quiet", "-m", "seed"]);
  symlinkSync(root, linked);

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

/** Whole-tree matches under `dir`, as `/`-separated relative paths. */
function wholeTree(exclude, globs = [...CLAUDE_INSTRUCTION_GLOBS], dir = root) {
  return new Set(
    findInstructionFiles(globs, { cwd: dir, exclude }).map((abs) =>
      relative(dir, abs).split(sep).join("/"),
    ),
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
        "src/build/CLAUDE.md",
        ".claude/skills/visible/SKILL.md",
      ].sort(),
    );
  });

  // A prune entry names one directory, not a basename to match at every depth.
  // Losing this splices a tracked instruction file out of the scan — the
  // false-positive direction, where the cost is content the model needed.
  it("keeps a tracked directory that shares a name with an ignored one", () => {
    assert.equal(
      wholeTree(contextScanExclude(root)).has("src/build/CLAUDE.md"),
      true,
    );
    assert.equal(repoPrunedDirs(root).has("build"), true);
  });

  // An absolute pattern makes the walker report entries by absolute path, which
  // a root-relative prune set matches only once the walk normalizes them.
  it("prunes the same set under an absolute glob as under its relative twin", () => {
    const pattern = join("**", "CLAUDE.md");
    const exclude = contextScanExclude(root);
    const byRelative = [...wholeTree(exclude, [pattern])].sort();
    const byAbsolute = [...wholeTree(exclude, [join(root, pattern)])].sort();
    assert.deepEqual(byAbsolute, byRelative);
    assert.deepEqual(byAbsolute, ["CLAUDE.md", "src/build/CLAUDE.md"]);
  });

  it("prunes a nested worktree through a symlinked scan root", () => {
    const scanned = wholeTree(contextScanExclude(linked), undefined, linked);
    assert.equal(scanned.has("worktrees/wt/CLAUDE.md"), false);
    // Non-vacuity: the walk did reach this root's own files.
    assert.equal(scanned.has("CLAUDE.md"), true);
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
        worktreePorcelainZ([
          ["worktree /repo", "HEAD abc", "branch refs/heads/main"],
          ["worktree /repo/wt", "HEAD def", "branch refs/heads/other"],
          [
            "worktree /gone",
            "HEAD ghi",
            "prunable gitdir file points to non-existent location",
          ],
          ["worktree /bare", "bare"],
        ]),
      ),
      ["/repo/wt"],
    );
  });

  // No filesystem can force `prunable`, and none can hold a repo whose path has
  // a newline in it on every platform this runs on, so both are pinned here as
  // pure strings. The newline is what `-z` exists for: under newline framing
  // this record truncates and the prune names a directory that does not exist.
  it("keeps a worktree path containing a newline whole", () => {
    assert.deepEqual(
      parseWorktreeList(
        worktreePorcelainZ([
          ["worktree /repo", "HEAD abc", "branch refs/heads/main"],
          ["worktree /repo/odd\nname", "HEAD def", "detached"],
        ]),
      ),
      ["/repo/odd\nname"],
    );
  });
});

describe("linkedWorktrees", () => {
  // Against real git output, so the `-z` framing the parser above assumes is
  // the framing git actually emits rather than the one this file made up.
  it("names the fixture's linked worktrees and not its main one", () => {
    const run = (file, args, cwd) =>
      execFileSync(file, args, { cwd, encoding: "utf8", env: cleanGitEnv });
    const real = realpathSync(root);
    assert.deepEqual(
      linkedWorktrees(root, run)
        .map((path) => relative(real, path).split(sep).join("/"))
        .sort(),
      [".claude/skills/wt", "worktrees/wt"],
    );
  });
});
