/**
 * WHAT the SessionStart scan looks at, as opposed to what it does with what it
 * finds (that is claude-hooks-scan-coverage.test.mjs).
 *
 * The scan covers what Claude Code loads AT LAUNCH: the launch directory's own
 * instruction files, its whitelisted `.claude/` markdown, and the CLAUDE.md
 * chain in the directories above it. It deliberately does NOT walk the tree
 * below — Claude Code loads a subdirectory's CLAUDE.md only when it reads a file
 * there, scan-loaded-instructions scans it at that moment, and globbing for it
 * here cost a session launched in a home directory ~100 seconds of blocked
 * startup. So these cases pin all three directions: the launch set is scanned,
 * the parent chain is scanned, and neither the tree below nor the bulk
 * directories are walked.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, sep } from "node:path";

const projectDir = mkdtempSync(join(tmpdir(), "sanitizer-scan-scope-proj-"));
process.env.CLAUDE_PROJECT_DIR = projectDir;

const { scanProject, CLAUDE_CONTEXT_SUBDIRS } =
  await import("../claude-hooks/scan-invisible-chars.mjs");

// The launch directory is a CHILD of the fixture root, so the root doubles as
// the parent directory whose CLAUDE.md Claude Code loads in full at launch.
const root = mkdtempSync(join(tmpdir(), "sanitizer-scan-scope-"));
const dir = join(root, "launch-dir");
mkdirSync(dir);

after(() => {
  for (const path of [root, projectDir])
    rmSync(path, { recursive: true, force: true });
});

/** Create `rel` (a `/`-separated path) under the launch directory. */
function write(rel) {
  const abs = join(dir, ...rel.split("/"));
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, "clean prose\n");
  return rel;
}

// Loaded at launch from the launch directory itself: its instruction files, the
// `.claude` tree's own markdown, and one deep file inside every whitelisted
// subdirectory.
const SCANNED = [
  write("CLAUDE.md"),
  write("CLAUDE.local.md"),
  write("AGENTS.md"),
  write(".claude/notes.md"),
  ...CLAUDE_CONTEXT_SUBDIRS.map((sub) =>
    write(`.claude/${sub}/nested/deep/file.md`),
  ),
];

// Loaded LATER, when a tool reads that subdirectory — scan-loaded-instructions'
// job, not this hook's. Scanning them here is the whole-tree walk this scope
// exists to stop paying for.
const LAZY = [
  write("packages/foo/CLAUDE.md"),
  write("packages/foo/AGENTS.md"),
  write("packages/foo/.claude/skills/scoped/SKILL.md"),
];

// Never context at all: bulk data under `.claude/`, and dependency trees.
const NOT_SCANNED = [
  write(".claude/worktrees/wt/CLAUDE.md"),
  write(".claude/worktrees/wt/docs/guide.md"),
  write(".claude/worktrees/wt/.claude/skills/s/SKILL.md"),
  write(".claude/projects/session-transcript.md"),
  write(".claude/todos/notes.md"),
  write("node_modules/pkg/CLAUDE.md"),
  write("node_modules/pkg/.claude/skills/s/SKILL.md"),
];

// A parent-directory memory file, loaded in full at launch.
const ancestorClaude = join(root, "CLAUDE.md");
writeFileSync(ancestorClaude, "clean prose\n");

const scan = scanProject(dir);
/** The targets inside the launch directory, as `/`-separated relative paths. */
const inLaunchDir = new Set(
  scan.targets
    .filter((abs) => abs.startsWith(dir + sep))
    .map((abs) =>
      abs
        .slice(dir.length + 1)
        .split(sep)
        .join("/"),
    ),
);

describe("SessionStart scan scope", () => {
  it("scans every launch-time context file under the launch dir, and nothing else", () => {
    assert.deepEqual([...inLaunchDir].sort(), [...SCANNED].sort());
  });

  // Named per file so a regression says WHICH directory stopped being scanned,
  // and so the whitelist cannot shrink without a test failing.
  for (const rel of SCANNED)
    it(`scans ${rel}`, () => assert.ok(inLaunchDir.has(rel)));

  for (const rel of [...LAZY, ...NOT_SCANNED])
    it(`does not walk to ${rel}`, () => assert.ok(!inLaunchDir.has(rel)));

  it("scans the parent directory's CLAUDE.md", () => {
    assert.ok(scan.targets.includes(ancestorClaude));
  });

  it("walks the parent chain to the filesystem root", async () => {
    // The chain itself is the library's, and it must reach the root rather than
    // stopping at some fixed depth — a parent CLAUDE.md three levels up is
    // loaded in full exactly like the one directly above.
    const { ancestorInstructionFiles } =
      await import("../src/claude-context.mjs");
    const chain = ancestorInstructionFiles(dir);
    assert.ok(chain.includes(join(root, "CLAUDE.md")));
    assert.ok(chain.includes(join(sep, "CLAUDE.md")));
    assert.ok(chain.includes(join(sep, "CLAUDE.local.md")));
  });

  it("lists no ancestor candidate that does not exist", () => {
    // Only the parent CLAUDE.md that exists joins the targets. The rest of the
    // chain — a phantom CLAUDE.md in every directory up to `/` — would file ~10
    // entries per session into the `absent` bucket and bury the one thing that
    // bucket reports.
    assert.ok(!scan.targets.includes(join(sep, "CLAUDE.md")));
    assert.deepEqual(scan.absent, []);
    // The accounting invariant, where the ancestor chain enters it. The +1 is
    // the parent CLAUDE.md, the one ancestor that exists.
    assert.equal(scan.scanned, SCANNED.length + 1);
    assert.equal(scan.targets.length, scan.scanned);
  });

  it("has a non-empty whitelist driving those cases", () => {
    assert.ok(CLAUDE_CONTEXT_SUBDIRS.length > 0);
  });

  it("scans the library's whitelist, not a copy of it", async () => {
    // Identity, not deep equality: a second list that happens to agree today is
    // exactly the drift this module was extracted to end. The hook re-exports
    // what it imports, so `===` here proves the walk above ran on the library's
    // own arrays.
    const lib = await import("../src/claude-context.mjs");
    const hook = await import("../claude-hooks/scan-invisible-chars.mjs");
    assert.equal(hook.CLAUDE_CONTEXT_SUBDIRS, lib.CLAUDE_CONTEXT_SUBDIRS);
    assert.equal(hook.CLAUDE_INSTRUCTION_GLOBS, lib.CLAUDE_INSTRUCTION_GLOBS);
    assert.equal(hook.CLAUDE_LAUNCH_GLOBS, lib.CLAUDE_LAUNCH_GLOBS);
    const pub = await import("../src/instructions.mjs");
    assert.equal(pub.CLAUDE_CONTEXT_SUBDIRS, lib.CLAUDE_CONTEXT_SUBDIRS);
    assert.equal(pub.CLAUDE_INSTRUCTION_GLOBS, lib.CLAUDE_INSTRUCTION_GLOBS);
    assert.equal(pub.CLAUDE_LAUNCH_GLOBS, lib.CLAUDE_LAUNCH_GLOBS);
    assert.equal(pub.excludeFromContextScan, lib.excludeFromContextScan);
    assert.equal(pub.ancestorInstructionFiles, lib.ancestorInstructionFiles);
  });

  it("costs the same on a launch dir with a large tree under it", () => {
    // The regression this scope exists to prevent, driven the only way that
    // cannot pass vacuously: plant a wide, deep subtree full of instruction
    // files and assert the target count does not move. The `**`-rooted walk
    // returned 80 more.
    const before = scanProject(dir).targets.length;
    for (let i = 0; i < 40; i++) {
      write(`bulk/p${i}/a/b/c/CLAUDE.md`);
      write(`bulk/p${i}/a/b/c/.claude/skills/s/SKILL.md`);
    }
    assert.equal(scanProject(dir).targets.length, before);
  });
});
