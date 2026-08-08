/**
 * WHAT the SessionStart scan looks at, as opposed to what it does with what it
 * finds (that is claude-hooks-scan-coverage.test.mjs).
 *
 * The scan used to glob every markdown file under `.claude/`, which swept in
 * `.claude/worktrees/` — whole checked-out copies of the repo — and blocked
 * session startup for tens of seconds reading files that never reach the model.
 * The targets are now a whitelist of the `.claude/` subdirectories Claude Code
 * actually loads as context, so these cases pin BOTH directions: every
 * whitelisted subdirectory is still scanned (a scan that quietly stopped looking
 * is the failure that matters), and the bulk directories are not.
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

const dir = mkdtempSync(join(tmpdir(), "sanitizer-scan-scope-"));

after(() => {
  for (const path of [dir, projectDir])
    rmSync(path, { recursive: true, force: true });
});

/** Create `rel` (a `/`-separated path) under the fixture root, with content. */
function write(rel) {
  const abs = join(dir, ...rel.split("/"));
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, "clean prose\n");
  return rel;
}

// Context Claude Code loads: root + nested instruction files, the `.claude`
// tree's own markdown, and one deep file inside every whitelisted subdirectory.
const SCANNED = [
  write("CLAUDE.md"),
  write("CLAUDE.local.md"),
  write("AGENTS.md"),
  write("packages/foo/CLAUDE.md"),
  write(".claude/notes.md"),
  // A directory-scoped skill: `**` never descends into a dot directory, so this
  // only turns up if the nested `.claude` patterns are present.
  write("packages/foo/.claude/skills/scoped/SKILL.md"),
  ...CLAUDE_CONTEXT_SUBDIRS.map((sub) =>
    write(`.claude/${sub}/nested/deep/file.md`),
  ),
];

// Bulk data that lives under `.claude/` but is never loaded as context. The
// worktree entries are the reported 30-second startup: a full repo checkout,
// instruction files and all.
const NOT_SCANNED = [
  write(".claude/worktrees/wt/CLAUDE.md"),
  write(".claude/worktrees/wt/docs/guide.md"),
  write(".claude/worktrees/wt/.claude/skills/s/SKILL.md"),
  write(".claude/projects/session-transcript.md"),
  write(".claude/todos/notes.md"),
  write("node_modules/pkg/CLAUDE.md"),
  write("node_modules/pkg/.claude/skills/s/SKILL.md"),
];

describe("SessionStart scan scope", () => {
  const targets = new Set(
    scanProject(dir).targets.map((abs) =>
      abs
        .slice(dir.length + 1)
        .split(sep)
        .join("/"),
    ),
  );

  it("scans every context file, and nothing else", () => {
    assert.deepEqual([...targets].sort(), [...SCANNED].sort());
  });

  // Named per file so a regression says WHICH directory stopped being scanned,
  // and so the whitelist cannot shrink without a test failing.
  for (const rel of SCANNED)
    it(`scans ${rel}`, () => assert.ok(targets.has(rel)));

  for (const rel of NOT_SCANNED)
    it(`skips ${rel}`, () => assert.ok(!targets.has(rel)));

  it("has a non-empty whitelist driving those cases", () => {
    assert.ok(CLAUDE_CONTEXT_SUBDIRS.length > 0);
  });
});
