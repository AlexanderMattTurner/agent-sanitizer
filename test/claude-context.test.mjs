/**
 * The context scope as a LIBRARY value: the glob set and the prune predicate
 * that used to live inside the SessionStart hook, where nobody else could read
 * them.
 *
 * `test/claude-hooks-scan-scope.test.mjs` pins the hook's behavior over a real
 * fixture tree; this file pins the same scope through the public door, because
 * the whole point of the extraction is that a CLI, the Python port or a fork can
 * take Claude Code's exact scope instead of approximating it. The two halves it
 * has to get right are asymmetric: an unlisted CONTEXT directory is a silent
 * hole in the scan, and an unlisted BULK directory is the 30-second session
 * start. So the cases below assert both directions, and that the composed
 * `exclude` in findInstructionFiles ANDs the caller's predicate with the
 * built-in `node_modules` prune rather than replacing either.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, sep } from "node:path";

import {
  CLAUDE_CONTEXT_SUBDIRS,
  CLAUDE_INSTRUCTION_GLOBS,
  excludeFromContextScan,
  findInstructionFiles,
} from "../src/instructions.mjs";

const dir = mkdtempSync(join(tmpdir(), "sanitizer-claude-context-"));
after(() => rmSync(dir, { recursive: true, force: true }));

/** Create `rel` (a `/`-separated path) under the fixture root. */
function write(rel) {
  const abs = join(dir, ...rel.split("/"));
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, "clean prose\n");
  return rel;
}

const CONTEXT = [
  write("CLAUDE.md"),
  write("AGENTS.md"),
  write("CLAUDE.local.md"),
  write("packages/foo/CLAUDE.md"),
  write(".claude/notes.md"),
  write("packages/foo/.claude/skills/scoped/SKILL.md"),
  ...CLAUDE_CONTEXT_SUBDIRS.map((sub) => write(`.claude/${sub}/deep/file.md`)),
];

const BULK = [
  write(".claude/worktrees/wt/CLAUDE.md"),
  write(".claude/worktrees/wt/.claude/skills/s/SKILL.md"),
  write(".claude/projects/transcript.md"),
  write("node_modules/pkg/CLAUDE.md"),
];

/** Fixture-relative, `/`-separated paths from an absolute-path result list. */
const rel = (paths) =>
  paths
    .map((abs) =>
      abs
        .slice(dir.length + 1)
        .split(sep)
        .join("/"),
    )
    .sort();

describe("the exported Claude Code context scope", () => {
  it("finds exactly the context files through the public API", () => {
    const found = rel(
      findInstructionFiles([...CLAUDE_INSTRUCTION_GLOBS], {
        cwd: dir,
        exclude: excludeFromContextScan,
      }),
    );
    assert.deepEqual(found, [...CONTEXT].sort());
    // Spelled out separately from the deepEqual so a failure names the file:
    // a missing context file is a hole in the scan, an included bulk file is
    // the startup cost.
    for (const path of CONTEXT)
      assert.ok(found.includes(path), `missing ${path}`);
    for (const path of BULK)
      assert.ok(!found.includes(path), `swept in ${path}`);
  });

  it("judges bare names and root-relative paths alike", () => {
    assert.equal(excludeFromContextScan("node_modules"), true);
    // A bare directory name carries no `.claude` context, so it is judged only
    // against node_modules — a walker hands both forms to the same predicate.
    assert.equal(excludeFromContextScan("worktrees"), false);
    assert.equal(excludeFromContextScan(".claude/worktrees"), true);
    assert.equal(excludeFromContextScan(".claude"), false);
    assert.equal(excludeFromContextScan(".claude/notes.md"), false);
    assert.equal(excludeFromContextScan(".claude\\worktrees"), true);
    for (const sub of CLAUDE_CONTEXT_SUBDIRS)
      assert.equal(excludeFromContextScan(`.claude/${sub}`), false);
  });

  it("keeps pruning node_modules when a caller supplies its own exclude", () => {
    // The composed predicate is an OR: a caller-supplied scope narrows the walk,
    // it never re-opens node_modules. Without the OR, passing any exclude at all
    // would silently restore the walk this whitelist exists to prevent.
    const found = rel(
      findInstructionFiles(["**/CLAUDE.md"], {
        cwd: dir,
        exclude: (entry) => entry === "packages",
      }),
    );
    assert.deepEqual(found, ["CLAUDE.md"]);
  });

  it("still prunes node_modules with no exclude at all", () => {
    const found = rel(findInstructionFiles(["**/CLAUDE.md"], { cwd: dir }));
    assert.ok(found.includes("packages/foo/CLAUDE.md"));
    assert.ok(!found.some((path) => path.startsWith("node_modules/")));
  });

  it("exports frozen data, so no consumer can edit the shared scope", () => {
    assert.ok(Object.isFrozen(CLAUDE_CONTEXT_SUBDIRS));
    assert.ok(Object.isFrozen(CLAUDE_INSTRUCTION_GLOBS));
    // Every whitelisted subdirectory has a glob, and the nested-`.claude`
    // prefix is present: `**` alone never descends into a dot directory, so a
    // pattern set without it misses directory-scoped skills entirely.
    for (const sub of CLAUDE_CONTEXT_SUBDIRS)
      assert.ok(
        CLAUDE_INSTRUCTION_GLOBS.includes(`**/.claude/${sub}/**/*.md`),
        `no glob for ${sub}`,
      );
  });
});
