/**
 * The context scope as a LIBRARY value: the glob set, the prune predicate and
 * the scope falsifier, exercised through the public door.
 *
 * `test/claude-hooks-scan-scope.test.mjs` pins the hook's behavior over a real
 * fixture tree; this file pins the same scope through the public door, because
 * the whole point of the extraction is that a CLI, the Python port or a fork can
 * take Claude Code's exact scope instead of approximating it. The two halves it
 * has to get right are asymmetric: an unlisted CONTEXT directory is a silent
 * hole in the scan, and an unlisted BULK directory is the 30-second session
 * start. So the cases below assert both directions, and that the composed
 * `exclude` in findInstructionFiles ORs the caller's predicate with the built-in
 * `node_modules` prune rather than replacing either.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, sep } from "node:path";

import {
  CLAUDE_CONTEXT_KINDS,
  CLAUDE_CONTEXT_SUBDIRS,
  CLAUDE_INSTRUCTION_GLOBS,
  contextScopeContradiction,
  excludeFromContextScan,
  findInstructionFiles,
} from "../src/instructions.mjs";
import { isInsideDir } from "../src/claude-context.mjs";

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
    // Named per file first, so a failure says WHICH: a missing context file is
    // a hole in the scan, an included bulk file is the startup cost.
    for (const path of CONTEXT)
      assert.ok(found.includes(path), `missing ${path}`);
    for (const path of BULK)
      assert.ok(!found.includes(path), `swept in ${path}`);
    assert.deepEqual(found, [...CONTEXT].sort());
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

  it("bounds where a scanner may rewrite to inside the scan root", () => {
    // The predicate both instruction scanners gate their auto-clean on: a file
    // above the root is shared with every project under it, so it is reported
    // and never rewritten.
    const root = join(sep, "home", "u", "proj");
    assert.equal(isInsideDir(root, join(root, "CLAUDE.md")), true);
    assert.equal(isInsideDir(root, join(root, "a", "b", "CLAUDE.md")), true);
    assert.equal(isInsideDir(root, join(sep, "home", "u", "CLAUDE.md")), false);
    // A sibling whose name merely starts with the root's is outside it, and the
    // root itself is not a file this decides about.
    assert.equal(isInsideDir(root, `${root}-other${sep}CLAUDE.md`), false);
    assert.equal(isInsideDir(root, root), false);
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

describe("what a loaded path says about the scope table", () => {
  // The InstructionsLoaded event is the only channel that can prove the table
  // wrong, and a notice that fires on ordinary loads is a notice nobody reads.
  // So each reporting case below is paired with the nearest path that must stay
  // silent, and the silent set carries every kind the event is known to name.
  const SILENT = [
    ["the project's own memory file", join(sep, "p", "CLAUDE.md")],
    ["a nested memory file", join(sep, "p", "packages", "foo", "CLAUDE.md")],
    ["a local memory file", join(sep, "p", "CLAUDE.local.md")],
    ["the user-global memory file", join(sep, "u", ".claude", "CLAUDE.md")],
    ["a project rule", join(sep, "p", ".claude", "rules", "style.md")],
    ["a nested rule", join(sep, "p", ".claude", "rules", "deep", "x.md")],
    ["a user-global rule", join(sep, "u", ".claude", "rules", "x.md")],
    // An `@import` names a file of the user's choosing. The table claims
    // nothing about it, and guessing would report on every session that uses
    // one — the fail-open that keeps this notice worth reading.
    ["an @import of arbitrary markdown", join(sep, "p", "docs", "style.md")],
    ["a source file", join(sep, "p", "src", "main.js")],
    // A memory file inside a pruned directory is still a memory file: judging
    // it by the directory would report `worktrees/` as newly-loading context.
    [
      "a memory file inside a worktree checkout",
      join(sep, "p", ".claude", "worktrees", "wt", "CLAUDE.md"),
    ],
    // The two bulk directories by name, on files the dir-file rule does NOT
    // rescue: asking for storage to be whitelisted is asking for the whole-tree
    // walk back, so these reach the reporting branch and must still say nothing.
    [
      "a note inside a worktree checkout",
      join(sep, "p", ".claude", "worktrees", "wt", "docs", "notes.md"),
    ],
    [
      "a session transcript",
      join(sep, "u", ".claude", "projects", "proj", "transcript.md"),
    ],
  ];

  for (const [label, path] of SILENT)
    it(`says nothing about ${label}`, () => {
      assert.equal(contextScopeContradiction(path), null);
    });

  it("reports a `.claude/` subdirectory the whitelist does not carry", () => {
    // The drift that matters: context loading out of a directory the launch
    // scan prunes, so every OTHER file in it is unscanned at session start.
    const notice = contextScopeContradiction(
      join(sep, "p", ".claude", "policies", "house.md"),
    );
    assert.match(notice, /\.claude\/policies\//u);
    assert.match(notice, /CLAUDE_CONTEXT_SUBDIRS/u);
  });

  for (const [label, path, named] of [
    [
      "a nested AGENTS.md",
      join(sep, "p", "packages", "foo", "AGENTS.md"),
      "AGENTS.md",
    ],
    ["a skill", join(sep, "p", ".claude", "skills", "s", "SKILL.md"), "skills"],
    [
      "a loose .claude note",
      join(sep, "p", ".claude", "notes.md"),
      ".claude/*.md",
    ],
  ])
    it(`reports ${label}, a kind the table marks event-blind`, () => {
      // Not a hole — the lazy scan just covered it — but the table and the docs
      // built on it now understate what the event reaches.
      const notice = contextScopeContradiction(path);
      assert.match(notice, /InstructionsLoaded named/u);
      assert.ok(notice.includes(named), `${notice} does not name ${named}`);
    });

  it("judges a directory-scoped skill by its own `.claude`, not the tree above it", () => {
    // Innermost wins for naming a kind: this file IS a skill, whatever pruned
    // directory it sits under, and reporting it as a `worktrees` finding would
    // send the reader to add bulk data to the whitelist.
    const skill = join(
      sep,
      "p",
      ".claude",
      "worktrees",
      "wt",
      ".claude",
      "skills",
      "s",
      "SKILL.md",
    );
    assert.match(contextScopeContradiction(skill), /named skills/u);
    // Pruning still reads the OUTERMOST tree, or the walk it exists for stops
    // applying one level down.
    assert.equal(
      excludeFromContextScan(".claude/worktrees/wt/.claude/skills"),
      true,
    );
  });

  it("answers for every kind the table carries, and says so by name", () => {
    // Drives the table itself, so a row added without a decision about the
    // event cannot slip in unexercised. The spec per row: a bulk directory is
    // storage and always silent; every other kind is silent exactly when the
    // event is credited with it, and names itself when it is not.
    for (const row of CLAUDE_CONTEXT_KINDS) {
      const path =
        row.shape === "dir-file"
          ? join(sep, "p", row.name)
          : row.shape === "claude-md"
            ? join(sep, "p", ".claude", "note.md")
            : join(sep, "p", ".claude", row.name, "f.md");
      const silent = row.eventNamed || row.shape === "claude-bulk";
      const notice = contextScopeContradiction(path);
      assert.equal(notice === null, silent, `${path}: ${notice}`);
      if (notice) assert.ok(notice.includes(row.name), notice);
    }
  });
});
