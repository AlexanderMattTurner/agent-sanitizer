/**
 * The globSync workaround for nodejs/node#61012, driven at an affected Node
 * version whatever Node runs the suite, so CI on a fixed Node still exercises
 * the rewrite through the real walker.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  globSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  compatGlobs,
  expandDotGlobstar,
  globstarSkipsDotSegments,
} from "../src/glob-compat.mjs";

describe("globstarSkipsDotSegments", () => {
  for (const [version, affected] of [
    ["22.0.0", true],
    ["22.21.9", true],
    ["22.22.0", true],
    ["22.22.1", false],
    ["22.23.3", false],
    ["23.11.1", true],
    ["24.13.0", true],
    ["24.13.1", false],
    ["24.14.0", false],
    ["25.3.9", true],
    ["25.4.0", false],
    ["26.0.0", false],
  ])
    it(`${version} -> ${affected}`, () => {
      assert.equal(globstarSkipsDotSegments(version), affected);
    });
});

describe("expandDotGlobstar", () => {
  for (const [pattern, expected] of [
    ["**/CLAUDE.md", ["**/CLAUDE.md"]],
    [".claude/*.md", [".claude/*.md"]],
    ["**/{CLAUDE,AGENTS}.md", ["**/{CLAUDE,AGENTS}.md"]],
    ["**/.claude/*.md", [".claude/*.md", "**/*/.claude/*.md"]],
    ["src/**/.claude/*.md", ["src/.claude/*.md", "src/**/*/.claude/*.md"]],
    ["/abs/**/.x", ["/abs/.x", "/abs/**/*/.x"]],
    [
      "{**/.claude/*.md,AGENTS.md}",
      ["{.claude/*.md,AGENTS.md}", "{**/*/.claude/*.md,AGENTS.md}"],
    ],
    ["**/.a/**/.b", [".a/.b", ".a/**/*/.b", "**/*/.a/.b", "**/*/.a/**/*/.b"]],
  ])
    it(`${pattern}`, () => {
      assert.deepEqual(expandDotGlobstar(pattern), expected);
    });

  for (const pattern of [
    "**/{.claude,.cursor}/*.md",
    "**/{x,.claude}/*.md",
    "**/\\.claude/*.md",
  ])
    it(`throws on the unreachable dot segment in ${pattern}`, () => {
      assert.throws(() => expandDotGlobstar(pattern), /nodejs\/node#61012/);
    });
});

describe("compatGlobs", () => {
  it("leaves every pattern alone on a fixed Node", () => {
    const patterns = ["**/.claude/*.md", "**/{.claude,.cursor}/*.md"];
    assert.equal(compatGlobs(patterns, "22.22.1"), patterns);
  });

  it("finds every non-dot depth through the real walker on an affected Node", () => {
    const dir = mkdtempSync(join(tmpdir(), "glob-compat-"));
    try {
      for (const rel of [
        ".claude/notes.md",
        "a/b/.claude/notes.md",
        "pkg/.claude/skills/x/SKILL.md",
        ".hidden/.claude/notes.md",
      ]) {
        mkdirSync(join(dir, rel, ".."), { recursive: true });
        writeFileSync(join(dir, rel), "x");
      }
      const patterns = compatGlobs(
        ["**/.claude/*.md", "**/.claude/skills/**/*.md"],
        "22.22.0",
      );
      assert.deepEqual(globSync(patterns, { cwd: dir }).sort(), [
        ".claude/notes.md",
        "a/b/.claude/notes.md",
        "pkg/.claude/skills/x/SKILL.md",
      ]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
