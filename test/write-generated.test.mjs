/**
 * `writeGenerated` is what keeps `pnpm gen:unicode` (fired by `prepack`, i.e. by
 * `test/package-exports.test.mjs`'s `npm pack`) from truncating a generated
 * module while a parallel suite is importing it. These tests pin the helper's
 * behaviour and, because the fix only holds if no generator bypasses it, assert
 * that every `scripts/gen-*.mjs` writes through it.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";

import { writeGenerated } from "../scripts/lib/write-generated.mjs";

const ROOT = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();

describe("writeGenerated", () => {
  /** @type {string} */
  let dir;
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "write-generated-"));
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("creates a missing file with mode 0644 and reports a write", () => {
    const path = join(dir, "new.mjs");
    assert.equal(writeGenerated(path, "export const a = 1;\n"), true);
    assert.equal(readFileSync(path, "utf8"), "export const a = 1;\n");
    assert.equal(statSync(path).mode & 0o7777, 0o644);
    assert.deepEqual(
      readdirSync(dir).filter((n) => n.endsWith(".tmp")),
      [],
    );
  });

  it("does not touch a file that already holds exactly these bytes", () => {
    const path = join(dir, "same.mjs");
    writeFileSync(path, "same\n");
    const past = new Date(1_000_000_000_000);
    utimesSync(path, past, past);
    const before = statSync(path);
    assert.equal(writeGenerated(path, "same\n"), false);
    const after = statSync(path);
    assert.equal(after.ino, before.ino);
    assert.equal(after.mtimeMs, before.mtimeMs);
  });

  it("replaces changed bytes in full, leaving no temp sibling", () => {
    const path = join(dir, "changed.mjs");
    writeFileSync(path, "old contents that are longer than the new ones\n");
    assert.equal(writeGenerated(path, "new\n"), true);
    assert.equal(readFileSync(path, "utf8"), "new\n");
    assert.deepEqual(
      readdirSync(dir).filter((n) => n.endsWith(".tmp")),
      [],
    );
  });

  it("swaps by rename: the old inode is never opened for writing", () => {
    const path = join(dir, "inode.mjs");
    writeFileSync(path, "before\n");
    const oldIno = statSync(path).ino;
    writeGenerated(path, "after\n");
    // A truncate-then-write would keep the inode and expose an empty file.
    assert.notEqual(statSync(path).ino, oldIno);
  });

  it("preserves an existing file's mode", () => {
    const path = join(dir, "mode.sh");
    writeFileSync(path, "#!/bin/sh\n");
    chmodSync(path, 0o755);
    writeGenerated(path, "#!/bin/sh\necho hi\n");
    assert.equal(statSync(path).mode & 0o7777, 0o755);
  });

  it("compares bytes, not decoded text", () => {
    const path = join(dir, "bytes.mjs");
    writeFileSync(path, Buffer.from([0xff, 0xfe]));
    // A lossy utf8 read decodes both bytes to U+FFFD, so a text comparison
    // would wrongly call this file already up to date.
    assert.equal(writeGenerated(path, "\uFFFD\uFFFD"), true);
    assert.equal(readFileSync(path, "utf8"), "\uFFFD\uFFFD");
  });

  it("swaps by rename without fsync, which Windows rejects on a directory", () => {
    const source = readFileSync(
      join(ROOT, "scripts/lib/write-generated.mjs"),
      "utf8",
    );
    assert.match(source, /\brenameSync\(tmp, path\)/);
    assert.doesNotMatch(source, /\bfsyncSync\b|from "[^"]*atomic-replace/);
  });

  it("throws when the directory is missing instead of creating it", () => {
    assert.throws(() => writeGenerated(join(dir, "nope", "x.json"), "{}"), {
      code: "ENOENT",
    });
  });
});

describe("generator output writes", () => {
  const generators = execFileSync("git", ["ls-files", "scripts/gen-*.mjs"], {
    cwd: ROOT,
    encoding: "utf8",
  })
    .split("\n")
    .filter((f) => f && f !== "scripts/gen-unicode.mjs");

  it("enumerates the generators (guards against a vacuous pass)", () => {
    assert.ok(generators.length >= 9, generators.join(", "));
    assert.ok(generators.includes("scripts/gen-cf-charset.mjs"));
    assert.ok(generators.includes("scripts/gen-unicode-properties.mjs"));
  });

  for (const rel of generators) {
    it(`${rel} writes only through writeGenerated`, () => {
      const source = readFileSync(join(ROOT, rel), "utf8");
      assert.doesNotMatch(
        source,
        /\bwrite(?:File)?Sync\b|\bwriteFile\b|\bcreateWriteStream\b|\bappendFile/,
        "a bare fs write truncates the output in place; use writeGenerated",
      );
      assert.match(source, /\bwriteGenerated\(/, "no writeGenerated call");
      assert.match(
        source,
        /import \{ writeGenerated \} from "\.\/lib\/write-generated\.mjs";/,
      );
    });
  }
});
