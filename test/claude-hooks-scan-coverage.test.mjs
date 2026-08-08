/**
 * The SessionStart scan accounts for every file it was asked to look at.
 *
 * The scan is the only thing between a poisoned `CLAUDE.md` and a session that
 * loads it as instructions, and it announces `outcome: "clean"` on the trace
 * channel — the channel whose whole purpose is that a MISSING announcement is
 * loud. A per-file read error swallowed into an empty findings list turned "we
 * could not read this file" into "this file is fine", and the announcement said
 * clean. Every target the finder returned is therefore either SCANNED or listed
 * as SKIPPED, and a skip is never reported as cleanliness.
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Set before the hook imports: the scanner walks CLAUDE_PROJECT_DIR and
// REWRITES the contaminated instruction files it finds, so pointing it at this
// repo would let the test edit the tree.
const projectDir = mkdtempSync(join(tmpdir(), "sanitizer-coverage-proj-"));
process.env.CLAUDE_PROJECT_DIR = projectDir;

const scanInvisible = await import("../claude-hooks/scan-invisible-chars.mjs");
const { scanProject, findInstructionFiles, findMdFiles, ALERT_FILE, cliMain } =
  scanInvisible;

/** A target the finder lists but nothing can read: a dangling symlink. */
function dangling(dir, name) {
  symlinkSync(join(dir, "no-such-target"), join(dir, name));
}

/** The trace lines a run emitted, in order. */
function collector() {
  const lines = [];
  return {
    lines,
    sink: (event, fields) => lines.push({ event, ...fields }),
  };
}

describe("scanProject accounts for every target the finder returned", () => {
  it("reports on found + skipped == the finder's list", () => {
    const dir = mkdtempSync(join(tmpdir(), "sanitizer-coverage-"));
    writeFileSync(join(dir, "AGENTS.md"), "plain, clean prose\n");
    dangling(dir, "CLAUDE.md");
    mkdirSync(join(dir, ".claude"));
    writeFileSync(join(dir, ".claude", "notes.md"), "also clean\n");

    const { targets, scanned, findings, skipped } = scanProject(dir);
    const expectedTargets = new Set([
      ...findInstructionFiles(dir),
      ...findMdFiles(join(dir, ".claude")),
    ]);
    assert.equal(targets.length, expectedTargets.size);
    assert.ok(targets.length > 0, "the finder returned nothing to account for");
    // The invariant: nothing falls off the list.
    assert.equal(scanned + skipped.length, targets.length);
    assert.deepEqual(
      skipped.map((s) => s.file),
      ["CLAUDE.md"],
    );
    assert.deepEqual(findings, []);
    rmSync(dir, { recursive: true, force: true });
  });

  it("holds when EVERY target is unreadable", () => {
    const dir = mkdtempSync(join(tmpdir(), "sanitizer-coverage-none-"));
    dangling(dir, "CLAUDE.md");
    dangling(dir, "AGENTS.md");

    const { targets, scanned, findings, skipped } = scanProject(dir);
    assert.equal(targets.length, 2);
    assert.equal(scanned, 0);
    assert.deepEqual(findings, []);
    assert.equal(skipped.length, targets.length);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("a scan that could not read a target never announces clean", () => {
  before(() => {
    dangling(projectDir, "CLAUDE.md");
    rmSync(ALERT_FILE, { force: true });
  });
  after(() => rmSync(ALERT_FILE, { force: true }));

  it("announces partial, names the skipped files, and arms the gate", async () => {
    const { lines, sink } = collector();
    await cliMain({ trace: sink });

    const announced = lines.filter(
      (l) => l.event === "scan_invisible_chars_ran",
    );
    assert.equal(announced.length, 1);
    assert.equal(
      announced[0].outcome,
      "partial",
      "an unread instruction file was reported as absence of findings",
    );
    assert.equal(announced[0].skipped, 1);
    assert.equal(announced[0].scanned, 0);

    // The gate is the enforcement: it asks once on the next tool call, so an
    // unvetted instruction file reaches the operator instead of nobody.
    assert.ok(existsSync(ALERT_FILE), "the PreToolUse gate was not armed");
    assert.match(readFileSync(ALERT_FILE, "utf8"), /CLAUDE\.md/u);
  });
});

describe("a fully readable project still announces clean", () => {
  it("does not arm the gate when nothing was missed", async () => {
    // The positive marker: without it, a test asserting "not clean" would pass
    // just as happily against a scan that never says clean at all.
    const dir = mkdtempSync(join(tmpdir(), "sanitizer-coverage-ok-"));
    writeFileSync(join(dir, "CLAUDE.md"), "nothing hidden here\n");
    const { scanned, skipped, findings } = scanProject(dir);
    assert.equal(skipped.length, 0);
    assert.equal(scanned, 1);
    assert.deepEqual(findings, []);
    rmSync(dir, { recursive: true, force: true });
  });
});
