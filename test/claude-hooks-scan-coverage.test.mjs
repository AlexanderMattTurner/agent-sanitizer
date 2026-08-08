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
const {
  scanProject,
  findInstructionFiles,
  findMdFiles,
  ALERT_FILE,
  LONG_RUN_THRESHOLD,
  cliMain,
} = scanInvisible;

// Same reason as in claude-hooks-posture.test.mjs: an unreadable fixture left
// under $TMPDIR is an unscannable instruction file for every suite whose
// project dir is $TMPDIR.
after(() => {
  rmSync(projectDir, { recursive: true, force: true });
  rmSync(ALERT_FILE, { force: true });
});

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
  // The control for the describe above. It must drive cliMain and inspect the
  // same two observables — the announced outcome and ALERT_FILE — or "never
  // announces clean" would pass just as happily against a scan that never says
  // clean at all, or one that arms the gate unconditionally.
  before(() => {
    // PROJECT_DIR resolved at module load, so the control has to repair the
    // project the previous describe sabotaged rather than point somewhere else.
    rmSync(join(projectDir, "CLAUDE.md"), { force: true });
    writeFileSync(join(projectDir, "CLAUDE.md"), "nothing hidden here\n");
    rmSync(ALERT_FILE, { force: true });
  });
  after(() => rmSync(ALERT_FILE, { force: true }));

  it("announces clean and does not arm the gate", async () => {
    const { lines, sink } = collector();
    await cliMain({ trace: sink });

    assert.deepEqual(
      lines
        .filter((l) => l.event === "scan_invisible_chars_ran")
        .map((l) => l.outcome),
      ["clean"],
    );
    assert.equal(
      existsSync(ALERT_FILE),
      false,
      "the gate was armed on a project with nothing to report",
    );
    // And the accounting agrees: every target read, nothing skipped.
    const { targets, scanned, skipped, findings } = scanProject(projectDir);
    assert.equal(scanned, targets.length);
    assert.deepEqual(skipped, []);
    assert.deepEqual(findings, []);
  });
});

describe("a contaminated project is cleaned on disk and reported", () => {
  // The `found` outcome — the third arm, and the only one that reaches the
  // auto-clean path. It went untested, which is how a clean-counting condition
  // that was vacuously TRUE for every file (`cleanFile(…) !== null`, on a
  // function with no null return) shipped: it made "all N cleaned" unfalsifiable,
  // so the alert arm below became unreachable and nothing noticed.
  const payload = "\u{e0001}".repeat(LONG_RUN_THRESHOLD + 2);
  const clean = "real prose the strip must keep\n";

  before(() => {
    writeFileSync(join(projectDir, "CLAUDE.md"), `${clean}hidden:${payload}\n`);
    rmSync(ALERT_FILE, { force: true });
  });
  after(() => {
    writeFileSync(join(projectDir, "CLAUDE.md"), "nothing hidden here\n");
    rmSync(ALERT_FILE, { force: true });
  });

  it("announces found, strips the payload, and leaves the prose", async () => {
    const { lines, sink } = collector();
    await cliMain({ trace: sink });

    const announced = lines.filter(
      (l) => l.event === "scan_invisible_chars_ran",
    );
    assert.deepEqual(
      announced.map((l) => l.outcome),
      ["found"],
    );
    assert.equal(announced[0].files, 1);

    // The clean actually happened, through cleanFile's atomic replace.
    const after = readFileSync(join(projectDir, "CLAUDE.md"), "utf8");
    assert.equal(after.includes("\u{e0001}"), false, "payload survived");
    assert.ok(after.startsWith(clean), "legitimate prose was mangled");

    // Everything was cleaned, so there is nothing for the gate to ask about.
    // This is the assertion the tautology made unfalsifiable in the other
    // direction — pair it with the re-scan below so "no alert" cannot mean
    // "the scan quietly did nothing".
    assert.equal(
      existsSync(ALERT_FILE),
      false,
      "the gate was armed even though every file was cleaned",
    );
    assert.deepEqual(scanProject(projectDir).findings, []);
  });

  it("counts a file it did NOT clean as uncleaned, and arms the gate", async () => {
    // Drive the alert arm directly: a findings entry naming a file that is
    // already clean makes cleanFile return false (nothing to strip), which must
    // leave `cleaned` short of the findings count and route to the alert. Under
    // the `!== null` tautology this file counted as cleaned and the gate stayed
    // silent about a payload nothing had removed.
    writeFileSync(join(projectDir, "AGENTS.md"), clean);
    rmSync(ALERT_FILE, { force: true });
    const { sink } = collector();
    await cliMain({
      trace: sink,
      scan: () => ({
        targets: [join(projectDir, "AGENTS.md")],
        scanned: 1,
        skipped: [],
        findings: [
          {
            file: "AGENTS.md",
            findings: [
              {
                line: 1,
                charCount: LONG_RUN_THRESHOLD,
                method: "invisible Unicode sequence",
                decoded: "U+E0001",
              },
            ],
          },
        ],
      }),
    });

    assert.ok(
      existsSync(ALERT_FILE),
      "a file that could not be cleaned did not arm the gate",
    );
    assert.match(readFileSync(ALERT_FILE, "utf8"), /AGENTS\.md/u);
    rmSync(join(projectDir, "AGENTS.md"), { force: true });
  });
});
