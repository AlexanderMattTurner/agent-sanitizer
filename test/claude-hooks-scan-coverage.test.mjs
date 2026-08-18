/**
 * The SessionStart scan accounts for every file it was asked to look at.
 *
 * The scan is the only thing between a poisoned `CLAUDE.md` and a session that
 * loads it as instructions, and it announces `outcome: "clean"` on the trace
 * channel — the channel whose whole purpose is that a MISSING announcement is
 * loud. A per-file read error swallowed into an empty findings list turned "we
 * could not read this file" into "this file is fine", and the announcement said
 * clean. Every target the finder returned is therefore SCANNED, listed as
 * SKIPPED, or listed as ABSENT, and a skip is never reported as cleanliness.
 *
 * The three-way split matters in the other direction too: a path that resolves
 * to nothing has no content to vet, so calling it a coverage gap blocks the
 * operator over a risk that does not exist.
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { withCapturedStdout } from "./helpers/capture-stdout.mjs";

// Set before the hook imports: the scanner walks CLAUDE_PROJECT_DIR and
// REWRITES the contaminated instruction files it finds, so pointing it at this
// repo would let the test edit the tree.
const projectDir = mkdtempSync(join(tmpdir(), "sanitizer-coverage-proj-"));
process.env.CLAUDE_PROJECT_DIR = projectDir;

const scanInvisible = await import("../claude-hooks/scan-invisible-chars.mjs");
const {
  scanProject,
  findInstructionFiles,
  alertDir,
  LONG_RUN_THRESHOLD,
  cliMain,
} = scanInvisible;
const { invisibleCharAlert } =
  await import("../claude-hooks/lib/invisible-alert.mjs");

// Same reason as in claude-hooks-posture.test.mjs: an unreadable fixture left
// under $TMPDIR is an unscannable instruction file for every suite whose
// project dir is $TMPDIR.
after(() => {
  rmSync(projectDir, { recursive: true, force: true });
  rmSync(alertDir(), { recursive: true, force: true });
});

/** A target the finder lists that resolves to nothing: a dangling symlink. */
function dangling(dir, name) {
  symlinkSync(join(dir, "no-such-target"), join(dir, name));
}

/**
 * A target that EXISTS and cannot be read: a directory where a file belongs, so
 * the read fails EISDIR. Root-proof, unlike a chmod-000 fixture — CI runs as
 * uid 0, which reads a mode-000 file happily.
 */
function unreadable(dir, name) {
  mkdirSync(join(dir, name));
}

// Every scan run goes through here rather than calling cliMain directly: the
// hook's stdout envelope must not reach the real stream, which under
// `--test-reporter=tap` carries this suite's own result.
/** @param {Parameters<typeof cliMain>[0]} [opts] */
const runScan = (opts) => withCapturedStdout(() => cliMain(opts));

/** The trace lines a run emitted, in order. */
function collector() {
  const lines = [];
  return {
    lines,
    sink: (event, fields) => lines.push({ event, ...fields }),
  };
}

describe("scanProject accounts for every target the finder returned", () => {
  it("reports on found + skipped + absent == the finder's list", () => {
    const dir = mkdtempSync(join(tmpdir(), "sanitizer-coverage-"));
    writeFileSync(join(dir, "AGENTS.md"), "plain, clean prose\n");
    unreadable(dir, "CLAUDE.md");
    dangling(dir, "CLAUDE.local.md");
    mkdirSync(join(dir, ".claude"));
    writeFileSync(join(dir, ".claude", "notes.md"), "also clean\n");

    const { targets, scanned, findings, skipped, absent } = scanProject(dir);
    const expectedTargets = new Set(findInstructionFiles(dir));
    assert.equal(targets.length, expectedTargets.size);
    assert.ok(targets.length > 0, "the finder returned nothing to account for");
    // The invariant: nothing falls off the list.
    assert.equal(scanned + skipped.length + absent.length, targets.length);
    assert.deepEqual(
      skipped.map((s) => s.file),
      ["CLAUDE.md"],
    );
    // The dangling link resolves to nothing, so it is not unvetted CONTENT —
    // it is accounted for without being reported as a coverage gap.
    assert.deepEqual(absent, ["CLAUDE.local.md"]);
    assert.deepEqual(findings, []);
    rmSync(dir, { recursive: true, force: true });
  });

  it("holds when EVERY target is unreadable", () => {
    const dir = mkdtempSync(join(tmpdir(), "sanitizer-coverage-none-"));
    unreadable(dir, "CLAUDE.md");
    unreadable(dir, "AGENTS.md");

    const { targets, scanned, findings, skipped, absent } = scanProject(dir);
    assert.equal(targets.length, 2);
    assert.equal(scanned, 0);
    assert.deepEqual(findings, []);
    assert.deepEqual(absent, []);
    assert.equal(skipped.length, targets.length);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("a target that resolves to nothing is not a coverage gap", () => {
  // The false positive this bucket exists to kill: a dangling `.claude/*.md`
  // symlink — routine in a dotfiles checkout — used to be reported as an
  // instruction file "loaded but never checked for hidden Unicode", and it armed
  // the blocking gate on every session. There are no bytes behind the path, so
  // Claude Code cannot load it either: nothing reaches the model, and nothing is
  // unvetted.
  before(() => {
    rmSync(join(projectDir, "CLAUDE.md"), { recursive: true, force: true });
    writeFileSync(join(projectDir, "CLAUDE.md"), "nothing hidden here\n");
    mkdirSync(join(projectDir, ".claude"), { recursive: true });
    dangling(join(projectDir, ".claude"), "README.md");
    rmSync(alertDir(), { recursive: true, force: true });
  });
  after(() => {
    rmSync(join(projectDir, ".claude"), { recursive: true, force: true });
    rmSync(alertDir(), { recursive: true, force: true });
  });

  it("announces clean and leaves the gate unarmed", async () => {
    const { targets, scanned, skipped, absent } = scanProject(projectDir);
    assert.deepEqual(absent, [join(".claude", "README.md")]);
    assert.deepEqual(skipped, []);
    assert.equal(scanned, targets.length - 1);

    const { lines, sink } = collector();
    await runScan({ trace: sink });
    const announced = lines.filter(
      (l) => l.event === "scan_invisible_chars_ran",
    );
    assert.deepEqual(
      announced.map((l) => l.outcome),
      ["clean"],
    );
    // Announced for the record, so a real disappearing-file race is still
    // visible on the trace channel — just not as an operator-facing block.
    assert.equal(announced[0].absent, 1);
    assert.equal(
      invisibleCharAlert() !== null,
      false,
      "a dangling symlink armed the blocking gate",
    );
  });
});

describe("a scan that could not read a target never announces clean", () => {
  before(() => {
    rmSync(join(projectDir, "CLAUDE.md"), { recursive: true, force: true });
    unreadable(projectDir, "CLAUDE.md");
    rmSync(alertDir(), { recursive: true, force: true });
  });
  after(() => rmSync(alertDir(), { recursive: true, force: true }));

  it("announces partial, names the skipped files, and arms the gate", async () => {
    const { lines, sink } = collector();
    await runScan({ trace: sink });

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
    assert.ok(
      invisibleCharAlert() !== null,
      "the PreToolUse gate was not armed",
    );
    assert.match(invisibleCharAlert() ?? "", /CLAUDE\.md/u);
  });
});

describe("a fully readable project still announces clean", () => {
  // The control for the describe above. It must drive cliMain and inspect the
  // same two observables — the announced outcome and the alert store — or "never
  // announces clean" would pass just as happily against a scan that never says
  // clean at all, or one that arms the gate unconditionally.
  before(() => {
    // PROJECT_DIR resolved at module load, so the control has to repair the
    // project the previous describe sabotaged rather than point somewhere else.
    rmSync(join(projectDir, "CLAUDE.md"), { recursive: true, force: true });
    writeFileSync(join(projectDir, "CLAUDE.md"), "nothing hidden here\n");
    rmSync(alertDir(), { recursive: true, force: true });
  });
  after(() => rmSync(alertDir(), { recursive: true, force: true }));

  it("announces clean and does not arm the gate", async () => {
    const { lines, sink } = collector();
    await runScan({ trace: sink });

    assert.deepEqual(
      lines
        .filter((l) => l.event === "scan_invisible_chars_ran")
        .map((l) => l.outcome),
      ["clean"],
    );
    assert.equal(
      invisibleCharAlert() !== null,
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
    rmSync(alertDir(), { recursive: true, force: true });
  });
  after(() => {
    writeFileSync(join(projectDir, "CLAUDE.md"), "nothing hidden here\n");
    rmSync(alertDir(), { recursive: true, force: true });
  });

  it("announces found, strips the payload, and leaves the prose", async () => {
    const { lines, sink } = collector();
    await runScan({ trace: sink });

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
      invisibleCharAlert() !== null,
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
    rmSync(alertDir(), { recursive: true, force: true });
    const { sink } = collector();
    await runScan({
      trace: sink,
      scan: () => ({
        targets: [join(projectDir, "AGENTS.md")],
        scanned: 1,
        skipped: [],
        absent: [],
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
      invisibleCharAlert() !== null,
      "a file that could not be cleaned did not arm the gate",
    );
    assert.match(invisibleCharAlert() ?? "", /AGENTS\.md/u);
    rmSync(join(projectDir, "AGENTS.md"), { force: true });
  });

  it("reports a contaminated file ABOVE the project without rewriting it", async () => {
    // The parent chain is scanned (Claude Code loads it in full at launch) but
    // never auto-cleaned: that file is shared with every other project under
    // the same directory, so the hook reports it and leaves the rewrite to the
    // operator. The finding is reported by ABSOLUTE path, which is also the
    // path shape autoCleanFindings has to not re-root under the project.
    const outside = mkdtempSync(join(tmpdir(), "sanitizer-coverage-above-"));
    const above = join(outside, "CLAUDE.md");
    const contaminated = `${clean}hidden:${payload}\n`;
    writeFileSync(above, contaminated);
    rmSync(alertDir(), { recursive: true, force: true });

    const { sink } = collector();
    await runScan({
      trace: sink,
      scan: () => ({
        targets: [above],
        scanned: 1,
        skipped: [],
        absent: [],
        findings: [
          {
            file: above,
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

    assert.equal(
      readFileSync(above, "utf8"),
      contaminated,
      "a file outside the project was rewritten",
    );
    assert.ok(
      invisibleCharAlert() !== null,
      "an uncleaned file above the project did not arm the gate",
    );
    assert.match(invisibleCharAlert() ?? "", /CLAUDE\.md/u);
    rmSync(outside, { recursive: true, force: true });
  });
});
