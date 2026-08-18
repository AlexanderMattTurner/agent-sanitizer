/**
 * The cross-hook alert store, as the two hooks that share it actually use it.
 *
 * Both of the defects pinned here were silent losses of a security signal, not
 * crashes: a session inheriting a previous session's acknowledgement degrades
 * the gate's one blocking ask to a passive note nobody reads, and a lost
 * concurrent append drops a finding the gate would have asked about. The store
 * is keyed by (project, session) and holds one file per finding precisely so
 * neither state is constructible.
 */
import { describe, it, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

// Set before the hook module loads: the store paths are keyed to it.
const projectDir = mkdtempSync(join(tmpdir(), "sanitizer-alert-store-"));
process.env.CLAUDE_PROJECT_DIR = projectDir;

const {
  acknowledgeAlert,
  alertAckFile,
  alertAcknowledged,
  alertDir,
  appendAlert,
  invisibleCharAlert,
} = await import("../claude-hooks/lib/invisible-alert.mjs");

const SESSIONS = ["sess-alpha", "sess-beta"];

function clear() {
  for (const id of [...SESSIONS, undefined]) {
    rmSync(alertDir(id), { recursive: true, force: true });
    rmSync(alertAckFile(id), { force: true });
  }
}

beforeEach(clear);
after(() => {
  clear();
  rmSync(projectDir, { recursive: true, force: true });
});

describe("a session cannot inherit another session's answer", () => {
  it("keys the findings by session", () => {
    appendAlert("alpha's finding", SESSIONS[0]);
    assert.match(invisibleCharAlert(SESSIONS[0]), /alpha's finding/u);
    assert.equal(invisibleCharAlert(SESSIONS[1]), null);
  });

  it("keys the acknowledgement by session, so the next session re-asks", () => {
    // The defect this replaces: the ack was keyed by PROJECT and reset by a
    // destructive clear at SessionStart, so any path that skipped the clear (a
    // scanner that exits early on a dep-load failure) left the new session
    // reading the previous one's answer — the blocking ask silently degraded to
    // a passive reminder for the whole session.
    appendAlert("still-injected CLAUDE.md", SESSIONS[0]);
    acknowledgeAlert(SESSIONS[0]);
    assert.equal(alertAcknowledged(SESSIONS[0]), true);

    appendAlert("still-injected CLAUDE.md", SESSIONS[1]);
    assert.equal(
      alertAcknowledged(SESSIONS[1]),
      false,
      "a fresh session inherited the previous session's acknowledgement",
    );
  });

  it("needs no clear to start empty", () => {
    // The whole point of session-keying: nothing has to run, in any order, for
    // a new session's store to be empty. SessionStart is not ordered against
    // the InstructionsLoaded events fired for the files loaded at launch, so a
    // clear could erase a finding recorded moments earlier.
    appendAlert("a past session's finding", SESSIONS[0]);
    assert.equal(invisibleCharAlert(SESSIONS[1]), null);
    assert.equal(
      invisibleCharAlert(SESSIONS[0]),
      "a past session's finding",
      "the older session's own store was disturbed",
    );
  });
});

describe("concurrent findings cannot lose each other", () => {
  it("keeps every finding recorded in one session", () => {
    // The defect this replaces: a lockless read-modify-write on ONE file, so
    // two hooks recording a finding at the same time kept only the later
    // write's view. One O_EXCL file per finding has no shared cell to lose.
    const findings = Array.from({ length: 25 }, (_, i) => `finding-${i}`);
    for (const text of findings) appendAlert(text, SESSIONS[0]);
    const alert = invisibleCharAlert(SESSIONS[0]);
    for (const text of findings)
      assert.match(alert, new RegExp(`\\b${text}\\b`, "u"));
  });

  it("gives each finding its own file", () => {
    // Non-vacuity for the assertion above: it would also pass on a single
    // appended file, which is exactly the shape that loses updates.
    appendAlert("one", SESSIONS[0]);
    appendAlert("two", SESSIONS[0]);
    assert.equal(readdirSync(alertDir(SESSIONS[0])).length, 2);
  });

  it("reports the loss on stderr when a finding cannot be recorded", () => {
    // Fail loudly: the write returning false used to be discarded by both
    // callers, so a finding that never landed left no trace anywhere.
    const written = [];
    const realWrite = process.stderr.write;
    // @ts-expect-error -- test double for the stderr channel
    process.stderr.write = (chunk) => (written.push(String(chunk)), true);
    let recorded;
    try {
      // A FILE where the store's directory must go: mkdir fails, so no finding
      // can be recorded under it.
      writeFileSync(alertDir(SESSIONS[1]), "");
      recorded = appendAlert("a finding with nowhere to go", SESSIONS[1]);
    } finally {
      process.stderr.write = realWrite;
      rmSync(alertDir(SESSIONS[1]), { force: true });
    }
    assert.equal(recorded, false);
    assert.match(
      written.join(""),
      /could not record an instruction-file finding/u,
    );
  });
});

describe("the store refuses what it does not own", () => {
  it("reads nothing through a symlinked store directory", () => {
    // The store path is predictable and world-visible. Followed, a symlink
    // planted there would let a co-tenant aim the gate's reader at a directory
    // of unrelated files this uid owns and splice their bytes into a permission
    // prompt.
    const decoy = mkdtempSync(join(tmpdir(), "sanitizer-alert-decoy-"));
    writeFileSync(join(decoy, "planted"), "attacker text");
    symlinkSync(decoy, alertDir(SESSIONS[0]));
    try {
      assert.equal(invisibleCharAlert(SESSIONS[0]), null);
    } finally {
      rmSync(alertDir(SESSIONS[0]), { force: true });
      rmSync(decoy, { recursive: true, force: true });
    }
  });

  it("still has a real store to read when nothing is planted", () => {
    // Non-vacuity for the refusal above: the same call DOES return findings
    // from a store this uid actually created.
    appendAlert("a genuine finding", SESSIONS[0]);
    assert.ok(existsSync(alertDir(SESSIONS[0])));
    assert.match(invisibleCharAlert(SESSIONS[0]), /a genuine finding/u);
  });
});
