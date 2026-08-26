/**
 * The cross-hook alert store, as the two hooks that share it actually use it.
 *
 * Every defect pinned here was a silent loss of a security signal, not a crash:
 * a session inheriting a previous session's acknowledgement degrades the gate's
 * one blocking ask to a passive note nobody reads, a lost concurrent append
 * drops a finding the gate would have asked about, and a finding with no session
 * to own it re-arms that ask for sessions that cannot act on it. The store is
 * keyed by (project, session) and holds one file per finding precisely so the
 * first two are unconstructible; the shared prefix that has no session keeps the
 * third out with a lifetime.
 */
import { describe, it, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  lutimesSync,
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
  instructionsLoadedFile,
  instructionsLoadedNoticeFile,
  instructionsLoadedSeen,
  invisibleCharAlert,
  recordInstructionsLoaded,
  sweepStaleSessions,
} = await import("../claude-hooks/lib/invisible-alert.mjs");

const SESSIONS = ["sess-alpha", "sess-beta"];

function clear() {
  for (const id of [...SESSIONS, undefined]) {
    rmSync(alertDir(id), { recursive: true, force: true });
    rmSync(alertAckFile(id), { force: true });
    rmSync(instructionsLoadedFile(id), { force: true });
    rmSync(instructionsLoadedNoticeFile(id), { force: true });
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

describe("the shared no-session fallback has a lifetime", () => {
  // A hook that faults before it can parse its payload has no session id, so
  // its finding lands under the shared prefix that no session owns. Nothing
  // clears that prefix when a session ends, so without a lifetime one such
  // finding re-arms the gate's blocking ask for every later session — and on a
  // host that exports no session id at all the ack lands there too and
  // suppresses the ask permanently. Both are the inheritance that keying by
  // session exists to make unconstructible.
  const MINUTE_MS = 60 * 1000;
  const HOUR_MS = 60 * MINUTE_MS;
  const DAY_MS = 24 * HOUR_MS;

  /** Backdate an artifact by `ms`, following no symlink. */
  function ageBy(path, ms) {
    const past = (Date.now() - ms) / 1000;
    lutimesSync(path, past, past);
  }

  /** Backdate an artifact past any plausible fallback lifetime. */
  function age(path) {
    ageBy(path, HOUR_MS);
  }

  /** The one file appendAlert just wrote under the shared prefix. */
  function soleFallbackEntry() {
    const names = readdirSync(alertDir());
    assert.equal(names.length, 1, "expected exactly one fallback finding");
    return join(alertDir(), names[0]);
  }

  it("surfaces a fresh fallback finding to the session running now", () => {
    // Non-vacuity control for the expiry below: the fallback is READ, so the
    // expiry cases fail for the lifetime and not because nothing is spliced in.
    appendAlert("a fault with no session id");
    assert.match(
      invisibleCharAlert(SESSIONS[0]),
      /a fault with no session id/u,
    );
  });

  it("still surfaces a fallback finding just inside the lifetime", () => {
    // Pins the lifetime's LOWER bound: a launch-time fault has to reach the
    // session's first tool call, which can be many minutes later. A TTL mistyped
    // in seconds passes every other case here and fails this one.
    appendAlert("a fault 29 minutes ago");
    ageBy(soleFallbackEntry(), 29 * MINUTE_MS);
    assert.match(invisibleCharAlert(SESSIONS[0]), /a fault 29 minutes ago/u);
  });

  it("does not surface an expired fallback finding to a later session", () => {
    appendAlert("a fault from a session that ended days ago");
    age(soleFallbackEntry());
    assert.equal(
      invisibleCharAlert(SESSIONS[1]),
      null,
      "a later session inherited a fallback finding it cannot act on",
    );
  });

  it("expires the ack on a host that exports no session id", () => {
    // There every session shares the fallback prefix, so an ack that never
    // expires degrades the one-time blocking ask to the passive reminder for
    // the life of the machine.
    appendAlert("a finding on a host with no session id");
    acknowledgeAlert();
    assert.equal(alertAcknowledged(), true, "the ack did not take at all");
    age(alertAckFile());
    assert.equal(
      alertAcknowledged(),
      false,
      "the gate stayed acknowledged, so it can never ask again",
    );
  });

  it("keeps a session-keyed ack, however old", () => {
    // The lifetime is the fallback's alone: a real session's ack ends with the
    // session, so ageing it must not make the gate re-ask mid-session.
    acknowledgeAlert(SESSIONS[0]);
    age(alertAckFile(SESSIONS[0]));
    assert.equal(alertAcknowledged(SESSIONS[0]), true);
  });

  it("sweeps the expired fallback artifacts off disk", () => {
    // The read bound alone would leave the bytes in $TMPDIR forever on a host
    // with no session id, where the stale-session loop skips the prefix as the
    // current session's own.
    appendAlert("an expired finding");
    const entry = soleFallbackEntry();
    acknowledgeAlert();
    age(entry);
    age(alertAckFile());
    sweepStaleSessions(SESSIONS[0]);
    assert.equal(existsSync(entry), false, "the expired finding was kept");
    assert.equal(existsSync(alertAckFile()), false, "the expired ack was kept");
  });

  it("keeps fresh fallback artifacts through a sweep", () => {
    // Non-vacuity for the sweep above: it must age entries out, not empty the
    // store on every InstructionsLoaded fire.
    appendAlert("a finding recorded moments ago");
    const entry = soleFallbackEntry();
    acknowledgeAlert();
    sweepStaleSessions(SESSIONS[0]);
    assert.equal(existsSync(entry), true);
    assert.equal(existsSync(alertAckFile()), true);
  });

  it("leaves an expired entry it does not own", () => {
    // The store's path is predictable, so a co-tenant can plant an entry in it.
    // The sweep unlinks by path, so without the ownership check it would delete
    // whatever a planted symlink names — a file of the victim's this uid owns.
    appendAlert("a real finding");
    const decoy = mkdtempSync(join(tmpdir(), "sanitizer-alert-decoy-"));
    const target = join(decoy, "unrelated");
    writeFileSync(target, "the victim's own file");
    const planted = join(alertDir(), "planted");
    try {
      symlinkSync(target, planted);
      ageBy(planted, HOUR_MS);
      sweepStaleSessions(SESSIONS[0]);
      assert.equal(existsSync(target), true, "the sweep followed a symlink");
      assert.equal(
        existsSync(planted),
        true,
        "the sweep removed a foreign entry",
      );
    } finally {
      rmSync(decoy, { recursive: true, force: true });
    }
  });

  it("keeps an InstructionsLoaded marker the fallback lifetime has passed", () => {
    // The lifetime governs findings and the ack only. This marker answers "did a
    // scan run at all", so expiring it mid-session would render the gap notice
    // on a session that WAS scanned.
    // Swept from the session-less host itself, which is the only configuration
    // where these markers are at risk: with a real session id the loop over the
    // other prefixes reaps them at the stale-session age instead.
    recordInstructionsLoaded();
    age(instructionsLoadedFile());
    sweepStaleSessions();
    assert.equal(instructionsLoadedSeen(), true);
  });

  it("sweeps an InstructionsLoaded marker at the stale-session age", () => {
    // Non-vacuity for the case above, and the leak it closes: that loop skips
    // the CURRENT session's prefix, which on a session-less host is this one, so
    // without this nothing ever removes these two markers there.
    recordInstructionsLoaded();
    ageBy(instructionsLoadedFile(), 8 * DAY_MS);
    sweepStaleSessions();
    assert.equal(instructionsLoadedSeen(), false);
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
    // Fail loudly: a caller that discards the write's false return leaves a
    // finding that never landed with no trace anywhere.
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

/**
 * The reason this reader produces is spliced into a permissionDecisionReason, so
 * it must carry no Layer-1 payload. Note what this path does NOT need to prove:
 * the store is a UTF-8 FILE, so `readFileSync` has already mapped any planted
 * lone surrogate to U+FFFD before the scrubber sees it. A surrogate assertion
 * here would pass whatever `invisible-alert.mjs` injects, so the injected
 * function's own obligation is pinned in claude-hooks-host-seams.test.mjs.
 */
describe("the alert reason is scrubbed before it reaches a reason field", () => {
  it("strips Layer-1 payloads through the injected seam", () => {
    appendAlert("vis\u200Bible\u001B[31mred\u001B[0m", SESSIONS[0]);
    const reason = invisibleCharAlert(SESSIONS[0]);
    // Positive marker first: the finding really came back, so each absence
    // below is a strip and not an empty read.
    assert.match(reason, /visiblered/u);
    assert.ok(!reason.includes("\u200B"), "zero-width space survived");
    assert.ok(!reason.includes("\u001B"), "ANSI introducer survived");
  });
});
