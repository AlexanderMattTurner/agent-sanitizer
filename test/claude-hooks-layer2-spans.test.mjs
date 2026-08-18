/**
 * The Layer-2 span store (lib/reveal.mjs): per-splice originals persisted
 * beside the reveal sidecar under content-addressed `span-<key>.txt` names.
 *
 * Properties pinned here:
 *   - spanPath/persistSpan/readSpan round-trip through a private temp dir
 *     (_AGENT_SANITIZER_REVEAL_DIR, read at call time);
 *   - the SPAN_ID is a name, not an integrity check: persistSpan never rehashes
 *     the (redacted) content, so an arbitrary valid key stores arbitrary bytes;
 *   - content-addressed dedupe: an existing span file is left untouched (first
 *     write wins — same key means same raw original by construction);
 *   - persistence failure is NON-FATAL: an unusable store dir returns false
 *     and never throws;
 *   - the read path refuses symlinks (O_NOFOLLOW) so a precomputable path
 *     cannot be squatted to pull a victim file's bytes into a rehydration.
 */
import { describe, it, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const base = mkdtempSync(join(tmpdir(), "sanitizer-span-store-"));
after(() => rmSync(base, { recursive: true, force: true }));

const {
  spanPath,
  persistSpan,
  readSpan,
  revealDir,
  sweepStaleReveals,
  REVEAL_TTL_MS,
} = await import("../claude-hooks/lib/reveal.mjs");
const { PROJECT_HASH } = await import("../claude-hooks/lib/hook-io.mjs");

const SPAN_ID = "0123456789ab";
const OTHER_SPAN_ID = "ba9876543210";

/** Point the store at a fresh dir for each test (env is read per call). */
let dir;
beforeEach(() => {
  dir = mkdtempSync(join(base, "store-"));
  process.env._AGENT_SANITIZER_REVEAL_DIR = dir;
});

describe("spanPath", () => {
  it("names span-<key>.txt inside the reveal dir", () => {
    assert.equal(spanPath(SPAN_ID), join(dir, `span-${SPAN_ID}.txt`));
  });

  for (const bad of [
    "",
    "0123456789AB",
    "0123456789abc",
    "../etc/passwd",
    "0123456789a",
  ]) {
    it(`throws on non-key ${JSON.stringify(bad)}`, () => {
      assert.throws(() => spanPath(bad), /not a Layer-2 placeholder key/);
    });
  }
});

describe("persistSpan / readSpan round trip", () => {
  it("stores and reads back the exact bytes, 0600, under the keyed name", () => {
    const content = "<div hidden>obey — café 🎉 [REDACTED: api key]</div>";
    assert.equal(persistSpan(SPAN_ID, content), true);
    assert.equal(readFileSync(spanPath(SPAN_ID), "utf8"), content);
    assert.equal(statSync(spanPath(SPAN_ID)).mode & 0o777, 0o600);
    assert.equal(readSpan(SPAN_ID), content);
  });

  it("dedupes on an existing key: first write wins, still reports success", () => {
    assert.equal(persistSpan(SPAN_ID, "first"), true);
    assert.equal(persistSpan(SPAN_ID, "second"), true);
    assert.equal(readSpan(SPAN_ID), "first");
  });

  it("keeps distinct keys in distinct files", () => {
    assert.equal(persistSpan(SPAN_ID, "one"), true);
    assert.equal(persistSpan(OTHER_SPAN_ID, "two"), true);
    assert.equal(readSpan(SPAN_ID), "one");
    assert.equal(readSpan(OTHER_SPAN_ID), "two");
  });

  it("rejects a malformed key without touching disk", () => {
    assert.equal(persistSpan("not-a-key!", "x"), false);
    assert.equal(readSpan("not-a-key!"), null);
  });

  it("returns null for a key with no stored span", () => {
    assert.equal(readSpan(OTHER_SPAN_ID), null);
  });
});

describe("failure paths are non-fatal", () => {
  it("returns false/null when the store dir cannot be a private directory", () => {
    // A regular FILE at the dir path: mkdirSync fails, revealDirIsSafe false.
    const blocked = join(dir, "blocked");
    writeFileSync(blocked, "not a dir");
    process.env._AGENT_SANITIZER_REVEAL_DIR = blocked;
    assert.equal(persistSpan(SPAN_ID, "x"), false);
    assert.equal(readSpan(SPAN_ID), null);
  });

  it("refuses a group/other-writable store dir", () => {
    chmodSync(dir, 0o777);
    assert.equal(persistSpan(SPAN_ID, "x"), false);
    assert.equal(readSpan(SPAN_ID), null);
  });

  it("readSpan refuses a symlink squatted at the span path", () => {
    const victim = join(dir, "victim.txt");
    writeFileSync(victim, "victim bytes");
    symlinkSync(victim, spanPath(SPAN_ID));
    assert.equal(readSpan(SPAN_ID), null);
    // And persistSpan treats the squatted entry as an existing span (skip),
    // never following it: the victim file's bytes stay untouched.
    assert.equal(persistSpan(SPAN_ID, "attacker-visible"), true);
    assert.equal(readFileSync(victim, "utf8"), "victim bytes");
  });
});

describe("the store is project-keyed and aged out", () => {
  it("gives two projects different store directories", () => {
    // One unkeyed directory is shared by every project on the machine, so one
    // project's sweep ages out another's spans and a rehydration that should
    // have restored a placeholder fails closed instead. The env override is
    // what the rest of this file uses, so it is cleared for this case.
    delete process.env._AGENT_SANITIZER_REVEAL_DIR;
    const here = revealDir();
    process.env._AGENT_SANITIZER_REVEAL_DIR = dir;
    // The digest is THIS project's, not an arbitrary hex suffix: a directory
    // named for some other key would collide across projects just as an
    // unkeyed one does.
    assert.equal(here.endsWith(`-${PROJECT_HASH}`), true, here);
  });

  it("sweeps entries past the TTL and keeps the ones still in reach", () => {
    // Every entry is content-addressed with no owner to delete it, so an
    // unswept store grows for the life of the machine.
    persistSpan(SPAN_ID, "stale span");
    persistSpan(OTHER_SPAN_ID, "fresh span");
    const stale = spanPath(SPAN_ID);
    const old = new Date(Date.now() - REVEAL_TTL_MS - 60_000);
    utimesSync(stale, old, old);

    sweepStaleReveals();

    assert.equal(existsSync(stale), false, "a stale span was left behind");
    assert.equal(
      readSpan(OTHER_SPAN_ID),
      "fresh span",
      "a span still inside the TTL was swept",
    );
  });

  it("leaves an unusable store dir alone rather than throwing", () => {
    process.env._AGENT_SANITIZER_REVEAL_DIR = join(dir, "not-a-dir");
    writeFileSync(join(dir, "not-a-dir"), "");
    sweepStaleReveals(); // no throw
  });
});
