/**
 * The Layer-2 span store (lib/reveal.mjs): per-splice originals persisted
 * beside the reveal sidecar under content-addressed `span-<key>.txt` names.
 *
 * Properties pinned here:
 *   - spanPath/persistSpan/readSpan round-trip through a private temp dir
 *     (_AGENT_SANITIZER_REVEAL_DIR, read at call time);
 *   - the KEY is a name, not an integrity check: persistSpan never rehashes
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
  mkdtempSync,
  rmSync,
  readFileSync,
  writeFileSync,
  statSync,
  symlinkSync,
  chmodSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const base = mkdtempSync(join(tmpdir(), "sanitizer-span-store-"));
after(() => rmSync(base, { recursive: true, force: true }));

const { spanPath, persistSpan, readSpan } =
  await import("../claude-hooks/lib/reveal.mjs");

const KEY = "0123456789ab";
const OTHER_KEY = "ba9876543210";

/** Point the store at a fresh dir for each test (env is read per call). */
let dir;
beforeEach(() => {
  dir = mkdtempSync(join(base, "store-"));
  process.env._AGENT_SANITIZER_REVEAL_DIR = dir;
});

describe("spanPath", () => {
  it("names span-<key>.txt inside the reveal dir", () => {
    assert.equal(spanPath(KEY), join(dir, `span-${KEY}.txt`));
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
    assert.equal(persistSpan(KEY, content), true);
    assert.equal(readFileSync(spanPath(KEY), "utf8"), content);
    assert.equal(statSync(spanPath(KEY)).mode & 0o777, 0o600);
    assert.equal(readSpan(KEY), content);
  });

  it("dedupes on an existing key: first write wins, still reports success", () => {
    assert.equal(persistSpan(KEY, "first"), true);
    assert.equal(persistSpan(KEY, "second"), true);
    assert.equal(readSpan(KEY), "first");
  });

  it("keeps distinct keys in distinct files", () => {
    assert.equal(persistSpan(KEY, "one"), true);
    assert.equal(persistSpan(OTHER_KEY, "two"), true);
    assert.equal(readSpan(KEY), "one");
    assert.equal(readSpan(OTHER_KEY), "two");
  });

  it("rejects a malformed key without touching disk", () => {
    assert.equal(persistSpan("not-a-key!", "x"), false);
    assert.equal(readSpan("not-a-key!"), null);
  });

  it("returns null for a key with no stored span", () => {
    assert.equal(readSpan(OTHER_KEY), null);
  });
});

describe("failure paths are non-fatal", () => {
  it("returns false/null when the store dir cannot be a private directory", () => {
    // A regular FILE at the dir path: mkdirSync fails, revealDirIsSafe false.
    const blocked = join(dir, "blocked");
    writeFileSync(blocked, "not a dir");
    process.env._AGENT_SANITIZER_REVEAL_DIR = blocked;
    assert.equal(persistSpan(KEY, "x"), false);
    assert.equal(readSpan(KEY), null);
  });

  it("refuses a group/other-writable store dir", () => {
    chmodSync(dir, 0o777);
    assert.equal(persistSpan(KEY, "x"), false);
    assert.equal(readSpan(KEY), null);
  });

  it("readSpan refuses a symlink squatted at the span path", () => {
    const victim = join(dir, "victim.txt");
    writeFileSync(victim, "victim bytes");
    symlinkSync(victim, spanPath(KEY));
    assert.equal(readSpan(KEY), null);
    // And persistSpan treats the squatted entry as an existing span (skip),
    // never following it: the victim file's bytes stay untouched.
    assert.equal(persistSpan(KEY, "attacker-visible"), true);
    assert.equal(readFileSync(victim, "utf8"), "victim bytes");
  });
});
