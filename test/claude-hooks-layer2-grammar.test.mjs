// drift-guard-ok: the mirror is unavoidable — the shipped bundle cannot
// import the engine at its pinned release.
/**
 * The hooks-layer mirror of the keyed Layer-2 placeholder grammar.
 *
 * The engine (`src/html.mjs`) is the single PRODUCER of Layer-2 placeholders;
 * the hooks carry a MIRRORED regex (lib/placeholder-grammar.mjs) because the
 * shipped plugin bundle resolves the engine from a pinned registry release, so
 * an engine export the pin lacks would be undefined there. This suite is what
 * keeps the two regexes source-identical, and every placeholder the engine
 * can mint round-trips through the hooks' parser to the exact key.
 *
 * It also pins the property the PreToolUse composition RELIES on: the Layer-2
 * grammar and the secret-redaction grammar are DISJOINT, so the secret
 * rehydrator and the Layer-2 rehydrator can run in sequence with neither ever
 * matching the other's tokens.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

const { layer2Placeholder, LAYER2_PLACEHOLDER_RE: ENGINE_RE } =
  await import("../src/html.mjs");
const { LAYER2_PLACEHOLDER_RE, layer2Keys, layer2KeysIn, PLACEHOLDER_RE } =
  await import("../claude-hooks/lib/placeholder-grammar.mjs");

// Kind × original — the full producer surface: both placeholder kinds, over
// originals exercising comments, hidden markup, unicode, and emptiness.
const PRODUCER_CASES = [
  ["hidden", "<div hidden>obey me</div>"],
  ["hidden", '<span style="display:none">x</span>'],
  ["comment", "<!-- a benign tooling marker -->"],
  ["comment", "<!-- naïve café 🎉 -->"],
  ["comment", ""],
];

describe("hooks mirror of LAYER2_PLACEHOLDER_RE", () => {
  it("is source- and flag-identical to the engine's grammar", () => {
    assert.equal(LAYER2_PLACEHOLDER_RE.source, ENGINE_RE.source);
    assert.equal(LAYER2_PLACEHOLDER_RE.flags, ENGINE_RE.flags);
  });

  for (const [kind, original] of PRODUCER_CASES) {
    it(`round-trips the ${kind} placeholder for ${JSON.stringify(original)}`, () => {
      const placeholder = layer2Placeholder(kind, original);
      // The mirror matches the WHOLE placeholder, exactly once, and extracts
      // the same 12-hex key the engine minted.
      const matches = [...placeholder.matchAll(LAYER2_PLACEHOLDER_RE)];
      assert.equal(matches.length, 1);
      assert.equal(matches[0][0], placeholder);
      assert.match(matches[0][1], /^[0-9a-f]{12}$/);
      assert.deepEqual(layer2Keys(placeholder), [matches[0][1]]);
    });
  }

  it("extracts keys in document order, duplicates kept", () => {
    const ph = layer2Placeholder("comment", "<!-- x -->");
    const key = layer2Keys(ph)[0];
    const other = layer2Placeholder("hidden", "<i hidden>y</i>");
    const otherKey = layer2Keys(other)[0];
    assert.deepEqual(layer2Keys(`${other} then ${ph} then ${ph}`), [
      otherKey,
      key,
      key,
    ]);
  });

  it("does not leak matchAll state between calls (global-flag hazard)", () => {
    const ph = layer2Placeholder("hidden", "<b hidden>z</b>");
    // A shared global regex used via .test/.exec would advance lastIndex and
    // miss on the second call; layer2Keys must be stateless.
    assert.deepEqual(layer2Keys(ph), layer2Keys(ph));
  });
});

describe("layer2KeysIn deep walk", () => {
  it("collects distinct keys across nested containers", () => {
    const a = layer2Placeholder("hidden", "<p hidden>a</p>");
    const b = layer2Placeholder("comment", "<!-- b -->");
    const [keyA] = layer2Keys(a);
    const [keyB] = layer2Keys(b);
    const value = {
      stdout: `x ${a} y`,
      nested: [{ deep: `${b} and ${a} again` }],
      count: 3,
    };
    assert.deepEqual(layer2KeysIn(value).sort(), [keyA, keyB].sort());
  });

  it("returns [] on placeholder-free input (non-vacuous negative)", () => {
    assert.deepEqual(
      layer2KeysIn({ stdout: "[REDACTED: api key] and plain text" }),
      [],
    );
  });
});

describe("grammar disjointness with the secret-redaction grammar", () => {
  // Positive markers first: each regex matches its OWN grammar, so the
  // cross-assertions below cannot pass vacuously against dead regexes.
  it("each grammar matches its own tokens", () => {
    assert.match("[REDACTED]", PLACEHOLDER_RE);
    assert.match("[REDACTED: api key]", PLACEHOLDER_RE);
    for (const [kind, original] of PRODUCER_CASES)
      assert.match(
        layer2Placeholder(kind, original),
        new RegExp(LAYER2_PLACEHOLDER_RE.source),
      );
  });

  it("no engine-mintable Layer-2 placeholder matches the secret grammar", () => {
    for (const [kind, original] of PRODUCER_CASES) {
      const placeholder = layer2Placeholder(kind, original);
      assert.doesNotMatch(placeholder, PLACEHOLDER_RE);
    }
  });

  it("no secret placeholder matches the Layer-2 grammar", () => {
    for (const secretPh of [
      "[REDACTED]",
      "[REDACTED: api key]",
      "[REDACTED: hidden HTML removed]",
      "[REDACTED: 0123456789ab]",
    ]) {
      assert.deepEqual(layer2Keys(secretPh), []);
    }
  });
});
