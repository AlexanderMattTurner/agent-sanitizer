/**
 * The env-value pre-gate's invisible tolerance derives from the generated
 * cross-language charset, not a hand-curated subset: a configured secret
 * spliced with any code point the daemon's redactor matches across (a tag char
 * U+E0001, an Egyptian control U+13439, …) must still trip `hasEnvBoundSecret`,
 * or the daemon is never called and the value reaches the model verbatim. The
 * tolerance is asserted FROM the generated charset, so a code point added to the
 * SSOT is covered the day it lands.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { hasEnvBoundSecret } from "../claude-hooks/lib/secret-annotate.mjs";

const charset = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL(
        "../python/agent_sanitizer/data/invisible-charset.json",
        import.meta.url,
      ),
    ),
    "utf8",
  ),
);
const allInvisible = [
  ...new Set([...charset.cf_codepoints, ...charset.extra_codepoints]),
];

// A credential-shaped name that exists only in the env each test passes.
const NAME = "AIS_TEST_ONLY_DEPLOY_TOKEN";
const VALUE = "sk-abc123def456ghi789";
const ZWSP = "\u200B";

/**
 * @param {string} text
 * @param {string} [value]
 */
const gate = (text, value = VALUE) =>
  hasEnvBoundSecret(text, { [NAME]: value });

describe("hasEnvBoundSecret tolerates the full generated invisible charset", () => {
  it("has a charset to check (non-vacuous)", () => {
    assert.ok(allInvisible.length > 300, `only ${allInvisible.length} cps`);
  });

  it("matches the plain value", () => {
    assert.equal(gate(`out ${VALUE} put`), true);
  });

  it("matches the value spliced with EVERY charset code point", () => {
    const missed = allInvisible.filter((cp) => {
      const spliced =
        VALUE.slice(0, 3) + String.fromCodePoint(cp) + VALUE.slice(3);
      return !gate(`out ${spliced} put`);
    });
    assert.deepEqual(
      missed.map((cp) => `U+${cp.toString(16).toUpperCase()}`),
      [],
      "spliced value escaped the pre-gate",
    );
  });

  it("still refuses a genuinely different value", () => {
    assert.equal(gate("out sk-abc999 put"), false);
  });

  it("refuses a visible character spliced into the value", () => {
    assert.equal(gate(`out ${VALUE.slice(0, 3)}x${VALUE.slice(3)} put`), false);
  });
});

describe("hasEnvBoundSecret with a long configured value", () => {
  // A PEM key or service-account JSON bound to a credential-named var: the gate
  // runs on every output, so a value this long must neither throw nor slow it.
  const LONG = Array.from({ length: 20000 }, (_, i) =>
    String.fromCharCode(33 + ((i * 7) % 90)),
  ).join("");

  it("answers without throwing on output that lacks it", () => {
    assert.equal(gate("echo hello", LONG), false);
  });

  it("matches it plain and spliced", () => {
    assert.equal(gate(`a ${LONG} b`, LONG), true);
    const spliced = LONG.slice(0, 9000) + ZWSP + LONG.slice(9000);
    assert.equal(gate(`a ${spliced} b`, LONG), true);
  });
});

describe("hasEnvBoundSecret with a value that itself holds an invisible", () => {
  const VALUE_WITH_INVISIBLE = `abcdefgh${ZWSP}ijklmnop`;

  it("matches the value as typed, with the invisible removed, or re-spliced", () => {
    for (const text of [
      `out ${VALUE_WITH_INVISIBLE} put`,
      "out abcdefghijklmnop put",
      `out abcdefgh${ZWSP}${ZWSP}${ZWSP}ijklmnop put`,
      `out a\u2060bcdefgh${ZWSP}ijklmnop put`,
    ])
      assert.equal(
        gate(text, VALUE_WITH_INVISIBLE),
        true,
        JSON.stringify(text),
      );
    assert.equal(
      gate("out abcdefghxijklmnop put", VALUE_WITH_INVISIBLE),
      false,
    );
  });

  it("is linear over a long invisible run followed by a non-match", () => {
    // A long invisible run that ends in a non-match must cost linear time.
    const hostile = `abcdefgh${ZWSP.repeat(200000)}x`;
    assert.equal(gate(hostile, VALUE_WITH_INVISIBLE), false);
  });

  it("matches a value made only of invisibles exactly, not as a match-everything needle", () => {
    const onlyInvisible = ZWSP.repeat(16);
    assert.equal(gate("ordinary text", onlyInvisible), false);
    assert.equal(gate(`x${onlyInvisible}y`, onlyInvisible), true);
  });
});

describe("hasEnvBoundSecret reads names and values from the SAME env", () => {
  // Reading the names from process.env and the values from `env` let a caller's
  // snapshot hold a secret the gate never looked at.
  it("fires on a value bound only in the passed env", () => {
    assert.equal(process.env[NAME], undefined);
    assert.equal(gate(`out ${VALUE} put`), true);
  });
  it("stays shut when the passed env does not hold the value", () => {
    assert.equal(hasEnvBoundSecret(`out ${VALUE} put`, {}), false);
  });
  it("ignores a value shorter than the configured floor", () => {
    assert.equal(gate("out sk-short put", "sk-short"), false);
  });
});
