/**
 * The env-value pre-gate's invisible tolerance derives from the generated
 * cross-language charset, not a hand-curated subset.
 *
 * This closes a real fail-open. `envValueRegex` previously tolerated a ~17-char
 * curated list of bidi/zero-width controls, a strict subset of the set the
 * daemon's redactor matches across — so a configured secret spliced with any
 * code point in the gap (a tag char U+E0001, an Egyptian control U+13439, …)
 * failed `hasEnvBoundSecret`, the daemon was never called, and the value
 * reached the model verbatim. The tolerance is asserted here FROM the generated
 * charset, so a code point added to the SSOT is covered the day it lands —
 * one source read by a consumer, no second list to drift.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { envValueRegex } from "../claude-hooks/lib/secret-annotate.mjs";

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

const VALUE = "sk-abc123def456ghi789";

describe("envValueRegex tolerates the full generated invisible charset", () => {
  it("has a charset to check (non-vacuous)", () => {
    assert.ok(allInvisible.length > 300, `only ${allInvisible.length} cps`);
  });

  it("matches the plain value", () => {
    assert.ok(envValueRegex(VALUE).test(`out ${VALUE} put`));
  });

  it("matches the value spliced with EVERY charset code point", () => {
    const re = envValueRegex(VALUE);
    const missed = allInvisible.filter((cp) => {
      const spliced =
        VALUE.slice(0, 3) + String.fromCodePoint(cp) + VALUE.slice(3);
      return !re.test(`out ${spliced} put`);
    });
    assert.deepEqual(
      missed.map((cp) => `U+${cp.toString(16).toUpperCase()}`),
      [],
      "spliced value escaped the pre-gate",
    );
  });

  it("still refuses a genuinely different value", () => {
    assert.equal(envValueRegex(VALUE).test("out sk-abc999 put"), false);
  });
});

describe("envValueRegex is memoized", () => {
  // The class the fix above installs is ~4 KB of source joined at EVERY interior
  // gap, so a 20-char value compiles a ~75 KB pattern — once per configured var,
  // on every PostToolUse output. Identity, not timing: a cache that silently
  // stopped caching would still pass a wall-clock assertion on a fast machine.
  it("returns the same instance for the same value", () => {
    assert.equal(envValueRegex(VALUE), envValueRegex(VALUE));
  });

  it("does not confuse distinct values", () => {
    const other = `${VALUE}-other`;
    assert.notEqual(envValueRegex(VALUE), envValueRegex(other));
    assert.ok(envValueRegex(other).test(`out ${other} put`));
    // The cached instance must still be usable twice — a `g`/`y` flag would
    // carry `lastIndex` between calls and make the second test() miss.
    const re = envValueRegex(VALUE);
    assert.ok(re.test(`out ${VALUE} put`));
    assert.ok(re.test(`out ${VALUE} put`), "shared instance carried state");
  });
});

describe("envValueRegex with a value that itself holds an invisible", () => {
  // `a<ZWSP>a` used to build `a[…]*<ZWSP>[…]*a`: the required literal is a member
  // of both neighbouring starred classes, so a long ZWSP run followed by a
  // non-match backtracked over quadratically many partitions (~6 s at 16k).
  const ZWSP = "​";
  const VALUE_WITH_INVISIBLE = `abc${ZWSP}def`;

  it("never leaves a required literal that the neighbouring runs also match", () => {
    // The linearity argument is "each literal between two runs is matched by
    // neither", so check that directly rather than timing a hostile input: a
    // wall-clock bound measures the runner, and the structural condition is the
    // whole cause. Positive marker: the runs are present to strip.
    const { source } = envValueRegex(VALUE_WITH_INVISIBLE);
    assert.match(source, /\]\*/u);
    const literals = source.replace(/\[[^\]]*\]\*/gu, "");
    assert.equal(literals, "abcdef");
    const leaked = [...literals].filter((ch) =>
      allInvisible.includes(ch.codePointAt(0)),
    );
    assert.deepEqual(leaked, []);
  });

  it("still matches the value as typed, with the invisible removed, or re-spliced", () => {
    const re = envValueRegex(VALUE_WITH_INVISIBLE);
    for (const text of [
      `out ${VALUE_WITH_INVISIBLE} put`,
      "out abcdef put",
      `out abc${ZWSP}${ZWSP}${ZWSP}def put`,
      `out a⁠bc${ZWSP}def put`,
    ])
      assert.ok(re.test(text), JSON.stringify(text));
    assert.equal(re.test("out abcxdef put"), false);
  });

  it("matches a value made only of invisibles exactly, not as a match-everything pattern", () => {
    const re = envValueRegex(`${ZWSP}${ZWSP}`);
    assert.equal(re.test("ordinary text"), false);
    assert.ok(re.test(`x${ZWSP}${ZWSP}y`));
  });
});
