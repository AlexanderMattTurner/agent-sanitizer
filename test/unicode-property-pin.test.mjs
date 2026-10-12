/**
 * No shipped code and no generator asks the RUNNING Node for a Unicode property.
 *
 * A live `\p{…}` / `\P{…}` escape answers from the ICU the runtime bundles, so
 * the same package version behaved differently on Node 22.22 (Unicode 16) and
 * Node 22.23 (Unicode 17): different emoji anchors, different ideograph bases,
 * different generated tables. Every such property is now read from the vendored
 * UCD slices (scripts/lib/ucd.mjs) and compiled into a committed data module.
 * This guard keeps it that way: it tokenizes every module in src/,
 * claude-hooks/ and scripts/gen-*.mjs with acorn and fails on a property escape
 * in a regex literal, or in a string or template that could feed `new RegExp`.
 * Comments are not tokens, so prose that names an escape does not trip it.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { tokenizer } from "acorn";

import { repoRoot } from "./helpers/repo-root.mjs";

// Files allowed a live escape, with the reason. Empty: nothing needs one.
/** @type {Record<string, string>} */
const ALLOWLIST = {};

/** An unescaped `\p{` or `\P{` (an even run of backslashes before it is literal). */
const PROPERTY_ESCAPE = /(?<!\\)(?:\\\\)*\\[pP]\{/;

/**
 * The live property escapes in `source`, as `line: text` strings.
 * @param {string} source
 * @returns {string[]}
 */
export function liveEscapes(source) {
  const found = [];
  for (const token of tokenizer(source, {
    ecmaVersion: "latest",
    sourceType: "module",
    locations: true,
  })) {
    const label = token.type.label;
    const text =
      label === "regexp"
        ? token.value.pattern
        : label === "string" || label === "template"
          ? token.value
          : null;
    if (typeof text === "string" && PROPERTY_ESCAPE.test(text))
      found.push(`${token.loc.start.line}: ${text}`);
  }
  return found;
}

/** Every scanned module, repo-relative. Enumerated by `git ls-files` pathspec
 * (a git `*` crosses `/`) so the guard-pair scan attributes to this suite
 * exactly the files it reads, not every file under scripts/. */
const SCANNED = execFileSync(
  "git",
  ["ls-files", "--", "src/*.mjs", "claude-hooks/*.mjs", "scripts/gen-*.mjs"],
  { cwd: repoRoot, encoding: "utf8" },
)
  .split("\n")
  .filter((path) => path !== "")
  .sort();

describe("no live Unicode property escape in shipped code or generators", () => {
  it("scans the modules that decide behaviour (non-vacuous)", () => {
    for (const expected of [
      "src/invisible.mjs",
      "src/unicode-properties.mjs",
      "claude-hooks/lib/authored-content.mjs",
      "scripts/gen-joining-type.mjs",
      "scripts/gen-invisible-charset.mjs",
      "scripts/gen-standardized-variants.mjs",
      "scripts/gen-unicode-properties.mjs",
    ])
      assert.ok(SCANNED.includes(expected), `${expected} is not scanned`);
  });

  it("detects every form an escape can take, and not a comment or `\\\\p{`", () => {
    const planted = [
      "const a = /\\p{Extended_Pictographic}/u;",
      "const b = /[^\\P{Cf}]/v;",
      'const c = new RegExp("\\\\p{Script=Hangul}", "u");',
      'const d = new RegExp(`\\\\p{Script=${name}}`, "u");',
    ];
    for (const sample of planted)
      assert.equal(liveEscapes(sample).length, 1, sample);
    for (const benign of [
      "// a comment naming \\p{Cf}\nconst x = 1;",
      "/** `\\p{Unified_Ideograph}` */ const y = 2;",
      "const z = /\\\\p{literal}/;", // an escaped backslash, then "p{"
    ])
      assert.deepEqual(liveEscapes(benign), [], benign);
  });

  for (const file of SCANNED.filter((name) => !(name in ALLOWLIST)))
    it(`${file} has none`, () => {
      assert.deepEqual(
        liveEscapes(readFileSync(join(repoRoot, file), "utf8")),
        [],
        `${file} asks the runtime for a Unicode property — read it from the pinned UCD (scripts/lib/ucd.mjs) instead`,
      );
    });

  it("allowlists only scanned files that still hold an escape", () => {
    for (const file of Object.keys(ALLOWLIST)) {
      assert.ok(SCANNED.includes(file), `${file} is not scanned`);
      const found = liveEscapes(readFileSync(join(repoRoot, file), "utf8"));
      assert.ok(
        found.length > 0,
        `${file} no longer needs its allowlist entry`,
      );
    }
  });
});
