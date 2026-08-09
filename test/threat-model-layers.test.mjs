/**
 * The layer numbering is a PUBLIC vocabulary: `Layer 4` shows up in thrown
 * messages, hook warnings and operator-facing issue text, and the only place a
 * reader can look it up is THREAT-MODEL.md. A layer that the code names but the
 * threat model never gives a section to is therefore an undocumented promise —
 * which is exactly what happened to Layer 4, named 17 times in `src/output.mjs`
 * with no section of its own for the operator who saw the message to read.
 *
 * So this derives the live set of layer numbers from the code that speaks them
 * and asserts THREAT-MODEL.md has a heading for each, plus that the opening
 * paragraph's count word still matches. Adding `Layer 6` to a warning string
 * fails here until the section and the count are written in the same change.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";
import { describe, it } from "node:test";

// The shipped tree, not the instrumented copy Stryker runs this beside: the
// subject is what the code SAYS to an operator, which mutation does not change.
// `git rev-parse --show-toplevel` used to resolve this and appeared to work,
// because the sandbox sits inside the checkout and git walks up out of it — a
// silent escape that held only while `tempDirName` stayed at its default.
import { repoRoot } from "./helpers/repo-root.mjs";

const read = (relative) => readFileSync(join(repoRoot, relative), "utf8");

/**
 * Tracked files that speak the layer vocabulary to a human: library sources,
 * the hook stack, the CLI, and the Python redaction engine. Docs are excluded —
 * they are the thing under test, not evidence of what the code claims.
 */
const SOURCE_GLOBS = [
  "src/*.mjs",
  "bin/*.mjs",
  "claude-hooks/*.mjs",
  "claude-hooks/lib/*.mjs",
  "plugin/scripts/*.sh",
  "python/agent_sanitizer/*.py",
  "python/agent_sanitizer/secrets/*.py",
];

const sourceFiles = execFileSync(
  "git",
  ["ls-files", "-z", "--", ...SOURCE_GLOBS],
  { cwd: repoRoot, encoding: "utf8" },
)
  .split("\0")
  .filter(Boolean);

/**
 * `Layer 4`, `Layer-4`, `Layers 1–4` (any dash) — but never the `processLayer1`
 * / `layer1.mjs` identifiers, which carry no separator and would otherwise
 * inflate the set with names that are not the operator-facing vocabulary.
 */
const LAYER_MENTION = /\bLayers?[ -](\d)(?:\s*[-–—]\s*(\d))?/gu;

/** Every layer number the sources name, ranges expanded, ascending. */
function layersNamedInCode() {
  const seen = new Map();
  for (const file of sourceFiles) {
    const text = read(file);
    for (const [, from, to] of text.matchAll(LAYER_MENTION)) {
      // `Layers 1–4` covers 2 and 3 as surely as it covers its endpoints, so
      // expand the range; a lone mention is the degenerate range [n, n].
      const ends = [Number(from), to === undefined ? Number(from) : Number(to)];
      for (let n = Math.min(...ends); n <= Math.max(...ends); n += 1) {
        if (!seen.has(n)) seen.set(n, file);
      }
    }
  }
  return seen;
}

const COUNT_WORDS = [
  "Zero",
  "One",
  "Two",
  "Three",
  "Four",
  "Five",
  "Six",
  "Seven",
  "Eight",
  "Nine",
];

describe("THREAT-MODEL.md documents every layer the code names", () => {
  const threatModel = read("THREAT-MODEL.md");
  const named = layersNamedInCode();
  const numbers = [...named.keys()].sort((a, b) => a - b);

  it("finds the layer vocabulary in the sources (non-vacuous)", () => {
    assert.ok(sourceFiles.length > 0, "no source files matched SOURCE_GLOBS");
    // The five shipped layers are the floor: a pattern that stopped matching
    // would otherwise turn this whole file into a no-op that passes.
    assert.deepEqual(
      numbers.filter((n) => n <= 5),
      [1, 2, 3, 4, 5],
      "the sources no longer name Layers 1-5 — did LAYER_MENTION stop matching?",
    );
  });

  for (const n of numbers) {
    it(`has a section heading for Layer ${n}`, () => {
      const heading = new RegExp(`^#{2,4} .*\\bLayer[ -]?${n}\\b`, "mu");
      assert.match(
        threatModel,
        heading,
        `Layer ${n} is named in ${named.get(n)} but THREAT-MODEL.md has no heading for it`,
      );
    });
  }

  it("opens with a layer count that matches", () => {
    const stated = /^(\w+) sanitization layers/mu.exec(threatModel);
    assert.ok(
      stated,
      "THREAT-MODEL.md no longer opens with an '<N> sanitization layers' count",
    );
    assert.ok(
      numbers.length < COUNT_WORDS.length,
      `${numbers.length} layers — extend COUNT_WORDS past nine`,
    );
    assert.equal(
      stated[1],
      COUNT_WORDS[numbers.length],
      `THREAT-MODEL.md says ${stated[1]} sanitization layers; the code names ${numbers.length} (${numbers.join(", ")})`,
    );
  });
});
