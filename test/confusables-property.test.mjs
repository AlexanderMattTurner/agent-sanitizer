/**
 * Property/fuzz tests for the confusable-folding core. Example tests pin known
 * shapes; these pin the INVARIANTS over the real input domain so a future edit
 * surfaces a counterexample anywhere — not just at the hand-picked cases.
 *
 * The confusable scanner is INJECTED as a deterministic fake matching the
 * documented `{ findings: [{ index, char, latinEquivalent }] }` shape, so the
 * folder's offset/length/null logic is exercised independently of any engine.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import {
  foldConfusables,
  normalizeConfusables,
  selectFoldableFindings,
} from "../src/confusables.mjs";
import { fcRunOptions, cp } from "./test-helpers.mjs";

const runOptions = fcRunOptions({ numRuns: 500 });
const check = (arbitrary, predicate) =>
  fc.assert(fc.property(arbitrary, predicate), runOptions);

// Confusable glyphs → ASCII canon. Mix of BMP (1 unit) and astral (2 units) so
// length-changing folds are exercised. ASCII chars in the alphabet are never
// flagged (they are the canon, not a confusable).
const FOLD_MAP = {
  [cp(0x0430)]: "a", // Cyrillic а
  [cp(0x043e)]: "o", // Cyrillic о
  [cp(0x0435)]: "e", // Cyrillic е
  [cp(0x0440)]: "p", // Cyrillic р
  [cp(0x0441)]: "c", // Cyrillic с
  [cp(0x1d400)]: "a", // 𝐀 mathematical bold A (astral)
  [cp(0x1d401)]: "b", // 𝐁 (astral)
  // Length-INCREASING folds (1 glyph → 2 ASCII): a real engine maps ﬁ→"fi",
  // ĳ→"ij". The old map had only 1→1 / 2→1 folds, so the highest-index-first
  // splice was never exercised against a growing replacement.
  [cp(0xfb01)]: "fi", // ﬁ LATIN SMALL LIGATURE FI
  [cp(0x0133)]: "ij", // ĳ LATIN SMALL LIGATURE IJ
};

/** Deterministic confusable scanner over FOLD_MAP, iterating by code point. */
const scan = (text) => {
  const findings = [];
  let index = 0;
  for (const ch of text) {
    if (Object.prototype.hasOwnProperty.call(FOLD_MAP, ch))
      findings.push({ index, char: ch, latinEquivalent: FOLD_MAP[ch] });
    index += ch.length;
  }
  return { findings };
};

/**
 * Reference fold computed independently of the implementation: walk the input
 * by code point and replace each flagged glyph. Order-independent, so it is a
 * fair oracle for the highest-index-first splice.
 */
const manualFold = (text) => {
  let out = "";
  for (const ch of text)
    out += Object.prototype.hasOwnProperty.call(FOLD_MAP, ch)
      ? FOLD_MAP[ch]
      : ch;
  return out;
};

// A token boundary is any ASCII character that is not a letter or digit. Stated
// as an ASCII test plus a regex class, independently of the implementation's
// explicit code-point ranges, so the two formulations can disagree.
const isBoundary = (ch) => ch.charCodeAt(0) < 128 && /[^A-Za-z0-9]/.test(ch);

/** `text` split into alternating tokens and boundary characters, in order. */
const partsOf = (text) => {
  const parts = [];
  let token = "";
  for (const ch of text) {
    if (!isBoundary(ch)) {
      token += ch;
      continue;
    }
    if (token) parts.push({ token });
    parts.push({ boundary: ch });
    token = "";
  }
  if (token) parts.push({ token });
  return parts;
};

/** The non-empty tokens of `text`, in order (boundaries dropped). */
const tokensOf = (text) =>
  partsOf(text)
    .filter((part) => part.token !== undefined)
    .map((part) => part.token);

const isAllAscii = (text) =>
  [...text].every((ch) => /** @type {number} */ (ch.codePointAt(0)) <= 0x7f);

/**
 * Independent oracle for the per-token fold gate normalizeConfusables applies:
 * fold a token only when folding leaves it pure ASCII, otherwise emit it
 * verbatim. Boundaries pass through untouched.
 */
const manualGatedFold = (text) =>
  partsOf(text)
    .map((part) => {
      if (part.boundary !== undefined) return part.boundary;
      const folded = manualFold(part.token);
      return isAllAscii(folded) ? folded : part.token;
    })
    .join("");

// Alphabet: confusables (BMP + astral), plain ASCII anchors, a benign non-ASCII
// non-confusable (é, never flagged), and structural chars.
const charCp = fc.constantFrom(
  0x0430,
  0x043e,
  0x0435,
  0x0440,
  0x0441,
  0x1d400,
  0x1d401,
  0xfb01, // ﬁ (1→2 fold)
  0x0133, // ĳ (1→2 fold)
  0x61, // a
  0x2f, // /
  0x2e, // .
  0x20, // space
  0xe9, // é (non-ASCII, non-confusable)
);
const text = fc
  .array(charCp, { maxLength: 60 })
  .map((codes) => codes.map((c) => cp(c)).join(""));

// Any UTF-16 unit including lone surrogates, to prove the fold never throws on
// astral / malformed input even when scan returns findings for known glyphs.
const anyUnit = fc
  .array(fc.oneof(charCp, fc.constantFrom(0xd800, 0xdc00, 0xdbff, 0xdfff)), {
    maxLength: 60,
  })
  .map((codes) =>
    codes
      .map((code) => (code <= 0xffff ? String.fromCharCode(code) : cp(code)))
      .join(""),
  );

describe("foldConfusables (property)", () => {
  it("equals an independent manual fold (only flagged spans change)", () => {
    check(text, (t) => {
      assert.equal(foldConfusables(t, scan(t).findings), manualFold(t));
    });
  });

  it("leaves every non-flagged code point untouched", () => {
    check(text, (t) => {
      const folded = foldConfusables(t, scan(t).findings);
      // Strip all confusable glyphs from input and their ASCII canon from
      // output: the remaining code-point sequences must be identical.
      const flagged = new Set(Object.keys(FOLD_MAP));
      // FOLD_MAP values may be multi-char ("fi", "ij"); split into their
      // constituent code points so the canon set is per-character.
      const canon = new Set(Object.values(FOLD_MAP).flatMap((v) => [...v]));
      const inputRest = [...t].filter((ch) => !flagged.has(ch)).join("");
      const outputRest = [...folded].filter((ch) => !canon.has(ch)).join("");
      // inputRest may still contain "a" (ASCII anchor) which is also a canon
      // value, so compare only the non-canon residue of the input.
      const inputResidue = [...inputRest]
        .filter((ch) => !canon.has(ch))
        .join("");
      assert.equal(outputRest, inputResidue);
    });
  });

  it("keeps offsets correct when a fold changes length (astral 2→1)", () => {
    check(text, (t) => {
      // A length-changing fold that mis-splices would diverge from the manual
      // oracle; equality across fuzzed astral placements pins offset handling.
      assert.equal(foldConfusables(t, scan(t).findings), manualFold(t));
    });
  });

  it("never throws on astral / lone-surrogate input", () => {
    check(anyUnit, (t) => {
      assert.equal(typeof foldConfusables(t, scan(t).findings), "string");
    });
  });

  it("is idempotent: a second fold finds nothing to change", () => {
    check(text, (t) => {
      const once = foldConfusables(t, scan(t).findings);
      assert.equal(foldConfusables(once, scan(once).findings), once);
    });
  });

  it("is a no-op on all-ASCII input (an honest scanner flags nothing)", () => {
    const asciiText = fc
      .array(fc.integer({ min: 0x20, max: 0x7e }), { maxLength: 60 })
      .map((codes) => codes.map((c) => String.fromCharCode(c)).join(""));
    check(asciiText, (t) => {
      assert.equal(foldConfusables(t, scan(t).findings), t);
    });
  });

  it("throws when a finding's char does not match the bytes at its index", () => {
    // Build an honest finding, then corrupt its char so it no longer matches the
    // input at the reported offset: the fail-loud guard must reject it anywhere.
    const withConfusable = text.filter((t) => scan(t).findings.length > 0);
    check(withConfusable, (t) => {
      const findings = scan(t).findings;
      const corrupted = findings.map((f) => ({
        ...f,
        char: `/${f.char}`, // prefix the char so startsWith(char, index) fails
      }));
      assert.throws(
        () => foldConfusables(t, corrupted),
        /does not match input at index/,
      );
    });
  });
});

describe("normalizeConfusables (property)", () => {
  it("returns null exactly when no mapped field changed", () => {
    check(text, (t) => {
      const input = { file_path: t };
      const result = normalizeConfusables("Read", input, { scan });
      // The gated oracle, not a raw fold: a token that would keep a non-ASCII
      // glyph after folding is left alone (see manualGatedFold).
      const gated = manualGatedFold(t);
      // null iff the field is unchanged by the gated fold.
      assert.equal(result === null, gated === t);
      if (result !== null) {
        assert.equal(result.updatedInput.file_path, gated);
        // The original input object is not mutated.
        assert.equal(input.file_path, t);
      }
    });
  });

  it("rewrites a token only into its pure-ASCII fold, never half-folds one", () => {
    // The precision property. Folding never changes a boundary character and
    // never merges tokens, so input and output tokens line up one-to-one: each
    // pair is either untouched, or fully folded to ASCII. A token that comes
    // back changed but still non-ASCII is the prose-mangling bug.
    check(text, (t) => {
      const result = normalizeConfusables("Read", { file_path: t }, { scan });
      if (result === null) return;
      const before = tokensOf(t);
      const after = tokensOf(result.updatedInput.file_path);
      assert.equal(after.length, before.length);
      for (const [i, token] of after.entries()) {
        if (token === before[i]) continue;
        assert.ok(
          isAllAscii(token),
          `token ${JSON.stringify(before[i])} was rewritten to ${JSON.stringify(token)}, which is still non-ASCII`,
        );
      }
    });
  });
});

describe("selectFoldableFindings (property)", () => {
  it("returns a subset of the findings, order preserved", () => {
    check(text, (t) => {
      const findings = scan(t).findings;
      const kept = selectFoldableFindings(t, findings);
      assert.deepEqual(
        kept,
        findings.filter((finding) => kept.includes(finding)),
      );
    });
  });

  it("folding the selected findings equals the gated oracle", () => {
    check(text, (t) => {
      const kept = selectFoldableFindings(t, scan(t).findings);
      assert.equal(foldConfusables(t, kept), manualGatedFold(t));
    });
  });

  it("drops a finding exactly when its token keeps a non-ASCII glyph", () => {
    check(text, (t) => {
      const kept = new Set(
        selectFoldableFindings(t, scan(t).findings).map((f) => f.index),
      );
      const foldedTokens = tokensOf(manualGatedFold(t));
      for (const finding of scan(t).findings) {
        // Which token does this finding sit in? Count tokens before its offset.
        const tokenIndex = tokensOf(t.slice(0, finding.index + 1)).length - 1;
        assert.equal(
          kept.has(finding.index),
          isAllAscii(foldedTokens[tokenIndex]),
        );
      }
    });
  });

  it("never touches all-ASCII commands (fast-path) — null", () => {
    const asciiText = fc
      .array(fc.integer({ min: 0x20, max: 0x7e }), { maxLength: 60 })
      .map((codes) => codes.map((c) => String.fromCharCode(c)).join(""));
    check(asciiText, (command) =>
      assert.equal(normalizeConfusables("Bash", { command }, { scan }), null),
    );
  });

  it("ignores tools with no mapped field", () => {
    check(text, (value) =>
      assert.equal(
        normalizeConfusables("WebSearch", { query: value }, { scan }),
        null,
      ),
    );
  });

  it("is idempotent: the folded form has nothing left to normalize", () => {
    check(text, (t) => {
      const first = normalizeConfusables("Read", { file_path: t }, { scan });
      if (first === null) return;
      assert.equal(
        normalizeConfusables("Read", first.updatedInput, { scan }),
        null,
      );
    });
  });

  it("never throws on astral / lone-surrogate field values", () => {
    check(anyUnit, (t) => {
      const result = normalizeConfusables("Read", { file_path: t }, { scan });
      assert.ok(
        result === null || typeof result.updatedInput.file_path === "string",
      );
    });
  });
});
