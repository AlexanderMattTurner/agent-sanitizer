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
  hasNonAscii,
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
  // A fold whose ASCII canon contains a token BOUNDARY: ½ → "1/2" splits one
  // input token into two output tokens. Exercises the case where the gate's
  // one-token-in decision produces more than one token out.
  [cp(0x00bd)]: "1/2", // ½ VULGAR FRACTION ONE HALF
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
 * True for a token the gate declines on sight: a single non-ASCII code point
 * standing alone between boundaries, with no ASCII alphanumeric beside it. Such
 * a token is a one-letter foreign word (Russian `с`, `о`, `у`, `а`) as often as
 * it is a disguised argument, and one character is not a deny-rule target.
 */
const isLoneGlyph = (token) => [...token].length === 1 && !isAllAscii(token);

/**
 * Independent oracle for the per-token fold gate normalizeConfusables applies:
 * fold a token only when folding leaves it pure ASCII and the token is more
 * than a lone glyph, otherwise emit it verbatim. Boundaries pass untouched.
 */
const manualGatedFold = (text) =>
  partsOf(text)
    .map((part) => {
      if (part.boundary !== undefined) return part.boundary;
      if (isLoneGlyph(part.token)) return part.token;
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
  0x00bd, // ½ (fold whose canon carries a token boundary)
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

  // Reference fold for arbitrary (possibly overlapping) findings: splice the
  // whole string, highest index first. Its guard reads the PARTIALLY FOLDED
  // string, which is what the real function validates an overlapping finding
  // against, so the two agree on which findings are rejected as well as on the
  // output — letting a generator emit invalid findings and compare outcomes.
  const naiveFold = (t, findings) => {
    let out = t;
    for (const finding of [...findings].sort(
      (lhs, rhs) => rhs.index - lhs.index,
    )) {
      if (!out.startsWith(finding.char, finding.index))
        throw new Error(`does not match input at index ${finding.index}`);
      out =
        out.slice(0, finding.index) +
        finding.latinEquivalent +
        out.slice(finding.index + finding.char.length);
    }
    return out;
  };

  // A differential test compares OUTCOMES, so both calls are wrapped; the error
  // is re-asserted by its message at the call site rather than swallowed.
  const attempt = (fn) => {
    try {
      return { value: fn() };
    } catch (error) {
      return { error };
    }
  };

  const rawFinding = fc.record({
    start: fc.nat({ max: 63 }), // code-point position, taken modulo the text
    // Bias half the findings to the highest offset still available: a uniformly
    // placed one almost never reaches past the previous fold, so overlaps —
    // the case under test — would be a rounding error in the generated corpus.
    abutting: fc.boolean(),
    glyphs: fc.integer({ min: 1, max: 2 }),
    latinEquivalent: fc.string({
      unit: fc.constantFrom("a", "b", "z", "/", "1"),
      minLength: 1,
      maxLength: 3,
    }),
  });

  /** UTF-16 offset of each code-point boundary of `t`, plus its length. */
  const boundaries = (t) => {
    const offsets = [0];
    for (const point of t)
      offsets.push(offsets[offsets.length - 1] + point.length);
    return offsets;
  };

  it("equals a naive whole-string splice on VALID overlapping findings", () => {
    check(
      fc.tuple(text, fc.array(rawFinding, { maxLength: 5 })),
      ([t, raws]) => {
        // Each `char` is read from the text as the folds applied so far have left
        // it, which is the state the real function validates against — so every
        // finding is valid when applied and the comparison is on OUTPUT, not on
        // who rejects what. Reading from the original text instead would make
        // essentially every overlap a mismatch and never exercise the fold.
        let folded = t;
        let cursor = t.length;
        const findings = [];
        for (const raw of raws) {
          const points = [...folded];
          const offsets = boundaries(folded);
          const starts = points
            .map((_, i) => i)
            .filter((i) => offsets[i] < cursor);
          if (starts.length === 0) break;
          const at = raw.abutting
            ? starts[starts.length - 1]
            : starts[raw.start % starts.length];
          const char = points.slice(at, at + raw.glyphs).join("");
          // An ASCII-only `char` is refused by a finding-shape guard the naive
          // splice does not model, so it is out of this property's scope.
          if (!hasNonAscii(char)) continue;
          const index = offsets[at];
          findings.push({ index, char, latinEquivalent: raw.latinEquivalent });
          folded =
            folded.slice(0, index) +
            raw.latinEquivalent +
            folded.slice(index + char.length);
          cursor = index;
        }
        assert.equal(
          foldConfusables(t, findings),
          naiveFold(t, findings),
          `text=${JSON.stringify(t)} findings=${JSON.stringify(findings)}`,
        );
      },
    );
  });

  it("rejects an invalid overlapping finding exactly when the reference does", () => {
    check(
      fc.tuple(text, fc.array(rawFinding, { maxLength: 5 })),
      ([t, raws]) => {
        // Chars read from the ORIGINAL text: a finding overlapping an applied fold
        // then names bytes the fold rewrote, so both sides must reject it.
        const points = [...t];
        if (points.length === 0) return;
        const offsets = boundaries(t);
        const findings = [];
        for (const raw of raws) {
          const at = raw.start % points.length;
          const char = points.slice(at, at + raw.glyphs).join("");
          if (!hasNonAscii(char)) continue;
          findings.push({
            index: offsets[at],
            char,
            latinEquivalent: raw.latinEquivalent,
          });
        }
        const actual = attempt(() => foldConfusables(t, findings));
        const reference = attempt(() => naiveFold(t, findings));
        const context = `text=${JSON.stringify(t)} findings=${JSON.stringify(findings)}`;
        assert.equal(
          actual.error === undefined,
          reference.error === undefined,
          `outcome differs from the naive reference: ${context} actual=${actual.error?.message ?? JSON.stringify(actual.value)} reference=${reference.error?.message ?? JSON.stringify(reference.value)}`,
        );
        if (actual.error !== undefined) {
          assert.match(actual.error.message, /does not match input at index/);
          return;
        }
        assert.equal(actual.value, reference.value, context);
      },
    );
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
    // The precision property, stated without assuming a 1:1 token count: a fold
    // whose canon contains a boundary (½ → "1/2") splits one token into two. So
    // assert on the SET instead — every output token either survived from the
    // input verbatim or is pure ASCII. A token that comes back changed but still
    // non-ASCII is the prose-mangling bug.
    check(text, (t) => {
      const result = normalizeConfusables("Read", { file_path: t }, { scan });
      if (result === null) return;
      const before = new Set(tokensOf(t));
      for (const token of tokensOf(result.updatedInput.file_path)) {
        if (before.has(token)) continue;
        assert.ok(
          isAllAscii(token),
          `output token ${JSON.stringify(token)} is neither an input token nor pure ASCII`,
        );
      }
    });
  });
});

describe("selectFoldableFindings (property)", () => {
  it("returns a subsequence of the input findings, by identity", () => {
    // The gate only ever DROPS findings: it must not clone, reorder, rewrite or
    // invent one. Walk the two arrays together rather than filtering the input
    // by the output, which would hold for any output the gate produced.
    check(text, (t) => {
      const findings = scan(t).findings;
      const kept = selectFoldableFindings(t, findings);
      assert.ok(kept.length <= findings.length);
      let cursor = 0;
      for (const finding of kept) {
        while (cursor < findings.length && findings[cursor] !== finding)
          cursor++;
        assert.ok(
          cursor < findings.length,
          `kept a finding that is not an element of the input at its original position: ${JSON.stringify(finding)}`,
        );
        cursor++;
      }
    });
  });

  it("folding the selected findings equals the gated oracle", () => {
    check(text, (t) => {
      const kept = selectFoldableFindings(t, scan(t).findings);
      assert.equal(foldConfusables(t, kept), manualGatedFold(t));
    });
  });

  it("keeps a finding exactly when the oracle folds the token it sits in", () => {
    check(text, (t) => {
      const kept = new Set(
        selectFoldableFindings(t, scan(t).findings).map((f) => f.index),
      );
      // Walk the INPUT tokens, deciding each one independently — indexing into
      // the folded token list would misalign the moment a fold introduces a
      // boundary (½ → "1/2" turns one token into two).
      let offset = 0;
      for (const part of partsOf(t)) {
        const piece = part.token ?? part.boundary;
        if (part.token !== undefined) {
          const folds =
            !isLoneGlyph(part.token) && isAllAscii(manualFold(part.token));
          for (const finding of scan(part.token).findings)
            assert.equal(
              kept.has(offset + finding.index),
              folds,
              `finding at ${offset + finding.index} in token ${JSON.stringify(part.token)}: expected kept=${folds}`,
            );
        }
        offset += piece.length;
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
