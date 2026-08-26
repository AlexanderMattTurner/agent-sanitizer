/**
 * Fast-check property tests for src/output.mjs. Pins the structural invariants
 * the example tests sample only at fixed points:
 *
 *   - sanitizeText never throws (no html/exfil, non-throwing redact) and its
 *     cleaned output carries no raw ESC byte and no payload-capable long
 *     invisible run after Layer 1;
 *   - `modified` is true exactly when cleaned !== input;
 *   - sanitizeValue preserves the JSON shape (key sets, array lengths) and is a
 *     no-op (deep-equal, modified=false) on all-clean input.
 *
 * Adversarial inputs are built from code points (never literal control bytes;
 * see CLAUDE.md > Code Style).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import {
  sanitizeText,
  sanitizeValue,
  deleteVerbatimSpans,
  MAX_DEPTH,
  FILTER_WARNING,
} from "../src/output.mjs";
import { SGR_RE } from "../src/invisible.mjs";
import { occurrences } from "../src/view-map.mjs";
import {
  fcRunOptions,
  cp,
  keptOutsideNeedles,
  unicodeChar,
  loneSurrogate,
} from "./test-helpers.mjs";

const runOptions = fcRunOptions({ numRuns: 300 });

const ESC = cp(0x1b);

// ESC + invisible/format chars + ANSI fragments + ordinary unicode/surrogates.
// Built from code points so no literal control byte sits in this source file.
const adversarialChar = fc.oneof(
  unicodeChar,
  loneSurrogate,
  fc.constantFrom(
    ESC, // bare ESC introducer
    `${ESC}[31m`, // SGR fragment
    `${ESC}[0m`,
    `${ESC}[32m`,
    `${ESC}]8;;http://x${cp(0x07)}`, // 7-bit OSC + BEL terminator
    cp(0x009b), // 8-bit C1 CSI introducer
    cp(0x009d), // 8-bit C1 OSC introducer
    cp(0x200b), // ZWSP (Cf)
    cp(0x200c), // ZWNJ (Cf, carve-out)
    cp(0x200d), // ZWJ (Cf, carve-out)
    cp(0xfe0f), // VS-16
    cp(0x00ad), // soft hyphen
    cp(0x034f), // zero-width combining mark (Mn blank filler)
    cp(0x2800), // braille blank filler
    cp(0xe0041), // Unicode TAG (deniable-encoding channel)
    cp(0x1f600), // astral (parser totality)
  ),
);
const adversarialInput = fc
  .array(adversarialChar, { maxLength: 200 })
  .map((parts) => parts.join(""));

const cpr = (a, b) => `${String.fromCodePoint(a)}-${String.fromCodePoint(b)}`;
// No payload-capable long invisible run may survive Layer 1. STRIP categories:
// Cf format, the variation selectors, and the blank-rendering fillers — built
// from code points so this source holds no literal invisible byte.
const LONG_INVISIBLE_RUN = new RegExp(
  `(?:\\p{Cf}|[${cpr(0xfe00, 0xfe0f)}]|[${cpr(0xe0100, 0xe01ef)}]|[\u115F\u1160\u3164\uFFA0\u2800]){10,}`,
  "u",
);

describe("property: sanitizeText invariants (Layer 1 only)", () => {
  it("never throws and produces ESC-free, payload-run-free cleaned text", async () => {
    await fc.assert(
      fc.asyncProperty(adversarialInput, async (input) => {
        const r = await sanitizeText(input);
        assert.equal(typeof r.cleaned, "string");
        // No raw ESC introducer may survive Layer 1. Built from the ESC constant
        // (a code point) so this source holds no literal control byte (T2/T6).
        assert.doesNotMatch(
          r.cleaned,
          new RegExp(`[${ESC}]`),
          "raw ESC survived Layer 1",
        );
        assert.doesNotMatch(
          r.cleaned,
          LONG_INVISIBLE_RUN,
          "a payload-capable invisible run survived Layer 1",
        );
        // `modified` faithfully tracks whether bytes changed.
        assert.equal(r.modified, r.cleaned !== input);
        // Any change carries at least one operator-visible warning, UNLESS
        // the entire diff is display-only SGR color (the `sgrNote`
        // carve-out) — content never vanishes silently. Deciding "diff is
        // SGR-only" by stripping SGR_RE from both sides and comparing (not
        // just trusting `r.sgrNote` alone) closes a regression a plain
        // `warnings.length > 0 || r.sgrNote === true` disjunction would miss:
        // a bug that sets sgrNote=true on a NON-SGR change (or misroutes a
        // real warning into the note) would satisfy the old OR while genuine
        // content removal went completely unwarned.
        if (r.cleaned !== input) {
          const diffIsSgrOnly =
            input.replace(SGR_RE, "") === r.cleaned.replace(SGR_RE, "");
          if (diffIsSgrOnly && r.sgrNote === true) {
            // Legitimate carve-out: the only change was cosmetic SGR color,
            // reported via the terse note instead of a warning.
          } else {
            assert.ok(
              r.warnings.length > 0,
              "content changed beyond SGR-only styling but no warning was " +
                `emitted (sgrNote=${r.sgrNote}, diffIsSgrOnly=${diffIsSgrOnly})`,
            );
          }
        }
      }),
      runOptions,
    );
  });

  it("is a no-op on text with no control/invisible chars", async () => {
    const benignChar = fc.constantFrom(..."0123456789 .,-_/:#%@".split(""));
    const benign = fc
      .array(benignChar, { minLength: 1, maxLength: 200 })
      .map((parts) => parts.join(""));
    await fc.assert(
      fc.asyncProperty(benign, async (input) => {
        const r = await sanitizeText(input);
        assert.equal(r.cleaned, input);
        assert.equal(r.modified, false);
        assert.deepEqual(r.warnings, []);
      }),
      runOptions,
    );
  });
});

// ─── sanitizeValue shape preservation ────────────────────────────────────────

const benignChar = fc.constantFrom(..."0123456789 .,-_/:#%@".split(""));
const benignString = fc
  .array(benignChar, { maxLength: 20 })
  .map((parts) => parts.join(""));
const nonStringScalar = fc.oneof(
  fc.integer(),
  fc.double({ noNaN: true }),
  fc.boolean(),
  fc.constant(null),
);
const objectOf = (valueArb) =>
  fc
    .dictionary(
      fc.string({ maxLength: 8 }).filter((key) => key !== "__proto__"),
      valueArb,
      { maxKeys: 5 },
    )
    .map((obj) => ({ ...obj }));

const { benignTree } = fc.letrec((tie) => ({
  benignTree: fc.oneof(
    { maxDepth: 4, withCrossShrink: true },
    benignString,
    nonStringScalar,
    fc.array(tie("benignTree"), { maxLength: 5 }),
    objectOf(tie("benignTree")),
  ),
}));
const { adversarialTree } = fc.letrec((tie) => ({
  adversarialTree: fc.oneof(
    { maxDepth: 4, withCrossShrink: true },
    adversarialInput,
    nonStringScalar,
    fc.array(tie("adversarialTree"), { maxLength: 5 }),
    objectOf(tie("adversarialTree")),
  ),
}));

// String leaves are wildcards (sanitizeText may rewrite them); every array
// length, object key set, and non-string scalar must match exactly.
function sameShape(before, after) {
  if (typeof before === "string") return typeof after === "string";
  if (Array.isArray(before))
    return (
      Array.isArray(after) &&
      before.length === after.length &&
      before.every((item, i) => sameShape(item, after[i]))
    );
  if (before !== null && typeof before === "object") {
    if (after === null || typeof after !== "object" || Array.isArray(after))
      return false;
    const keysBefore = Object.keys(before).sort();
    const keysAfter = Object.keys(after).sort();
    return (
      keysBefore.length === keysAfter.length &&
      keysBefore.every(
        (key, i) => key === keysAfter[i] && sameShape(before[key], after[key]),
      )
    );
  }
  return Object.is(before, after);
}

describe("property: sanitizeValue preserves structure", () => {
  it("returns a benign tree deep-equal and unchanged", async () => {
    await fc.assert(
      fc.asyncProperty(benignTree, async (value) => {
        const warnings = [];
        const r = await sanitizeValue(value, {}, warnings);
        assert.deepEqual(r.value, value);
        assert.equal(r.modified, false);
        assert.equal(warnings.length, 0);
      }),
      runOptions,
    );
  });

  it("preserves shape on adversarial leaves; modified iff a leaf changed", async () => {
    await fc.assert(
      fc.asyncProperty(adversarialTree, async (value) => {
        const warnings = [];
        const r = await sanitizeValue(value, {}, warnings);
        assert.ok(sameShape(value, r.value), "shape changed");
        let changed = false;
        try {
          assert.deepEqual(r.value, value);
        } catch {
          changed = true;
        }
        assert.equal(r.modified, changed);
      }),
      runOptions,
    );
  });

  // The depth fail-closed guard (R3) must never throw, regardless of how deep
  // the random nesting goes. Drive sanitizeValue with an array nested to a
  // random depth straddling MAX_DEPTH (some runs under, some well over) and
  // assert it resolves to a string leaf and never blows the stack.
  it("never throws on arbitrarily deep nesting (straddles MAX_DEPTH)", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: MAX_DEPTH * 3 }),
        async (depth) => {
          let node = "leaf";
          for (let i = 0; i < depth; i++) node = [node];
          const r = await sanitizeValue(node, {}, []);
          // Descend min(depth, MAX_DEPTH) array levels to the innermost value.
          let inner = r.value;
          const levels = Math.min(depth, MAX_DEPTH);
          for (let i = 0; i < levels; i++) {
            assert.ok(Array.isArray(inner));
            inner = inner[0];
          }
          assert.equal(typeof inner, "string");
          // Past the cap the innermost is the withhold placeholder; otherwise
          // the original (clean) leaf survives.
          assert.equal(
            inner,
            depth > MAX_DEPTH
              ? "[withheld: structured output nested beyond 200 levels]"
              : "leaf",
          );
        },
      ),
      runOptions,
    );
  });
});

// ─── deleteVerbatimSpans: deletion-only invariant ────────────────────────────

describe("property: deleteVerbatimSpans only deletes", () => {
  const safeText = fc
    .array(fc.constantFrom(..."abcXYZ ".split("")), { maxLength: 40 })
    .map((parts) => parts.join(""));
  const spanArb = fc.array(fc.constantFrom("X", "Y", "Z", "", "Q"), {
    maxLength: 4,
  });

  it("output equals the text with every span independently removed (no injected bytes)", () => {
    fc.assert(
      fc.property(safeText, spanArb, (text, spans) => {
        const { text: out, removed } = deleteVerbatimSpans(text, spans);
        // A length-only invariant can't catch an INJECTION: a buggy deleter that
        // both removed bytes and spliced new ones in could still shrink the text.
        // The expected residue comes from the shared set-union oracle (the same
        // one test/splice-property.test.mjs asserts against): every index of
        // the ORIGINAL text no span covered. It
        // only ever keeps bytes already present in `text`, so any byte in `out`
        // that did not come from `text` — or any byte deleted that no span
        // matched in the INPUT — fails this exact-equality check.
        const expected = keptOutsideNeedles(text, spans);
        assert.equal(out, expected);
        // Every span here is a single character, so no two matches overlap and
        // each removed byte is one removed occurrence.
        assert.equal(removed, text.length - expected.length);
        assert.ok(out.length <= text.length, "output grew");
      }),
      runOptions,
    );
  });
});

// ─── invariant: a Layer-5 filter can only DELETE, never INJECT ───────────────

describe("property: no filterInjection-supplied byte reaches the model-facing context", () => {
  const benignChar = fc.constantFrom(..."abcXYZ 0123".split(""));
  const benign = fc
    .array(benignChar, { maxLength: 60 })
    .map((parts) => parts.join(""));
  // Spans the hostile filter asks to delete (some present in text, some not).
  const spanArb = fc.array(fc.constantFrom("X", "Y", "Z", "ab", "XYZ", ""), {
    maxLength: 4,
  });
  // The filter may return a valid enum code or no warning at all.
  const codeArb = fc.constantFrom(undefined, ...Object.values(FILTER_WARNING));
  // Counterexamples this property has caught, pinned so they replay on EVERY
  // run rather than waiting for the generator to rediscover them:
  //   ["aZb", ["Z", "ab"]] — deleting "Z" joins "a" to "b", so a span-by-span
  //   deleter finds an "ab" the INPUT never contained and erases the rest of
  //   the output. Only the two spans' matches in the original text may go.
  const deletionRunOptions = fcRunOptions({
    numRuns: 300,
    examples: [["aZb", ["Z", "ab"], undefined]],
  });

  it("cleaned is the input with spans DELETED (never injected) and warnings are library-owned only", async () => {
    await fc.assert(
      fc.asyncProperty(benign, spanArb, codeArb, async (text, spans, code) => {
        const filterInjection = () =>
          code === undefined
            ? { removeSpans: spans }
            : { removeSpans: spans, warning: code };
        const r = await sanitizeText(text, { filterInjection });
        // Deletion-only: cleaned equals the input with those spans removed by
        // an INDEPENDENT oracle — any filter-injected byte would break this.
        // The oracle is a left-to-right scan of the ORIGINAL text (not the
        // collect-sort-splice the implementation uses): at each position the
        // first span, in the order the filter listed them, whose occurrence
        // starts there is deleted. Spans here can overlap ("X" inside "XYZ"),
        // so the union of occurrences is NOT the answer — the second of two
        // overlapping matches is dropped, not applied at a shifted offset. A
        // chained per-span `replaceAll` is not the answer either: it deletes
        // matches that only exist because an earlier deletion joined the bytes
        // around it (deleting "Z" from "aZb" would then delete the "ab" the
        // input never contained).
        let expected = "";
        for (let i = 0; i < text.length;) {
          const hit = spans.find(
            (span) => span && occurrences(text, span).includes(i),
          );
          if (hit === undefined) {
            expected += text[i];
            i++;
            continue;
          }
          i += hit.length;
        }
        assert.equal(r.cleaned, expected);
        // Benign input yields no Layer-1 finding, so the ONLY possible warning
        // is the filter's — and it must be a LIBRARY-owned message (the mapped
        // enum), never the raw code or filter free text. All three library
        // messages start with this stable marker.
        for (const w of r.warnings) {
          assert.notEqual(w, code);
          assert.match(w, /^Layer-5 injection filter/);
        }
        assert.ok(r.warnings.length <= 1);
      }),
      deletionRunOptions,
    );
  });

  it("a free-text (non-enum) warning throws instead of reaching warnings", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc
          .string({ maxLength: 40 })
          .filter((s) => !Object.values(FILTER_WARNING).includes(s)),
        async (poison) => {
          await assert.rejects(
            () =>
              sanitizeText("clean docs", {
                filterInjection: () => ({ warning: poison }),
              }),
            /unrecognized warning value/,
          );
        },
      ),
      runOptions,
    );
  });
});
