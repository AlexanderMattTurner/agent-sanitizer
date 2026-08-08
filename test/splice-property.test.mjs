/**
 * Fast-check property tests for the codebase's two splice primitives.
 *
 * `spliceRanges` (Layer 2) splices byte RANGES the HTML AST already resolved.
 * The AST path only ever feeds it disjoint, in-bounds ranges, so its documented
 * defense-in-depth behavior (merging overlapping/nested/duplicate ranges;
 * adjacent ranges are deliberately NOT merged) is otherwise unexercised.
 *
 * `spliceOrdered` (view-map) splices NEEDLE matches, and is the single
 * implementation behind all three needle-splicing call sites — Layer 5's
 * `deleteVerbatimSpans`, and rehydration's `rehydrateNewString` /
 * whole-file Write substitution. Its invariant is the same one, stated over
 * matches instead of ranges: every match is located in the ORIGINAL text, so
 * the only bytes that can be removed or replaced are bytes some needle actually
 * matched in the input — a chained `split`/`join` per needle does NOT hold that
 * line (see the non-vacuity test below).
 *
 * The headline invariant for both is the Layer-2/Layer-5 promise: every byte
 * *outside* the spliced regions is preserved verbatim, in order.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { spliceRanges, LAYER2_PLACEHOLDER_RE } from "../src/html.mjs";
import {
  occurrences,
  orderedMatches,
  spliceOrdered,
  rehydrateNewString,
} from "../src/view-map.mjs";
import { deleteVerbatimSpans } from "../src/output.mjs";
import { rehydrateRedacted } from "../src/rehydrate.mjs";
import { fcRunOptions, keptOutsideNeedles } from "./test-helpers.mjs";

const runOptions = fcRunOptions({ numRuns: 500 });

// Text drawn from chars that can never form a placeholder. The placeholder
// begins with "[", which this alphabet excludes, so any "[" in the output is an
// inserted placeholder — letting us strip placeholders unambiguously and
// compare what remains against the kept bytes computed independently.
const safeChar = fc.constantFrom(
  ..."abcdefghijklmnopqrstuvwxyz0123456789 .,_-".split(""),
);
const safeText = fc
  .array(safeChar, { minLength: 0, maxLength: 60 })
  .map((chars) => chars.join(""));

// A range generator with indices in [0, maxIndex]: start = min, end = max,
// kind drawn from both placeholder kinds. Overlaps/nesting/adjacency/
// duplicates arise naturally. Callers pass `len` for in-bounds ranges or
// `len + n` to probe out-of-bounds handling.
const rangesUpTo = (maxIndex) =>
  fc.array(
    fc
      .tuple(
        fc.integer({ min: 0, max: maxIndex }),
        fc.integer({ min: 0, max: maxIndex }),
        fc.constantFrom("hidden", "comment"),
      )
      .map(([a, b, kind]) => ({
        start: Math.min(a, b),
        end: Math.max(a, b),
        kind,
      })),
    { maxLength: 6 },
  );

const stripPlaceholders = (text) => text.replace(LAYER2_PLACEHOLDER_RE, "");

// Independent (set-union, not the merge algorithm) computation of the bytes
// that must survive: every index not covered by any range, in order.
const keptBytes = (text, ranges) => {
  const covered = new Array(text.length).fill(false);
  for (const { start, end } of ranges)
    for (let i = start; i < end; i++) covered[i] = true;
  let out = "";
  for (let i = 0; i < text.length; i++) if (!covered[i]) out += text[i];
  return out;
};

describe("property: spliceRanges preserves bytes outside the ranges", () => {
  it("removing placeholders from the output yields exactly the kept bytes", () => {
    fc.assert(
      fc.property(
        safeText.chain((text) =>
          fc.tuple(fc.constant(text), rangesUpTo(text.length)),
        ),
        ([text, ranges]) => {
          const out = spliceRanges(text, ranges);
          assert.equal(stripPlaceholders(out.text), keptBytes(text, ranges));
          // Each reported pair locates a well-formed keyed placeholder in the
          // output; substituting every original back (right to left) must
          // reproduce the input byte for byte.
          let rebuilt = out.text;
          for (let i = out.pairs.length - 1; i >= 0; i--) {
            const { placeholder, original, start } = out.pairs[i];
            assert.match(
              placeholder,
              new RegExp(`^(?:${LAYER2_PLACEHOLDER_RE.source})$`),
            );
            assert.equal(
              rebuilt.slice(start, start + placeholder.length),
              placeholder,
            );
            rebuilt =
              rebuilt.slice(0, start) +
              original +
              rebuilt.slice(start + placeholder.length);
          }
          assert.equal(rebuilt, text);
        },
      ),
      runOptions,
    );
  });

  it("is a no-op when given no ranges", () => {
    fc.assert(
      fc.property(safeText, (text) => {
        assert.deepEqual(spliceRanges(text, []), { text, pairs: [] });
      }),
      runOptions,
    );
  });

  it("never throws and returns a string even for out-of-bounds ranges", () => {
    fc.assert(
      fc.property(
        safeText.chain((text) =>
          fc.tuple(fc.constant(text), rangesUpTo(text.length + 10)),
        ),
        ([text, ranges]) => {
          assert.equal(typeof spliceRanges(text, ranges).text, "string");
        },
      ),
      runOptions,
    );
  });
});

// ─── spliceOrdered: the needle-splicing primitive ────────────────────────────

// Marker delimiting each spliced-in replacement in the output. Built from a code
// point so no raw control byte sits in this source, and drawn from outside every
// generated alphabet so the replacements can be located unambiguously.
const MARK = String.fromCharCode(0x00);

// Text over an alphabet the needles below are drawn from, so matches are dense.
const needleText = fc
  .array(fc.constantFrom(..."abXYZ ".split("")), { maxLength: 40 })
  .map((chars) => chars.join(""));

// Needles that can CROSS-OVERLAP each other in `needleText` ("abX" and "bXY"
// both match "abXY"), plus a self-overlapping one and the empty needle. Overlap
// is the case first-match-wins resolves, so it must be generated, not assumed
// away.
const overlappingNeedles = fc.array(
  fc.constantFrom("X", "Y", "Z", "ab", "abX", "bXY", "aa", ""),
  { maxLength: 4 },
);

// Single-character, pairwise-distinct needles: no two matches can overlap, so
// the union-of-occurrences oracle below is exact rather than an upper bound.
const disjointNeedles = fc.array(fc.constantFrom("X", "Y", "Z", "Q", ""), {
  maxLength: 4,
});

// The pre-fix implementation of deleteVerbatimSpans, kept as a reference for the
// non-vacuity test: it deletes span-by-span, so an earlier deletion joins the
// bytes around it and can create a later span's match.
const chainedDelete = (text, spans) => {
  let out = text;
  let removed = 0;
  for (const span of spans) {
    if (!span) continue;
    const parts = out.split(span);
    removed += parts.length - 1;
    out = parts.join("");
  }
  return { text: out, removed };
};

/** Run a marker splice, returning the result plus the matches it consumed. */
const markSplice = (text, needles) => {
  /** @type {{text: string, index: number}[]} */
  const used = [];
  const out = spliceOrdered(text, orderedMatches(text, needles), (match) => {
    used.push(match);
    return MARK;
  });
  return { out, used };
};

describe("property: spliceOrdered only touches verbatim matches of the original text", () => {
  it("the spliced-out chunks re-assemble the input exactly", () => {
    fc.assert(
      fc.property(needleText, overlappingNeedles, (text, needles) => {
        const { out, used } = markSplice(text, needles);
        // Every replaced chunk is a real occurrence of its needle at its
        // reported index IN THE ORIGINAL TEXT — never a match manufactured by
        // an earlier splice.
        for (const match of used) {
          assert.ok(occurrences(text, match.text).includes(match.index));
          assert.equal(
            text.slice(match.index, match.index + match.text.length),
            match.text,
          );
        }
        // The reported spans locate each replacement in the output.
        assert.equal(out.spans.length, used.length);
        for (const span of out.spans)
          assert.equal(out.text.slice(span.start, span.end), MARK);
        // Putting the replaced chunks back where the markers are must reproduce
        // the input byte for byte: nothing outside a match was disturbed, and
        // the matches were consumed in order without gaps or double-counting.
        const kept = out.text.split(MARK);
        assert.equal(kept.length, used.length + 1);
        const rebuilt = used.reduce(
          (acc, match, i) => acc + match.text + kept[i + 1],
          kept[0],
        );
        assert.equal(rebuilt, text);
      }),
      runOptions,
    );
  });

  it("a replacement carrying a needle's own bytes is never re-matched", () => {
    fc.assert(
      fc.property(needleText, overlappingNeedles, (text, needles) => {
        // Each replacement is its needle doubled, so a second pass over the
        // output would find and re-splice it, growing the span further. One
        // ordered pass over the original text cannot.
        const { used } = markSplice(text, needles);
        const out = spliceOrdered(
          text,
          orderedMatches(text, needles),
          (match) => match.text + match.text,
        );
        assert.equal(out.spans.length, used.length);
        out.spans.forEach((span, i) => {
          assert.equal(
            out.text.slice(span.start, span.end),
            used[i].text + used[i].text,
          );
        });
        const grown = used.reduce((sum, match) => sum + match.text.length, 0);
        assert.equal(out.text.length, text.length + grown);
      }),
      runOptions,
    );
  });

  it("is a no-op when nothing matches", () => {
    fc.assert(
      fc.property(needleText, (text) => {
        assert.deepEqual(
          spliceOrdered(text, orderedMatches(text, []), () => MARK),
          { text, spans: [] },
        );
      }),
      runOptions,
    );
  });
});

// ─── deleteVerbatimSpans (Layer 5) ───────────────────────────────────────────

describe("property: deleteVerbatimSpans removes only bytes the spans matched in the ORIGINAL text", () => {
  it("equals the complement of the union of the spans' occurrences", () => {
    fc.assert(
      fc.property(needleText, disjointNeedles, (text, spans) => {
        const { text: out, removed } = deleteVerbatimSpans(text, spans);
        assert.equal(out, keptOutsideNeedles(text, spans));
        // Distinct single-character spans cannot overlap, so each occurrence is
        // one removal — but a span repeated in the list names the same
        // occurrences twice and must still be counted once.
        assert.equal(removed, orderedMatches(text, [...new Set(spans)]).length);
      }),
      runOptions,
    );
  });

  it("with overlapping spans, deletes exactly the chunks a marker splice reports", () => {
    fc.assert(
      fc.property(needleText, overlappingNeedles, (text, spans) => {
        // The marker run proves (property above) that each removed chunk was a
        // verbatim match of the ORIGINAL text; deletion is that same pass with
        // an empty replacement.
        const { out: marked } = markSplice(text, spans);
        const { text: out, removed } = deleteVerbatimSpans(text, spans);
        assert.equal(out, marked.text.split(MARK).join(""));
        assert.equal(removed, marked.spans.length);
        // A deletion can only shrink, and it can never remove a byte no span
        // covered — so it never drops below the union complement.
        assert.ok(out.length <= text.length);
        assert.ok(out.length >= keptOutsideNeedles(text, spans).length);
      }),
      runOptions,
    );
  });

  it("the previous chained split/join implementation FAILS this invariant (non-vacuity)", () => {
    // Deleting "-XX-" joins "PRE" to "POST", creating a "PREPOST" the input
    // never contained; the chained implementation then deletes the whole
    // document — a Layer-5 filter naming two short spans could erase every byte
    // of legitimate tool output. If this reference ever stops failing, the
    // properties above have stopped discriminating.
    const text = "PRE-XX-POST";
    const spans = ["-XX-", "PREPOST"];
    assert.deepEqual(chainedDelete(text, spans), { text: "", removed: 2 });
    assert.notEqual(
      chainedDelete(text, spans).text,
      keptOutsideNeedles(text, spans),
    );
    assert.deepEqual(deleteVerbatimSpans(text, spans), {
      text: "PREPOST",
      removed: 1,
    });
    assert.equal(
      deleteVerbatimSpans(text, spans).text,
      keptOutsideNeedles(text, spans),
    );
  });
});

// ─── rehydration: placeholder → secret substitution ──────────────────────────

// Two redaction placeholders and the secrets they stand for. Each secret's
// bytes contain the OTHER placeholder's text verbatim — the case a chained
// `split(ph).join(secret)` corrupts in either processing order, since whichever
// pass runs second re-matches (and mangles) the secret the first pass inserted.
// Secrets are delimited by "«", a character the generated content never
// contains, so the substituted values can be located in the output without
// re-implementing the splice.
const PH_1 = "[REDACTED:1]";
const PH_2 = "[REDACTED:2]";
const SECRET_1 = `«sec-one-${PH_2}«`;
const SECRET_2 = `«sec-two-${PH_1}«`;
const SECRET_BODIES = [SECRET_1, SECRET_2].map((secret) => secret.slice(1, -1));

// Model-authored text over an alphabet with no "[" and no "«", with the two
// placeholders interleaved at arbitrary positions.
const authored = fc
  .array(
    fc.oneof(
      fc.constantFrom(..."abc \n".split("")),
      fc.constant(PH_1),
      fc.constant(PH_2),
    ),
    { maxLength: 24 },
  )
  .map((parts) => parts.join(""));

// Split a substitution result into the bytes that came from the input text
// (outside any secret) and the secret bodies spliced in. Unambiguous because
// only a substituted secret can contribute a "«".
const partitionSecrets = (out) => {
  const pieces = out.split("«");
  return {
    kept: pieces.filter((_, i) => i % 2 === 0).join(""),
    bodies: pieces.filter((_, i) => i % 2 === 1),
  };
};

const spanPairs = [
  { placeholder: PH_1, original: SECRET_1, start: 0 },
  { placeholder: PH_2, original: SECRET_2, start: PH_1.length },
];

describe("property: rehydrateNewString substitutes only the placeholders in new_string", () => {
  it("keeps every non-placeholder byte and never re-substitutes an inserted secret", () => {
    fc.assert(
      fc.property(authored, (newS) => {
        const res = rehydrateNewString(PH_1 + PH_2, newS, spanPairs, spanPairs);
        assert.ok(!("deny" in res), `unexpected deny: ${res.deny}`);
        const { kept, bodies } = partitionSecrets(res.text);
        // Bytes outside a placeholder occurrence in the ORIGINAL new_string
        // survive verbatim, in order.
        assert.equal(kept, keptOutsideNeedles(newS, [PH_1, PH_2]));
        // One WHOLE secret per placeholder occurrence: the placeholder each
        // secret embeds was not re-substituted — that would nest the other
        // secret inside it, splitting the "«" delimiter pair and yielding a
        // partial body no SECRET_BODIES entry matches.
        assert.equal(bodies.length, orderedMatches(newS, [PH_1, PH_2]).length);
        for (const body of bodies)
          assert.ok(
            SECRET_BODIES.includes(body),
            `secret body ${JSON.stringify(body)} is not a whole secret value`,
          );
      }),
      runOptions,
    );
  });
});

describe("property: a whole-file Write substitutes only the placeholders in the content", () => {
  const disk = `A=${SECRET_1}\nB=${SECRET_2}\n`;
  const viewText = `A=${PH_1}\nB=${PH_2}\n`;
  const view = {
    text: viewText,
    pairs: [
      { placeholder: PH_1, original: SECRET_1, start: viewText.indexOf(PH_1) },
      { placeholder: PH_2, original: SECRET_2, start: viewText.indexOf(PH_2) },
    ],
  };
  // io backed by the fixture above: map mode returns the view, and plain mode
  // re-redacts both secrets so the exposure gate passes. Neither secret is a
  // substring of the other and the generated content carries no "«", so no pass
  // of this stub's own chained replacement can create a match for the next.
  const io = {
    readFile: () => disk,
    redactMap: () => view,
    redact: (text) =>
      text.split(SECRET_1).join(PH_1).split(SECRET_2).join(PH_2),
  };

  it("keeps every non-placeholder byte and never re-substitutes an inserted secret", async () => {
    await fc.assert(
      fc.asyncProperty(
        // At least one placeholder, or the Write is not a rehydration candidate.
        authored.filter(
          (content) => content.includes(PH_1) || content.includes(PH_2),
        ),
        async (content) => {
          const res = await rehydrateRedacted(
            "Write",
            { file_path: "/f", content },
            io,
          );
          assert.ok(
            res && "updatedInput" in res,
            `expected a rewrite, got ${JSON.stringify(res)}`,
          );
          const { kept, bodies } = partitionSecrets(res.updatedInput.content);
          assert.equal(kept, keptOutsideNeedles(content, [PH_1, PH_2]));
          assert.equal(
            bodies.length,
            orderedMatches(content, [PH_1, PH_2]).length,
          );
          for (const body of bodies) assert.ok(SECRET_BODIES.includes(body));
        },
      ),
      runOptions,
    );
  });
});
