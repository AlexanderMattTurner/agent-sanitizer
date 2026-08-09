/**
 * Example/unit tests for the pure offset engine (view-map.mjs), pinning the
 * security-relevant behaviors and closing every line/branch the property suite
 * (view-map-property.test.mjs) doesn't reach: the empty-span verbatim fast
 * path, the per-placeholder distinct-secret substitution path, and EVERY deny
 * branch of rehydrateNewString.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  occurrences,
  overlapAwareCount,
  orderedMatches,
  spliceOrdered,
  alignDeletions,
  resolveSpan,
  rehydrateNewString,
  pairsToUtf16,
  toUtf16View,
  pairDiskSpans,
  makeFileView,
  anchorSpans,
  viewMapDefect,
} from "../src/view-map.mjs";

// Secrets assembled at runtime so no complete token literal trips push
// protection; distinct values under the SAME placeholder text exercise the
// ambiguity branches.
const SECRET_A = ["hunter2hunter2", "hunter2xA"].join("");
const SECRET_B = ["hunter2hunter2", "hunter2xB"].join("");
const PH = "[REDACTED]";
const PH_KEY = "[REDACTED: Key]";
const ZW = String.fromCharCode(0x200b);

// ─── occurrences ─────────────────────────────────────────────────────────────

describe("occurrences", () => {
  it("returns non-overlapping ascending indices", () => {
    assert.deepEqual(occurrences("aaaa", "aa"), [0, 2]);
    assert.deepEqual(occurrences("abcabc", "abc"), [0, 3]);
  });

  it("returns [] when the needle is absent", () => {
    assert.deepEqual(occurrences("abc", "z"), []);
  });

  it("a length-1 needle steps by exactly its length", () => {
    // Forward progress comes from the `if (needle === "") return []` guard (which
    // rules out the only zero-length step) plus the `i + needle.length` advance;
    // for a length-1 needle each step is 1, so overlapping single chars are
    // reported once each without revisiting an index.
    assert.deepEqual(occurrences("aaa", "a"), [0, 1, 2]);
    assert.deepEqual(occurrences("aXa", "a"), [0, 2]);
  });
});

// ─── overlapAwareCount (R5) ──────────────────────────────────────────────────

describe("overlapAwareCount", () => {
  it("counts self-overlapping matches that occurrences() steps past", () => {
    // "aa" in "aaa" is ONE non-overlapping match but TWO overlapping ones; the
    // ambiguity gate must see the overlapping count to flag it.
    assert.equal(occurrences("aaa", "aa").length, 1);
    assert.equal(overlapAwareCount("aaa", "aa"), 2);
    assert.equal(overlapAwareCount("aaaa", "aa"), 3);
  });

  it("agrees with occurrences() when matches do not overlap", () => {
    assert.equal(overlapAwareCount("abcabc", "abc"), 2);
    assert.equal(overlapAwareCount("xyz", "q"), 0);
    assert.equal(overlapAwareCount("a", "a"), 1);
  });

  it("returns 0 for an empty needle (no infinite loop)", () => {
    assert.equal(overlapAwareCount("anything", ""), 0);
  });
});

// ─── orderedMatches / spliceOrdered ──────────────────────────────────────────

describe("spliceOrdered", () => {
  const splice = (text, needles, replacementFor) =>
    spliceOrdered(text, orderedMatches(text, needles), replacementFor);

  it("substitutes every match in one pass over the original text", () => {
    assert.deepEqual(
      splice("a-X-b-Y-", ["X", "Y"], (match) => `<${match.text}>`),
      {
        text: "a-<X>-b-<Y>-",
        spans: [
          { start: 2, end: 5 },
          { start: 8, end: 11 },
        ],
      },
    );
  });

  it("never re-matches a needle its own replacement introduced", () => {
    // Substituting "A" -> "B" and "B" -> "A" must SWAP them, not run the second
    // needle over the first's output (which would leave both as "A").
    assert.equal(
      splice("AB", ["A", "B"], (match) => (match.text === "A" ? "B" : "A"))
        .text,
      "BA",
    );
  });

  it("skips a match overlapping the previous one (first-match-wins)", () => {
    // "abX" (index 0) and "bXY" (index 1) overlap; only the first is spliced,
    // and the second is dropped rather than applied at a shifted offset.
    const result = splice("abXY", ["abX", "bXY"], () => "#");
    assert.deepEqual(result, { text: "#Y", spans: [{ start: 0, end: 1 }] });
  });

  it("is a no-op with no matches", () => {
    assert.deepEqual(
      splice("abc", ["z", ""], () => "#"),
      {
        text: "abc",
        spans: [],
      },
    );
  });
});

// ─── alignDeletions ──────────────────────────────────────────────────────────

describe("alignDeletions", () => {
  it("recovers an interior deleted run sitting immediately before cleaned[start]", () => {
    // content is "a<ZW>bc", cleaned "abc": the run sits before cleaned[1]='b'.
    const dels = alignDeletions(`a${ZW}bc`, "abc");
    assert.deepEqual(dels, [{ start: 1, deleted: ZW }]);
  });

  it("recovers a trailing run as start === cleaned.length", () => {
    const dels = alignDeletions(`ab${ZW}`, "ab");
    assert.deepEqual(dels, [{ start: 2, deleted: ZW }]);
  });

  it("recovers a leading run at start 0", () => {
    const dels = alignDeletions(`${ZW}ab`, "ab");
    assert.deepEqual(dels, [{ start: 0, deleted: ZW }]);
  });

  it("returns [] when nothing was deleted", () => {
    assert.deepEqual(alignDeletions("abc", "abc"), []);
  });

  it("throws when cleaned is not a subsequence of content", () => {
    assert.throws(
      () => alignDeletions("abc", "axc"),
      /layer-1 view is not a subsequence of the file/,
    );
  });

  it("throws when cleaned is longer than content can supply", () => {
    assert.throws(
      () => alignDeletions("ab", "abc"),
      /layer-1 view is not a subsequence of the file/,
    );
  });
});

// ─── resolveSpan ─────────────────────────────────────────────────────────────

// view with no secrets ⇒ view.text === cleaned and pairs empty.
// No pairs at all, so the space tag is a formality — but it is still declared,
// because `resolveSpan` now demands one.
const plainView = (cleaned) => makeFileView(cleaned, [], "utf16");

describe("resolveSpan", () => {
  it("maps a span across an interior stripped run, counting it in invisibleBytes", () => {
    const content = `ab${ZW}cd`;
    const cleaned = "abcd";
    const dels = alignDeletions(content, cleaned);
    const res = resolveSpan(content, cleaned, plainView(cleaned), dels, 1, 3);
    assert.equal(res.cleanedText, "bc");
    assert.equal(res.diskText, `b${ZW}c`);
    assert.equal(res.invisibleBytes, 1);
    assert.deepEqual(res.pairs, []);
  });

  it("keeps a run sitting exactly at the span end OUTSIDE the span (preserved)", () => {
    const content = `ab${ZW}cd`;
    const cleaned = "abcd";
    const dels = alignDeletions(content, cleaned);
    // Span [0,2) ends exactly where the run attaches (before cleaned[2]='c').
    const res = resolveSpan(content, cleaned, plainView(cleaned), dels, 0, 2);
    assert.equal(res.cleanedText, "ab");
    assert.equal(res.diskText, "ab");
    assert.equal(res.invisibleBytes, 0);
  });

  it("keeps a run sitting exactly at the span start OUTSIDE the span (preserved)", () => {
    const content = `ab${ZW}cd`;
    const cleaned = "abcd";
    const dels = alignDeletions(content, cleaned);
    // Span [2,4) starts where the run attaches; the run stays before the span.
    const res = resolveSpan(content, cleaned, plainView(cleaned), dels, 2, 4);
    assert.equal(res.cleanedText, "cd");
    assert.equal(res.diskText, "cd");
    assert.equal(res.invisibleBytes, 0);
  });

  it("maps view offsets across a placeholder expansion and returns contained pairs", () => {
    // cleaned: "x" + SECRET_A + "y"; view replaces SECRET_A with PH.
    const cleaned = `x${SECRET_A}y`;
    // ASCII throughout, so code-point and UTF-16 offsets coincide and the view
    // is declared in the space `resolveSpan` requires.
    const view = makeFileView(
      `x${PH}y`,
      [{ placeholder: PH, original: SECRET_A, start: 1 }],
      "utf16",
    );
    const res = resolveSpan(cleaned, cleaned, view, [], 0, view.text.length);
    assert.equal(res.cleanedText, cleaned);
    assert.equal(res.diskText, cleaned);
    assert.equal(res.invisibleBytes, 0);
    assert.deepEqual(res.pairs, view.pairs);
  });

  it("returns null when the span START cuts strictly inside a placeholder", () => {
    const cleaned = `x${SECRET_A}y`;
    const view = makeFileView(
      `x${PH}y`,
      [{ placeholder: PH, original: SECRET_A, start: 1 }],
      "utf16",
    );
    // Offset 2 is strictly inside the placeholder [1, 1+PH.length).
    const res = resolveSpan(cleaned, cleaned, view, [], 2, view.text.length);
    assert.equal(res, null);
  });

  it("returns null when the span END cuts strictly inside a placeholder", () => {
    const cleaned = `x${SECRET_A}y`;
    const view = makeFileView(
      `x${PH}y`,
      [{ placeholder: PH, original: SECRET_A, start: 1 }],
      "utf16",
    );
    const res = resolveSpan(cleaned, cleaned, view, [], 0, 2);
    assert.equal(res, null);
  });

  it("returns only the pairs wholly inside the span (the trailing one is dropped)", () => {
    // Two placeholders; span covers only the first. The filter keeps pairs
    // wholly inside [viewStart, viewEnd).
    const cleaned = `${SECRET_A} ${SECRET_B}`;
    const view = makeFileView(
      `${PH} ${PH_KEY}`,
      [
        { placeholder: PH, original: SECRET_A, start: 0 },
        { placeholder: PH_KEY, original: SECRET_B, start: PH.length + 1 },
      ],
      "utf16",
    );
    const res = resolveSpan(cleaned, cleaned, view, [], 0, PH.length);
    assert.deepEqual(res.pairs, [view.pairs[0]]);
  });
});

// ─── rehydrateNewString ──────────────────────────────────────────────────────

describe("rehydrateNewString", () => {
  it("verbatim fast path: empty span leaves new_string unchanged", () => {
    const out = rehydrateNewString("", "plain new text", [], []);
    assert.deepEqual(out, { text: "plain new text", secrets: [] });
  });

  it("verbatim fast path: an empty span passes new_string through even when it has plain placeholder-shaped-but-unknown text", () => {
    const out = rehydrateNewString("old", "no placeholders here", [], []);
    assert.deepEqual(out, { text: "no placeholders here", secrets: [] });
  });

  it("1:1 positional map when the new placeholder sequence equals the span's", () => {
    const spanPairs = [
      { placeholder: PH, original: SECRET_A, start: 0 },
      { placeholder: PH_KEY, original: SECRET_B, start: 100 },
    ];
    const oldS = `${PH}|${PH_KEY}`;
    const newS = `before ${PH} mid ${PH_KEY} after`;
    const out = rehydrateNewString(oldS, newS, spanPairs, spanPairs);
    assert.equal(out.text, `before ${SECRET_A} mid ${SECRET_B} after`);
    assert.deepEqual(out.secrets, [SECRET_A, SECRET_B]);
  });

  it("per-placeholder distinct-secret substitution when the sequence does NOT match 1:1", () => {
    // Span has ONE pair under PH; new_string uses PH twice. The fast-path
    // sequence-equality check fails (counts differ), so it falls to the
    // per-placeholder branch: PH maps to its single distinct secret everywhere.
    const spanPairs = [{ placeholder: PH, original: SECRET_A, start: 0 }];
    const oldS = PH;
    const newS = `${PH} and again ${PH}`;
    const out = rehydrateNewString(oldS, newS, spanPairs, spanPairs);
    assert.equal(out.text, `${SECRET_A} and again ${SECRET_A}`);
    assert.deepEqual(out.secrets, [SECRET_A]);
  });

  it("DENY: new_string names a secret redacted OUTSIDE the matched old_string", () => {
    const filePairs = [{ placeholder: PH, original: SECRET_A, start: 0 }];
    const out = rehydrateNewString("literal old", `note ${PH}`, [], filePairs);
    assert.equal("text" in out, false);
    assert.equal(typeof out.deny, "string");
    assert.ok(out.deny.length > 0);
    assert.match(out.deny, /outside the matched old_string/);
  });

  it("ALLOW: a placeholder-shaped literal the model matched verbatim in old_string is not a deny", () => {
    // filePairs has PH, but old_string also contains the literal PH text, so it
    // is treated as literal file text the model matched verbatim (continue).
    const filePairs = [{ placeholder: PH, original: SECRET_A, start: 0 }];
    const out = rehydrateNewString(
      `the literal ${PH} marker`,
      `the literal ${PH} marker, edited`,
      [],
      filePairs,
    );
    assert.equal(out.text, `the literal ${PH} marker, edited`);
    assert.deepEqual(out.secrets, []);
  });

  it("DENY: literal placeholder text collides with a real secret sharing that placeholder", () => {
    // Span produces ONE secret under PH (produced=1); old_string contains PH
    // TWICE (occurrences=2 > produced). Cannot tell which occurrence in
    // new_string is the literal vs the secret.
    const spanPairs = [{ placeholder: PH, original: SECRET_A, start: 0 }];
    const oldS = `${PH} literal ${PH}`;
    const newS = `${PH} literal ${PH}`;
    const out = rehydrateNewString(oldS, newS, spanPairs, spanPairs);
    assert.equal("text" in out, false);
    assert.equal(typeof out.deny, "string");
    assert.ok(out.deny.length > 0);
    assert.match(out.deny, /mixes literal/);
  });

  it("DENY: multiple distinct secrets share one placeholder and new_string changes their count/order", () => {
    // Two pairs under the SAME placeholder PH but DISTINCT originals. The
    // new_string has a single PH occurrence (count differs from the span's 2),
    // so the fast path is skipped and the per-placeholder branch sees >1 value.
    const spanPairs = [
      { placeholder: PH, original: SECRET_A, start: 0 },
      { placeholder: PH, original: SECRET_B, start: 100 },
    ];
    const oldS = `${PH}|${PH}`;
    const newS = `just ${PH}`;
    const out = rehydrateNewString(oldS, newS, spanPairs, spanPairs);
    assert.equal("text" in out, false);
    assert.equal(typeof out.deny, "string");
    assert.ok(out.deny.length > 0);
    assert.match(out.deny, /multiple distinct secrets/);
  });

  it("R6: a secret whose bytes contain another placeholder text is not re-substituted", () => {
    // The per-placeholder branch (new_string uses PH twice, so the sequence is
    // not 1:1 with the span) must build the output in ONE pass. Here SECRET_A's
    // bytes literally contain PH_KEY's placeholder text: a chained
    // split(PH).join(secret) then split(PH_KEY).join(SECRET_B) would clobber the
    // PH_KEY substring INSIDE the just-inserted SECRET_A. A single ordered pass
    // never re-scans inserted bytes.
    const SECRET_WITH_PH_KEY = `val${PH_KEY}end`;
    const spanPairs = [
      { placeholder: PH, original: SECRET_WITH_PH_KEY, start: 0 },
      { placeholder: PH_KEY, original: SECRET_B, start: 50 },
    ];
    const oldS = `${PH} ${PH_KEY}`;
    const newS = `${PH} ${PH} ${PH_KEY}`; // PH twice ⇒ not a 1:1 sequence
    const out = rehydrateNewString(oldS, newS, spanPairs, spanPairs);
    assert.equal(
      out.text,
      `${SECRET_WITH_PH_KEY} ${SECRET_WITH_PH_KEY} ${SECRET_B}`,
    );
    // The PH_KEY text survives verbatim inside each inserted SECRET_A.
    assert.equal(occurrences(out.text, PH_KEY).length, 2);
    assert.deepEqual(out.secrets, [SECRET_WITH_PH_KEY, SECRET_B]);
  });

  it("filePairs deduplicates: a placeholder absent from new_string is skipped", () => {
    // filePairs references PH_KEY but new_string never mentions it ⇒ the
    // `!newS.includes(phText)` guard continues past it without denying.
    const filePairs = [{ placeholder: PH_KEY, original: SECRET_B, start: 0 }];
    const out = rehydrateNewString("old", "new text only", [], filePairs);
    assert.deepEqual(out, { text: "new text only", secrets: [] });
  });
});

// ─── pairsToUtf16 (code-point → UTF-16 start normalization) ──────────────────

describe("pairsToUtf16", () => {
  it("is the identity for BMP-only text (code point == UTF-16 unit)", () => {
    // No astral chars: every start already equals its UTF-16 offset.
    const text = `key: ${PH_KEY} tail`;
    const pairs = [{ placeholder: PH_KEY, original: "AKIA1234", start: 5 }];
    assert.deepEqual(pairsToUtf16(text, pairs), pairs);
  });

  it("shifts a start right by one unit per astral char before it", () => {
    // Two emoji (astral, 2 UTF-16 units each) precede the placeholder, so its
    // code-point start (3) maps to UTF-16 offset 3 + 2 = 5.
    const text = `🔑🔑 ${PH_KEY}`;
    const cpStart = Array.from(text).indexOf("["); // 3 code points in
    assert.equal(cpStart, 3);
    const utf16Start = text.indexOf("["); // 5 UTF-16 units in
    assert.equal(utf16Start, 5);
    const out = pairsToUtf16(text, [
      { placeholder: PH_KEY, original: "AKIA1234", start: cpStart },
    ]);
    assert.equal(out[0].start, utf16Start);
    assert.equal(
      text.slice(out[0].start, out[0].start + PH_KEY.length),
      PH_KEY,
    );
  });

  it("returns the empty pairs array unchanged", () => {
    const empty = [];
    assert.equal(pairsToUtf16("🔑 no pairs", empty), empty);
  });

  it("throws on an out-of-range start instead of yielding an undefined offset (R7)", () => {
    // A redactor offset past the end of `text` indexes the prefix table out of
    // range; silently returning `start: undefined` poisons every downstream
    // comparison. Fail loudly on high, negative, and non-integer offsets.
    const text = "abc"; // 3 code points → valid starts are 0..3
    assert.throws(
      () => pairsToUtf16(text, [{ placeholder: PH, original: "x", start: 4 }]),
      /out of range \[0, 3\]/,
    );
    assert.throws(
      () => pairsToUtf16(text, [{ placeholder: PH, original: "x", start: -1 }]),
      /out of range/,
    );
    assert.throws(
      () =>
        pairsToUtf16(text, [{ placeholder: PH, original: "x", start: 1.5 }]),
      /out of range/,
    );
    // Boundary: start === codePoints.length (points at the very end) is valid.
    assert.deepEqual(
      pairsToUtf16(text, [{ placeholder: PH, original: "x", start: 3 }]),
      [{ placeholder: PH, original: "x", start: 3 }],
    );
  });

  it("throws on out-of-order or overlapping pairs (mapViewOffset's else-break contract)", () => {
    // mapViewOffset stops scanning at the first pair whose start is past the
    // offset (`else break`), which is only sound if pairs are sorted and never
    // overlap. Enforce that at ingestion — fail closed on a violation.
    const text = `${PH} ${PH}`;
    const s2 = text.indexOf(PH, 1);
    // Out of order: the second pair's start precedes the first pair's.
    assert.throws(
      () =>
        pairsToUtf16(text, [
          { placeholder: PH, original: "a", start: s2 },
          { placeholder: PH, original: "b", start: 0 },
        ]),
      /sorted and non-overlapping/,
    );
    // Overlapping: the first placeholder's span (start 0, len 10) still covers
    // offset 1, where the second pair claims to start.
    assert.throws(
      () =>
        pairsToUtf16(text, [
          { placeholder: PH, original: "a", start: 0 },
          { placeholder: PH, original: "b", start: 1 },
        ]),
      /sorted and non-overlapping/,
    );
    // Adjacent (previous end === next start) is the tight boundary and is valid.
    const adj = `${PH}${PH}`;
    assert.deepEqual(
      pairsToUtf16(adj, [
        { placeholder: PH, original: "a", start: 0 },
        { placeholder: PH, original: "b", start: PH.length },
      ]).map((pair) => pair.start),
      [0, PH.length],
    );
  });

  it("normalizes several pairs, each by the astral count preceding it", () => {
    const text = `🔑 ${PH_KEY} 🔑 ${PH}`;
    const cp = Array.from(text);
    const s1 = cp.indexOf("["); // first placeholder, code-point offset
    const s2 = cp.indexOf("[", s1 + 1); // second placeholder, code-point offset
    const out = pairsToUtf16(text, [
      { placeholder: PH_KEY, original: "AKIA1", start: s1 },
      { placeholder: PH, original: "AKIA2", start: s2 },
    ]);
    assert.equal(
      text.slice(out[0].start, out[0].start + PH_KEY.length),
      PH_KEY,
    );
    assert.equal(text.slice(out[1].start, out[1].start + PH.length), PH);
  });
});

describe("pairDiskSpans", () => {
  it("maps a redaction pair to its [start,end) disk span", () => {
    // Happy path: one placeholder, no deletions, so the disk span is the
    // pair's own [start, start+original.length).
    const spans = pairDiskSpans(
      makeFileView(
        "[REDACTED]",
        [{ placeholder: "[REDACTED]", original: "secret", start: 0 }],
        "utf16",
      ),
      [],
    );
    assert.deepEqual(spans, [{ start: 0, end: "secret".length }]);
  });

  it("rejects the overlapping pair set at CONSTRUCTION, not inside the mapper", () => {
    // pairDiskSpans used to carry its own "maps inside another placeholder"
    // throw for this input. makeFileView now refuses to build a view from it at
    // all, which is why that interior guard is gone rather than merely
    // untested: the second pair's start (3) is strictly interior to the first
    // placeholder "[REDACTED]" (offsets [0,10)), the one shape that could have
    // reached it.
    assert.throws(
      () =>
        makeFileView(
          "[REDACTED]",
          [
            { placeholder: "[REDACTED]", original: "secret", start: 0 },
            { placeholder: "[X]", original: "y", start: 3 },
          ],
          "utf16",
        ),
      /sorted and non-overlapping/,
    );
  });

  it("refuses a raw {text, pairs} object that never went through makeFileView", () => {
    // The brand is the whole point: a raw object's pair offsets may still be in
    // code-point space, which mis-anchors an edit on any astral-bearing file.
    const raw = {
      text: "[REDACTED]",
      pairs: [{ placeholder: "[REDACTED]", original: "secret", start: 0 }],
    };
    assert.throws(() => pairDiskSpans(raw, []), /makeFileView/);
    assert.throws(() => resolveSpan("s", "s", raw, [], 0, 1), /makeFileView/);
  });

  it("freezes the carrier and does not write through to the redactor's pairs", () => {
    // The bug this replaces: `view.pairs = pairsToUtf16(view.text, view.pairs)`
    // mutated the object the injected redactor returned, so a redactor that
    // memoizes its map result got its pairs converted twice.
    const text = `\u{1F511} ${PH}`;
    const redactorPairs = [
      {
        placeholder: PH,
        original: SECRET_A,
        start: Array.from(text).indexOf("["),
      },
    ];
    const snapshot = structuredClone(redactorPairs);
    const view = toUtf16View(makeFileView(text, redactorPairs, "codePoint"));
    assert.deepEqual(redactorPairs, snapshot, "redactor pairs were mutated");
    assert.equal(Object.isFrozen(view), true);
    assert.equal(Object.isFrozen(view.pairs), true);
    // Each pair is frozen too, not just the array holding them — an unfrozen
    // element is still a write-through to whatever the redactor handed over.
    assert.equal(Object.isFrozen(view.pairs[0]), true);
    // Converted once: the UTF-16 start really points at the placeholder.
    assert.equal(
      view.text.slice(view.pairs[0].start, view.pairs[0].start + PH.length),
      PH,
    );
    // And converting the SAME redactor object a second time is idempotent.
    assert.deepEqual(
      toUtf16View(makeFileView(text, redactorPairs, "codePoint")).pairs,
      view.pairs,
    );
  });

  it("refuses to convert a view that is already in UTF-16 space", () => {
    // The double-conversion this whole brand exists to make impossible: the
    // second pass would re-count the astral char and shift every start again.
    const text = `\u{1F511} ${PH}`;
    const once = toUtf16View(
      makeFileView(
        text,
        [
          {
            placeholder: PH,
            original: SECRET_A,
            start: Array.from(text).indexOf("["),
          },
        ],
        "codePoint",
      ),
    );
    assert.throws(() => toUtf16View(once), /codePoint/);
  });

  it("refuses a code-point view where a UTF-16 one is required", () => {
    // A view built straight off the redactor's output is branded, so the old
    // brand check would have waved it through — and mis-anchored every edit on
    // an astral-bearing file by exactly the surrogate count before the secret.
    const text = `\u{1F511} ${PH}`;
    const raw = makeFileView(
      text,
      [
        {
          placeholder: PH,
          original: SECRET_A,
          start: Array.from(text).indexOf("["),
        },
      ],
      "codePoint",
    );
    assert.throws(() => pairDiskSpans(raw, []), /utf16/);
    assert.throws(
      () => resolveSpan(text, text, raw, [], 0, text.length),
      /utf16/,
    );
  });

  it("reads pair offsets in the space the view declares", () => {
    // U+1F511 is one code point but two UTF-16 units, so start 2 is in range
    // for a utf16 view and past the end for a codePoint one. Nothing else here
    // pins that the range check counts units in the declared space: every other
    // view in this suite has starts valid in BOTH spaces, so collapsing
    // unitLength to `text.length` would survive the rest of the file.
    const text = "\u{1F511}";
    const pair = { placeholder: PH, original: SECRET_A, start: 2 };
    assert.doesNotThrow(() => makeFileView(text, [pair], "utf16"));
    assert.throws(
      () => makeFileView(text, [pair], "codePoint"),
      /out of range \[0, 1\]/,
    );
  });
});

// ─── anchorSpans (Write-path position anchoring) ─────────────────────────────

describe("anchorSpans", () => {
  const utf16 = (text, pairs) =>
    toUtf16View(makeFileView(text, pairs, "codePoint"));

  it("finds a plain common prefix and suffix", () => {
    const view = utf16("head MIDDLE tail", []);
    assert.deepEqual(anchorSpans("head CHANGED tail", view), {
      prefixEnd: 5,
      suffixStart: 11,
    });
  });

  it("prefix wins when prefix and suffix would overlap", () => {
    // content "aaXaa" vs view "aaaa": raw prefix 2 and raw suffix 2 would
    // together cover more than the shorter string allows; the suffix is capped
    // after the prefix is fixed.
    const view = utf16("aaaa", []);
    const { prefixEnd, suffixStart } = anchorSpans("aaXaa", view);
    assert.equal(prefixEnd, 2);
    assert.ok(suffixStart >= prefixEnd, "regions overlap");
    assert.equal(suffixStart, 4 - 2);
  });

  it("returns the full range for identical strings and zero for disjoint ones", () => {
    const view = utf16("same text", []);
    assert.deepEqual(anchorSpans("same text", view), {
      prefixEnd: 9,
      suffixStart: 9,
    });
    const other = utf16("abc", []);
    assert.deepEqual(anchorSpans("xyz", other), {
      prefixEnd: 0,
      suffixStart: 3,
    });
  });

  it("snaps a prefix boundary out of a placeholder interior", () => {
    // Common prefix extends INTO the placeholder text ("K=[REDACTED" shared,
    // then the strings diverge inside it); the boundary snaps back to the
    // placeholder's start so resolveSpan never sees a cut placeholder.
    const view = utf16(`K=${PH}\n`, [
      { placeholder: PH, original: SECRET_A, start: 2 },
    ]);
    const { prefixEnd } = anchorSpans(`K=${PH.slice(0, -1)}X\n`, view);
    assert.equal(prefixEnd, 2);
  });

  it("keeps a suffix boundary landing exactly at a placeholder start (whole placeholder in the suffix)", () => {
    const view = utf16(`K=${PH}\n`, [
      { placeholder: PH, original: SECRET_A, start: 2 },
    ]);
    const { suffixStart } = anchorSpans(`X${PH}\n`, view);
    assert.equal(suffixStart, 2);
  });

  it("snaps a suffix boundary out of a placeholder interior", () => {
    // Common suffix reaches back INTO the placeholder ("REDACTED]\n" shared,
    // missing the opening "["); the boundary snaps forward to the
    // placeholder's end so the cut placeholder stays out of the suffix.
    const view = utf16(`K=${PH}\n`, [
      { placeholder: PH, original: SECRET_A, start: 2 },
    ]);
    const { suffixStart } = anchorSpans(`X${PH.slice(1)}\n`, view);
    assert.equal(suffixStart, 2 + PH.length);
  });

  it("snaps boundaries off a split surrogate pair", () => {
    const EMOJI = String.fromCodePoint(0x1f511); // 2 UTF-16 units
    // Prefix: content shares the high surrogate then diverges on the low one.
    const view = utf16(`a${EMOJI}b`, []);
    const highOnly = `a${EMOJI[0]}${String.fromCharCode(0xdc00)}b`;
    const { prefixEnd } = anchorSpans(highOnly, view);
    assert.equal(prefixEnd, 1, "prefix boundary split a surrogate pair");
    // Suffix: content shares the low surrogate backwards then diverges.
    const lowOnly = `x${String.fromCharCode(0xd800)}${EMOJI[1]}b`;
    const { suffixStart } = anchorSpans(lowOnly, view);
    assert.equal(suffixStart, 3, "suffix boundary split a surrogate pair");
  });

  it("requires a UTF-16-space view built by makeFileView", () => {
    assert.throws(
      () => anchorSpans("x", { text: "x", pairs: [] }),
      /requires a view built by makeFileView/,
    );
    assert.throws(
      () => anchorSpans("x", makeFileView("x", [], "codePoint")),
      /requires a view with utf16 pair offsets/,
    );
  });
});

// ─── viewMapDefect ───────────────────────────────────────────────────────────

describe("viewMapDefect", () => {
  const cleaned = `key=${SECRET_A} tail`;
  // The production path: a code-point-space redactor map, converted once into
  // the UTF-16 carrier viewMapDefect (and every splice) consumes.
  const u16 = (text, pairs) =>
    toUtf16View(makeFileView(text, pairs, "codePoint"));

  it("accepts a sound map, including the empty one", () => {
    const sound = u16(`key=${PH} tail`, [
      { placeholder: PH, original: SECRET_A, start: 4 },
    ]);
    assert.equal(viewMapDefect(cleaned, sound), null);
    assert.equal(viewMapDefect("abc", u16("abc", [])), null);
  });

  it("flags a placeholder that is not at its stated offset", () => {
    const view = u16(`key=${PH} tail`, [
      { placeholder: PH, original: SECRET_A, start: 3 },
    ]);
    assert.match(viewMapDefect(cleaned, view), /offset 3/);
  });

  it("flags originals that do not reconstruct the cleaned text", () => {
    const view = u16(`key=${PH} tail`, [
      { placeholder: PH, original: SECRET_B, start: 4 },
    ]);
    const defect = viewMapDefect(cleaned, view);
    assert.match(defect, /does not reconstruct/);
    // Defect messages must never carry a secret byte.
    assert.ok(!defect.includes(SECRET_A) && !defect.includes(SECRET_B));
  });

  it("flags a no-pair view whose text silently differs from the file", () => {
    assert.match(viewMapDefect("abc", u16("abx", [])), /does not reconstruct/);
  });

  it("converts offsets once: a sound map behind an astral char stays sound", () => {
    // "😀" is one code point but two UTF-16 units; the redactor's code-point
    // offset 5 lands at UTF-16 offset 6 via toUtf16View's conversion, and the
    // validation must judge the CONVERTED pair.
    const astralCleaned = `😀key=${SECRET_A}`;
    const view = u16(`😀key=${PH}`, [
      { placeholder: PH, original: SECRET_A, start: 5 },
    ]);
    assert.equal(viewMapDefect(astralCleaned, view), null);
  });

  it("refuses the un-converted code-point carrier", () => {
    // Guards the call-site contract: viewMapDefect indexes by UTF-16 offset,
    // so handing it the pre-conversion view must throw, not mis-judge.
    assert.throws(
      () => viewMapDefect("abc", makeFileView("abc", [], "codePoint")),
      /utf16/,
    );
  });

  it("rejects a hand-rolled view object", () => {
    assert.throws(
      () => viewMapDefect("abc", { text: "abc", pairs: [] }),
      /makeFileView/,
    );
  });
});
