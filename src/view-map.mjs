/**
 * Pure offset/text machinery for mapping between a file's on-disk bytes and
 * the sanitized view the model reads (Layer 1 invisible/ANSI stripping, then
 * Layer 4 secret redaction). No I/O — consumed by `./rehydrate.mjs`,
 * which owns file access, the injected redactor, and policy.
 *
 * Coordinate spaces, disk → view:
 *   disk    — the file's real bytes
 *   cleaned — disk minus the runs Layer 1 deleted (`alignDeletions` recovers
 *             them; a run at `start` sits immediately before cleaned[start])
 *   view    — cleaned with each secret replaced by its [REDACTED…]
 *             placeholder (`pairs` from the injected redactor’s map mode)
 *
 * The view is carried by {@link makeFileView}, the ONLY constructor the
 * consumers of this module may use: it brands the result, and the brand carries
 * the coordinate SPACE the pair offsets live in — `"codePoint"` as the injected
 * redactor emits them, `"utf16"` as every function below indexes by. Conversion
 * is a separate, one-way door ({@link toUtf16View}) that accepts only a
 * `"codePoint"` view and returns a new `"utf16"` one, so converting twice throws
 * instead of shifting every astral-preceded offset a second time. Each consumer
 * asserts the space it needs, so a wrongly-spaced view fails at the boundary
 * rather than resolving onto the wrong bytes.
 *
 * The space is part of the value rather than a convention in a comment because
 * the two spaces are otherwise indistinguishable — bare numbers in a bare
 * object — which is exactly why the original double-conversion bug was silently
 * accepted.
 */

/**
 * Brand stamped by {@link makeFileView} and asserted by every function that
 * consumes a view. A Symbol, not a string key: it cannot be spelled by a plain
 * object literal built elsewhere (in this module's tests or in a consumer), so
 * the assertion below proves the carrier came through the constructor rather
 * than merely resembling one.
 */
const FILE_VIEW = Symbol("agent-sanitizer:file-view");

/**
 * @typedef {{ placeholder: string, original: string, start: number }} RedactionPair
 * @typedef {"codePoint" | "utf16"} OffsetSpace
 *   Units a {@link FileView}'s pair offsets are expressed in. `codePoint` is
 *   what the redactor's map mode emits (Python indexes strings by code point);
 *   `utf16` is what every function in this module indexes by (JS
 *   `indexOf`/`slice`/`.length` count UTF-16 code units).
 */

/**
 * A branded, frozen carrier from {@link makeFileView}, tagged with the space its
 * `pairs` offsets live in. Its own JSDoc block: a `@template` applies to every
 * typedef in the comment it sits in, so sharing one with the two above would
 * make `RedactionPair` and `OffsetSpace` generic too.
 * @template {OffsetSpace} S
 * @typedef {{ readonly space: S, readonly text: string,
 *   readonly pairs: readonly RedactionPair[] }} FileView
 */

/**
 * Wrap a redactor's map-mode result in a frozen, branded view tagged with the
 * space its offsets are in.
 *
 * The redactor's own object is never touched. It used to be: the caller did
 * `view.pairs = pairsToUtf16(view.text, view.pairs)`, an in-place mutation of a
 * value returned from an INJECTED seam. A redactor that memoizes its map result
 * (a reasonable thing for a caller to build) hands back the same object on the
 * second identical call, which then got converted a SECOND time — every
 * placeholder preceded by an astral character shifts again and the same input
 * yields a different verdict.
 *
 * Construction no longer converts. It brands and records the space, and
 * {@link toUtf16View} does the conversion behind a check that the input is
 * still in code-point space — so `toUtf16View(alreadyConverted)` throws where
 * `makeFileView(v.text, v.pairs)` on an existing view used to silently convert
 * a second time. That was the one door this carrier left open.
 *
 * Both the array AND each pair object are copied before freezing, so nothing
 * here reaches back into the seam's (possibly memoized) value, and a caller that
 * later mutates its own pairs cannot change what this view resolves.
 * @template {OffsetSpace} S
 * @param {string} text redacted view text
 * @param {readonly RedactionPair[]} pairs redactor pairs, offsets in `space`
 * @param {S} space
 * @returns {FileView<S>}
 */
export function makeFileView(text, pairs, space) {
  assertPairsOrdered(text, pairs, space);
  return Object.freeze({
    [FILE_VIEW]: true,
    space,
    text,
    pairs: Object.freeze(pairs.map((pair) => Object.freeze({ ...pair }))),
  });
}

/**
 * Offsets counted the way `space` counts them: UTF-16 code units, or code
 * points as the Python redactor emits them.
 * @param {string} text
 * @param {OffsetSpace} space
 * @returns {number}
 */
function unitLength(text, space) {
  return space === "utf16" ? text.length : Array.from(text).length;
}

/**
 * Throw unless `pairs` is in range, sorted by `start` and non-overlapping, with
 * every offset read in `space`.
 *
 * Every consumer here — `mapViewOffset`'s `else break`, `pairDiskSpans`'s
 * sequential walk — assumes exactly this. An out-of-range start indexes past
 * the text and silently yields `undefined`, which then poisons every downstream
 * offset comparison (`undefined < n` is always false); an out-of-order or
 * overlapping pair stops the scan early and mis-maps an offset onto the wrong
 * bytes. Enforced at CONSTRUCTION so no view can exist in that state, rather
 * than at each read.
 * @param {string} text the view text the offsets index into
 * @param {readonly RedactionPair[]} pairs
 * @param {OffsetSpace} space
 * @returns {void}
 */
function assertPairsOrdered(text, pairs, space) {
  const total = unitLength(text, space);
  // The previous pair's placeholder end. `start < prevEnd` catches an
  // out-of-order start and an overlap in one comparison.
  let prevEnd = 0;
  for (const pair of pairs) {
    if (!Number.isInteger(pair.start) || pair.start < 0 || pair.start > total)
      throw new Error(
        `redaction pair start ${pair.start} is out of range [0, ${total}]`,
      );
    if (pair.start < prevEnd)
      throw new Error(
        `redaction pairs must be sorted and non-overlapping: pair start ${pair.start} precedes previous pair end ${prevEnd}`,
      );
    prevEnd = pair.start + unitLength(pair.placeholder, space);
  }
}

/**
 * Throw unless `view` came from {@link makeFileView} AND carries `space`.
 *
 * Two failures, one gate. A hand-rolled `{text, pairs}` has offsets that may or
 * may not have been converted; a real view in the WRONG space has offsets that
 * definitely have not. Either mis-anchors an edit onto the wrong bytes whenever
 * an astral character precedes a placeholder — silently, and only for
 * emoji-bearing files. Fail loudly at the boundary instead.
 * @param {unknown} view
 * @param {OffsetSpace} space  the space the calling function indexes by
 * @param {string} fn name of the calling function, for the error
 * @returns {void}
 */
function assertFileView(view, space, fn) {
  if (
    view === null ||
    typeof view !== "object" ||
    /** @type {any} */ (view)[FILE_VIEW] !== true
  )
    throw new Error(
      `${fn} requires a view built by makeFileView(); got a raw object whose ` +
        `pair offsets have not been normalized to UTF-16`,
    );
  const actual = /** @type {FileView<OffsetSpace>} */ (view).space;
  if (actual !== space)
    throw new Error(
      `${fn} requires a view with ${space} pair offsets, got ${actual}`,
    );
}

/**
 * Non-overlapping occurrence indices of `needle` in `haystack`.
 * @param {string} haystack
 * @param {string} needle
 * @returns {number[]}
 */
export function occurrences(haystack, needle) {
  // An empty needle has no meaningful occurrence here, and `indexOf("", k)`
  // clamps to `haystack.length` rather than returning -1, so stepping by the
  // needle length (0) would loop forever and grow `out` until a RangeError.
  // Callers must never act on a zero-length match; return none.
  if (needle === "") return [];
  const out = [];
  let i = haystack.indexOf(needle);
  while (i !== -1) {
    out.push(i);
    i = haystack.indexOf(needle, i + needle.length);
  }
  return out;
}

/**
 * Count of ALL matches of `needle` in `haystack`, including self-overlapping
 * ones (stepping by 1, not by the needle length). `occurrences` deliberately
 * steps by the needle length so it never reports overlapping spans — correct
 * for splicing, but it undercounts a self-overlapping needle (e.g. "aa" in
 * "aaa" is one non-overlapping match yet two overlapping ones). Ambiguity
 * gating must use THIS count: an old_string that overlaps itself has more than
 * one anchor a human (or the real Edit tool) could mean, so it is ambiguous even
 * when `occurrences` reports a single non-overlapping match.
 * @param {string} haystack
 * @param {string} needle
 * @returns {number}
 */
export function overlapAwareCount(haystack, needle) {
  if (needle === "") return 0;
  let count = 0;
  let i = haystack.indexOf(needle);
  while (i !== -1) {
    count++;
    i = haystack.indexOf(needle, i + 1);
  }
  return count;
}

/**
 * The character runs Layer 1 deleted, located by greedy subsequence alignment
 * (stripping only deletes, so `cleaned` is always a subsequence of `content`).
 * Throws if the subsequence property does not hold — the caller fails closed.
 * @param {string} content disk bytes
 * @param {string} cleaned Layer-1 view of the same bytes
 * @returns {{start: number, deleted: string}[]}
 */
export function alignDeletions(content, cleaned) {
  const deletions = [];
  let run = "";
  let ci = 0;
  for (let di = 0; di < content.length; di++) {
    if (ci < cleaned.length && content[di] === cleaned[ci]) {
      if (run) {
        deletions.push({ start: ci, deleted: run });
        run = "";
      }
      ci++;
    } else {
      run += content[di];
    }
  }
  if (ci !== cleaned.length)
    throw new Error("layer-1 view is not a subsequence of the file");
  if (run) deletions.push({ start: ci, deleted: run });
  return deletions;
}

/**
 * Disk offset of cleaned-view offset `cleanedOffset`. A deleted run attaches
 * immediately BEFORE the cleaned character at its `start`, so a span start
 * lands after an adjacent run (preserving it) and a span end stops before one.
 * @param {{start: number, deleted: string}[]} deletions sorted by start
 * @param {number} cleanedOffset
 * @param {boolean} isEnd span-end (exclusive) rather than span-start mapping
 * @returns {number}
 */
function diskOffset(deletions, cleanedOffset, isEnd) {
  let extra = 0;
  for (const del of deletions) {
    if (del.start < cleanedOffset || (!isEnd && del.start === cleanedOffset))
      extra += del.deleted.length;
    else break;
  }
  return cleanedOffset + extra;
}

/**
 * Re-express each pair's `start` from a Unicode code-point offset — what the
 * redactor's map mode emits (Python indexes strings by code point) — to a
 * UTF-16 code-unit offset into `text`, the basis every other function here uses
 * (JS `indexOf`/`slice`/`.length` count UTF-16 units). The two are identical for
 * BMP-only text and diverge only when an astral character (e.g. an emoji)
 * precedes a placeholder, where the code-point offset undercounts by one per
 * astral char. `pair.start` is compared against UTF-16 view offsets throughout,
 * so this conversion MUST run once at ingestion or an astral-preceded
 * placeholder mis-anchors the edit onto the wrong bytes.
 *
 * Exactly once, though: applying it to its own output shifts every
 * astral-preceded placeholder a second time, and bare arrays of numbers give
 * nothing to check that against. Prefer {@link toUtf16View}, which runs this
 * behind a space check so the second application throws instead. This stays
 * exported — it is public API on the `./view-map` subpath, and removing it
 * would be a breaking change the release workflow cannot express (it caps
 * automated bumps at minor) — for callers doing their own offset bookkeeping,
 * who own the once-only discipline themselves.
 * @param {string} text the redacted view text the offsets index into
 * @param {RedactionPair[]} pairs
 * @returns {RedactionPair[]}
 */
export function pairsToUtf16(text, pairs) {
  if (pairs.length === 0) return pairs;
  assertPairsOrdered(text, pairs, "codePoint");
  const codePoints = Array.from(text);
  // prefix[i] = UTF-16 length of the first i code points of `text`.
  const prefix = new Array(codePoints.length + 1);
  prefix[0] = 0;
  for (let i = 0; i < codePoints.length; i++)
    prefix[i + 1] = prefix[i] + codePoints[i].length;
  return pairs.map((pair) => ({ ...pair, start: prefix[pair.start] }));
}

/**
 * The same view with its pair offsets re-expressed in UTF-16 code units — a NEW
 * frozen carrier; `view` is untouched.
 *
 * The one-way door. Only a `"codePoint"` view is accepted, so converting an
 * already-converted view throws rather than shifting every astral-preceded
 * offset a second time — which either mis-anchors the edit or rejects it as
 * cutting a placeholder, both from an input that was fine the first time it was
 * seen. Offset range/sort/overlap validity is not this door's job — every
 * carrier is checked at construction (see {@link assertPairsOrdered}), in
 * whichever space it declares.
 * @param {FileView<"codePoint">} view
 * @returns {FileView<"utf16">}
 */
export function toUtf16View(view) {
  assertFileView(view, "codePoint", "toUtf16View");
  // Copied because `view.pairs` is readonly and `pairsToUtf16` keeps the
  // published mutable signature; makeFileView copies again on the way in.
  return makeFileView(
    view.text,
    pairsToUtf16(view.text, [...view.pairs]),
    "utf16",
  );
}

/**
 * Map a redacted-view offset to its Layer-1-cleaned offset, or null when the
 * offset falls strictly inside a placeholder (no cleaned position corresponds).
 * @param {readonly RedactionPair[]} pairs
 * @param {number} offset view offset
 * @returns {number | null}
 */
function mapViewOffset(pairs, offset) {
  let delta = 0;
  for (const pair of pairs) {
    const end = pair.start + pair.placeholder.length;
    if (end <= offset) delta += pair.placeholder.length - pair.original.length;
    else if (pair.start < offset) return null;
    else break;
  }
  return offset - delta;
}

/**
 * Resolve view span [viewStart, viewEnd) to its on-disk text and the redaction
 * pairs it wholly contains, mapping across placeholder expansion (view →
 * cleaned) and stripped invisible runs (cleaned → disk). Null when a boundary
 * cuts through a placeholder. `invisibleBytes` counts stripped characters
 * inside the span (replaced along with it); runs at the boundaries stay
 * outside and are preserved. `cleanedText` is the span's Layer-1 view — the
 * caller MUST verify that re-cleaning `diskText` reproduces it before acting:
 * greedy alignment is ambiguous when a deleted run's edge character equals the
 * adjacent kept character (an ANSI sequence ending in `m` before a kept `m`),
 * and a mis-attributed run would mis-anchor the edit.
 * @param {string} content disk file content
 * @param {string} cleaned Layer-1 view of `content`
 * @param {FileView<"utf16">} view
 * @param {{start: number, deleted: string}[]} deletions
 * @param {number} viewStart
 * @param {number} viewEnd
 */
export function resolveSpan(
  content,
  cleaned,
  view,
  deletions,
  viewStart,
  viewEnd,
) {
  assertFileView(view, "utf16", "resolveSpan");
  const cleanedStart = mapViewOffset(view.pairs, viewStart);
  const cleanedEnd = mapViewOffset(view.pairs, viewEnd);
  if (cleanedStart === null || cleanedEnd === null) return null;
  const diskText = content.slice(
    diskOffset(deletions, cleanedStart, false),
    diskOffset(deletions, cleanedEnd, true),
  );
  return {
    diskText,
    cleanedText: cleaned.slice(cleanedStart, cleanedEnd),
    invisibleBytes: diskText.length - (cleanedEnd - cleanedStart),
    pairs: view.pairs.filter(
      (pair) =>
        pair.start >= viewStart &&
        pair.start + pair.placeholder.length <= viewEnd,
    ),
  };
}

/**
 * All occurrences of any needle in `text`, ordered by position. Every index is
 * computed against the ORIGINAL `text`, so the caller can splice them in one
 * pass ({@link spliceOrdered}). Redaction placeholder texts never
 * substring-overlap one another (each ends in "]" right after its
 * distinguishing label), so for that caller the sorted matches are also
 * non-overlapping; needles from an untrusted source (a Layer-5 filter's
 * removeSpans) can overlap, which spliceOrdered resolves first-match-wins.
 * Distinct needles matching at the SAME index keep `needles` order (Array#sort
 * is stable), so first-match-wins is deterministic.
 * @param {string} text
 * @param {string[]} needles
 * @returns {{text: string, index: number}[]}
 */
export function orderedMatches(text, needles) {
  const out = [];
  for (const needle of needles)
    for (const index of occurrences(text, needle))
      out.push({ text: needle, index });
  return out.sort((left, right) => left.index - right.index);
}

/**
 * Replace every match in `matches` with `replacementFor(match, i)` in a SINGLE
 * ordered pass over `text`. THE splice primitive for this codebase — the sole
 * sound way to substitute several needles at once.
 *
 * A chained `text.split(needle).join(value)` per needle is unsound in both
 * directions, which is why no caller may hand-roll one:
 *   - substitution: an inserted value whose bytes contain a LATER needle is
 *     re-matched by the next split and corrupted (or partially exposed);
 *   - deletion: an earlier deletion joins the bytes on either side of it and
 *     can CREATE a later needle's match, deleting text that needle never
 *     matched in the input ("PRE-XX-POST" minus "-XX-" yields "PREPOST").
 * Because every index in `matches` is measured against the original `text`,
 * this pass only ever touches bytes the caller actually matched.
 *
 * Overlapping matches are resolved first-match-wins: a match starting before
 * the previous one ended is skipped, never spliced at a shifted offset.
 * `i` is the match's index in `matches` (stable across skips) so a caller
 * pairing matches positionally with its own array stays aligned.
 * @param {string} text
 * @param {{text: string, index: number}[]} matches ordered by index, indices into `text`
 * @param {(match: {text: string, index: number}, i: number) => string} replacementFor
 * @returns {{text: string, spans: {start: number, end: number}[]}} spliced text
 *   and the [start, end) range each replacement occupies in it
 */
export function spliceOrdered(text, matches, replacementFor) {
  let out = "";
  let last = 0;
  /** @type {{start: number, end: number}[]} */
  const spans = [];
  matches.forEach((match, i) => {
    if (match.index < last) return;
    out += text.slice(last, match.index);
    const start = out.length;
    out += replacementFor(match, i);
    spans.push({ start, end: out.length });
    last = match.index + match.text.length;
  });
  return { text: out + text.slice(last), spans };
}

/**
 * On-disk [start, end) span of every redaction pair, mapped from its view
 * offset through placeholder expansion (view → cleaned) and stripped invisible
 * runs (cleaned → disk). A run abutting the secret stays outside its span (it
 * was never part of the secret); interior runs are included. Callers use these
 * to detect an edit whose on-disk footprint intrudes into bytes the model was
 * never shown.
 * @param {FileView<"utf16">} view
 * @param {{start: number, deleted: string}[]} deletions
 * @returns {{start: number, end: number}[]}
 */
export function pairDiskSpans(view, deletions) {
  assertFileView(view, "utf16", "pairDiskSpans");
  return view.pairs.map((pair) => {
    // pair.start is a placeholder boundary, and makeFileView rejected any pair
    // set that is out of order or overlapping (see pairsToUtf16), so it is never
    // strictly interior to another placeholder: mapViewOffset always resolves.
    // The throw is kept anyway, and is NOT dead weight — it is the difference
    // between crashing and corrupting. `null + pair.original.length` is a
    // NUMBER in JS (null coerces to 0), so dropping this check would turn a
    // violated invariant into a silently wrong disk span anchored at offset 0,
    // i.e. an edit footprint pointing at the wrong bytes.
    const cleanedStart = mapViewOffset(view.pairs, pair.start);
    /* c8 ignore start -- unreachable through makeFileView, which rejects the
       overlapping pair set that is the only way to produce null here (see the
       constructor test in test/view-map.test.mjs); kept as a fail-loud guard
       against a future regression in that ordering check. `ignore next N` does
       NOT suppress the branch here — only the statement — so the range form is
       required to keep the src branch floor at 100%. */
    if (cleanedStart === null)
      throw new Error("redaction pair start maps inside another placeholder");
    /* c8 ignore stop */
    const cleanedEnd = cleanedStart + pair.original.length;
    return {
      start: diskOffset(deletions, cleanedStart, false),
      end: diskOffset(deletions, cleanedEnd, true),
    };
  });
}

/**
 * Substitute the placeholders in a model-authored new_string with the secrets
 * they stand for. Resolution, strictest first: if the new placeholder
 * sequence equals the matched span's, map 1:1 by position; otherwise each
 * placeholder text must name a single distinct secret within the span. A
 * placeholder naming a secret outside the span, or one whose text also
 * appears literally in the matched file text, is unresolvable → deny.
 * @param {string} oldS matched old_string (≡ the view span text)
 * @param {string} newS model-authored replacement
 * @param {readonly RedactionPair[]} spanPairs
 * @param {readonly RedactionPair[]} filePairs
 * @returns {{text: string, secrets: string[]} | {deny: string}}
 */
export function rehydrateNewString(oldS, newS, spanPairs, filePairs) {
  const spanTexts = [...new Set(spanPairs.map((pair) => pair.placeholder))];
  for (const phText of new Set(filePairs.map((pair) => pair.placeholder))) {
    if (!newS.includes(phText)) continue;
    if (!spanTexts.includes(phText)) {
      if (!oldS.includes(phText))
        return {
          deny:
            `new_string contains "${phText}", which stands for a redacted secret outside ` +
            `the matched old_string; extend old_string to cover that secret, or drop it`,
        };
      continue; // literal file text the model matched verbatim
    }
    const produced = spanPairs.filter(
      (pair) => pair.placeholder === phText,
    ).length;
    if (occurrences(oldS, phText).length > produced)
      return {
        deny:
          `the matched text mixes literal "${phText}" text with a redacted secret sharing ` +
          `that placeholder; cannot tell which occurrences in new_string are which — ` +
          `edit the literal text and the secret's line separately`,
      };
  }
  // With an empty span (the verbatim fast path) both sequences below are
  // empty, so newS falls through unchanged.
  const newSeq = orderedMatches(newS, spanTexts);
  if (
    newSeq.length === spanPairs.length &&
    newSeq.every((match, i) => match.text === spanPairs[i].placeholder)
  ) {
    return {
      text: spliceOrdered(newS, newSeq, (_match, i) => spanPairs[i].original)
        .text,
      secrets: spanPairs.map((pair) => pair.original),
    };
  }

  // Each placeholder text must name exactly one secret; resolve that mapping
  // first, then splice in a SINGLE ordered pass (see spliceOrdered for why a
  // chained `out.split(ph).join(secret)` per placeholder is unsound).
  const valueByPh = new Map();
  for (const phText of new Set(newSeq.map((match) => match.text))) {
    const values = [
      ...new Set(
        spanPairs
          .filter((pair) => pair.placeholder === phText)
          .map((pair) => pair.original),
      ),
    ];
    if (values.length > 1)
      return {
        deny:
          `multiple distinct secrets in the matched text share the placeholder "${phText}" ` +
          `and new_string changes their count or order; keep each one in place, or ` +
          `edit them one at a time with unique surrounding context`,
      };
    valueByPh.set(phText, values[0]);
  }
  return {
    text: spliceOrdered(newS, newSeq, (match) => valueByPh.get(match.text))
      .text,
    secrets: [...valueByPh.values()],
  };
}
