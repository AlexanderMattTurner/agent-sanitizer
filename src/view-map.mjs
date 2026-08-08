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
 * consumers of this module may use: it owns the code-point → UTF-16 offset
 * conversion and brands the result, so the conversion happens exactly once per
 * view and every function below can assert it happened.
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
 * @typedef {{ text: string, pairs: readonly RedactionPair[] }} FileView
 *   A branded, frozen carrier from {@link makeFileView}. `pairs` are in UTF-16
 *   offsets, sorted and non-overlapping — both enforced at construction.
 */

/**
 * Build the branded file view from a redactor's map-mode result.
 *
 * The redactor's own object is never touched. It used to be: the caller did
 * `view.pairs = pairsToUtf16(view.text, view.pairs)`, an in-place mutation of a
 * value returned from an INJECTED seam. A redactor that memoizes its map result
 * (a reasonable thing for a caller to build) hands back the same object on the
 * second identical call, which then gets converted a SECOND time — every
 * placeholder preceded by an astral character shifts again and the same input
 * yields a different verdict. Converting into a fresh frozen carrier makes that
 * unrepresentable: the conversion is part of construction, and construction
 * cannot be applied to its own output without going through the redactor again.
 *
 * The frozen `pairs` array is likewise a copy — `pairsToUtf16` returns its
 * argument unchanged for the empty case, and freezing the redactor's array
 * would reach back into the seam's memoized value.
 * @param {string} text redacted view text
 * @param {RedactionPair[]} pairs redactor pairs, in CODE-POINT offsets
 * @returns {FileView}
 */
export function makeFileView(text, pairs) {
  return Object.freeze({
    [FILE_VIEW]: true,
    text,
    pairs: Object.freeze([...pairsToUtf16(text, pairs)]),
  });
}

/**
 * Throw unless `view` came from {@link makeFileView}. Every offset function
 * here reads `view.pairs` as UTF-16 offsets; a hand-rolled `{text, pairs}` whose
 * pairs are still in code-point space mis-anchors an edit onto the wrong bytes
 * whenever an astral character precedes a placeholder — silently, and only for
 * emoji-bearing files. Fail loudly at the boundary instead.
 * @param {unknown} view
 * @param {string} fn name of the calling function, for the error
 * @returns {void}
 */
function assertFileView(view, fn) {
  if (
    view === null ||
    typeof view !== "object" ||
    /** @type {any} */ (view)[FILE_VIEW] !== true
  )
    throw new Error(
      `${fn} requires a view built by makeFileView(); got a raw object whose ` +
        `pair offsets have not been normalized to UTF-16`,
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
 * @param {string} text the redacted view text the offsets index into
 * @param {{placeholder: string, original: string, start: number}[]} pairs
 * @returns {{placeholder: string, original: string, start: number}[]}
 */
export function pairsToUtf16(text, pairs) {
  if (pairs.length === 0) return pairs;
  const codePoints = Array.from(text);
  // prefix[i] = UTF-16 length of the first i code points of `text`.
  const prefix = new Array(codePoints.length + 1);
  prefix[0] = 0;
  for (let i = 0; i < codePoints.length; i++)
    prefix[i + 1] = prefix[i] + codePoints[i].length;
  // Code-point end of the previous pair's placeholder span. mapViewOffset's
  // `else break` (and pairDiskSpans) assume pairs are sorted by start and never
  // overlap; an out-of-order or overlapping pair would make the scan stop early
  // and mis-map an offset onto the wrong bytes. Enforce the contract here.
  let prevEnd = 0;
  return pairs.map((pair) => {
    // A redactor offset outside [0, codePoints.length] indexes `prefix` out of
    // range and would silently yield `start: undefined`, which then poisons
    // every downstream offset comparison (undefined < n is always false) and
    // mis-anchors or corrupts the edit. Fail loudly instead — an out-of-range
    // pair means the injected redactor's map contract was violated.
    if (
      !Number.isInteger(pair.start) ||
      pair.start < 0 ||
      pair.start > codePoints.length
    )
      throw new Error(
        `redaction pair start ${pair.start} is out of range [0, ${codePoints.length}]`,
      );
    // Sorted + non-overlapping: `start` must be monotonically non-decreasing and
    // each pair's placeholder span must end at or before the next pair's start.
    // `prevEnd` already encodes the previous end, so `start < prevEnd` catches
    // both an out-of-order start and an overlap in one comparison. Fail closed.
    if (pair.start < prevEnd)
      throw new Error(
        `redaction pairs must be sorted and non-overlapping: pair start ${pair.start} precedes previous pair end ${prevEnd}`,
      );
    prevEnd = pair.start + Array.from(pair.placeholder).length;
    return { ...pair, start: prefix[pair.start] };
  });
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
 * @param {FileView} view
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
  assertFileView(view, "resolveSpan");
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
 * @param {FileView} view
 * @param {{start: number, deleted: string}[]} deletions
 * @returns {{start: number, end: number}[]}
 */
export function pairDiskSpans(view, deletions) {
  assertFileView(view, "pairDiskSpans");
  return view.pairs.map((pair) => {
    // pair.start is a placeholder boundary, and makeFileView rejected any pair
    // set that is out of order or overlapping (see pairsToUtf16), so it is never
    // strictly interior to another placeholder: mapViewOffset always resolves.
    // The brand assertion above is what makes that a guarantee rather than a
    // hope, which is why there is no second null check here — the one input that
    // could produce null cannot be constructed.
    const cleanedStart = /** @type {number} */ (
      mapViewOffset(view.pairs, pair.start)
    );
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
