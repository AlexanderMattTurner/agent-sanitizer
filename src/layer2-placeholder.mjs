/**
 * The Layer-2 placeholder grammar: the one producer of keyed splice
 * placeholders, the regex that parses them, and the un-keyed marker for a
 * withheld unparseable input. `./html.mjs` re-exports all three as its public
 * API; the hooks reach them through claude-hooks/lib/placeholder-grammar.mjs.
 *
 * Split out of `./html.mjs` because that module loads the remark/rehype/unified
 * graph (~200ms) at import, and the hooks that only PARSE placeholders — the
 * PreToolUse rehydrator on every Edit/Write, the PostToolUse span persistence —
 * must not pay for it. This module imports nothing but `node:crypto`.
 */
import { createHash } from "node:crypto";

// The kind-specific prose of a Layer-2 placeholder. The full placeholder is
// built by {@link layer2Placeholder} and matched by {@link LAYER2_PLACEHOLDER_RE};
// keep all three in sync — they are ONE grammar.
const PLACEHOLDER_LABEL = Object.freeze({
  hidden: "hidden HTML",
  comment: "HTML comment",
});

// How many lowercase-hex chars of the sha256 make the placeholder key. 48 bits
// is far past accidental-collision range for the handful of splices one
// document carries, while keeping the placeholder short enough to read.
const PLACEHOLDER_KEY_LEN = 12;

/**
 * The keyed, content-addressed placeholder for one Layer-2 splice:
 * `[hidden HTML removed #<key>]` / `[HTML comment removed #<key>]`, where
 * `<key>` is the first 12 lowercase-hex chars of sha256 over the UTF-8
 * encoding of the ORIGINAL spliced text. Content-addressed on purpose:
 * identical spliced content yields the identical placeholder, so a rehydrator
 * can match placeholder → original by key alone, and duplicated content never
 * produces conflicting keys.
 * @param {"comment" | "hidden"} kind
 * @param {string} original the exact text the splice removed
 * @returns {string}
 */
export function layer2Placeholder(kind, original) {
  const key = createHash("sha256")
    .update(original, "utf8")
    .digest("hex")
    .slice(0, PLACEHOLDER_KEY_LEN);
  return `[${PLACEHOLDER_LABEL[kind]} removed #${key}]`;
}

/**
 * The single grammar definition for keyed Layer-2 placeholders — the exact
 * output of {@link layer2Placeholder}, capture group 1 = the key. Global so
 * callers can scan a document for every placeholder; reset `lastIndex` (or
 * use `matchAll`) between uses.
 */
export const LAYER2_PLACEHOLDER_RE =
  /\[(?:hidden HTML|HTML comment) removed #([0-9a-f]{12})\]/g;

// Shown when the remark/rehype parse itself fails (e.g. a RangeError from
// pathologically nested markup). `sanitize` never throws, so the HTML layer
// fails CLOSED by withholding the whole input behind this one placeholder:
// content it could not inspect for hidden payloads is treated as hidden.
export const UNPARSEABLE_PLACEHOLDER = "[HTML unparseable — withheld]";
