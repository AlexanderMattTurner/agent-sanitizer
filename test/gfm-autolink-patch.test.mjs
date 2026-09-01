/**
 * The patched GFM autolink-literal extension answers what upstream answers.
 *
 * `patches/micromark-extension-gfm-autolink-literal@2.1.0.patch` rewrites
 * `previousUnbalanced`, the predicate that decides whether an autolink literal
 * may start here. Layer 3 reads its URLs off this parse (`collectUrls` in
 * `src/html.mjs`), so a wrong answer is a detection miss: a bare URL that
 * stops being a `link` node is a URL `detectExfil` and `detectConfusableHosts`
 * never see, and it fails open.
 *
 * The cases below are the shapes that separate a WRONG memo from a right one.
 * They were found by shrinking a randomized differential — 72,000 generated
 * documents parsed under both builds — down to the smallest input whose URL
 * list moved. Every expectation here is the UNPATCHED parser's own answer, so
 * this file pins upstream behaviour rather than the patch's.
 *
 * The shape they share: a label that DOES resolve into a link, followed by an
 * autolink candidate. The label-start token keeps `_balanced === false` and is
 * spliced out of `events` by the resolver, so a memo that only re-checks
 * `_balanced` — the first version of this patch — still reports "unbalanced
 * label before here" and truncates the following autolink at the next `]`.
 *
 * `test/algorithmic-complexity.test.mjs` covers the cost this patch exists to
 * remove; it times the parse and cannot see a wrong answer.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import remarkGfm from "remark-gfm";
import remarkParse from "remark-parse";
import { unified } from "unified";

const parser = unified().use(remarkParse).use(remarkGfm);

/** Every URL the markdown tree carries, in document order. */
function urls(text) {
  const found = [];
  (function visit(node) {
    if (typeof node.url === "string") found.push(node.url);
    for (const child of node.children ?? []) visit(child);
  })(parser.parse(text));
  return found;
}

const LINK = "[a](b) ";

/** input -> the unpatched parser's URL list. */
const CASES = [
  // A resolved link, then a bare URL. The trailing `]>` belongs to the
  // autolink: this is the pair the first memo got wrong.
  [
    "[(b)](https://e.com)https://example.com/a]> ",
    ["https://e.com", "https://example.com/a]>"],
  ],
  [
    "[lorem(b)](https://e.com)https://example.com/a> ",
    ["https://e.com", "https://example.com/a>"],
  ],
  [
    "![(b)](https://e.com)contact@example.org]",
    ["https://e.com", "mailto:contact@example.org"],
  ],
  [
    "[(b)](https://e.com)[(c)](https://f.com)https://example.com/a]",
    ["https://e.com", "https://f.com", "https://example.com/a"],
  ],
  [
    "[x]\n\n> [lorem(b)](https://e.com)https://example.com/a]> ",
    ["https://e.com", "https://example.com/a]>"],
  ],
  // An autolink candidate inside a label that resolves, then another outside.
  [
    "[see www.example.com](https://e.com) www.other.com",
    ["https://e.com", "http://www.other.com"],
  ],
  // An unclosed `[`: the answer stays "unbalanced" for the rest of the
  // document, which is the case the patch makes cheap.
  ["[ text www.a.com", ["http://www.a.com"]],
  ['[ {"a":1} ] https://example.com/a', ["https://example.com/a"]],
  // Long enough that the memo is exercised many times over one document.
  [
    LINK.repeat(50) + "https://tail.com/p]",
    [...Array(50).fill("b"), "https://tail.com/p"],
  ],
  [
    "[ " + "word https://x.com/a abc@d.org ".repeat(20),
    Array.from({ length: 40 }, (_, i) =>
      i % 2 === 0 ? "https://x.com/a" : "mailto:abc@d.org",
    ),
  ],
];

describe("patched gfm-autolink-literal: URL extraction matches upstream", () => {
  for (const [input, expected] of CASES)
    it(
      JSON.stringify(input.length > 60 ? input.slice(0, 57) + "..." : input),
      () => {
        assert.deepEqual(urls(input), expected);
      },
    );

  it("reads a URL out of every case, so none passes on an empty list", () => {
    // Non-vacuity: `deepEqual([], [])` would hold for a parser that stopped
    // producing link nodes at all.
    for (const [input, expected] of CASES)
      assert.ok(expected.length > 0, `${JSON.stringify(input)} expects no URL`);
  });
});
