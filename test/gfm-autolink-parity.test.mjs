/**
 * `src/gfm.mjs` parses exactly what `remark-gfm` parses.
 *
 * `src/vendor/gfm-autolink-literal.mjs` is one of `remark-gfm`'s five micromark
 * extensions with a performance fix applied (generated at install time from the
 * pinned upstream plus `scripts/patches/*.patch`, never committed), and
 * `src/gfm.mjs` re-assembles the other four around it. The fix is meant to change cost and
 * nothing else, so upstream is the oracle: `remark-gfm` stays a devDependency
 * for exactly this comparison, and the assertions cannot go stale the way a
 * table of golden values does.
 *
 * The cases are the shapes that separate a WRONG memo from a right one. They
 * were found by shrinking a randomized differential — tens of thousands of
 * generated documents parsed under both builds — to the smallest input whose
 * URL list moved. What they share: a label that DOES resolve into a link,
 * followed by an autolink candidate. The label-start token keeps
 * `_balanced === false` and is spliced out of `events`, so a memo that only
 * re-checks `_balanced` still reports "unbalanced label before here" and
 * truncates the following autolink at the next `]`.
 *
 * Why this file and not a growth ratio: Layer 3 reads its URLs off this parse
 * (`collectUrls` in `src/html.mjs`), so a wrong answer is a detection miss with
 * no error — a bare URL that stops being a `link` node is a URL `detectExfil`
 * and `detectConfusableHosts` never see, and it fails open.
 * `test/algorithmic-complexity.test.mjs` covers the cost; it cannot see a wrong
 * answer.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import remarkGfmUpstream from "remark-gfm";
import remarkParse from "remark-parse";
import { unified } from "unified";

import {
  OUTPUT_PATH,
  PATCH_PATH,
  UPSTREAM_SHA256,
  applyPatch,
  readUpstream,
  renderGfmAutolink,
} from "../scripts/gen-gfm-autolink.mjs";
import remarkGfmVendored from "../src/gfm.mjs";

const ours = unified().use(remarkParse).use(remarkGfmVendored);
const upstream = unified().use(remarkParse).use(remarkGfmUpstream);

/** Every URL a tree carries, in document order — what Layer 3 consumes. */
function urls(processor, text) {
  const found = [];
  (function visit(node) {
    if (typeof node.url === "string") found.push(node.url);
    for (const child of node.children ?? []) visit(child);
  })(processor.parse(text));
  return found;
}

const LINK = "[a](b) ";

const CASES = [
  // A resolved link, then a bare URL. The `]>` belongs to the autolink; a memo
  // keyed on `_balanced` alone truncates it there.
  "[(b)](https://e.com)https://example.com/a]> ",
  "[lorem(b)](https://e.com)https://example.com/a> ",
  "![(b)](https://e.com)contact@example.org]",
  "[(b)](https://e.com)[(c)](https://f.com)https://example.com/a]",
  "[x]\n\n> [lorem(b)](https://e.com)https://example.com/a]> ",
  // An autolink candidate inside a label that resolves, then one outside.
  "[see www.example.com](https://e.com) www.other.com",
  // An unclosed `[`: the answer stays "unbalanced" for the rest of the
  // document, which is the case the fix makes cheap.
  "[ text www.a.com",
  '[ {"a":1} ] https://example.com/a',
  // Long enough that the memo is exercised many times over one document.
  LINK.repeat(50) + "https://tail.com/p]",
  "[ " + "word https://x.com/a abc@d.org ".repeat(20),
  // The other four extensions ride on the same assembly.
  "~~gone~~ https://e.com/a\n\n| a | b |\n| - | - |\n| https://c.com | d |\n",
  "- [x] done https://e.com/a\n\nText[^fn]\n\n[^fn]: https://f.com/b\n",
];

describe("src/gfm.mjs parses what remark-gfm parses", () => {
  for (const input of CASES) {
    const name = input.length > 60 ? `${input.slice(0, 57)}...` : input;
    it(JSON.stringify(name), () => {
      const expected = urls(upstream, input);
      // Non-vacuity: `deepEqual([], [])` holds for a parser that stopped
      // producing link nodes at all, so every case must carry a URL.
      assert.ok(expected.length > 0, "case reaches no URL — it proves nothing");
      assert.deepEqual(urls(ours, input), expected);
    });
  }

  it("agrees on the whole tree, not only the URLs", () => {
    // The URL walk above cannot see a heading level, a table alignment or a
    // footnote definition moving, and this assembly replaces all five
    // extensions rather than only the autolink one.
    for (const input of CASES)
      assert.deepEqual(
        JSON.parse(JSON.stringify(ours.parse(input))),
        JSON.parse(JSON.stringify(upstream.parse(input))),
        `tree differs for ${JSON.stringify(input)}`,
      );
  });
});

// The unpatched line and the patched marker are the two halves of one claim:
// checking only the marker passes on a file that kept the slow walk beside
// it, and checking only the absence passes on an empty one.
const UNPATCHED = "if (events.length > 0 && !result) {";
const PATCHED = "_gfmAutolinkLiteralSkipTo";

describe("scripts/gen-gfm-autolink.mjs builds src/vendor/gfm-autolink-literal.mjs", () => {
  it("is deterministic and equals the file `prepare` left on disk", () => {
    const rendered = renderGfmAutolink();
    assert.equal(renderGfmAutolink(), rendered);
    assert.equal(readFileSync(OUTPUT_PATH, "utf8"), rendered);
  });

  it("changed previousUnbalanced and nothing else's line count", () => {
    const upstream = readUpstream();
    const rendered = renderGfmAutolink();
    assert.ok(upstream.includes(UNPATCHED), "upstream no longer has the line");
    assert.ok(!upstream.includes(PATCHED), "upstream already has the marker");
    assert.ok(rendered.includes(PATCHED), "the patch did not land");
    assert.ok(
      !rendered.includes(UNPATCHED),
      "the unpatched walk is still here",
    );
    assert.ok(
      rendered.startsWith("/**\n * GENERATED by scripts/gen-gfm-autolink.mjs"),
    );
  });

  it("refuses an upstream file other than the pinned one", () => {
    assert.match(UPSTREAM_SHA256, /^[0-9a-f]{64}$/);
    assert.throws(
      () => renderGfmAutolink(`${readUpstream()}\n`),
      /not the .* of @2\.1\.0 that/,
    );
  });

  it("fails loudly when a hunk does not apply", () => {
    const patch = readFileSync(PATCH_PATH, "utf8");
    assert.throws(
      () =>
        applyPatch(
          readUpstream().replace(
            UNPATCHED,
            "if (events.length > 1 && !result) {",
          ),
          patch,
        ),
      /hunk 1 does not apply/,
    );
    assert.throws(() => applyPatch("a\nb", "--- a\n+++ b\n"), /no hunks/);
    assert.throws(
      () => applyPatch("a\nb", "--- a\n+++ b\n@@ -1,1 +1,3 @@\n a\n+x\n"),
      /line counts disagree/,
    );
  });
});
