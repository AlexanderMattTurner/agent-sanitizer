/**
 * The HTML layer parses through its own parse5 tree adapter, which defers a
 * front removal instead of splicing it (`src/html-tree-adapter.mjs`). The
 * deferral is a speed change and must be nothing else, so every test here is a
 * differential one: the same input, parsed with the DEFAULT adapter, must yield
 * the same tree.
 *
 * The shapes that can tell the two apart are the ones where a detach happens in
 * the middle of a parse rather than during the final drain — the adoption agency
 * algorithm (`<b><p></b>`), foster parenting out of a table, and a template's
 * content — so they are pinned by name below and then swept over randomized tag
 * soup, which is what caught the first version of this adapter leaving a
 * detached node in its old parent's array.
 *
 * The conversion to hast is chunked the same way (`fromParse5Bounded`), and is
 * held to one `fromParse5` call over the same corpus. Its depth ceiling is the
 * one deliberate difference, pinned at the end.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { defaultTreeAdapter, parseFragment, serialize } from "parse5";
import { fromParse5 } from "hast-util-from-parse5";
import { VFile } from "vfile";

import {
  MAX_HTML_DEPTH,
  createTreeAdapter,
  fromParse5Bounded,
} from "../src/html-tree-adapter.mjs";

const OPTIONS = {
  sourceCodeLocationInfo: true,
  onParseError: null,
  scriptingEnabled: false,
};

/** The parse5 tree as data: every field except the parent back-reference. */
const shape = (node) =>
  JSON.stringify(node, (key, value) =>
    key === "parentNode" ? undefined : value,
  );

/** `[ours, theirs]` for one input, each as a serialized tree. */
function bothAdapters(html) {
  const { adapter, settle } = createTreeAdapter();
  const ours = parseFragment(html, { ...OPTIONS, treeAdapter: adapter });
  settle();
  const theirs = parseFragment(html, {
    ...OPTIONS,
    treeAdapter: defaultTreeAdapter,
  });
  return [ours, theirs];
}

function assertSameTree(html) {
  const [ours, theirs] = bothAdapters(html);
  assert.equal(serialize(ours), serialize(theirs), html);
  assert.equal(shape(ours), shape(theirs), html);
}

/** Nodes reachable from `node`, so a stale entry counts as a node. */
function count(node) {
  let total = 1;
  for (const child of node.childNodes ?? []) total += count(child);
  return total;
}

const MID_PARSE_DETACH = {
  "adoption agency": "<b><p></b><script>",
  "adoption agency, nested": "<b><i><p>x</i>y</b>z",
  "foster parenting": "<table>text<tr><td>x</td></tr></table>",
  "foster parenting, comment": "<table><tbody><!--c--><td>a",
  template: "<template><p>in template</p></template>",
  "table in table": "<table><table><td>a",
  "form in form": "<form><form><input></form>",
  select: "<select><option><option></select>",
};

const ORDINARY = {
  "many top-level siblings":
    '<p class="x">hi <a href="https://e.com/">l</a></p>\n'.repeat(400),
  "comment run": "<!--c-->\n".repeat(200),
  "deep nesting": "<div><span><em>deep</em></span></div>".repeat(50),
  "raw text": "<textarea><p>raw</p></textarea><style>p{color:red}</style>",
  "foreign content":
    "<svg><foreignObject><p>x</p></foreignObject></svg><math><mi>x</mi></math>",
  "unclosed element": "<p>unclosed",
  "stray close": "</p>stray close",
  doctype: "<!DOCTYPE html><p>doc</p>",
  entities: "<p>&amp;&#x41;&nbsp;</p>",
  empty: "",
};

/**
 * Randomized tag soup, the same 400 inputs on every run: a failure here has to
 * name a case somebody can reproduce.
 * @returns {string[]}
 */
function tagSoup() {
  const pieces = [
    "<p>",
    "</p>",
    "<b>",
    "</b>",
    "<table>",
    "<tr>",
    "<td>",
    "</table>",
    "<!--",
    "-->",
    "<div style='display:none'>",
    "</div>",
    "<template>",
    "</template>",
    "<script>",
    "</script>",
    "<style>",
    "</style>",
    "<form>",
    "</form>",
    "<li>",
    "<select>",
    "<option>",
    "<svg>",
    "</svg>",
    "<math>",
    "</math>",
    "<textarea>",
    "</textarea>",
    "<tbody>",
    "<input>",
    "text ",
    "\n",
    "&amp;",
    "<!DOCTYPE html>",
  ];
  let seed = 20260826;
  const next = () =>
    (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  const inputs = [];
  for (let i = 0; i < 400; i++) {
    let html = "";
    for (let j = 0, n = 1 + Math.floor(next() * 30); j < n; j++)
      html += pieces[Math.floor(next() * pieces.length)];
    inputs.push(html);
  }
  return inputs;
}

describe("html tree adapter matches the default adapter", () => {
  for (const [label, html] of Object.entries(MID_PARSE_DETACH))
    it(`mid-parse detach: ${label}`, () => assertSameTree(html));

  for (const [label, html] of Object.entries(ORDINARY))
    it(`ordinary: ${label}`, () => assertSameTree(html));

  it("leaves no detached node behind (non-vacuity for the sweep)", () => {
    // `<b><p></b><script>` moves the `<p>` out of the `<b>` mid-parse. An
    // adapter that defers that removal and never settles it reports one node
    // more than the default adapter does, which is the defect this pins.
    const [ours, theirs] = bothAdapters("<b><p></b><script>");
    assert.equal(count(ours), count(theirs));
    assert.ok(count(theirs) > 4, "input must build a tree worth counting");
  });

  it("ignores a detach of a node that has no parent", () => {
    // The `TreeAdapter` contract the default adapter implements: detaching an
    // already-detached node is a no-op, not a throw.
    const { adapter } = createTreeAdapter();
    const orphan = { nodeName: "#text", value: "x", parentNode: null };
    adapter.detachNode(orphan);
    defaultTreeAdapter.detachNode(orphan);
    assert.equal(orphan.parentNode, null);
  });

  it("agrees on randomized tag soup", () => {
    for (const html of tagSoup()) assertSameTree(html);
  });
});

/**
 * `fromParse5` and {@link fromParse5Bounded} over the same input, each on its
 * own parse (the bounded one rewrites the tree it converts). A throw is part of
 * the answer: `hast-util-from-parse5` throws on a template in foreign content,
 * and the bounded conversion must throw the same.
 * @param {string} html
 * @param {number} chunkDepth
 */
function bothConversions(html, chunkDepth) {
  const outcome = (convert) => {
    try {
      return { tree: convert(parseFragment(html, OPTIONS), new VFile(html)) };
    } catch (error) {
      return { error: String(error) };
    }
  };
  return [
    outcome((tree, file) => fromParse5Bounded(tree, file, chunkDepth)),
    outcome((tree, file) => fromParse5(tree, { file })),
  ];
}

describe("bounded conversion matches one fromParse5 call", () => {
  // Chunks of one, two and three levels put a cut under every shape the corpus
  // has: an unclosed element whose end comes from a cut child, a template whose
  // content is cut, foreign content, recovery-synthesized nodes with no
  // position.
  const corpus = [
    ...Object.values(MID_PARSE_DETACH),
    ...Object.values(ORDINARY),
    ...tagSoup(),
  ];
  for (const chunkDepth of [1, 2, 3])
    it(`in chunks of ${chunkDepth}`, () => {
      let trees = 0;
      for (const html of corpus) {
        const [ours, theirs] = bothConversions(html, chunkDepth);
        assert.deepEqual(ours, theirs, html);
        if (theirs.tree) trees++;
      }
      // Non-vacuity: two throws compare equal, so most of the corpus must have
      // converted for the agreement to say anything.
      assert.ok(trees > corpus.length * 0.8, `${trees}/${corpus.length}`);
    });

  it("converts a cut subtree separately (non-vacuity for the sweep)", () => {
    // A chunk of one cuts every child of the root, so the `<p>` stands in the
    // parse5 tree as a placeholder by the time the root is converted.
    const tree = parseFragment("<p>x</p>", OPTIONS);
    const converted = fromParse5Bounded(tree, new VFile("<p>x</p>"), 1);
    assert.equal(tree.childNodes[0].nodeName, "#text");
    assert.equal(typeof tree.childNodes[0].value, "object");
    assert.equal(converted.children[0].tagName, "p");
  });

  it(`refuses a node more than MAX_HTML_DEPTH (${MAX_HTML_DEPTH}) levels down, and only that`, () => {
    const nested = (depth) => {
      const html = "<div>".repeat(depth);
      return () =>
        fromParse5Bounded(parseFragment(html, OPTIONS), new VFile(html));
    };
    assert.equal(nested(MAX_HTML_DEPTH)().children.length, 1);
    assert.throws(nested(MAX_HTML_DEPTH + 1), {
      name: "RangeError",
      message: `HTML nested deeper than ${MAX_HTML_DEPTH} levels`,
    });
  });
});
