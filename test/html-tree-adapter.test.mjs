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
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { defaultTreeAdapter, parseFragment, serialize } from "parse5";

import { createTreeAdapter } from "../src/html-tree-adapter.mjs";

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
    // A fixed seed: the sweep must be the same set of inputs on every run, or a
    // failure here names a case nobody can reproduce.
    let seed = 20260826;
    const next = () =>
      (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    for (let i = 0; i < 400; i++) {
      let html = "";
      for (let j = 0, n = 1 + Math.floor(next() * 30); j < n; j++)
        html += pieces[Math.floor(next() * pieces.length)];
      assertSameTree(html);
    }
  });
});
