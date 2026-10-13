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
 * held to one `fromParse5` call over the same corpus. Its depth ceiling is one
 * deliberate difference, pinned at the end; the other is an element the
 * converter would take for a template with no template content to take, which
 * converts as an ordinary element instead of throwing.
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

// `\x3c` is `<`. These fixtures crash a sanitizer that predates the fix they
// test, so spelling the `<` as an escape keeps a review pipeline that runs
// such a sanitizer over a diff of this file from withholding the diff whole.
/** Elements the converter takes for a template, with no template content. */
const NO_TEMPLATE_CONTENT = {
  svg: "\x3csvg><template><circle/></template></svg>",
  math: "\x3cmath><template><mi>x</mi></template></math>",
  "nested in a template's content":
    "<template>\x3csvg><template>x</template></svg></template>",
  "selector-shaped names":
    "\x3ctemplate.x>a</template.x>\x3csvg>\x3ctemplate#i>b",
  "deep, so chunks cut around it":
    "\x3csvg><g><g><template><g><g><text>x</text></g></g></template></g></g></svg>",
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

/** Not a name the corpus holds, nor one the converter treats as a template. */
const STAND_IN = "x-stand-in";

/**
 * One `fromParse5` call converting a template-named element that has no
 * template content (one inside SVG, a `template.x` tag) as it converts any other
 * element of its namespace: the call sees it named {@link STAND_IN}, and its
 * hast node is named `template` again. Called on such an element as is,
 * `fromParse5` throws.
 * @param {any} tree
 * @param {VFile} file
 * @returns {{ tree: any, renamed: number }}
 */
function fromParse5WithStandIns(tree, file) {
  let renamed = 0;
  const rename = (node) => {
    if (!node.content && /^template(?:[#.]|$)/.test(node.tagName ?? "")) {
      node.tagName = STAND_IN + node.tagName.slice("template".length);
      renamed++;
    }
    for (const child of node.childNodes ?? []) rename(child);
    if (node.content) rename(node.content);
  };
  const restore = (node) => {
    if (node.tagName === STAND_IN) node.tagName = "template";
    for (const child of node.children ?? []) restore(child);
    if (node.content) restore(node.content);
  };
  rename(tree);
  const converted = fromParse5(tree, { file });
  restore(converted);
  return { tree: converted, renamed };
}

/**
 * {@link fromParse5Bounded} and {@link fromParse5WithStandIns} over the same
 * input, each on its own parse (both rewrite the tree they convert).
 * @param {string} html
 * @param {number} chunkDepth
 */
function bothConversions(html, chunkDepth) {
  const ours = fromParse5Bounded(
    parseFragment(html, OPTIONS),
    new VFile(html),
    chunkDepth,
  );
  const theirs = fromParse5WithStandIns(
    parseFragment(html, OPTIONS),
    new VFile(html),
  );
  return [ours, theirs];
}

describe("bounded conversion matches one fromParse5 call", () => {
  // Chunks of one, two and three levels put a cut under every shape the corpus
  // has: an unclosed element whose end comes from a cut child, a template whose
  // content is cut, foreign content, recovery-synthesized nodes with no
  // position.
  const corpus = [
    ...Object.values(MID_PARSE_DETACH),
    ...Object.values(ORDINARY),
    ...Object.values(NO_TEMPLATE_CONTENT),
    ...tagSoup(),
  ];
  for (const chunkDepth of [1, 2, 3])
    it(`in chunks of ${chunkDepth}`, () => {
      let renamed = 0;
      for (const html of corpus) {
        const [ours, theirs] = bothConversions(html, chunkDepth);
        assert.deepEqual(ours, theirs.tree, html);
        if (theirs.renamed > 0) renamed++;
      }
      // Non-vacuity: the corpus must hold the elements a bare `fromParse5`
      // throws on, or the stand-in path went unexercised.
      assert.ok(renamed >= Object.keys(NO_TEMPLATE_CONTENT).length, renamed);
    });

  it("converts a template-named element with no template content as an ordinary element", () => {
    const html = "\x3csvg><template id=t><circle/></template></svg>";
    // The dependency's own answer. Once it stops throwing here, the mask in
    // fromParse5Bounded has nothing left to work around.
    assert.throws(() => fromParse5(parseFragment(html, OPTIONS)), TypeError);
    const svg = fromParse5Bounded(parseFragment(html, OPTIONS), new VFile(html))
      .children[0];
    const template = svg.children[0];
    assert.equal(template.tagName, "template");
    assert.equal(template.content, undefined);
    assert.deepEqual(template.properties, { id: "t" });
    assert.deepEqual(
      template.children.map((child) => child.tagName),
      ["circle"],
    );
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
