/**
 * Layer 2 reads a hide in its ELEMENT context, as a browser renders it:
 *
 *  - a non-replaced inline box (`<span>`, `<a>`, `<b>`) ignores `transform`,
 *    `text-indent`, `content-visibility` and the width/height an
 *    `overflow:hidden` collapse rests on, unless something blockifies it (its
 *    own display, absolute positioning, a float, a flex/grid parent);
 *  - a hide by an INHERITED property (font-size, visibility, color,
 *    text-indent) reaches a descendant only until that descendant sets the
 *    property back, so `<span style="font-size:0">` around a
 *    `<b style="font-size:14px">` shows the `<b>`; only the bytes that stay
 *    hidden are spliced;
 *  - a replaced element (`<img>`, `<video>`) has no text for a font-size,
 *    color or indent hide to hide.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { isHiddenElement, sanitizeHtml } from "../src/html.mjs";

/**
 * The input with every splice's original put back: a splice that cut the
 * wrong bytes cannot rehydrate to the input.
 * @param {NonNullable<ReturnType<typeof sanitizeHtml>>} result
 */
const rehydrate = (result) =>
  result.splices.reduce(
    (text, pair) => text.replace(pair.placeholder, pair.original),
    result.text,
  );

/**
 * The sanitized text with every placeholder replaced by `[X]`, so an expected
 * output reads as the rendered page does.
 * @param {string} input
 */
const shown = (input) => {
  const result = sanitizeHtml(input);
  if (!result) return input;
  assert.equal(rehydrate(result), input, "the splice must rehydrate");
  const again = sanitizeHtml(result.text);
  assert.ok(
    again === null || again.text === result.text,
    "a second pass must change nothing",
  );
  return result.text.replace(
    /\[(?:hidden HTML|HTML comment) removed #[0-9a-f]{12}\]/g,
    "[X]",
  );
};

// Legitimate markup every case of which a browser renders in full. Each was
// spliced (wholly or in part) before the hide was read in element context.
const RENDERED_CORPUS = [
  // A box-only property on an inline box.
  '<p>See <span style="transform:scale(0)">INLINE-TRANSFORM</span> here</p>',
  '<p>See <span style="text-indent:-9999px">INLINE-INDENT</span> here</p>',
  '<p>See <span style="height:0;overflow:hidden">INLINE-HEIGHT</span> here</p>',
  '<p>See <a style="width:0;overflow:hidden" href="/x">INLINE-WIDTH</a> here</p>',
  '<p><em style="content-visibility:hidden">INLINE-CV</em></p>',
  '<p><b style="display:inline;transform:scale(0)">INLINE-EXPLICIT</b></p>',
  '<p><b style="display:var(--d);transform:scale(0)">INLINE-VAR</b></p>',
  // The same in markdown prose, where the tag is read alone.
  'See <span style="transform:scale(0)">MD-INLINE-TRANSFORM</span> here',
  'See <code style="text-indent:-9999px">MD-INLINE-INDENT</code> here',
  // The inline-block whitespace trick: font-size:0 on the list, the items
  // reset it.
  '<ul style="font-size:0">\n  <li style="display:inline-block;font-size:16px">One</li>\n  <li style="display:inline-block;font-size:16px">Two</li>\n</ul>',
  '<nav style="font-size:0"><a style="font-size:14px" href="/">Home</a> <a style="font:14px sans-serif" href="/b">Blog</a></nav>',
  // A tooltip parked under a hidden wrapper and shown on its own.
  '<div style="visibility:hidden"><div style="visibility:visible">Tooltip</div></div>',
  '<div style="visibility:hidden"><span style="visibility:initial">Shown</span></div>',
  // Text colored back over a transparent / same-color parent.
  '<div style="color:transparent"><span style="color:#333">Readable</span></div>',
  '<div style="color:#fff;background:#fff"><p style="color:#000">Dark on white</p></div>',
  '<div style="color:#fff;background:#fff"><p style="background:#000">White on black</p></div>',
  // A block resets an inherited offscreen indent.
  '<div style="text-indent:-9999px"><p style="text-indent:0">Indented back</p></div>',
  // An image under a font-size or color hide is still a picture.
  '<div style="font-size:0"><img src="a.png" alt=""></div>',
  '<img style="font-size:0" src="a.png">',
  '<img style="color:transparent" src="a.png">',
];

describe("element context: the rendered corpus is left untouched", () => {
  for (const input of RENDERED_CORPUS)
    it(`keeps ${JSON.stringify(input)}`, () =>
      assert.equal(sanitizeHtml(input), null));
});

// [input, the page as rendered, with each spliced span shown as [X]].
const SPLICE_CASES = [
  // ── an inline box blockified by its own style or its parent ──
  [
    '<div style="display:flex"><span style="transform:scale(0)">S</span></div>',
    '<div style="display:flex">[X]</div>',
  ],
  ['<span style="position:absolute;transform:scale(0)">S</span>', "[X]"],
  ['<span style="float:left;text-indent:-9999px">S</span>', "[X]"],
  ['<span style="display:block;transform:scale(0)">S</span>', "[X]"],
  ['<span style="display:inline-block;transform:scale(0)">S</span>', "[X]"],
  ['<div style="transform:scale(0)">S</div>', "[X]"],
  // Every hide that DOES apply to an inline box still splices it.
  ['<p>a <span style="opacity:0">S</span> b</p>', "<p>a [X] b</p>"],
  ['<p>a <span style="font-size:0">S</span> b</p>', "<p>a [X] b</p>"],
  // ── an inherited hide stops at the descendant that overrides it ──
  [
    '<p>A <span style="font-size:0">S1 <b style="font-size:14px">SHOWN</b> S2</span> Z</p>',
    '<p>A <span style="font-size:0">[X]<b style="font-size:14px">SHOWN</b>[X]</span> Z</p>',
  ],
  [
    '<div style="font-size:0">S1 <i><b style="font-size:12px">SHOWN</b> S2</i> S3</div>',
    '<div style="font-size:0">[X]<i><b style="font-size:12px">SHOWN</b>[X]</i>[X]</div>',
  ],
  [
    '<div style="visibility:hidden">S1<span style="visibility:visible">SHOWN</span><span>S2</span></div>',
    '<div style="visibility:hidden">[X]<span style="visibility:visible">SHOWN</span>[X]</div>',
  ],
  [
    '<div style="color:#fff;background:#fff">S1 <b style="color:#000">SHOWN</b> S2</div>',
    '<div style="color:#fff;background:#fff">[X]<b style="color:#000">SHOWN</b>[X]</div>',
  ],
  [
    '<div style="text-indent:-9999px">S1 <p style="text-indent:0">SHOWN</p></div>',
    '<div style="text-indent:-9999px">[X]<p style="text-indent:0">SHOWN</p></div>',
  ],
  // An image keeps its place between the spliced runs.
  [
    '<div style="font-size:0">S1 <img src="x.png"> S2</div>',
    '<div style="font-size:0">[X]<img src="x.png">[X]</div>',
  ],
  // Comments keep their own splice outside a run, and join the run inside one.
  [
    '<div style="font-size:0"><!--c1-->S1<!--c2-->S2<!--c3--><b style="font-size:9px">SHOWN</b><!--c4--></div>',
    '<div style="font-size:0">[X][X][X]<b style="font-size:9px">SHOWN</b>[X]</div>',
  ],
  // A box hide inside the region, and a hide inside the visible descendant.
  [
    '<div style="font-size:0"><span style="display:none">S</span><b style="font-size:9px">SHOWN <i hidden>S2</i></b></div>',
    '<div style="font-size:0">[X]<b style="font-size:9px">SHOWN [X]</b></div>',
  ],
  // ── a descendant that keeps the hide stays hidden with it ──
  [
    '<div style="font-size:0">S1 <b style="font-size:1.2em">S2</b></div>',
    "[X]",
  ],
  ['<div style="font-size:0">S1 <b style="font-size:150%">S2</b></div>', "[X]"],
  [
    '<div style="font-size:0">S1 <b style="font-size:larger">S2</b></div>',
    "[X]",
  ],
  ['<div style="font-size:0">S1 <b style="font:1em serif">S2</b></div>', "[X]"],
  [
    '<div style="font-size:0">S1 <b style="font-size:inherit">S2</b></div>',
    "[X]",
  ],
  ['<div style="font-size:0">S1 <b style="all:unset">S2</b></div>', "[X]"],
  [
    '<div style="visibility:hidden">S1 <b style="visibility:inherit">S2</b></div>',
    "[X]",
  ],
  [
    '<div style="color:#fff;background:#fff">S1 <b style="color:inherit">S2</b></div>',
    "[X]",
  ],
  // An inline box cannot reset an indent: it sits on the shifted line.
  [
    '<div style="text-indent:-9999px">S1 <span style="text-indent:0">S2</span></div>',
    "[X]",
  ],
  // An overriding value the cascade drops as invalid overrides nothing.
  ['<div style="font-size:0">S1 <b style="font-size:14pz">S2</b></div>', "[X]"],
  // Visibility reaches an image; a font-size hide does not.
  ['<div style="visibility:hidden">S1 <img src="x.png"> S2</div>', "[X]"],
  // parse5 moves the overriding child out of source order (foster parenting
  // out of a table), so no run can be trusted: the whole element is spliced.
  [
    '<div style="font-size:0">S1<table><b style="font-size:12px">SHOWN</b>S2<tr><td>x</td></tr></table></div>',
    "[X]",
  ],
];

describe("element context: exactly the bytes that stay hidden are spliced", () => {
  for (const [input, expected] of SPLICE_CASES)
    it(JSON.stringify(input), () => assert.equal(shown(input), expected));
});

describe("element context: isHiddenElement reads the parent it is given", () => {
  /** @param {string} tagName @param {Record<string, unknown>} properties */
  const elem = (tagName, properties = {}) => ({
    type: "element",
    tagName,
    properties,
    children: [],
  });
  const span = elem("span", { style: "transform:scale(0)" });
  it("an inline span with a transform alone is visible", () =>
    assert.equal(isHiddenElement(span), false));
  it("a flex parent blockifies it, so the transform hides it", () =>
    assert.equal(
      isHiddenElement(span, elem("div", { style: "display:flex" })),
      true,
    ));
  it("a grid parent does too", () =>
    assert.equal(
      isHiddenElement(span, elem("div", { style: "display:inline-grid" })),
      true,
    ));
  it("a block parent does not", () =>
    assert.equal(
      isHiddenElement(span, elem("div", { style: "display:block" })),
      false,
    ));
  it("a div is a block box whatever its parent", () =>
    assert.equal(
      isHiddenElement(elem("div", { style: "transform:scale(0)" })),
      true,
    ));
  it("the hidden attribute hides an image", () =>
    assert.equal(isHiddenElement(elem("img", { hidden: true })), true));
  it("visibility hides an image; font-size does not", () => {
    assert.equal(
      isHiddenElement(elem("img", { style: "visibility:hidden" })),
      true,
    );
    assert.equal(isHiddenElement(elem("img", { style: "font-size:0" })), false);
  });
});
