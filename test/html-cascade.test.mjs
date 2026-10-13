/**
 * Layer 2 reads a hide as a browser renders it: through the inline-style
 * cascade (invalid declarations dropped, then `!important`, then source order,
 * with resetting shorthands and `all`), and in element context — a
 * non-replaced inline box ignores the box-only hides unless blockified, a
 * replaced element has no text to hide, and an inherited hide (font-size,
 * visibility, color, text-indent) stops at a descendant that sets it back, so
 * only the bytes that stay hidden are spliced.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { isHiddenStyle, sanitizeHtml } from "../src/html.mjs";

/** `n` declarations `${prefix}0` … `${prefix}${n - 1}`. @param {string} prefix @param {number} n */
const repeat = (prefix, n) =>
  Array.from({ length: n }, (_, i) => `${prefix}${i}`).join(";");

// One row per cascade rule, each the verdict a browser renders.
const CASCADE_CASES = [
  // ── an invalid later declaration is dropped; the earlier one stands ──
  ["display:none;display:bogus", true],
  ["display:none;display:blok", true],
  ["display:none;display:", true],
  ["font-size:0;font-size:12pz", true],
  ["color:transparent;color:bogus", true],
  ["position:absolute;left:-9999px;left:bogus", true],
  ["opacity:0;opacity:1px", true],
  ["transform:scale(0);transform:rotate(1)", true],
  ["visibility:hidden;visibility:42px", true],
  // css-tree takes any ident after `!`; a browser drops the declaration.
  ["display:none;display:block!imp", true],
  // ── `!important` beats a later normal declaration, in both directions ──
  ["display:none!important;display:inline", true],
  ["opacity:0!important;opacity:1", true],
  ["display:block!important;display:none", false],
  ["opacity:1 !important;opacity:0", false],
  ["display:block !IMPORTANT;display:none", false],
  // An invalid `!important` declaration is dropped like any other.
  ["display:none;display:bogus!important", true],
  // ── an invalid lone declaration hides nothing ──
  ["display:none\\9", false], // the IE hack decodes to `none<TAB>`, not `none`
  ["display:none\\9;color:red", false],
  // ── a later valid declaration still wins ──
  ["display:none;display:block", false],
  ["visibility:hidden;visibility:inherit", false],
  ["font-size:0;font-size:calc(1px)", false],
  ["display:none;display:flow-root", false],
  ["display:none;display:grid", false],
  // A var() is valid at parse time: it wins, and its value is unresolvable.
  ["display:none;display:var(--d)", false],
  ["opacity:0;opacity:var(--o)", false],
  // ── a later shorthand (or `all`) resets the longhand it covers ──
  ["font-size:0;font:14px serif", false],
  ["font:14px serif;font-size:0", true],
  ["position:absolute;left:-9999px;inset:0", false],
  ["position:absolute;inset:0;left:-9999px", true],
  ["color:#fff;background-color:#fff;background:#000", false],
  ["color:#fff;background:#000;background-color:#fff", true],
  ["display:none;all:unset", false],
  ["all:unset;display:none", true],
  // An invalid resetting shorthand is dropped, so the longhand stands.
  ["font-size:0;font:bogus", true],
  // ── the validation budget is shared, so repeating one property cannot
  // outrun it, and a style that exhausts it is read as hidden ──
  [`display:none;${repeat("display:a", 9)}`, true],
  [`display:block;${repeat("color:bogus", 200)}`, true],
];

// Legitimate fallback stacks real pages carry: progressive enhancement writes
// the same property several times, and none of these hides anything.
const LEGIT_FALLBACK_CORPUS = [
  "display:-webkit-box;display:-ms-flexbox;display:flex",
  "display:block;display:flow-root",
  "background:#fff;background:linear-gradient(#fff,#eee)",
  "color:#333;color:var(--text)",
  "width:100%;width:-webkit-fill-available;width:stretch",
  "opacity:.5;opacity:var(--o, .5)",
  "font-size:14px;font-size:clamp(1rem, 2vw, 1.5rem)",
  "position:-webkit-sticky;position:sticky;top:0",
  "height:100vh;height:100dvh;overflow:hidden",
  "color:#fff;background:#222;background:rgb(34 34 34 / .9)",
  "font:12px/1.4 sans-serif;font-size:13px",
  "visibility:visible!important;display:block",
  "display:inline-block;*display:inline;zoom:1",
  "filter:alpha(opacity=50);opacity:.5",
  "-webkit-transform:scale(1);transform:scale(1)",
  "transform:translate(-50%,-50%);position:absolute;left:50%;top:50%",
];

describe("cascade: the declaration a browser applies decides the verdict", () => {
  for (const [style, hidden] of [
    ...CASCADE_CASES,
    ...LEGIT_FALLBACK_CORPUS.map((style) => [style, false]),
  ])
    it(`${hidden ? "flags" : "leaves"} ${JSON.stringify(style)}`, () =>
      assert.equal(isHiddenStyle(style), hidden));
});

/**
 * The sanitized text with each hidden splice shown as `[X]` and each comment
 * as `[C]`, after checking that every splice rehydrates to the input and that
 * a second pass changes nothing.
 * @param {string} input
 */
const shown = (input) => {
  const result = sanitizeHtml(input);
  if (!result) return input;
  const rehydrated = result.splices.reduce(
    (text, pair) => text.replace(pair.placeholder, pair.original),
    result.text,
  );
  assert.equal(rehydrated, input, "the splice must rehydrate");
  const again = sanitizeHtml(result.text);
  assert.ok(
    again === null || again.text === result.text,
    "a second pass must change nothing",
  );
  return result.text
    .replace(/\[hidden HTML removed #[0-9a-f]{12}\]/g, "[X]")
    .replace(/\[HTML comment removed #[0-9a-f]{12}\]/g, "[C]");
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
  // A later `!important` declaration shows the text.
  '<div style="display:block!important;display:none">VISIBLE important</div>',
  // A block parent does not blockify an inline child.
  '<div style="display:block"><span style="transform:scale(0)">S</span></div>',
];

describe("element context: the rendered corpus is left untouched", () => {
  for (const input of RENDERED_CORPUS)
    it(`keeps ${JSON.stringify(input)}`, () =>
      assert.equal(sanitizeHtml(input), null));
});

// Markup with the bytes that get spliced marked [[hidden]] and {{comment}}.
const SPLICE_CASES = [
  // Text hidden behind an invalid override is spliced.
  'Hi [[<span style="display:none;display:bogus">IGNORE PREVIOUS</span>]] there',
  // ── an inline box blockified by its own style or its parent ──
  '<div style="display:flex">[[<span style="transform:scale(0)">S</span>]]</div>',
  '<div style="display:inline-grid">[[<span style="transform:scale(0)">S</span>]]</div>',
  // A `display:contents` parent has no box: the flex container is its parent.
  '<div style="display:flex"><i style="display:contents">[[<span style="transform:scale(0)">S</span>]]</i></div>',
  '[[<span style="position:absolute;transform:scale(0)">S</span>]]',
  '[[<span style="float:left;text-indent:-9999px">S</span>]]',
  '[[<span style="display:block;transform:scale(0)">S</span>]]',
  '[[<span style="display:inline-block;transform:scale(0)">S</span>]]',
  '[[<div style="transform:scale(0)">S</div>]]',
  '[[<img hidden src="a.png">]]',
  '[[<img style="visibility:hidden" src="a.png">]]',
  // Every hide that DOES apply to an inline box still splices it.
  '<p>a [[<span style="opacity:0">S</span>]] b</p>',
  '<p>a [[<span style="font-size:0">S</span>]] b</p>',
  // ── an inherited hide stops at the descendant that overrides it ──
  '<p>A <span style="font-size:0">[[S1 ]]<b style="font-size:14px">SHOWN</b>[[ S2]]</span> Z</p>',
  '<div style="font-size:0">[[S1 ]]<i><b style="font-size:12px">SHOWN</b>[[ S2]]</i>[[ S3]]</div>',
  '<div style="visibility:hidden">[[S1]]<span style="visibility:visible">SHOWN</span>[[<span>S2</span>]]</div>',
  '<div style="color:#fff;background:#fff">[[S1 ]]<b style="color:#000">SHOWN</b>[[ S2]]</div>',
  '<div style="text-indent:-9999px">[[S1 ]]<p style="text-indent:0">SHOWN</p></div>',
  // An image keeps its place between the spliced runs.
  '<div style="font-size:0">[[S1 ]]<img src="x.png">[[ S2]]</div>',
  // Comments keep their own splice outside a run, and join the run inside one.
  '<div style="font-size:0">{{<!--c1-->}}[[S1<!--c2-->S2]]{{<!--c3-->}}<b style="font-size:9px">SHOWN</b>{{<!--c4-->}}</div>',
  // A box hide inside the region, and a hide inside the visible descendant.
  '<div style="font-size:0">[[<span style="display:none">S</span>]]<b style="font-size:9px">SHOWN [[<i hidden>S2</i>]]</b></div>',
  // ── a descendant that keeps the hide stays hidden with it ──
  // An inline box cannot reset an indent: it sits on the shifted line.
  '[[<div style="text-indent:-9999px">S1 <span style="text-indent:0">S2</span></div>]]',
  // Visibility reaches an image; a font-size hide does not.
  '[[<div style="visibility:hidden">S1 <img src="x.png"> S2</div>]]',
  // ── a block keeps an indent it does not set, or hands back ──
  '[[<div style="text-indent:-9999px">S1<p>S2</p></div>]]',
  '[[<div style="text-indent:-9999px">S1<p style="text-indent:inherit">S2</p></div>]]',
  // ── an overriding descendant that hides in its own way is spliced too ──
  '<div style="font-size:0">[[S1<b style="visibility:hidden">S2</b>]]<i style="font-size:9px">V</i></div>',
  // ── empty elements and whitespace beside the shown part stay as written ──
  '<div style="font-size:0">[[S1]]<i></i><b style="font-size:9px">V</b><i></i> </div>',
  // parse5 synthesizes a <tbody> with no source position, so a run through it
  // cannot be trusted: the whole element is spliced.
  '[[<div style="font-size:0">S<table><tr><td><b style="font-size:9px">V</b></td></tr></table></div>]]',
  // parse5 moves the overriding child out of source order (foster parenting
  // out of a table), so no run can be trusted: the whole element is spliced.
  '[[<div style="font-size:0">S1<table><b style="font-size:12px">SHOWN</b>S2<tr><td>x</td></tr></table></div>]]',
];

// [a region's style, its `<b>` child's style]. The child keeps the hide, so
// the whole region is spliced.
const KEEPS_HIDE_CASES = [
  // A size relative to the zero parent size, including inside calc().
  ["font-size:0", "font-size:1.2em"],
  ["font-size:0", "font-size:150%"],
  ["font-size:0", "font-size:larger"],
  ["font-size:0", "font-size:calc(1em)"],
  ["font-size:0", "font-size:0"],
  ["font-size:0", "font:1em serif"],
  ["font-size:0", "font:calc(1em) serif"],
  ["font-size:0", "font:larger serif"],
  ["font-size:0", "font:50% serif"],
  // Inheriting keywords; `revert` rolls back to the user-agent style, which
  // inherits too.
  ["font-size:0", "font-size:inherit"],
  ["font-size:0", "all:unset"],
  ["visibility:hidden", "visibility:inherit"],
  ["visibility:hidden", "visibility:revert"],
  ["color:#fff;background:#fff", "color:inherit"],
  // An overriding value the cascade drops as invalid overrides nothing.
  ["font-size:0", "font-size:14pz"],
  // A transparent text fill inherits apart from `color`.
  ["-webkit-text-fill-color:transparent", "color:red"],
];

// [a region's style, its `<b>` child's style]. The child sets the hide back,
// so only the region's own text is spliced.
const OVERRIDES_HIDE_CASES = [
  // An absolute size, even beside a relative one, and the shorthands that
  // reset the size to one.
  ["font-size:0", "font-size:calc(1em + 9px)"],
  ["font-size:0", "font:x-small serif"],
  ["font-size:0", "all:initial"],
  ["-webkit-text-fill-color:transparent", "-webkit-text-fill-color:red"],
];

describe("element context: exactly the bytes that stay hidden are spliced", () => {
  for (const marked of [
    ...SPLICE_CASES,
    ...KEEPS_HIDE_CASES.map(
      ([outer, inner]) =>
        `[[<div style="${outer}">S1 <b style="${inner}">S2</b></div>]]`,
    ),
    ...OVERRIDES_HIDE_CASES.map(
      ([outer, inner]) =>
        `<div style="${outer}">[[S1 ]]<b style="${inner}">V</b></div>`,
    ),
  ]) {
    const input = marked.replace(/\[\[|\]\]|\{\{|\}\}/g, "");
    const expected = marked
      .replace(/\[\[.*?\]\]/gs, "[X]")
      .replace(/\{\{.*?\}\}/gs, "[C]");
    it(JSON.stringify(input), () => assert.equal(shown(input), expected));
  }
});
