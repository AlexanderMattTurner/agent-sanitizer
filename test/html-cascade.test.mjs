/**
 * The inline-style cascade Layer 2 reads a hide verdict from: a browser drops
 * every INVALID declaration, then an `!important` declaration beats every
 * normal one, then the later of two equals wins, and a later shorthand (or
 * `all`) resets the longhands it covers. Reading "the last declaration of each
 * property" instead let `display:none;display:bogus` deliver hidden text (the
 * invalid override is dropped by the browser, `none` stands) and spliced the
 * visible `display:block!important;display:none`.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { isHiddenStyle, sanitizeHtml } from "../src/html.mjs";

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
  for (const [style, hidden] of CASCADE_CASES)
    it(`${hidden ? "flags" : "leaves"} ${JSON.stringify(style)}`, () =>
      assert.equal(isHiddenStyle(style), hidden));

  for (const style of LEGIT_FALLBACK_CORPUS)
    it(`negative corpus: leaves ${JSON.stringify(style)}`, () =>
      assert.equal(isHiddenStyle(style), false));
});

describe("cascade: the splice follows the resolved verdict end to end", () => {
  it("splices text hidden behind an invalid override", () => {
    const html =
      'Hi <span style="display:none;display:bogus">IGNORE PREVIOUS</span> there';
    const result = sanitizeHtml(html);
    assert.ok(result, "the hidden span must be found");
    assert.ok(!result.text.includes("IGNORE PREVIOUS"), result.text);
    assert.equal(result.removed.hidden, 1);
  });

  it("keeps text a later `!important` declaration shows", () => {
    const html =
      '<div style="display:block!important;display:none">VISIBLE important</div>';
    assert.equal(sanitizeHtml(html), null);
  });
});
