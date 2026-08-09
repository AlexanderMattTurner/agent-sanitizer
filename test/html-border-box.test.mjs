import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { isHiddenStyle } from "../src/html.mjs";

/**
 * The class this pins: `overflow:hidden` plus a near-zero CONTENT-box length was
 * read as "the element renders nothing". It does not. Padding and border widths
 * add to the BORDER box, so the universal responsive-embed idiom
 * (`height:0; padding-bottom:56.25%; overflow:hidden` — Bootstrap's `.ratio`,
 * and every hand-pasted padding-bottom hack) renders at 56.25% of its
 * container's width with all of its content on screen. Splicing it out removes
 * text the model needed, which is the harm CLAUDE.md's precision-over-recall
 * rule exists to prevent.
 *
 * Asserting the Bootstrap case alone would pin one symptom. The invariant is
 * over the whole axis-additive property set.
 */

// A style that IS provably hidden through the overflow branch, per axis.
const HIDDEN_BASES = {
  height: "height:0;overflow:hidden",
  width: "width:0;overflow:hidden",
  "max-height": "max-height:0;overflow:hidden",
  "max-width": "max-width:0;overflow:hidden",
};

// Every declaration that adds to that axis's border box. A near-zero content
// length plus any one of these no longer proves an empty rendered box.
//
// Deliberately restated here rather than imported from `src/html.mjs`. These
// are the CSS box model's property set, not the module's opinion about it, so
// this list is an INDEPENDENT oracle: importing the module's own array would
// let a property dropped from the implementation vanish from the test in the
// same edit, and the suite would agree with the bug. (Same reasoning
// `test/shipped-gates.test.mjs` gives for re-deriving the manifest without
// calling the module under test.)
const BLOCK_AXIS_ADDITIVE = [
  "padding",
  "padding-top",
  "padding-bottom",
  "padding-block",
  "padding-block-start",
  "padding-block-end",
  "border",
  "border-width",
  "border-top",
  "border-bottom",
  "border-top-width",
  "border-bottom-width",
  "border-block",
  "border-block-width",
  "border-block-start",
  "border-block-end",
  "border-block-start-width",
  "border-block-end-width",
];
const INLINE_AXIS_ADDITIVE = [
  "padding",
  "padding-left",
  "padding-right",
  "padding-inline",
  "padding-inline-start",
  "padding-inline-end",
  "border",
  "border-width",
  "border-left",
  "border-right",
  "border-left-width",
  "border-right-width",
  "border-inline",
  "border-inline-width",
  "border-inline-start",
  "border-inline-end",
  "border-inline-start-width",
  "border-inline-end-width",
];

const AXIS_OF = {
  height: BLOCK_AXIS_ADDITIVE,
  "max-height": BLOCK_AXIS_ADDITIVE,
  width: INLINE_AXIS_ADDITIVE,
  "max-width": INLINE_AXIS_ADDITIVE,
};

describe("zero-dimension hiding respects the border box", () => {
  it("every base is hidden on its own (non-vacuity)", () => {
    // Without this the cross product below could pass because the bases were
    // never hidden in the first place, making every "no longer hidden"
    // assertion trivially true.
    for (const [dim, base] of Object.entries(HIDDEN_BASES))
      assert.equal(isHiddenStyle(base), true, `${dim}: base must be hidden`);
  });

  for (const [dim, base] of Object.entries(HIDDEN_BASES))
    for (const prop of AXIS_OF[dim])
      it(`${dim}: a non-zero \`${prop}\` defeats the hide`, () => {
        const value = prop.startsWith("border") ? "4px solid red" : "40px";
        assert.equal(
          isHiddenStyle(`${base};${prop}:${value}`),
          false,
          `${prop} adds to the ${dim} border box, so the element renders`,
        );
      });

  it("an explicit zero on an additive property still hides", () => {
    // The fix must not become a blanket exemption: a declared zero contributes
    // no extent, so the element really is collapsed.
    assert.equal(isHiddenStyle("height:0;padding:0;overflow:hidden"), true);
    assert.equal(
      isHiddenStyle("height:0;padding:0 0 0 0;overflow:hidden"),
      true,
    );
    assert.equal(
      isHiddenStyle("height:0;border:0 solid red;overflow:hidden"),
      true,
    );
    assert.equal(isHiddenStyle("width:0;padding-left:0;overflow:hidden"), true);
    // A hex color parses as a `Hash`, not an `Identifier`. Pinned separately
    // from the `red` case above so the two spellings cannot both rest on the
    // identifier branch — a hex color is never a length, and treating it as
    // unresolvable would silently give up the hide.
    assert.equal(
      isHiddenStyle("height:0;border:0 solid #ccc;overflow:hidden"),
      true,
    );
    assert.equal(
      isHiddenStyle("height:0;border:0 solid #cccccc;overflow:hidden"),
      true,
    );
  });

  it("an additive property declared with an empty value fails OPEN", () => {
    // A declaration the parser hands back with no value tokens is not evidence
    // of zero extent — it is evidence of nothing, so it must read as visible.
    assert.equal(isHiddenStyle("height:0;padding-top:;overflow:hidden"), false);
  });

  it("a border shorthand with no explicit width computes to `medium`", () => {
    // `border:solid red` is 3px per side — an omitted width is NOT zero.
    assert.equal(
      isHiddenStyle("height:0;border:solid red;overflow:hidden"),
      false,
    );
    assert.equal(
      isHiddenStyle("height:0;border:thin solid;overflow:hidden"),
      false,
    );
  });

  it("an unresolvable additive value fails OPEN", () => {
    // The module's stated policy: a value this cannot resolve may well paint a
    // visible box, so it must read as visible rather than be ignored.
    for (const value of ["calc(50% - 2px)", "var(--gap)", "calc(var(--x) * 2)"])
      assert.equal(
        isHiddenStyle(`height:0;padding-bottom:${value};overflow:hidden`),
        false,
        `${value} is unresolvable and must not read as hidden`,
      );
  });

  it("real layout idioms produce zero findings", () => {
    // The negative corpus CLAUDE.md asks every new detector to carry.
    const legitimate = [
      "position:relative;height:0;padding-bottom:56.25%;overflow:hidden",
      "height:0;padding-bottom:75%;overflow:hidden",
      "height:0;padding-bottom:300px;overflow:hidden",
      "max-height:0;padding-top:40px;overflow:hidden",
      "width:0;padding-left:2em;overflow:hidden",
      "height:0;border-bottom:1px solid #ccc;overflow:hidden",
      // The logical spelling of the same aspect-ratio idiom.
      "height:0;padding-block-end:56.25%;overflow:hidden",
      "width:0;padding-inline-start:2em;overflow:hidden",
      "height:0;border-block-end:1px solid #ccc;overflow:hidden",
    ];
    for (const style of legitimate)
      assert.equal(
        isHiddenStyle(style),
        false,
        `spliced a visible idiom: ${style}`,
      );
  });

  it("the off-axis property does not defeat the hide", () => {
    // Precision in the other direction: horizontal padding cannot make a
    // zero-HEIGHT box tall, so the hide still holds.
    assert.equal(
      isHiddenStyle(
        "height:0;padding-left:40px;padding-right:40px;overflow:hidden",
      ),
      true,
    );
    assert.equal(
      isHiddenStyle(
        "width:0;padding-top:40px;padding-bottom:40px;overflow:hidden",
      ),
      true,
    );
  });
});
