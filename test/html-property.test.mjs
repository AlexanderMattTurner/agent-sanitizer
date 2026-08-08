/**
 * Fast-check property tests for the HTML layer (Layers 2 & 3).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { unified } from "unified";
import rehypeParse from "rehype-parse";
import { visit, EXIT } from "unist-util-visit";

import {
  sanitizeHtml,
  isHiddenStyle,
  isHiddenElement,
  checkExfilUrl,
  HIDDEN_PLACEHOLDER,
} from "../src/html.mjs";
import { fcRunOptions } from "./test-helpers.mjs";

const runOptions = fcRunOptions({ numRuns: 500 });
const applyHtml = (text) => sanitizeHtml(text)?.text ?? text;
const checkProperty = (arbitrary, predicate) =>
  fc.assert(fc.property(arbitrary, predicate), runOptions);

// "Forbidden" = a hidden ELEMENT. Comments are deliberately NOT forbidden:
// Layer 2 preserves them (see the module doc in ../src/html.mjs).
function containsForbiddenNode(htmlText) {
  const tree = unified().use(rehypeParse, { fragment: true }).parse(htmlText);
  let forbidden = false;
  visit(tree, (node) => {
    if (!isHiddenElement(node)) return undefined;
    forbidden = true;
    return EXIT;
  });
  return forbidden;
}

// ─── 1. Idempotence ──────────────────────────────────────────────────────────

const tagName = fc.constantFrom(
  "div",
  "span",
  "p",
  "script",
  "style",
  "a",
  "img",
  "iframe",
  "svg",
);
const safeAttrValue = fc
  .string({ maxLength: 30 })
  .map((raw) => raw.replace(/["<>&]/g, ""));
const attribute = fc
  .tuple(fc.constantFrom("style", "hidden", "src", "href", "id"), safeAttrValue)
  .map(([name, value]) => `${name}="${value}"`);
// Inner content excludes `<`/`>`/`&`: raw markup buried inside an element's
// text is itself adversarial markup, modeled explicitly by `malformedInlineToken`
// below. Left unrestricted it would generate FOREIGN-content edge cases
// (`<svg><!…` where a bogus comment inside svg absorbs the `</svg>` close, per
// the HTML foreign-content insertion mode) that the markdown balance walk
// cannot match against parse5 without becoming parse5 — a known limitation of
// the two-parser design, out of scope here.
const safeInner = fc
  .string({ maxLength: 40 })
  .map((raw) => raw.replace(/[<>&]/g, ""));
const htmlElement = fc
  .tuple(tagName, fc.array(attribute, { maxLength: 3 }), safeInner)
  .map(([name, attrs, inner]) => {
    const attrText = attrs.length === 0 ? "" : " " + attrs.join(" ");
    return `<${name}${attrText}>${inner}</${name}>`;
  });
// Malformed / adversarial inline tokens a well-formed `htmlElement` can never
// emit: bogus comments, bare unterminated end tags, and inline hidden VOID
// elements. These are the token shapes whose absence let a real idempotency bug
// (a bare `</A` absorbing a following hidden element per parse5, but not in the
// per-tag balance walk) slip past this suite — so the fuzzer must build them.
const malformedInlineToken = fc.constantFrom(
  // bogus comments / declarations
  "<!bogus secret>",
  "<?php evil ?>",
  "<![CDATA[ secret ]]>",
  "<!doctype html>",
  // bare unterminated end tags (parse5 opens a bogus comment that absorbs
  // the following inline markup)
  "</A",
  "</div",
  "</span x",
  "</b ",
  // inline hidden void elements (no closing tag; a balance region would
  // over-splice, so each must be a single-node splice)
  "<img hidden>",
  "<img src=x hidden>",
  '<input style="display:none">',
  "<br hidden>",
  "<hr hidden>",
  // stray partial open
  "<div hidden",
  "<span",
  // raw-text / RCDATA elements: `<!…`/`</…` — and hidden-tag LITERALS — inside
  // are opaque content, not markup, and must survive verbatim
  "<style><!x</style>",
  "<script><!--c--></script>",
  "<textarea></b</textarea>",
  "<title><!--t--></title>",
  '<style><div hidden="">p</div></style>',
  "<textarea><span hidden>p</span></textarea>",
);
const arbitraryHtmlFragment = fc
  .array(
    fc.oneof(
      { weight: 3, arbitrary: fc.string({ maxLength: 60 }) },
      { weight: 3, arbitrary: htmlElement },
      { weight: 2, arbitrary: malformedInlineToken },
    ),
    { maxLength: 8 },
  )
  .map((parts) => parts.join(" "));

describe("property: sanitizeHtml is idempotent", () => {
  it("second pass changes nothing AND pass one actually splices a hidden node", () =>
    checkProperty(arbitraryHtmlFragment, (input) => {
      // Idempotence is vacuously true for a no-op, so wrap the fuzzed body in a
      // guaranteed-hidden element and assert pass one removed it: the visible
      // marker survives, the secret does not, and a HIDDEN_PLACEHOLDER appears.
      // That positive postcondition proves the splice path ran; then assert the
      // second pass is a fixed point.
      const planted = `VISIBLE_MARK <div style="display:none">SECRET_PAYLOAD</div> ${input}`;
      const passOne = applyHtml(planted);
      assert.ok(passOne.includes("VISIBLE_MARK"));
      assert.ok(!passOne.includes("SECRET_PAYLOAD"));
      assert.ok(passOne.includes(HIDDEN_PLACEHOLDER));
      assert.equal(applyHtml(passOne), passOne);
    }));
});

// ─── 2. Hidden-style fuzz ────────────────────────────────────────────────────

const whitespace = fc.constantFrom("", " ", "\t", "\n ");
const importantFlag = fc.constantFrom(
  "",
  " !important",
  "!important",
  " ! Important",
);
const casedPropertyName = (lowercase) =>
  fc.constantFrom(
    lowercase,
    lowercase.toUpperCase(),
    lowercase[0].toUpperCase() + lowercase.slice(1),
  );
const zeroNumber = fc.constantFrom("0", "0.0", "0.00", "00", "0e0");
const zeroLength = fc
  .tuple(zeroNumber, fc.constantFrom("", "px", "em", "%", "pt", "rem"))
  .map(([number, unit]) => number + unit);
const offscreenLength = fc
  .tuple(
    fc.integer({ min: 901, max: 99999 }),
    fc.constantFrom("px", "em", "pt"),
  )
  .map(([number, unit]) => `-${number}${unit}`);
const unrelatedDecl = fc.constantFrom("", "; color: red", "; margin: 1px");
const wrapWithNoise = (declaration) =>
  fc
    .tuple(whitespace, declaration, importantFlag, whitespace, unrelatedDecl)
    .map(
      ([leading, decl, flag, trailing, extra]) =>
        leading + decl + flag + trailing + extra,
    );

const hidingDeclarations = {
  display: casedPropertyName("display").map((name) => `${name}: none`),
  visibility: casedPropertyName("visibility").map((name) => `${name}: hidden`),
  opacity: fc
    .tuple(casedPropertyName("opacity"), zeroNumber)
    .map(([name, number]) => `${name}: ${number}`),
  "offscreen-left": fc
    .tuple(
      casedPropertyName("position"),
      casedPropertyName("left"),
      offscreenLength,
    )
    .map(([pos, side, length]) => `${pos}: absolute; ${side}: ${length}`),
  "offscreen-top": fc
    .tuple(
      casedPropertyName("position"),
      casedPropertyName("top"),
      offscreenLength,
    )
    .map(([pos, side, length]) => `${pos}: fixed; ${side}: ${length}`),
  "clip-rect": casedPropertyName("position").map(
    (pos) => `${pos}: absolute; clip: rect(0,0,0,0)`,
  ),
  "text-indent": fc
    .tuple(casedPropertyName("text-indent"), offscreenLength)
    .map(([name, length]) => `${name}: ${length}`),
  "content-visibility": casedPropertyName("content-visibility").map(
    (name) => `${name}: hidden`,
  ),
  // rotateX/rotateY by an odd quarter-turn projects to zero area (edge-on).
  "transform-rotate": fc
    .tuple(
      casedPropertyName("transform"),
      fc.constantFrom("rotateX", "rotateY", "rotatex", "rotatey"),
      fc.constantFrom("90", "270", "-90", "90.0"),
    )
    .map(([name, fn, deg]) => `${name}: ${fn}(${deg}deg)`),
  // translateX/translateY past the viewport hides off-screen.
  "transform-translate": fc
    .tuple(
      casedPropertyName("transform"),
      fc.constantFrom("translateX", "translateY", "translatex", "translatey"),
      offscreenLength,
    )
    .map(([name, fn, length]) => `${name}: ${fn}(${length})`),
  // filter: opacity(0) drops the element to fully transparent.
  filter: fc
    .tuple(
      casedPropertyName("filter"),
      fc.constantFrom("0", "0.0", "0%", "0.5%"),
    )
    .map(([name, amount]) => `${name}: opacity(${amount})`),
  // clip-path clipping the box to nothing.
  "clip-path": fc
    .tuple(
      casedPropertyName("clip-path"),
      fc.constantFrom(
        "inset(50%)",
        "inset(60% 70%)",
        "circle(0)",
        "circle(0px)",
      ),
    )
    .map(([name, shape]) => `${name}: ${shape}`),
};

// Color-based hiding (same-color, transparent) is inherently about the `color`
// value, so the shared `unrelatedDecl` noise (which can append `; color: red`)
// would legitimately override the hide. These variants get color-free noise.
const colorHidingDeclarations = {
  // Same concrete color on both sides (white-on-white) — invisible to a human.
  "same-color": fc
    .constantFrom("#777777", "#000000", "#ffffff", "#abcdef")
    .map((hex) => `color: ${hex}; background: ${hex}`),
  // Fully transparent text with no gradient/text-fill painting it visible.
  "color-transparent": casedPropertyName("color").map(
    (name) => `${name}: transparent`,
  ),
};
const colorSafeExtra = fc.constantFrom("", "; margin: 1px", "; padding: 2px");
const wrapWithColorSafeNoise = (declaration) =>
  fc
    .tuple(whitespace, declaration, importantFlag, whitespace, colorSafeExtra)
    .map(
      ([leading, decl, flag, trailing, extra]) =>
        leading + decl + flag + trailing + extra,
    );
// `font-size:0` reliably collapses text to nothing on its own, so it stays a
// standalone hiding signal. `height`/`width` are deliberately NOT standalone
// here — with the default `overflow:visible` a zero-sized box still paints
// its overflowing children — so they only flag paired with `overflow:hidden`
// in the loop below (precision fix).
hidingDeclarations["font-size"] = fc
  .tuple(casedPropertyName("font-size"), zeroLength)
  .map(([name, length]) => `${name}: ${length}`);
for (const dimension of ["height", "width", "max-height", "max-width"]) {
  hidingDeclarations[`overflow+${dimension}`] = fc
    .tuple(
      casedPropertyName("overflow"),
      casedPropertyName(dimension),
      zeroLength,
    )
    .map(([overflow, dim, length]) => `${overflow}: hidden; ${dim}: ${length}`);
}

describe("property: hidden-style variants flagged by isHiddenStyle", () => {
  for (const [variantName, declaration] of Object.entries(hidingDeclarations)) {
    it(`flags ${variantName}`, () =>
      checkProperty(wrapWithNoise(declaration), (styleString) =>
        assert.equal(
          isHiddenStyle(styleString),
          true,
          `not flagged: ${JSON.stringify(styleString)}`,
        ),
      ));
  }
});

// Ordinary visible declarations a real page emits. isHiddenStyle splices the
// element's content out of the model's view, so flagging any of these would
// DELETE legitimate text — a curated allowlist pins that none ever reads as
// hidden, even wrapped in the same whitespace/!important/case noise the
// positive fuzz uses.
const visibleDeclaration = fc.constantFrom(
  "opacity: 0.15",
  "opacity: 0.5",
  "opacity: 1",
  "font-size: 11px",
  "font-size: 0.9em",
  "font-size: 14px",
  "transform: scale(0.8)",
  "transform: rotateY(45deg)",
  "transform: rotateY(89deg)",
  "transform: rotate(90deg)",
  "transform: translateX(-5px)",
  "position: absolute; left: -5px",
  "position: absolute; top: -1px",
  "position: absolute; left: -50vw",
  "position: absolute; left: -50%",
  "position: absolute; left: -10%",
  "position: absolute; left: calc(100% - 5px)",
  "position: absolute; left: -9999", // unitless nonzero length is invalid CSS, fails open
  "text-indent: -9999", // same, unitless
  "height: 0", // zero box alone (no overflow:hidden) still shows overflowing children
  "width: 0",
  "margin-left: -2em",
  "text-indent: -0.5em",
  "clip-path: inset(10%)",
  "clip-path: circle(50%)",
  "clip-path: inset(50% 0 0 0)", // one edge open (bottom half visible)
  "color: white",
  "color: white; background: #fefefe",
  "color: #777; background: #888",
  "color: red",
  "content-visibility: auto", // perf hint; content stays visible
  "content-visibility: visible",
  "transform: rotateX(89deg)", // not an odd quarter-turn
  "transform: rotateZ(90deg)", // in-plane spin stays visible
  "filter: opacity(1)",
  "filter: opacity(0.5)",
  "filter: blur(2px)",
  "color: transparent; -webkit-background-clip: text", // gradient-heading recipe
  "color: transparent; background-clip: text",
);

describe("property: color-based hidden-style variants flagged by isHiddenStyle", () => {
  for (const [variantName, declaration] of Object.entries(
    colorHidingDeclarations,
  )) {
    it(`flags ${variantName}`, () =>
      checkProperty(wrapWithColorSafeNoise(declaration), (styleString) =>
        assert.equal(
          isHiddenStyle(styleString),
          true,
          `not flagged: ${JSON.stringify(styleString)}`,
        ),
      ));
  }
});

describe("property: ordinary visible styles are never flagged hidden", () => {
  it("no curated visible declaration reads as hidden under noise", () =>
    checkProperty(wrapWithNoise(visibleDeclaration), (styleString) =>
      assert.equal(
        isHiddenStyle(styleString),
        false,
        `false positive: ${JSON.stringify(styleString)}`,
      ),
    ));
});

describe("property: isHiddenStyle never throws on arbitrary input", () => {
  it("returns a boolean for any string", () =>
    checkProperty(fc.string(), (styleString) => {
      assert.equal(typeof isHiddenStyle(styleString), "boolean");
    }));
  it("returns a boolean for plausibly-CSS strings", () => {
    const cssLike = fc
      .array(
        fc
          .tuple(
            fc.constantFrom(
              "color",
              "opacity",
              "transform",
              "clip-path",
              "left",
              "font-size",
              "background",
              "visibility",
            ),
            fc.string({ maxLength: 20 }),
          )
          .map(([prop, value]) => `${prop}:${value}`),
        { maxLength: 5 },
      )
      .map((decls) => decls.join(";"));
    checkProperty(cssLike, (styleString) => {
      assert.equal(typeof isHiddenStyle(styleString), "boolean");
    });
  });
});

// ─── 2b. CSS numeric parsing matches parseFloat (exponents/signs) ────────────

// A CSS numeric literal across the forms a browser honors: plain, signed,
// fractional, and scientific notation. Built as a string so the detector's
// regex capture — not a hand-rolled number — is what gets exercised.
const cssNumber = fc
  .tuple(
    fc.constantFrom("", "-", "+"),
    fc.constantFrom("0", "1", "9", "0.5", "1.5", "12", "0.0001"),
    fc.constantFrom("", "e3", "e-3", "E-4", "e+2", "e0"),
  )
  .map(([sign, mantissa, exp]) => `${sign}${mantissa}${exp}`)
  // Keep only literals JS parses to a finite number (a bare "+"/"-" or "0e"
  // would be NaN and is not a value a browser would render).
  .filter((s) => Number.isFinite(parseFloat(s)) && /\d/.test(s));

describe("property: isHiddenStyle reads CSS numerics at parseFloat magnitude", () => {
  // scale() is hidden iff |parseFloat(n)| < 0.01 — exponent forms included, so
  // scale(1e-3) reads as 0.001 (hidden) and scale(1e3) as 1000 (visible). The
  // verdict must equal the parseFloat-based oracle, never a capture truncated
  // at `e`.
  it("scale() verdict equals the |parseFloat| < epsilon oracle", () =>
    checkProperty(cssNumber, (n) => {
      const expected = Math.abs(parseFloat(n)) < 0.01;
      assert.equal(isHiddenStyle(`transform:scale(${n})`), expected);
    }));
  // opacity is CSS-clamped to [0,1]: hidden iff parseFloat(n) < 0.01 (NO abs),
  // so any negative is fully transparent (hidden) and 0.9/1 stay visible.
  it("opacity verdict equals the parseFloat < epsilon oracle (no abs)", () =>
    checkProperty(cssNumber, (n) => {
      const expected = parseFloat(n) < 0.01;
      assert.equal(isHiddenStyle(`opacity:${n}`), expected);
    }));
});

// ─── 3. URL exfil monotonicity ───────────────────────────────────────────────

const base64Char = fc.constantFrom(
  ..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".split(
    "",
  ),
);
const arbitraryFlaggableSegment = fc
  .array(base64Char, { minLength: 48, maxLength: 96 })
  .map((chars) => chars.join(""));
const arbitraryPayloadSegment = fc
  .array(base64Char, { minLength: 0, maxLength: 80 })
  .map((chars) => chars.join(""));
const arbitraryBaseUrl = fc.constantFrom(
  "https://x.com/p",
  "/log",
  "http://a/b/c",
);
const arbitraryParamName = fc.constantFrom("q", "data", "token", "x");

describe("property: checkExfilUrl monotonic in payload length", () => {
  it("appending bytes never un-flags", () => {
    let sawFlagged = 0;
    fc.assert(
      fc.property(
        arbitraryBaseUrl,
        arbitraryParamName,
        arbitraryFlaggableSegment,
        arbitraryPayloadSegment,
        (baseUrl, paramName, headSegment, extraSegment) => {
          const shortUrl = `${baseUrl}?${paramName}=${headSegment}`;
          const longUrl = `${baseUrl}?${paramName}=${headSegment}${extraSegment}`;
          const shortFlagged = checkExfilUrl(shortUrl) !== null;
          const longFlagged = checkExfilUrl(longUrl) !== null;
          if (shortFlagged) sawFlagged += 1;
          assert.ok(
            !shortFlagged || longFlagged,
            `mono violated: ${shortUrl} flagged but ${longUrl} not`,
          );
        },
      ),
      runOptions,
    );
    assert.ok(
      sawFlagged > 0,
      "no short URL was ever flagged — property vacuous",
    );
  });
});

// ─── 4. Round-trip: no forbidden node survives ──────────────────────────────

const adversarialStyle = fc.constantFrom(
  "display:none",
  "visibility:hidden",
  "opacity:0",
  "position:absolute;left:-9999px",
  "position:fixed;top:-10000px",
  "clip:rect(0,0,0,0);position:absolute",
  "text-indent:-9999px",
  "height:0",
  "overflow:hidden;max-width:0",
  "font-size:0",
);
const adversarialNode = fc.oneof(
  fc.constant("<div hidden>x</div>"),
  adversarialStyle.map((style) => `<div style="${style}">h</div>`),
  adversarialStyle.map((style) => `<span style='${style}'>x</span>`),
);
// Comments sit in the benign pool: they are preserved now, so they must mix
// with adversarial nodes without either surviving-hidden or being spliced.
const benignNode = fc.constantFrom(
  "hello",
  "<p>v</p>",
  "<b>b</b>",
  "<script>alert(1)</script>",
  "<!-- marker -->",
  "",
  "\n",
);
const arbitraryAdversarialDoc = fc
  .array(fc.oneof(benignNode, adversarialNode), { minLength: 1, maxLength: 8 })
  .map((parts) => parts.join("\n"));

describe("property: sanitizeHtml round-trip drops all forbidden nodes", () => {
  it("a hidden element never survives (script/comments preserved by design)", () =>
    checkProperty(arbitraryAdversarialDoc, (input) => {
      const sanitized = applyHtml(input);
      assert.equal(
        containsForbiddenNode(sanitized),
        false,
        `survived: ${JSON.stringify(sanitized)}`,
      );
    }));
});

// ─── 5. Splice fidelity ──────────────────────────────────────────────────────

const proseChunk = fc.stringMatching(/^[a-zA-Z0-9 .,'!?_*|-]{1,40}$/);
const prosePrefix = fc.stringMatching(
  /^[a-zA-Z0-9.,'!?_*|-][a-zA-Z0-9 .,'!?_*|-]{0,39}$/,
);

describe("property: splice fidelity", () => {
  it("a comment passes through byte-identical (comments are preserved)", () =>
    checkProperty(fc.tuple(prosePrefix, proseChunk), ([prefix, suffix]) => {
      const input = `${prefix}<!-- secret -->${suffix}`;
      assert.equal(applyHtml(input), input);
    }));
  it("a stripped hidden span leaves surrounding bytes byte-identical", () =>
    checkProperty(fc.tuple(prosePrefix, proseChunk), ([prefix, suffix]) =>
      assert.equal(
        applyHtml(`${prefix}<span style="display:none">x</span>${suffix}`),
        `${prefix}${HIDDEN_PLACEHOLDER}${suffix}`,
      ),
    ));
  it("a reported script does not modify the text at all", () =>
    checkProperty(fc.tuple(prosePrefix, proseChunk), ([prefix, suffix]) => {
      const input = `${prefix}<script>x</script>${suffix}`;
      const result = sanitizeHtml(input);
      assert.equal(result.text, input);
      assert.equal(result.warned.tags.script, 1);
    }));
});
