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
  layer2Placeholder,
  LAYER2_PLACEHOLDER_RE,
} from "../src/html.mjs";
import { fcRunOptions } from "./test-helpers.mjs";

const runOptions = fcRunOptions({ numRuns: 500 });
const applyHtml = (text) => sanitizeHtml(text)?.text ?? text;
const checkProperty = (arbitrary, predicate) =>
  fc.assert(fc.property(arbitrary, predicate), runOptions);
const hid = (original) => layer2Placeholder("hidden", original);
const com = (original) => layer2Placeholder("comment", original);
// Stateless copy of the shared /g grammar regex (`.test` on a /g regex advances
// lastIndex between calls, silently skipping matches).
const PLACEHOLDER_RE = new RegExp(LAYER2_PLACEHOLDER_RE.source);

// "Forbidden" = invisible on a rendered page: comments and hidden elements.
function containsForbiddenNode(htmlText) {
  // rehype-parse, not the layer's own parse: an oracle built from the code
  // under test cannot contradict it. This one runs parse5 with the DEFAULT tree
  // adapter, so it also checks the layer's adapter against a second reader.
  const tree = unified().use(rehypeParse, { fragment: true }).parse(htmlText);
  let forbidden = false;
  visit(tree, (node) => {
    if (node.type !== "comment" && !isHiddenElement(node)) return undefined;
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
  // Table tags need no table around them here: a stray `<td>`/`<tr>` at the
  // root of a fragment is exactly the shape whose parse MOVES when a sibling
  // is spliced, because parse5 places it by table scope rather than in order.
  "table",
  "tr",
  "td",
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
  // an UNTERMINATED processing instruction swallows the markup up to the next
  // `>`, so which bytes are markup depends on what a splice left around it
  "<? ",
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
      assert.ok(PLACEHOLDER_RE.test(passOne));
      // Keyed placeholders already in the text pass through byte-identically:
      // a re-run neither re-splices them nor mangles their keys.
      assert.equal(applyHtml(passOne), passOne);
    }));

  it("an UNPLANTED document is a fixed point too", () => {
    // The plant above opens the document with bare text, which pins every draw
    // to the markdown branch. Only a document parse5 reads as HTML SOURCE
    // reaches the branch where a splice reshapes the tree around it — a stray
    // `<td>` parse5 placed by table scope, a `<? ` whose bogus comment now ends
    // somewhere else — so the source branch needs its own unplanted draw.
    let spliced = 0;
    checkProperty(arbitraryHtmlFragment, (input) => {
      const passOne = applyHtml(input);
      if (PLACEHOLDER_RE.test(passOne)) spliced += 1;
      assert.equal(applyHtml(passOne), passOne, input);
    });
    // Idempotence over an unspliced document is vacuous, and nothing else here
    // forces a splice.
    assert.ok(spliced > 0, "no generated document was spliced");
  });
});

// ─── 1b. Round-trip: splices restore the input byte-identically ──────────────
//
// The point of the keyed-placeholder feature: nothing is LOST, only hidden
// behind an identity-carrying placeholder. For any generated document carrying
// comments and hidden elements, substituting each splice's original back at its
// recorded start offset must reproduce the input byte for byte — and every
// emitted placeholder must obey the shared grammar with a content-addressed key.
const roundTripPiece = fc.oneof(
  { weight: 3, arbitrary: fc.stringMatching(/^[a-zA-Z0-9 .,'!?_-]{0,30}$/) },
  {
    weight: 2,
    arbitrary: fc
      .stringMatching(/^[a-zA-Z0-9 .,_-]{0,20}$/)
      .filter((body) => !body.includes("--"))
      .map((body) => `<!-- ${body} -->`),
  },
  {
    weight: 2,
    arbitrary: fc
      .stringMatching(/^[a-zA-Z0-9 .,_-]{0,20}$/)
      .map((body) => `<div hidden>${body}</div>`),
  },
  {
    weight: 1,
    arbitrary: fc
      .stringMatching(/^[a-zA-Z0-9 ]{0,16}$/)
      .map((body) => `<span style="display:none">${body}</span>`),
  },
  { weight: 1, arbitrary: fc.constant("<p>visible</p>") },
);
const roundTripDoc = fc
  .array(roundTripPiece, { minLength: 1, maxLength: 8 })
  .map((parts) => parts.join(" "));

describe("property: every splice is round-trippable (keyed placeholders)", () => {
  it("substituting originals back at their offsets reproduces the input byte-identically", () => {
    let sawSplice = 0;
    fc.assert(
      fc.property(roundTripDoc, (input) => {
        const result = sanitizeHtml(input);
        if (result === null || result.text === input) return;
        sawSplice += 1;
        // Grammar: every placeholder in the output is the exact string
        // layer2Placeholder derives from its original — content-addressed, so
        // identical originals yield identical placeholders.
        for (const { placeholder, original, start } of result.splices) {
          assert.ok(
            placeholder === hid(original) || placeholder === com(original),
            `off-grammar placeholder: ${placeholder} for ${JSON.stringify(original)}`,
          );
          assert.equal(
            result.text.slice(start, start + placeholder.length),
            placeholder,
          );
        }
        // The number of grammar matches in the output equals the number of
        // splices plus any placeholder-shaped text the INPUT already carried
        // (the generators above emit none, so it is exactly the splice count).
        assert.equal(
          [...result.text.matchAll(LAYER2_PLACEHOLDER_RE)].length,
          result.splices.length,
        );
        // The headline: undo every splice (in reverse so offsets stay valid)
        // and get the input back, byte for byte.
        let restored = result.text;
        for (let i = result.splices.length - 1; i >= 0; i--) {
          const { placeholder, original, start } = result.splices[i];
          restored =
            restored.slice(0, start) +
            original +
            restored.slice(start + placeholder.length);
        }
        assert.equal(restored, input);
      }),
      runOptions,
    );
    assert.ok(sawSplice > 100, `only ${sawSplice} runs spliced — vacuous`);
  });
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
  fc.constant("<!-- secret -->"),
  fc.constant("<div hidden>x</div>"),
  adversarialStyle.map((style) => `<div style="${style}">h</div>`),
  adversarialStyle.map((style) => `<span style='${style}'>x</span>`),
);
const benignNode = fc.constantFrom(
  "hello",
  "<p>v</p>",
  "<b>b</b>",
  "<script>alert(1)</script>",
  "",
  "\n",
);
const arbitraryAdversarialDoc = fc
  .array(fc.oneof(benignNode, adversarialNode), { minLength: 1, maxLength: 8 })
  .map((parts) => parts.join("\n"));

describe("property: sanitizeHtml round-trip drops all forbidden nodes", () => {
  it("comment/hidden never survives (script is preserved by design)", () =>
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
  it("a stripped comment leaves surrounding bytes byte-identical", () =>
    checkProperty(fc.tuple(prosePrefix, proseChunk), ([prefix, suffix]) =>
      assert.equal(
        applyHtml(`${prefix}<!-- secret -->${suffix}`),
        `${prefix}${com("<!-- secret -->")}${suffix}`,
      ),
    ));
  it("a stripped hidden span leaves surrounding bytes byte-identical", () =>
    checkProperty(fc.tuple(prosePrefix, proseChunk), ([prefix, suffix]) =>
      assert.equal(
        applyHtml(`${prefix}<span style="display:none">x</span>${suffix}`),
        `${prefix}${hid('<span style="display:none">x</span>')}${suffix}`,
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

// ─── 6. Differential: two spellings, one language ────────────────────────────
//
// Each pattern below is spelled twice: the linear-time form the layer ships and
// a reference form written for readability. The pair is inline because every
// one of these patterns is module-private, and a difference on ANY generated
// input is a real defect — the whole point of the shipped spelling is that it
// accepts exactly the same language while failing in linear time.

// A pattern's verdict AND its captures, as a plain array so two patterns can be
// compared exactly (`null` when the pattern rejects).
const captures = (pattern, text) => {
  const match = text.match(pattern);
  return match === null ? null : match.slice();
};

const agree = (reference, shipped, text) => {
  assert.equal(
    reference.test(text),
    shipped.test(text),
    `verdicts differ on ${JSON.stringify(text)}`,
  );
  assert.deepEqual(
    captures(reference, text),
    captures(shipped, text),
    `captures differ on ${JSON.stringify(text)}`,
  );
};

const B64URL_MIXED_REFERENCE = /(?=.*[A-Z])(?=.*[0-9])/;
const base64UrlChar = fc.constantFrom(
  ..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-".split(
    "",
  ),
);
const base64UrlString = fc
  .array(base64UrlChar, { maxLength: 60 })
  .map((chars) => chars.join(""));

describe("differential: the base64url character-mix gate", () => {
  it("two scans agree with the lookahead pair", () =>
    checkProperty(base64UrlString, (value) =>
      assert.equal(
        B64URL_MIXED_REFERENCE.test(value),
        /[A-Z]/.test(value) && /[0-9]/.test(value),
      ),
    ));

  // The gate through the public surface. Three-character groups joined by `-`
  // hold every OTHER exfil rule off this value: the `-` keeps it out of the
  // standard-base64 and hex arms, and no group reaches the 20-character
  // contiguous run the credential-shape rule needs — so the character mix is
  // the only thing that can move the verdict. One alphabet per value, so
  // single-class values (which the gate must leave alone) are generated as
  // often as mixed ones rather than drowned out by them.
  const groupedValue = fc
    .constantFrom(
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      "0123456789",
      "abcdefghijklmnopqrstuvwxyz",
      "ABCdef123_",
    )
    .chain((alphabet) =>
      fc
        .array(fc.constantFrom(...alphabet.split("")), {
          minLength: 42,
          maxLength: 90,
        })
        .map((chars) =>
          chars
            .join("")
            .match(/.{1,3}/g)
            .join("-"),
        ),
    );
  it("decides checkExfilUrl's verdict on a hyphen-grouped query value", () => {
    let flagged = 0;
    let benign = 0;
    fc.assert(
      fc.property(groupedValue, (value) => {
        assert.ok(value.length >= 40 && value.length < 190);
        const mixed = B64URL_MIXED_REFERENCE.test(value);
        if (mixed) flagged += 1;
        else benign += 1;
        assert.equal(
          checkExfilUrl(`https://e.com/p?d=${value}`),
          mixed ? "suspicious query parameter" : null,
        );
      }),
      runOptions,
    );
    assert.ok(flagged > 0 && benign > 0, "one branch never generated");
  });
});

/** Each rewritten token pattern beside the spelling it replaced, plus one token
 * the pair must ACCEPT: two patterns that reject everything agree on
 * everything, and a random draw reaches an accepted token only by luck. */
const NUMERIC_PATTERN_PAIRS = [
  [
    "rgb() percentage channel",
    /^\+?(\d*\.?\d+)%$/,
    /^\+?(\d+(?:\.\d+)?|\.\d+)%$/,
    "50%",
  ],
  [
    "rgb() number channel",
    /^\+?(\d*\.?\d+)$/,
    /^\+?(\d+(?:\.\d+)?|\.\d+)$/,
    "128",
  ],
  [
    "hsl() hue",
    /^([+-]?\d*\.?\d+)(deg|grad|rad|turn)?$/,
    /^([+-]?(?:\d+(?:\.\d+)?|\.\d+))(deg|grad|rad|turn)?$/,
    "-90deg",
  ],
  [
    "hsl() saturation/lightness",
    /^\+?(\d*\.?\d+)%?$/,
    /^\+?(\d+(?:\.\d+)?|\.\d+)%?$/,
    ".5",
  ],
  [
    "transparent-zero alpha",
    /^\+?(?:0*\.?0+)%?$/,
    /^\+?(?:0+(?:\.0+)?|\.0+)%?$/,
    "0.0%",
  ],
];
// Whole units as single choices, so the generator reaches `90deg`/`.5turn` and
// not only their one-character prefixes.
const numericPiece = fc.constantFrom(
  ..."0123456789.+-%e ".split(""),
  "deg",
  "grad",
  "rad",
  "turn",
  "DEG",
);
const numericToken = fc
  .array(numericPiece, { maxLength: 12 })
  .map((pieces) => pieces.join(""));

// The token positions the two spellings can possibly disagree on: a sign, an
// integer part, a dot, a fraction part, a suffix. Random draws over these
// alone leave gaps — a leading-dot fraction with a `%` is one draw in
// thousands, and it is exactly the shape the disjoint arms exist for — so the
// cross product is enumerated in full rather than sampled.
const TOKEN_POSITIONS = [
  ["", "+", "-", "++", "+-"],
  ["", "0", "5", "12", "007"],
  ["", ".", ".."],
  ["", "0", "5", "25"],
  ["", "%", "deg", "grad", "rad", "turn", "DEG", "e5", "px", " ", "%%"],
];
const structuredTokens = TOKEN_POSITIONS.reduce(
  (tokens, position) =>
    tokens.flatMap((token) => position.map((part) => token + part)),
  [""],
);

describe("differential: the CSS numeric-token patterns", () => {
  for (const [label, reference, shipped, accepts] of NUMERIC_PATTERN_PAIRS) {
    it(`${label} accepts the same tokens with the same captures`, () => {
      assert.ok(shipped.test(accepts), `${label} rejects ${accepts}`);
      agree(reference, shipped, accepts);
      fc.assert(
        fc.property(numericToken, (token) => agree(reference, shipped, token)),
        runOptions,
      );
    });
    it(`${label} agrees on every sign/integer/dot/fraction/suffix combination`, () => {
      let accepted = 0;
      for (const token of structuredTokens) {
        if (shipped.test(token)) accepted += 1;
        agree(reference, shipped, token);
      }
      assert.ok(accepted > 0, "no enumerated token was ever accepted");
    });
  }
});

const UNTERMINATED_MARKUP_TAIL_REFERENCE = /<(?:[!?]|\/?[a-zA-Z])[^>]*$/;
const MARKUP_OPENER = /<(?:[!?]|\/?[a-zA-Z])/;
const markupChar = fc.constantFrom("<", ">", "/", "!", "?", "a", "B", " ");
const markupSoup = fc
  .array(markupChar, { maxLength: 24 })
  .map((chars) => chars.join(""));

describe("differential: the unterminated-markup tail test", () => {
  it("the slice after the last `>` agrees with the anchored tail pattern", () => {
    let open = 0;
    let closed = 0;
    fc.assert(
      fc.property(markupSoup, (raw) => {
        const unterminated = UNTERMINATED_MARKUP_TAIL_REFERENCE.test(raw);
        if (unterminated) open += 1;
        else closed += 1;
        assert.equal(
          unterminated,
          MARKUP_OPENER.test(raw.slice(raw.lastIndexOf(">") + 1)),
          `verdicts differ on ${JSON.stringify(raw)}`,
        );
      }),
      runOptions,
    );
    assert.ok(open > 0 && closed > 0, "one branch never generated");
  });
});
