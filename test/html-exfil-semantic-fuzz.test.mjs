/**
 * Semantic-correctness fuzzing for Layer 3 exfil-URL detection.
 *
 * exfil-property.test.mjs fuzzes STRUCTURAL invariants (never throws, a
 * flagged threat's target never echoes the payload). Those hold even if the
 * detector's precision is wrong — it could flag every ordinary link on a page
 * (alert-fatigue false positives) or miss a specific payload shape while some
 * aggregate invariant still passes. html.test.mjs pins exact verdicts for
 * isolated URLs, but never exercises them EMBEDDED in mixed documents, where
 * markdown/HTML extraction, neighboring links, and filler prose could bleed
 * one URL's verdict into another's.
 *
 * This suite fuzzes PRECISION directly: build random documents interleaving
 * KNOWN-BENIGN URLs (ordinary docs links, signed-CDN links, pagination
 * cursors, mailto:, relative anchors — each must produce NO threat) with
 * KNOWN-EXFIL-SHAPED URLs (blob params, template injection, credential-shaped
 * values, userinfo, oversized query/fragment, path blobs, javascript:/data:
 * schemes — each must be flagged with its exact reason and target), then
 * assert every specific URL's exact fate — not just "some invariant held".
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { detectExfil, checkExfilUrl, urlHost } from "../src/html.mjs";
import { fcRunOptions } from "./test-helpers.mjs";

// Each benign token is a genuine, complete URL of a shape that superficially
// resembles an exfil vector (long-ish queries, opaque tokens, hex runs) but is
// everyday legitimate traffic. Exact expected verdict: null, and no threat
// naming its host may appear in a document containing it.
const BENIGN_URLS = [
  "https://docs.example.com/guide/getting-started?ref=homepage",
  // Base64 JWT-prefixed pagination cursor in an allowlisted param name.
  "https://api.example.com/v2/items?cursor=eyJvZmZzZXQiOjEyMzR9&limit=50",
  "mailto:support@example.com?subject=Help",
  "/relative/path/page.html#section-2",
  "https://en.wikipedia.org/wiki/SHA-256#Comparison_of_SHA_functions",
  // Asset fingerprint: a short hex run in the path, well under the blob floor.
  "https://cdn.example.com/assets/app.3f9a1b2c4d5e6f70.js",
  "https://shop.example.com/search?q=blue+running+shoes&page=2&sort=price-asc",
  // SHA-256 content address: 64 hex chars, under the 128-char path-blob floor.
  `https://registry.example.com/blobs/sha256/${"a".repeat(64)}`,
  // Long opaque analytics click-ID in an allowlisted param name.
  `https://t.example.com/click?gclid=${"Zm9vQmFy".repeat(7)}`,
  // Signed-CDN URL: long by design, every param allowlisted.
  "https://cdn.example.com/a.js?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20240101T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=" +
    "b".repeat(64),
  // Percent-encoded but decodes to something short — must not flag.
  "https://benignpct.example.com/p?q=%41%42%43",
];

// Each exfil token is a genuine data-exfiltration shape with a UNIQUE host so
// a threat in a mixed document maps back to exactly one generated token. The
// expected reason and urlHost-derived target are pinned per token.
const EXFIL_URLS = [
  {
    url: `https://blobq.evil/p?xyz=${"A".repeat(44)}`,
    reason: "suspicious query parameter",
    target: "blobq.evil",
  },
  {
    url: "https://tmpl.evil/p?note={{document.cookie}}",
    reason: "suspicious query parameter",
    target: "tmpl.evil",
  },
  {
    url: "https://cred.evil/p?u=ghp_0a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7",
    reason: "credential-shaped token in URL parameter",
    target: "cred.evil",
  },
  {
    url: "https://user:hunter2@userinfo.evil/p",
    reason: "embedded credentials",
    target: "userinfo.evil",
  },
  {
    url: `https://longq.evil/p?note=${"-".repeat(200)}`,
    reason: "unusually long query string",
    target: "longq.evil",
  },
  {
    url: `https://frag.evil/p#${"A".repeat(200)}`,
    reason: "unusually long fragment",
    target: "frag.evil",
  },
  {
    url: `https://pathblob.evil/${"A".repeat(160)}`,
    reason: "encoded data blob in path segment",
    target: "pathblob.evil",
  },
  {
    url: "javascript:alert(document.domain)",
    reason: "script-executing URI",
    target: "",
  },
  {
    url: "data:text/html;base64,PHNjcmlwdD4",
    reason: "active-content data: URI",
    target: "(inline data: URI)",
  },
  {
    // url-safe base64 blob in a keyword param (the raw pre-parse scan). The
    // repetitive spelling keeps the fake blob's Shannon entropy far below the
    // gitleaks generic-api-key threshold so CI secret scanning doesn't flag a
    // deliberately planted test payload; the detector only needs a 40+ char
    // alphanumeric run, not real randomness.
    url: `https://kw.evil/p?token=${"Ab1".repeat(14)}`,
    reason: "suspicious query parameter",
    target: "kw.evil",
  },
  {
    // Percent-encoded blob: the raw value is percent-escapes, not a blob
    // shape, but decodes to a 40+ run of "A"s.
    url: `https://pctblob.evil/log?q=${"%41%5A".repeat(20)}`,
    reason: "suspicious query parameter",
    target: "pctblob.evil",
  },
];

// How a URL token is embedded in the document: markdown link/image or HTML
// attribute. Each renders the URL once, so each token yields at most one threat.
const RENDERERS = [
  /** @param {string} url */ (url) => `[a link](${url})`,
  /** @param {string} url */ (url) => `![an image](${url})`,
  /** @param {string} url */ (url) => `<a href="${url}">x</a>`,
  /** @param {string} url */ (url) => `<img src="${url}">`,
];

const pieceGen = fc.oneof(
  fc
    .tuple(fc.constantFrom(...BENIGN_URLS), fc.nat(RENDERERS.length - 1))
    .map(([url, r]) => ({ kind: "benign", url, r })),
  fc
    .tuple(fc.constantFrom(...EXFIL_URLS), fc.nat(RENDERERS.length - 1))
    .map(([token, r]) => ({ kind: "exfil", ...token, r })),
  fc
    .array(fc.constantFrom(..."abc 0123456789.,-_".split("")), {
      minLength: 1,
      maxLength: 12,
    })
    .map((cs) => ({ kind: "filler", text: cs.join("") })),
);

const docGen = fc.array(pieceGen, { minLength: 1, maxLength: 8 });

/** @param {any} p */
function render(p) {
  return p.kind === "filler" ? p.text : RENDERERS[p.r](p.url);
}

describe("semantic-correctness fuzz: exfil-URL precision on mixed documents", () => {
  it("flags exactly the exfil-shaped URLs — right reason and target, zero benign hits", () => {
    fc.assert(
      fc.property(docGen, (pieces) => {
        const doc = pieces.map(render).join(" ");
        const threats = detectExfil(doc) ?? [];
        const expected = pieces
          .filter((p) => p.kind === "exfil")
          .map((p) => `${p.reason} | ${p.target}`)
          .sort();
        const actual = threats.map((t) => `${t.reason} | ${t.target}`).sort();
        // Exact multiset equality: every generated exfil token is flagged with
        // its pinned reason+target, and NOTHING else in the document (benign
        // URLs, filler) produces a threat.
        assert.deepEqual(actual, expected);
      }),
      fcRunOptions(),
    );
  });

  // fc.assert-driven (not a plain loop) so checkExfilUrl/urlHost are
  // genuinely exercised by a fast-check property, not merely referenced in
  // ordinary example-test code that happens to share this file with the
  // property above — the fuzz-coverage obligation gate (test/fuzz-coverage.
  // test.mjs) requires the former and would otherwise be satisfied
  // vacuously by the latter.
  it("each benign token's isolated checkExfilUrl verdict is null", () => {
    fc.assert(
      fc.property(fc.constantFrom(...BENIGN_URLS), (url) => {
        assert.equal(checkExfilUrl(url), null, url);
      }),
      fcRunOptions(),
    );
  });

  it("each exfil token's isolated checkExfilUrl/urlHost verdict matches its pinned fate", () => {
    fc.assert(
      fc.property(fc.constantFrom(...EXFIL_URLS), ({ url, reason, target }) => {
        assert.equal(checkExfilUrl(url), reason, url);
        assert.equal(urlHost(url), target, url);
      }),
      fcRunOptions(),
    );
  });
});
