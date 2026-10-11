/**
 * The HTML and SVG attributes a browser resolves as URLs: the one table every
 * Layer-3 URL read (and Layer 2's data: resource count) goes through, so an
 * attribute is either read everywhere or nowhere. test/url-attributes.test.mjs
 * partitions the HTML Standard's URL-valued attributes between this table and
 * an exempt list that says why each one left out is never fetched.
 *
 * Per entry:
 *  - `attribute`: the name as written in markup;
 *  - `property`: its hast property name, as property-information (which builds
 *    this package's hast trees) spells it;
 *  - `grammar`: how the value holds its URLs —
 *      "url"     one URL,
 *      "urls"    a space-separated list (hast delivers an array),
 *      "srcset"  image candidate strings,
 *      "refresh" a `<meta http-equiv="refresh">` content value,
 *      "css"     a declaration list whose `url()` values load;
 *  - `elements`: the elements it is URL-valued on, or null for any element;
 *  - `context`: a "form" or "refresh" target is also flagged for leaving the
 *    page's origin at all;
 *  - `fetched`: whether the browser loads the URL with nobody deciding to (on
 *    render, on submit, on refresh, on a click aimed at something else), and
 *    `notFetchedOn` the elements where it instead waits to be followed.
 */

/**
 * @typedef {{
 *   attribute: string,
 *   property: string,
 *   grammar: "url" | "urls" | "srcset" | "refresh" | "css",
 *   elements: readonly string[] | null,
 *   context: "resource" | "form" | "refresh",
 *   fetched: boolean,
 *   notFetchedOn: readonly string[],
 * }} UrlAttribute
 */

/** @type {readonly UrlAttribute[]} */
export const URL_ATTRIBUTES = Object.freeze([
  {
    attribute: "src",
    property: "src",
    grammar: "url",
    elements: null,
    context: "resource",
    fetched: true,
    notFetchedOn: [],
  },
  {
    attribute: "href",
    property: "href",
    grammar: "url",
    elements: null,
    context: "resource",
    fetched: true,
    // A link waits for a click; `<base>` only changes how the page's relative
    // URLs resolve.
    notFetchedOn: ["a", "area", "base"],
  },
  {
    attribute: "xlink:href",
    property: "xLinkHref",
    grammar: "url",
    elements: null,
    context: "resource",
    fetched: true,
    notFetchedOn: ["a"],
  },
  {
    attribute: "background",
    property: "background",
    grammar: "url",
    elements: null,
    context: "resource",
    fetched: true,
    notFetchedOn: [],
  },
  {
    attribute: "srcset",
    property: "srcSet",
    grammar: "srcset",
    elements: null,
    context: "resource",
    fetched: true,
    notFetchedOn: [],
  },
  {
    attribute: "imagesrcset",
    property: "imageSrcSet",
    grammar: "srcset",
    elements: ["link"],
    context: "resource",
    fetched: true,
    notFetchedOn: [],
  },
  {
    attribute: "ping",
    property: "ping",
    grammar: "urls",
    elements: null,
    context: "resource",
    fetched: true,
    notFetchedOn: [],
  },
  {
    attribute: "action",
    property: "action",
    grammar: "url",
    elements: null,
    context: "form",
    fetched: true,
    notFetchedOn: [],
  },
  {
    attribute: "formaction",
    property: "formAction",
    grammar: "url",
    elements: null,
    context: "form",
    fetched: true,
    notFetchedOn: [],
  },
  {
    attribute: "data",
    property: "data",
    grammar: "url",
    elements: ["object"],
    context: "resource",
    fetched: true,
    notFetchedOn: [],
  },
  {
    attribute: "poster",
    property: "poster",
    grammar: "url",
    elements: ["video"],
    context: "resource",
    fetched: true,
    notFetchedOn: [],
  },
  {
    attribute: "cite",
    property: "cite",
    grammar: "url",
    elements: ["blockquote", "del", "ins", "q"],
    context: "resource",
    fetched: false,
    notFetchedOn: [],
  },
  {
    attribute: "longdesc",
    property: "longDesc",
    grammar: "url",
    elements: ["img", "iframe", "frame"],
    context: "resource",
    fetched: false,
    notFetchedOn: [],
  },
  {
    attribute: "content",
    property: "content",
    grammar: "refresh",
    elements: ["meta"],
    context: "refresh",
    fetched: true,
    notFetchedOn: [],
  },
  {
    attribute: "style",
    property: "style",
    grammar: "css",
    elements: null,
    context: "resource",
    fetched: true,
    notFetchedOn: [],
  },
]);
