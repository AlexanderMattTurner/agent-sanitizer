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
 *
 * A row states only where it differs from {@link DEFAULTS}.
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

// A single URL, on any element, fetched as a resource.
const DEFAULTS = Object.freeze({
  grammar: "url",
  elements: null,
  context: "resource",
  fetched: true,
  notFetchedOn: [],
});

/** @type {readonly UrlAttribute[]} */
export const URL_ATTRIBUTES = Object.freeze(
  /** @type {Array<Partial<UrlAttribute> & { attribute: string, property: string }>} */ ([
    { attribute: "src", property: "src" },
    // A link waits for a click; `<base>` only changes how the page's relative
    // URLs resolve.
    {
      attribute: "href",
      property: "href",
      notFetchedOn: ["a", "area", "base"],
    },
    { attribute: "xlink:href", property: "xLinkHref", notFetchedOn: ["a"] },
    { attribute: "background", property: "background" },
    { attribute: "srcset", property: "srcSet", grammar: "srcset" },
    {
      attribute: "imagesrcset",
      property: "imageSrcSet",
      grammar: "srcset",
      elements: ["link"],
    },
    { attribute: "ping", property: "ping", grammar: "urls" },
    { attribute: "action", property: "action", context: "form" },
    { attribute: "formaction", property: "formAction", context: "form" },
    { attribute: "data", property: "data", elements: ["object"] },
    { attribute: "poster", property: "poster", elements: ["video"] },
    {
      attribute: "cite",
      property: "cite",
      elements: ["blockquote", "del", "ins", "q"],
      fetched: false,
    },
    {
      attribute: "longdesc",
      property: "longDesc",
      elements: ["img", "iframe", "frame"],
      fetched: false,
    },
    {
      attribute: "content",
      property: "content",
      grammar: "refresh",
      elements: ["meta"],
      context: "refresh",
    },
    { attribute: "style", property: "style", grammar: "css" },
  ]).map((row) => Object.freeze({ ...DEFAULTS, ...row })),
);
