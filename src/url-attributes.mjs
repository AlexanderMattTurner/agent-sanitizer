/**
 * The attributes a browser resolves as URLs: the one table every Layer-3 URL
 * read (and Layer 2's data: resource count) goes through; its test partitions
 * the HTML Standard's URL attributes between it and an exempt list. `property`
 * is the hast spelling; `elements` null means any element; a "form" or
 * "refresh" `context` is also flagged for leaving the origin; `fetched` is a
 * load nobody decides on, except on `notFetchedOn`. Rows state only where they
 * differ from {@link DEFAULTS}.
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
    // A link waits for a click; `<base>` only re-bases relative URLs.
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
