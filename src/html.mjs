/**
 * Hidden-HTML splicing (Layer 2) and exfil-URL detection (Layer 3) for
 * web/HTML ingress.
 *
 * Layer 2 strips exactly what a human viewing the rendered page cannot see —
 * HTML comments and hidden elements (hiding inline styles, `hidden` attr) —
 * by splicing those byte ranges out of the original text and leaving a
 * placeholder; every byte outside a spliced range is preserved verbatim (no
 * re-serialization). Scripting/resource tags (script, style, svg, iframe, …)
 * and `data:` URI resources are REPORTED in the result's `warned` counts but
 * never removed, so fetched page source stays inspectable.
 *
 * Layer 3 reports data-exfil-shaped URLs (suspicious query params, oversized
 * payloads, embedded credentials) without modifying them; the caller surfaces
 * the report as a warning.
 *
 * Split into its own module so it can be lazy-loaded: pulling in the
 * remark/rehype/unified graph costs ~200ms of module-load time, so the main
 * entry `await import()`s this module only when its cheap regex gates match.
 */
// @ts-ignore -- css-tree ships no bundled types and @types/css-tree lags the 3.x
// API (e.g. `ident.decode`); the value AST is walked with local `any` types.
import * as csstree from "css-tree";
import { unified } from "unified";
import remarkParse from "remark-parse";
import remarkGfm from "remark-gfm";
import rehypeParse from "rehype-parse";
import { visit, SKIP, EXIT } from "unist-util-visit";
import {
  HTML_TAG_PRESENT,
  MD_LINK_HINT,
  SECRET_HINT,
  SECRET_HINT_EXT,
  matchesSecretHint,
} from "./gates.mjs";

// The cheap pre-gates live in the dependency-free `./gates.mjs` so the package
// root can re-export them without eagerly loading this module's remark/rehype
// graph. Re-exported here too so the `./html` subpath keeps exposing them.
export {
  HTML_TAG_PRESENT,
  MD_LINK_HINT,
  SECRET_HINT,
  SECRET_HINT_EXT,
  matchesSecretHint,
};

// ─── Layer 2: hidden-content detection ───────────────────────────────────────
//
// Values are tokenized by css-tree (its spec-compliant tokenizer/AST), not by
// hand-rolled regexes: `parseDeclarations` splits declarations, decodes CSS
// escapes, and strips `!important` through css-tree, and the structural
// detectors below inspect the resulting typed value nodes (Number, Dimension,
// Percentage, Function, …) directly. So an exponent (`scale(1e-3)`), an FF/CR
// escape terminator, an escaped `!important`, or a `;` inside a quoted value is
// read exactly as a browser reads it — the tokenizer-divergence bugs a
// hand-rolled parser kept re-introducing simply cannot arise. Ambiguity still
// fails OPEN (treated as visible): an unresolved unit, `calc()`, or `var()`
// never counts as hidden.

// A length/opacity/size is "near zero" when its magnitude is below this — a
// browser renders 0.0001px text or 0.001 opacity as effectively invisible, so
// requiring an exact 0 lets a trivially-perturbed value slip through.
const NEAR_ZERO_EPSILON = 0.01;

// A negative offset is "offscreen" only when it pushes the element ENTIRELY
// past the viewport edge — the magnitude that takes depends on the unit. An
// absolute unit (px and the font/char units) needs a large magnitude
// (< -900px). A viewport/percent unit clears the screen only at a full
// viewport-width: -100vw / -100% push a normal-width element fully out, but
// -50vw / -50% leave roughly half of it on screen, so the threshold is a full
// -100, not a partial shift. Flagging a partial shift would splice visible
// text, so this errs toward false-negative.
const OFFSCREEN_ABSOLUTE_THRESHOLD = -900;
const OFFSCREEN_VIEWPORT_THRESHOLD = -100;

// Absolute length units: a large negative magnitude is needed to clear the
// viewport. True viewport units clear it at a full -100. A `%` offset is
// viewport-relative for box offsets (left/top/…) but ELEMENT-relative inside a
// translate(), so it is handled by the callers, not these sets.
const ABSOLUTE_UNITS = new Set([
  "px",
  "em",
  "rem",
  "ex",
  "ch",
  "pt",
  "pc",
  "in",
  "cm",
  "mm",
]);
const VIEWPORT_UNITS = new Set(["vw", "vh", "vmin", "vmax"]);
// Angle units for rotateX/rotateY, normalized to degrees by hueDegrees.
const ANGLE_UNITS = new Set(["deg", "grad", "rad", "turn"]);

/**
 * The meaningful value tokens of a css-tree Value or Function node — its direct
 * children minus the Operator/whitespace separators — in document order.
 * @param {any} node
 * @returns {any[]}
 */
function valueTokens(node) {
  /** @type {any[]} */
  const tokens = [];
  if (!node || !node.children) return tokens;
  node.children.forEach((/** @type {any} */ child) => {
    if (child.type !== "Operator" && child.type !== "WhiteSpace")
      tokens.push(child);
  });
  return tokens;
}

/**
 * The single meaningful token of a value node, or null when the value is empty
 * or carries more than one token (`left:auto` → the Identifier; `left:1px 2px`
 * → null). A one-token requirement mirrors the old anchored `^…$` regexes.
 * @param {any} node
 * @returns {any | null}
 */
function soleToken(node) {
  const tokens = valueTokens(node);
  return tokens.length === 1 ? tokens[0] : null;
}

/**
 * True when a value is a single length/number/percentage whose magnitude is
 * (near) zero — `font-size:0`, `font-size:0.0001px`, `font-size:0%`. A keyword
 * (`medium`), a multi-token value, or `calc()` fails open.
 * @param {any} node
 * @returns {boolean}
 */
function isNearZeroLength(node) {
  const token = soleToken(node);
  if (
    !token ||
    (token.type !== "Number" &&
      token.type !== "Dimension" &&
      token.type !== "Percentage")
  )
    return false;
  return Math.abs(parseFloat(token.value)) < NEAR_ZERO_EPSILON;
}

/**
 * Group a Function node's children into its comma-separated argument lists.
 * `translate(0, -9999px)` → `[[Number 0], [Dimension -9999px]]`.
 * @param {any} fn
 * @returns {any[][]}
 */
function functionArgs(fn) {
  /** @type {any[][]} */
  const groups = [[]];
  if (fn.children)
    fn.children.forEach((/** @type {any} */ child) => {
      if (child.type === "Operator" && child.value === ",") groups.push([]);
      else if (child.type !== "WhiteSpace")
        groups[groups.length - 1].push(child);
    });
  return groups;
}

/**
 * True when a single length token is far enough offscreen to be fully clipped.
 * `%` counts for box offsets (`allowPercent`, viewport-relative) but not inside
 * a translate() (element-relative — unresolvable, fail open). A unitless Number
 * (invalid CSS), an unknown unit, `calc()`, and `auto` all fail open.
 * @param {any} token a css-tree value token
 * @param {boolean} allowPercent
 * @returns {boolean}
 */
function isOffscreenLength(token, allowPercent) {
  if (token.type === "Dimension") {
    const n = parseFloat(token.value);
    if (ABSOLUTE_UNITS.has(token.unit)) return n < OFFSCREEN_ABSOLUTE_THRESHOLD;
    if (VIEWPORT_UNITS.has(token.unit))
      return n <= OFFSCREEN_VIEWPORT_THRESHOLD;
    return false;
  }
  if (token.type === "Percentage" && allowPercent)
    return parseFloat(token.value) <= OFFSCREEN_VIEWPORT_THRESHOLD;
  return false;
}

/**
 * Like isOffscreenLength but for a box offset (`left`/`top`/…/`text-indent`):
 * the value must be a single token, and `%` is viewport-relative here so it
 * counts.
 * @param {any} node value node for the offset property
 * @returns {boolean}
 */
function isOffscreenOffset(node) {
  const token = soleToken(node);
  return token ? isOffscreenLength(token, true) : false;
}

/**
 * True when a `transform` renders text invisible: scaled to (near) nothing,
 * rotated edge-on (an odd quarter-turn around X or Y projects to zero area), or
 * translated far off any viewport. Walks the transform-function list so any
 * hiding function anywhere in the list is caught.
 * @param {any} node value node for `transform`
 * @returns {boolean}
 */
function isHidingTransform(node) {
  if (!node) return false;
  for (const fn of valueTokens(node)) {
    if (fn.type !== "Function") continue;
    const name = fn.name.toLowerCase();
    const args = valueTokens(fn);
    if (/^(?:scale|scale3d|scalex|scaley|matrix|matrix3d)$/.test(name)) {
      // scale/matrix collapse to nothing when EITHER axis factor is (near-)zero —
      // `scale(1,0)` / `scale3d(1,0,1)` collapse the Y axis, `matrix(1,0,0,0,…)`
      // sets scaleY (d) to 0 — so testing only the first factor missed the
      // multi-arg Y-collapse forms. css-tree reads the exponent form (`1e-3`) at
      // full value; scale()/matrix() factors are <number>s (never lengths). For
      // `matrix(a,b,c,d,…)` the two scale factors are a (index 0) and d (index 3).
      // The two scale factors' positions differ per function: scale/scale3d/
      // scaleX/scaleY carry them first (a single scaleX(0)/scaleY(0) sits at 0);
      // `matrix(a,b,c,d,…)` puts scaleX=a (0) and scaleY=d (3); `matrix3d` puts
      // scaleX=m11 (0) and scaleY=m22 (5). Do NOT use index 3 for matrix3d — that
      // is m14, which is legitimately 0 on the identity matrix (false positive).
      const numbers = args.filter(
        (/** @type {any} */ a) => a.type === "Number",
      );
      const factorIdx =
        name === "matrix" ? [0, 3] : name === "matrix3d" ? [0, 5] : [0, 1];
      if (
        factorIdx.some((/** @type {number} */ i) => {
          const f = numbers[i];
          return f && Math.abs(parseFloat(f.value)) < NEAR_ZERO_EPSILON;
        })
      )
        return true;
    } else if (name === "rotatex" || name === "rotatey") {
      // An axis rotation collapses the box to a line at an odd quarter-turn.
      // Only the axis-specific rotations collapse; a plain rotate()/rotateZ()
      // spins in-plane and stays visible. The angle needs an explicit unit (a
      // unitless nonzero angle is invalid CSS a browser drops); hueDegrees
      // normalizes deg/grad/rad/turn to [0,360), and a near-90/270 band absorbs
      // the float drift of rad→deg.
      const a = args[0];
      if (
        a &&
        a.type === "Dimension" &&
        ANGLE_UNITS.has(a.unit.toLowerCase())
      ) {
        const degrees = hueDegrees(`${a.value}${a.unit}`.toLowerCase());
        if (
          degrees !== null &&
          (Math.abs(degrees - 90) < NEAR_ZERO_EPSILON ||
            Math.abs(degrees - 270) < NEAR_ZERO_EPSILON)
        )
          return true;
      }
    } else if (
      name === "translate" ||
      name === "translatex" ||
      name === "translatey"
    ) {
      // A two-axis translate hides when EITHER axis clears the viewport. A `%`
      // translate is element-relative (unresolvable), so it fails open.
      for (const group of functionArgs(fn))
        if (group.length === 1 && isOffscreenLength(group[0], false))
          return true;
    }
  }
  return false;
}

/**
 * True when a `filter` renders content invisible: an `opacity()` function drops
 * the element to fully transparent. The amount is a <number-percentage>; a
 * percentage is divided to a fraction before the near-zero test. Other filter
 * functions keep content visible; an unresolvable amount fails OPEN.
 * @param {any} node value node for `filter`
 * @returns {boolean}
 */
function isHidingFilter(node) {
  if (!node) return false;
  for (const fn of valueTokens(node)) {
    if (fn.type !== "Function" || fn.name.toLowerCase() !== "opacity") continue;
    const amount = valueTokens(fn)[0];
    if (!amount) continue;
    if (
      amount.type === "Number" &&
      parseFloat(amount.value) < NEAR_ZERO_EPSILON
    )
      return true;
    if (
      amount.type === "Percentage" &&
      parseFloat(amount.value) / 100 < NEAR_ZERO_EPSILON
    )
      return true;
  }
  return false;
}

// One `clip: rect(...)` edge as a number and unit, or null for `auto`/any
// non-length token (unresolvable → fail open). A bare Number carries unit "".
/** @param {any} token @returns {{ num: number, unit: string } | null} */
function clipEdge(token) {
  if (token.type === "Dimension")
    return { num: parseFloat(token.value), unit: token.unit };
  if (token.type === "Number")
    return { num: parseFloat(token.value), unit: "" };
  if (token.type === "Percentage")
    return { num: parseFloat(token.value), unit: "%" };
  return null;
}

/**
 * True when a legacy `clip: rect(top, right, bottom, left)` clips the element to
 * ~ZERO AREA — the window's width (`right - left`) or height (`bottom - top`)
 * collapses to near nothing. Parses ALL FOUR edges (checking only the first
 * spliced a visible `rect(0px,100px,100px,0px)`); an `auto`/unresolvable edge,
 * a wrong edge count, or a pair in mismatched units fails OPEN.
 * @param {any} node value node for `clip`
 * @returns {boolean}
 */
function isClipRectHidden(node) {
  if (!node) return false;
  const rect = valueTokens(node).find(
    (t) => t.type === "Function" && t.name.toLowerCase() === "rect",
  );
  if (!rect) return false;
  const edges = valueTokens(rect).map(clipEdge);
  if (edges.length !== 4 || edges.some((edge) => edge === null)) return false;
  const [top, right, bottom, left] = /** @type {{num:number,unit:string}[]} */ (
    edges
  );
  /**
   * @param {{ num: number, unit: string }} a
   * @param {{ num: number, unit: string }} b
   */
  const collapsed = (a, b) =>
    a.unit === b.unit && Math.abs(a.num - b.num) < NEAR_ZERO_EPSILON;
  return collapsed(left, right) || collapsed(top, bottom);
}

/**
 * @param {(key: string) => any} nodeOf value node for a property, or null
 * @param {(key: string) => string} textOf decoded/lowercased text for a property
 * @returns {boolean}
 */
function isPositionedOffscreen(nodeOf, textOf) {
  const position = textOf("position");
  // `relative`/`sticky` shift the rendered box off its normal spot just like
  // `absolute`/`fixed` do, so a `left:-9999px` on any of them pushes the text
  // off any viewport. `static` ignores offsets and is excluded.
  if (!/\babsolute\b|\bfixed\b|\brelative\b|\bsticky\b/.test(position))
    return false;
  for (const side of ["left", "top", "right", "bottom"])
    if (isOffscreenOffset(nodeOf(side))) return true;
  // The legacy `clip` property only clips ABSOLUTELY-positioned boxes
  // (absolute/fixed); a relative/sticky element ignores it, so reading its
  // rect() as a hide there would splice visible text (fail open).
  if (!/\babsolute\b|\bfixed\b/.test(position)) return false;
  return isClipRectHidden(nodeOf("clip"));
}

// The full CSS named-color set canonicalized to `#rrggbb`, so any two identical
// resolvable named colors (`color:blue;background:blue`) — not just the handful
// that back white-on-white text — compare equal for the same-color hide test.
// `transparent` maps to itself (the sentinel isConcreteColor also accepts).
// var()/inherit/currentColor are deliberately absent: they resolve via the
// cascade and must fail OPEN, handled by isConcreteColor at the compare.
/** @type {Record<string, string>} */
// Stryker disable all — static CSS color data table (147 canonical name→hex
// entries). Mutating each hex/name literal yields hundreds of low-value,
// largely-equivalent mutants (no test can meaningfully pin every color) that
// balloon the html shard past its CI timeout. The canonicalization LOGIC that
// consumes this table stays under mutation. Same idiom as the Unicode data
// tables in standardized-variants.mjs/joining-type.mjs/cf-charset.mjs.
const NAMED_COLORS = {
  aliceblue: "#f0f8ff",
  antiquewhite: "#faebd7",
  aqua: "#00ffff",
  aquamarine: "#7fffd4",
  azure: "#f0ffff",
  beige: "#f5f5dc",
  bisque: "#ffe4c4",
  black: "#000000",
  blanchedalmond: "#ffebcd",
  blue: "#0000ff",
  blueviolet: "#8a2be2",
  brown: "#a52a2a",
  burlywood: "#deb887",
  cadetblue: "#5f9ea0",
  chartreuse: "#7fff00",
  chocolate: "#d2691e",
  coral: "#ff7f50",
  cornflowerblue: "#6495ed",
  cornsilk: "#fff8dc",
  crimson: "#dc143c",
  cyan: "#00ffff",
  darkblue: "#00008b",
  darkcyan: "#008b8b",
  darkgoldenrod: "#b8860b",
  darkgray: "#a9a9a9",
  darkgreen: "#006400",
  darkgrey: "#a9a9a9",
  darkkhaki: "#bdb76b",
  darkmagenta: "#8b008b",
  darkolivegreen: "#556b2f",
  darkorange: "#ff8c00",
  darkorchid: "#9932cc",
  darkred: "#8b0000",
  darksalmon: "#e9967a",
  darkseagreen: "#8fbc8f",
  darkslateblue: "#483d8b",
  darkslategray: "#2f4f4f",
  darkslategrey: "#2f4f4f",
  darkturquoise: "#00ced1",
  darkviolet: "#9400d3",
  deeppink: "#ff1493",
  deepskyblue: "#00bfff",
  dimgray: "#696969",
  dimgrey: "#696969",
  dodgerblue: "#1e90ff",
  firebrick: "#b22222",
  floralwhite: "#fffaf0",
  forestgreen: "#228b22",
  fuchsia: "#ff00ff",
  gainsboro: "#dcdcdc",
  ghostwhite: "#f8f8ff",
  gold: "#ffd700",
  goldenrod: "#daa520",
  gray: "#808080",
  green: "#008000",
  greenyellow: "#adff2f",
  grey: "#808080",
  honeydew: "#f0fff0",
  hotpink: "#ff69b4",
  indianred: "#cd5c5c",
  indigo: "#4b0082",
  ivory: "#fffff0",
  khaki: "#f0e68c",
  lavender: "#e6e6fa",
  lavenderblush: "#fff0f5",
  lawngreen: "#7cfc00",
  lemonchiffon: "#fffacd",
  lightblue: "#add8e6",
  lightcoral: "#f08080",
  lightcyan: "#e0ffff",
  lightgoldenrodyellow: "#fafad2",
  lightgray: "#d3d3d3",
  lightgreen: "#90ee90",
  lightgrey: "#d3d3d3",
  lightpink: "#ffb6c1",
  lightsalmon: "#ffa07a",
  lightseagreen: "#20b2aa",
  lightskyblue: "#87cefa",
  lightslategray: "#778899",
  lightslategrey: "#778899",
  lightsteelblue: "#b0c4de",
  lightyellow: "#ffffe0",
  lime: "#00ff00",
  limegreen: "#32cd32",
  linen: "#faf0e6",
  magenta: "#ff00ff",
  maroon: "#800000",
  mediumaquamarine: "#66cdaa",
  mediumblue: "#0000cd",
  mediumorchid: "#ba55d3",
  mediumpurple: "#9370db",
  mediumseagreen: "#3cb371",
  mediumslateblue: "#7b68ee",
  mediumspringgreen: "#00fa9a",
  mediumturquoise: "#48d1cc",
  mediumvioletred: "#c71585",
  midnightblue: "#191970",
  mintcream: "#f5fffa",
  mistyrose: "#ffe4e1",
  moccasin: "#ffe4b5",
  navajowhite: "#ffdead",
  navy: "#000080",
  oldlace: "#fdf5e6",
  olive: "#808000",
  olivedrab: "#6b8e23",
  orange: "#ffa500",
  orangered: "#ff4500",
  orchid: "#da70d6",
  palegoldenrod: "#eee8aa",
  palegreen: "#98fb98",
  paleturquoise: "#afeeee",
  palevioletred: "#db7093",
  papayawhip: "#ffefd5",
  peachpuff: "#ffdab9",
  peru: "#cd853f",
  pink: "#ffc0cb",
  plum: "#dda0dd",
  powderblue: "#b0e0e6",
  purple: "#800080",
  rebeccapurple: "#663399",
  red: "#ff0000",
  rosybrown: "#bc8f8f",
  royalblue: "#4169e1",
  saddlebrown: "#8b4513",
  salmon: "#fa8072",
  sandybrown: "#f4a460",
  seagreen: "#2e8b57",
  seashell: "#fff5ee",
  sienna: "#a0522d",
  silver: "#c0c0c0",
  skyblue: "#87ceeb",
  slateblue: "#6a5acd",
  slategray: "#708090",
  slategrey: "#708090",
  snow: "#fffafa",
  springgreen: "#00ff7f",
  steelblue: "#4682b4",
  tan: "#d2b48c",
  teal: "#008080",
  thistle: "#d8bfd8",
  tomato: "#ff6347",
  transparent: "transparent",
  turquoise: "#40e0d0",
  violet: "#ee82ee",
  wheat: "#f5deb3",
  white: "#ffffff",
  whitesmoke: "#f5f5f5",
  yellow: "#ffff00",
  yellowgreen: "#9acd32",
};
// Stryker restore all

/**
 * True when a canonicalized color is a concrete value we can compare for
 * equality — a resolved `#rrggbb` hex or `transparent`. `var(--x)`/`inherit`/
 * `currentColor` canonicalize to their raw token and are NOT concrete: their
 * effective color depends on the cascade, so a same-color hide can't be proven.
 * @param {string} canonical
 * @returns {boolean}
 */
function isConcreteColor(canonical) {
  return canonical === "transparent" || /^#[0-9a-f]{6}$/.test(canonical);
}

/** @param {number} n @returns {string} clamped two-hex-digit byte */
function hexByte(n) {
  return Math.max(0, Math.min(255, Math.round(n)))
    .toString(16)
    .padStart(2, "0");
}

/**
 * Parse one rgb() channel: an integer/number `0..255` (clamped, as a browser
 * clamps out-of-range) or a percentage `0%..100%` scaled to `0..255`. Returns
 * null (fail open) on any other shape — a `none`/`calc()`/negative channel we
 * cannot resolve to a concrete byte.
 * @param {string} token
 * @returns {number | null}
 */
function rgbChannel(token) {
  const pct = token.match(/^\+?(\d*\.?\d+)%$/);
  if (pct) return (Math.min(100, parseFloat(pct[1])) / 100) * 255;
  const num = token.match(/^\+?(\d*\.?\d+)$/);
  if (num) return parseFloat(num[1]);
  return null;
}

/**
 * Parse an hsl() hue as degrees (a `<number>` or an `<angle>` in
 * deg/grad/rad/turn), normalized to `[0,360)`. Returns null on anything else.
 * @param {string} token
 * @returns {number | null}
 */
function hueDegrees(token) {
  const match = token.match(/^([+-]?\d*\.?\d+)(deg|grad|rad|turn)?$/);
  if (!match) return null;
  const value = parseFloat(match[1]);
  const unit = match[2] || "deg";
  const deg =
    unit === "grad"
      ? (value * 360) / 400
      : unit === "rad"
        ? (value * 180) / Math.PI
        : unit === "turn"
          ? value * 360
          : value;
  return ((deg % 360) + 360) % 360;
}

/**
 * Parse an hsl() saturation/lightness: a percentage or (CSS Color 4) a bare
 * number, both read as `0..100` (clamped high). Returns null on any other shape.
 * @param {string} token
 * @returns {number | null}
 */
function hslPercent(token) {
  const match = token.match(/^\+?(\d*\.?\d+)%?$/);
  return match ? Math.min(100, parseFloat(match[1])) : null;
}

/**
 * Convert HSL (`h` in degrees, `s`/`l` in `0..100`) to lowercase `#rrggbb`.
 * @param {number} h @param {number} s @param {number} l @returns {string}
 */
function hslToHex(h, s, l) {
  const sat = s / 100;
  const light = l / 100;
  const c = (1 - Math.abs(2 * light - 1)) * sat;
  const hp = h / 60;
  const x = c * (1 - Math.abs((hp % 2) - 1));
  const [r, g, b] =
    hp < 1
      ? [c, x, 0]
      : hp < 2
        ? [x, c, 0]
        : hp < 3
          ? [0, c, x]
          : hp < 4
            ? [0, x, c]
            : hp < 5
              ? [x, 0, c]
              : [c, 0, x];
  const m = light - c / 2;
  return `#${hexByte((r + m) * 255)}${hexByte((g + m) * 255)}${hexByte((b + m) * 255)}`;
}

/**
 * Resolve an `rgb()/rgba()/hsl()/hsla()` function to `#rrggbb`, or
 * `"transparent"` when its alpha channel is a literal zero (fully transparent
 * text is invisible), or null when any component is unresolvable (fail open).
 * Accepts the legacy comma form and the CSS Color 4 space/`/`-alpha form
 * (`rgb(255 255 255 / 0.5)`, `hsl(0 0% 100%)`) and percentage channels.
 * @param {string} value  lowercased, trimmed
 * @returns {string | null}
 */
function canonicalizeColorFunction(value) {
  const outer = value.match(/^(rgba?|hsla?)\(([^()]*)\)$/);
  if (!outer) return null;
  const isRgb = outer[1].startsWith("rgb");
  let inner = outer[2].trim();
  // Split the CSS Color 4 `<color> / <alpha>` form; a literal-zero alpha is
  // fully transparent regardless of the color channels.
  const slash = inner.split("/");
  if (slash.length > 2) return null;
  let alpha = slash.length === 2 ? slash[1].trim() : null;
  if (slash.length === 2) inner = slash[0].trim();
  const parts = inner.split(/[\s,]+/).filter(Boolean);
  // The legacy comma form carries alpha as a 4th channel.
  if (alpha === null && parts.length === 4) {
    alpha = parts[3];
    parts.length = 3;
  }
  // A literal-zero alpha is fully transparent — bare number (`0`, `0.0`) or the
  // CSS Color 4 percentage form (`0%`), which a browser also renders invisible.
  if (alpha !== null && /^\+?0*\.?0+%?$/.test(alpha)) return "transparent";
  if (parts.length !== 3) return null;
  if (isRgb) {
    const channels = parts.map(rgbChannel);
    if (channels.some((c) => c === null)) return null;
    return `#${channels.map((c) => hexByte(/** @type {number} */ (c))).join("")}`;
  }
  const h = hueDegrees(parts[0]);
  const s = hslPercent(parts[1]);
  const l = hslPercent(parts[2]);
  if (h === null || s === null || l === null) return null;
  return hslToHex(h, s, l);
}

/**
 * Canonicalize a CSS color to lowercase `#rrggbb` so `white`, `#FFF`,
 * `#ffffff`, `rgb(255, 255, 255)`, `rgb(255 255 255)`, `rgb(100% 100% 100%)`,
 * and `hsl(0 0% 100%)` all compare equal. Returns the trimmed lowercased input
 * unchanged when it is not a form we recognize; callers gate the same-color
 * compare on isConcreteColor so an unresolved token (`var()`, `inherit`) never
 * falsely reads as a same-color hide.
 * @param {string} raw
 * @returns {string}
 */
function canonicalizeColor(raw) {
  const value = raw.trim().toLowerCase();
  if (!value) return "";
  // Own-key only: `in` would match inherited members, so a CSS value of
  // `__proto__`/`constructor`/`toString` returns an object or function here
  // (poisoning isHiddenStyle's return) instead of falling through as a plain
  // string.
  if (Object.hasOwn(NAMED_COLORS, value)) return NAMED_COLORS[value];
  const shortHex = value.match(/^#([0-9a-f])([0-9a-f])([0-9a-f])$/);
  if (shortHex)
    return `#${shortHex[1]}${shortHex[1]}${shortHex[2]}${shortHex[2]}${shortHex[3]}${shortHex[3]}`;
  if (/^#[0-9a-f]{6}$/.test(value)) return value;
  return canonicalizeColorFunction(value) ?? value;
}

// The leading color token of a `background` shorthand (the first token that
// canonicalizes to a real color), so `background:#fff` still compares. Returns
// "" (fail open, no same-color hide) when the shorthand carries an IMAGE layer
// — `url(...)`, a gradient, or `image-set(...)`: the painted image can make
// same-colored text perfectly readable over it (and if it fails to load the
// element's own background shows through), so the flat color token is not
// provably the rendered backdrop.
/** @param {string} shorthand @returns {string} */
function backgroundColor(shorthand) {
  if (/\burl\(|gradient\(|image-set\(/i.test(shorthand)) return "";
  for (const token of shorthand.split(/\s+/)) {
    const color = canonicalizeColor(token);
    if (color && (color.startsWith("#") || color === "transparent"))
      return color;
  }
  return "";
}

// One resolved `inset()` edge collapses the box only when it is a percentage of
// at least 50%: opposing edges (top/bottom, left/right) then sum to >=100% and
// leave zero area. A length (`inset(200px)`), `calc()`, or `0` cannot be proven
// to collapse without the box size, so it fails open (not collapsing).
/** @param {any} edge value token @returns {boolean} */
function isCollapsingInsetEdge(edge) {
  return edge.type === "Percentage" && parseFloat(edge.value) >= 50;
}

// Expand an `inset()`'s 1–4 edge tokens to `[top, right, bottom, left]` using
// the CSS margin-style shorthand rules.
/** @param {any[]} parts @returns {any[]} */
function expandInsetEdges(parts) {
  const [t, r = t, b = t, l = r] = parts;
  return [t, r, b, l];
}

// The edge tokens of an `inset()`, stopping at a `round <border-radius>` suffix.
/** @param {any} fn `inset` Function node @returns {any[]} */
function insetEdges(fn) {
  /** @type {any[]} */
  const edges = [];
  for (const token of valueTokens(fn)) {
    if (token.type === "Identifier" && token.name.toLowerCase() === "round")
      break;
    edges.push(token);
  }
  return edges;
}

/**
 * True when a `clip-path` clips the element to nothing: `circle(0)` (zero
 * radius, in any unit), or an `inset()` whose FOUR resolved edges ALL collapse
 * (each a percentage >=50%). A partial inset that leaves any edge open
 * (`inset(50% 0 0 0)` — bottom half visible) is NOT hidden: inspecting only the
 * first value would over-splice it. Decorative clips (`circle(50%)`, small
 * insets, polygons) render content and are left alone.
 * @param {any} node value node for `clip-path`
 * @returns {boolean}
 */
function isClipPathHidden(node) {
  if (!node) return false;
  for (const fn of valueTokens(node)) {
    if (fn.type !== "Function") continue;
    const name = fn.name.toLowerCase();
    if (name === "circle") {
      const radius = valueTokens(fn)[0];
      if (
        radius &&
        (radius.type === "Number" ||
          radius.type === "Dimension" ||
          radius.type === "Percentage") &&
        parseFloat(radius.value) === 0
      )
        return true;
    } else if (name === "inset") {
      const edges = insetEdges(fn);
      if (
        edges.length >= 1 &&
        edges.length <= 4 &&
        expandInsetEdges(edges).every(isCollapsingInsetEdge)
      )
        return true;
    }
  }
  return false;
}

// The color painted by `-webkit-text-stroke` (the `<color>` token of the
// shorthand, or the `-webkit-text-stroke-color` longhand), canonicalized — or
// "" when it does not resolve to a concrete color. The longhand is a whole
// color value so canonicalizeColor handles it directly; the shorthand is
// `<line-width> || <color>`, so the width token (a length) is skipped and the
// remaining color token canonicalized.
/** @param {(key: string) => string} val @returns {string} */
function textStrokeColor(val) {
  const longhand = canonicalizeColor(val("-webkit-text-stroke-color"));
  if (isConcreteColor(longhand)) return longhand;
  for (const token of val("-webkit-text-stroke").split(/\s+/).filter(Boolean)) {
    const color = canonicalizeColor(token);
    if (isConcreteColor(color)) return color;
  }
  return "";
}

// Gradient-clipped / outlined headings are VISIBLE despite an effectively
// transparent fill: `background-clip:text` (or its `-webkit-` alias) paints the
// background through the glyph shapes, and `-webkit-text-stroke` paints a visible
// outline around the (transparent-filled) glyphs. Either means the transparent
// paint is not the whole story, so the same-`transparent` hide must fail open.
// A concrete `-webkit-text-fill-color` is NOT checked here: the caller resolves
// the EFFECTIVE fill (fill override ?? color) before this runs, so a concrete
// fill already keeps `effectiveColor` non-transparent and never reaches here.
/** @param {(key: string) => string} val @returns {boolean} */
function isTextPaintedVisible(val) {
  if (
    val("background-clip") === "text" ||
    val("-webkit-background-clip") === "text"
  )
    return true;
  const stroke = textStrokeColor(val);
  return isConcreteColor(stroke) && stroke !== "transparent";
}

// True when the element paints a background IMAGE layer — a `background-image`
// longhand set to anything but `none`, or a `background` shorthand carrying
// `url(...)`, a gradient, or `image-set(...)`. A same-color text/background hide
// CANNOT be proven when an image layer is present: the painted image can make
// same-colored text readable, and if it fails to load the element's own
// background shows through. Centralized so EVERY hide branch consults one
// image-layer check — the `background` shorthand path already failed open via
// {@link backgroundColor}, but the `background-color` longhand path inspected
// only the flat color and missed a co-declared `background-image`, splicing
// visible text. `background-clip:text` is NOT an image layer here — it paints
// the background THROUGH the glyphs and is handled by {@link isTextPaintedVisible}.
/** @param {(key: string) => string} textOf @returns {boolean} */
function hasImageLayer(textOf) {
  const img = textOf("background-image");
  if (img && img !== "none") return true;
  return /\burl\(|gradient\(|image-set\(/i.test(textOf("background"));
}

/**
 * @param {(key: string) => any} nodeOf value node for a property, or null
 * @param {(key: string) => string} textOf decoded/lowercased text for a property
 * @returns {boolean}
 */
function isOverflowHidden(nodeOf, textOf) {
  if (textOf("overflow") !== "hidden") return false;
  for (const dim of ["height", "width", "max-height", "max-width"])
    // Near-zero (epsilon band), not exact 0, so `height:0.0001px` still counts —
    // matching the standalone size checks a browser renders as invisible.
    if (isNearZeroLength(nodeOf(dim))) return true;
  return false;
}

// The length units that denote a font-size in a `font` SHORTHAND. Only a length
// with one of these units is a size (a bare number there is a weight, a `%` a
// stretch), so those never misread as a zero size. `q` (quarter-mm) is a font
// length unit too, though it never gates an offset above.
const FONT_SIZE_UNITS = new Set([...ABSOLUTE_UNITS, "q"]);

/**
 * True when a `font` SHORTHAND's font-size collapses the text to nothing. The
 * font-size is the FIRST length token in the shorthand (it precedes an optional
 * `/line-height` and the family); a near-zero one hides the text just like the
 * `font-size` longhand.
 * @param {any} node value node for `font`
 * @returns {boolean}
 */
function isFontShorthandHidden(node) {
  if (!node) return false;
  for (const token of valueTokens(node))
    if (token.type === "Dimension" && FONT_SIZE_UNITS.has(token.unit))
      return Math.abs(parseFloat(token.value)) < NEAR_ZERO_EPSILON;
  return false;
}

// A CSS property-name ident AFTER escape decoding: up to two leading hyphens
// (vendor prefix / custom property), then a letter or underscore, then letters,
// digits, hyphens, or underscores. css-tree will accept an escaped ident as a
// declaration property (e.g. `\3a` decoding to `:`); this gate rejects anything
// a real browser's ident tokenizer would reject so a decoded non-ident property
// never drives a hidden verdict.
const CSS_PROPERTY_IDENT_RE = /^-{0,2}[A-Za-z_][A-Za-z0-9_-]*$/;

/**
 * Reconstruct a declaration's decoded value as a string for keyword/color
 * comparisons. Identifier tokens are escape-decoded through css-tree's ident
 * decoder (so `no\6e e`/`hi\64 den` read as `none`/`hidden`, with FF/CR/CRLF
 * terminators and invalid codepoints handled per the CSS spec); every other
 * token is re-serialized. A whole-value `Raw` (an unparsed value) is returned
 * verbatim — it never matches a hiding keyword, so it fails open.
 * @param {any} valueNode
 * @returns {string}
 */
function declText(valueNode) {
  if (!valueNode) return "";
  if (valueNode.type === "Raw") return valueNode.value;
  /** @type {string[]} */
  const parts = [];
  if (valueNode.children)
    valueNode.children.forEach((/** @type {any} */ child) =>
      parts.push(
        child.type === "Identifier"
          ? csstree.ident.decode(child.name)
          : csstree.generate(child),
      ),
    );
  return parts.join(" ");
}

/**
 * Parse a style string into a map of decoded lowercase property name -> parsed
 * value node, via css-tree's tolerant declaration-list parser. This replaces the
 * hand-rolled declaration splitter, per-declaration salvage, escape decoder, and
 * `!important` stripper in one pass: css-tree recovers per-declaration exactly
 * as a browser does (a bogus declaration is dropped, the rest kept), keeps a `;`
 * inside a string/`url()`/paren as part of the value, and exposes `!important`
 * as `node.important` (so an escaped spelling `none!\69mportant` is stripped for
 * free). Property names are escape-decoded and gated to real CSS idents;
 * anything else is dropped (fail open). Later declarations win, per the cascade.
 * @param {string} styleStr
 * @returns {Map<string, any>}
 */
function parseDeclarations(styleStr) {
  /** @type {Map<string, any>} */
  const decls = new Map();
  let ast;
  try {
    ast = csstree.parse(styleStr, {
      context: "declarationList",
      parseValue: true,
      parseCustomProperty: false,
      onParseError() {},
    });
    /* c8 ignore start -- the only reachable throw path is a non-string / deeply
       pathological input (css-tree's onParseError recovers ordinary bad CSS);
       this fail-open upholds the module's never-throws contract for those. */
  } catch {
    return decls;
  }
  /* c8 ignore stop */
  csstree.walk(ast, {
    visit: "Declaration",
    enter(/** @type {any} */ node) {
      // ident.decode is pure string iteration and cannot throw on a real ident
      // token; property is escape-decoded then gated to a clean CSS ident.
      const property = csstree.ident.decode(node.property).trim().toLowerCase();
      if (!CSS_PROPERTY_IDENT_RE.test(property)) return;
      decls.set(property, node.value);
    },
  });
  return decls;
}

/**
 * @param {string} styleStr
 * @returns {boolean}
 */
export function isHiddenStyle(styleStr) {
  const decls = parseDeclarations(styleStr);
  if (decls.size === 0) return false;

  /** @param {string} key */
  const nodeOf = (key) => decls.get(key) ?? null;
  // `!important` is already excluded by css-tree; escapes are decoded in
  // declText. Trim/lowercase for the case-insensitive keyword compares.
  /** @param {string} key */
  const textOf = (key) => declText(decls.get(key)).trim().toLowerCase();

  if (textOf("display") === "none") return true;
  if (textOf("visibility") === "hidden" || textOf("visibility") === "collapse")
    return true;
  // `content-visibility:hidden` skips rendering the element's contents entirely
  // (not even laid out), so the text is invisible to a human but present in the
  // source. `auto`/`visible` keep it rendered and must not match.
  if (textOf("content-visibility") === "hidden") return true;

  // CSS clamps opacity to [0,1], so any NEGATIVE value renders fully
  // transparent — `< EPSILON` (no `Math.abs`) treats `-1`/`-0.5` as hidden.
  // `opacity` is a <number> or <percentage>; any other token (`0px`, a bare
  // Dimension) is an INVALID declaration a browser ignores (element stays
  // visible), so fail open on anything that isn't a single Number/Percentage.
  const opacity = soleToken(nodeOf("opacity"));
  if (opacity) {
    let fraction = null;
    if (opacity.type === "Number") fraction = parseFloat(opacity.value);
    else if (opacity.type === "Percentage")
      fraction = parseFloat(opacity.value) / 100;
    if (fraction !== null && fraction < NEAR_ZERO_EPSILON) return true;
  }

  // `height`/`width` are deliberately NOT tested standalone here: with the
  // default `overflow:visible`, a zero-sized box still paints its overflowing
  // children, so a bare `width:0`/`height:0` leaves content on screen.
  // `isOverflowHidden` below already covers the case where a zero dimension
  // DOES hide content — gated on `overflow:hidden` also being present.
  // `font-size:0`, in contrast, reliably collapses text to nothing on its own.
  if (isNearZeroLength(nodeOf("font-size"))) return true;
  // The `font` shorthand also carries the font-size, so a `font:0px/1 serif`
  // collapses text just like the longhand — check its size token too.
  if (isFontShorthandHidden(nodeOf("font"))) return true;

  if (isPositionedOffscreen(nodeOf, textOf)) return true;

  if (isOffscreenOffset(nodeOf("text-indent"))) return true;

  // Clipped to nothing: the modern equivalent of the legacy `clip: rect(0…)`.
  if (isClipPathHidden(nodeOf("clip-path"))) return true;
  if (isHidingTransform(nodeOf("transform"))) return true;
  if (isHidingFilter(nodeOf("filter"))) return true;

  // Same-color text on its background (white-on-white) and fully transparent
  // text are invisible to a human but plain text to the model. Colors are
  // canonicalized so `white`/`#fff`/`rgb(255,255,255)` mixes still compare.
  // The color actually PAINTED onto the glyphs: `-webkit-text-fill-color`
  // overrides `color` for the fill when it is concrete, so both hide branches
  // must reason about this effective fill, not the raw `color` property — else a
  // `color:#fff;-webkit-text-fill-color:#000` element (black text) is compared as
  // white and spliced white-on-white.
  const color = canonicalizeColor(textOf("color"));
  const fillOverride = canonicalizeColor(textOf("-webkit-text-fill-color"));
  const effectiveColor = isConcreteColor(fillOverride) ? fillOverride : color;
  // `color:transparent` (or a transparent fill override) hides text — UNLESS the
  // glyphs are painted by a background-clip:text gradient, a concrete
  // -webkit-text-fill-color, or a text stroke, in which case the text is visible.
  if (effectiveColor === "transparent" && !isTextPaintedVisible(textOf))
    return true;
  const background =
    canonicalizeColor(textOf("background-color")) ||
    backgroundColor(textOf("background"));
  // Only flag same-color when BOTH sides resolve to a concrete color (`#rrggbb`
  // or `transparent`), AND no background IMAGE layer is present (an image can
  // make same-colored text readable). `var(--x)`, `inherit`, and `currentColor`
  // canonicalize to their raw token, so two identical unresolved tokens (e.g. the
  // ubiquitous `color:var(--fg);background:var(--fg)`, which resolve to DIFFERENT
  // effective colors) would otherwise read as hidden and splice out visible text.
  // Fail open on anything we can't resolve.
  if (
    effectiveColor &&
    effectiveColor === background &&
    isConcreteColor(effectiveColor) &&
    !hasImageLayer(textOf)
  )
    return true;

  return isOverflowHidden(nodeOf, textOf);
}

// Scripting / resource-loading tags whose PRESENCE is reported to the model
// but whose content is preserved: their bodies are page source the model may
// legitimately need to inspect (how a page's scripts work, its styles, its
// SVGs), so unlike hidden elements they are never removed.
export const REPORTED_TAGS = new Set([
  "script",
  "style",
  "object",
  "embed",
  "iframe",
  "svg",
  "math",
]);

// HTML void elements: they never carry content and never emit a closing tag, so
// a hidden one (<img hidden>, <input hidden>, …) must be spliced as a single node
// — opening a balance region for it would run to the container's end (no close
// ever arrives) and delete the visible text that follows.
const VOID_ELEMENTS = new Set([
  "area",
  "base",
  "br",
  "col",
  "embed",
  "hr",
  "img",
  "input",
  "link",
  "meta",
  "param",
  "source",
  "track",
  "wbr",
]);

// Foreign-content roots. Inside SVG and MathML the HTML parser honours a
// self-closing `/>` (it does not in HTML content), so such a tag opens and
// closes in one node and the text after it is a sibling, not its child.
const FOREIGN_ELEMENTS = new Set(["svg", "math"]);

/**
 * True when `value` is a foreign-content tag that closed itself. Splicing it as
 * a balance region instead would run to the container's end and delete every
 * visible word after a decorative hidden `<svg/>`.
 * @param {string} tagName
 * @param {string} value
 * @returns {boolean}
 */
function isSelfClosedForeign(tagName, value) {
  return FOREIGN_ELEMENTS.has(tagName) && /\/\s*>\s*$/.test(value);
}

// Elements whose content is RAW TEXT / RCDATA / script data: parse5 recognizes
// NO markup inside them (a `<!…` is not a comment, a `<b>` is not a tag) until
// the matching end tag. The per-tag balance walk must model this or it would
// splice a `<!…>` inside `<style>`/`<script>` as a bogus comment — mangling
// source these tags are meant to preserve verbatim (and diverging from the
// flow/source branch, which parse5 handles correctly). `noscript` is omitted:
// under fragment parsing (scripting disabled) parse5 parses its content as
// normal markup, so scanning it is correct. Once `plaintext` opens it runs to
// EOF and never closes.
const RAW_TEXT_ELEMENTS = new Set([
  "script",
  "style",
  "textarea",
  "title",
  "xmp",
  "iframe",
  "noembed",
  "noframes",
  "plaintext",
]);

/**
 * True for an element a rendered page would not show: `hidden` attribute or a
 * hiding inline style. Works on both hast nodes and parseHtmlTag results.
 * @param {any} node
 * @returns {boolean}
 */
export function isHiddenElement(node) {
  if (node.type !== "element") return false;
  const { properties = {} } = node;
  if (properties.hidden !== undefined && properties.hidden !== null)
    return true;
  // `aria-hidden="true"` is deliberately NOT treated as a hiding signal: it
  // removes the element only from the ACCESSIBILITY TREE, not the rendered
  // page — a sighted human viewing the page still sees it (it's routinely
  // used on decorative icons and icon-font glyphs, and on visible text
  // duplicated for screen-reader dedup). Splicing on it would delete content
  // a human plainly sees, which is real harm under the precision-over-recall
  // doctrine for this layer.
  if (properties.style && isHiddenStyle(properties.style)) return true;
  return false;
}

/** @param {any} el */
function hasDataSrc(el) {
  return (
    typeof el.properties?.src === "string" &&
    el.properties.src.startsWith("data:")
  );
}

/**
 * @param {string} htmlValue
 * @returns {any}
 */
function parseHtmlTag(htmlValue) {
  const tree = unified().use(rehypeParse, { fragment: true }).parse(htmlValue);
  /** @type {any} */
  let firstElement = null;
  visit(tree, "element", (node) => {
    firstElement = node;
    return EXIT;
  });
  return firstElement;
}

// Returns null on a closing tag: `</x>` alone can never be the *start* of a
// hidden element, so only opens drive the surrounding loop's removal mode.
/**
 * @param {string} htmlValue
 * @returns {string | null}
 */
export function isHiddenOpen(htmlValue) {
  if (htmlValue.startsWith("</")) return null;
  const el = parseHtmlTag(htmlValue);
  if (!el) return null;
  if (isHiddenElement(el)) return el.tagName;
  return null;
}

// The lowercased name of an HTML closing tag (`</div>` -> "div"), or null when
// the value isn't a well-formed closing tag. The charset spans HTML custom-
// element and namespaced names (hyphens, dots, colons) so a close like
// `</foo-bar>` balances its matching open instead of throwing on a null match;
// callers treat null as "not the tag we're closing" and strip it as part of the
// surrounding removal region.
/**
 * @param {string} htmlValue
 * @returns {string | null}
 */
export function closingTagName(htmlValue) {
  // The charset is a superset of CommonMark's closing-tag grammar, so remark
  // never emits a `</…>` html node this fails to match; the null guard below is
  // defense-in-depth against a future parser/grammar change (hence unreachable).
  const match = htmlValue.match(/^<\/(?<tagName>[a-zA-Z][a-zA-Z0-9:._-]*)\s*>/);
  /* c8 ignore next */
  if (!match?.groups) return null;
  return match.groups.tagName.toLowerCase();
}

// ─── Layer 2: splice engine ──────────────────────────────────────────────────

export const COMMENT_PLACEHOLDER = "[HTML comment removed]";
export const HIDDEN_PLACEHOLDER = "[hidden HTML removed]";
// Shown when the remark/rehype parse itself fails (e.g. pathologically nested
// markup overflows the recursive tree walk with a RangeError). The top-level
// `sanitize`/`sanitizeText` contract is "never throws, `cleaned` is always a
// string", and this module is the only seam those callers own — so the HTML
// layer must fail CLOSED here: withhold the whole unparseable input behind one
// placeholder rather than let the exception escape and suppress all tool
// output. Withholding (not passing through) is the safe choice — content we
// could not inspect for hidden payloads is treated as if it were hidden.
export const UNPARSEABLE_PLACEHOLDER = "[HTML unparseable — withheld]";

/**
 * Replace each range of `text` with its kind's placeholder, preserving every
 * byte outside the ranges verbatim. Overlapping/nested ranges are merged
 * (defense-in-depth — the scanners emit disjoint ranges).
 * @param {string} text
 * @param {Array<{start: number, end: number, kind: "comment" | "hidden"}>} ranges
 * @returns {string}
 */
export function spliceRanges(text, ranges) {
  const sorted = [...ranges].sort(
    (left, right) => left.start - right.start || left.end - right.end,
  );
  /** @type {typeof ranges} */
  const merged = [];
  for (const range of sorted) {
    const last = merged[merged.length - 1];
    if (last && range.start < last.end) {
      if (range.end > last.end) last.end = range.end;
      // A hidden range absorbed into a comment range (the comment sorts first
      // on a tie) must keep the hidden label — hidden content placeholdered as
      // "[HTML comment removed]" would understate what was stripped. Hidden
      // dominates: if either side is hidden, the union is hidden.
      if (range.kind === "hidden") last.kind = "hidden";
    } else {
      merged.push({ ...range });
    }
  }
  let out = "";
  let cursor = 0;
  for (const range of merged) {
    out +=
      text.slice(cursor, range.start) +
      (range.kind === "comment" ? COMMENT_PLACEHOLDER : HIDDEN_PLACEHOLDER);
    cursor = range.end;
  }
  return out + text.slice(cursor);
}

/** @returns {{ tags: Record<string, number>, dataSrc: number }} */
function newWarned() {
  return { tags: {}, dataSrc: 0 };
}

/**
 * @param {ReturnType<typeof newWarned>} warned
 * @param {string} tagName
 */
function countTag(warned, tagName) {
  warned.tags[tagName] = (warned.tags[tagName] || 0) + 1;
}

/**
 * @param {ReturnType<typeof newWarned>} into
 * @param {ReturnType<typeof newWarned>} from
 */
function mergeWarned(into, from) {
  for (const [tag, count] of Object.entries(from.tags))
    into.tags[tag] = (into.tags[tag] || 0) + count;
  into.dataSrc += from.dataSrc;
}

/** @param {ReturnType<typeof newWarned>} warned */
function hasWarned(warned) {
  return warned.dataSrc > 0 || Object.keys(warned.tags).length > 0;
}

/**
 * Scan raw HTML for hidden content to strip and preserved tags to report.
 * Returned ranges are offsets into `html`; comments and hidden elements span
 * the whole element including its content (rehype positions cover open tag
 * through matching close, and parse5 extends an unclosed element to the end
 * of the fragment — fail-closed for truncated markup).
 * @param {string} html
 * @returns {{ ranges: Array<{start: number, end: number, kind: "comment" | "hidden"}>, warned: ReturnType<typeof newWarned> }}
 */
export function scanHtmlFragment(html) {
  const tree = unified().use(rehypeParse, { fragment: true }).parse(html);
  /** @type {Array<{start: number, end: number, kind: "comment" | "hidden"}>} */
  const ranges = [];
  const warned = newWarned();
  // @ts-ignore -- visit callback returns EXIT/SKIP only on matches; implicit undefined return is intentional
  // eslint-disable-next-line consistent-return
  visit(tree, (/** @type {any} */ node) => {
    const isComment = node.type === "comment";
    if (isComment || isHiddenElement(node)) {
      /* c8 ignore start -- parse5 omits positions only on recovery-synthesized
         elements (tbody and friends), which carry no attributes and so can
         never be hidden; fail closed on the whole fragment if that assumption
         ever breaks. */
      if (!node.position) {
        ranges.length = 0;
        ranges.push({ start: 0, end: html.length, kind: "hidden" });
        return EXIT;
      }
      /* c8 ignore stop */
      ranges.push({
        start: node.position.start.offset,
        end: node.position.end.offset,
        kind: isComment ? "comment" : "hidden",
      });
      return SKIP; // children are inside the spliced range
    }
    if (node.type !== "element") return; // eslint-disable-line consistent-return -- unist visit: undefined return means "continue", same as falling off the end
    if (REPORTED_TAGS.has(node.tagName)) countTag(warned, node.tagName);
    if (hasDataSrc(node)) warned.dataSrc += 1;
  });
  return { ranges, warned };
}

const mdParser = unified().use(remarkParse).use(remarkGfm);

// A markup-declaration-open (`<!`) or processing-instruction-ish (`<?`) start.
// Inside an inline html node these begin a *bogus comment* unless they open a
// proper `<!--…-->` comment (handled on the fast path) — `<!bogus>`, `<?php?>`,
// `<![CDATA[…]]>` all tokenize to comments the HTML-source branch already
// strips. The prose branch matched only literal `<!--`, so the bogus forms
// leaked through; this finds the candidates to validate.
const BOGUS_COMMENT_OPEN_RE = /<[!?]/g;

// Raw source ending in UNTERMINATED markup — a `<` that opens a construct with
// no closing `>` yet: an open tag (`<span`), an end tag (`</A`), or a bogus
// comment / declaration (`<!`, `<?`). Per the HTML tokenizer such a construct
// keeps consuming the input stream until the next `>`, so it absorbs the
// following inline-html node (an open tag swallows it as bogus attributes; a
// bogus end tag / `<!…` opens a bogus comment). parse5 (the flow/source branch,
// via rehype) models this; the per-tag balance walk below does not, so without
// this a fragment parses differently as a flow block than as a paragraph —
// breaking idempotency once a first pass demotes a block to phrasing (see
// html-property "second pass changes nothing"). An open/end tag requires a
// name letter after the `<`/`</`, so literal prose like `a < b` or an `i <3 u`
// emoticon is not mistaken for markup.
const UNTERMINATED_MARKUP_TAIL_RE = /<(?:[!?]|\/?[a-zA-Z])[^>]*$/;

/**
 * Fold a raw source slice into the "inside an unterminated tag" state. A `>`
 * closes any open construct (so only the tail after the last `>` can leave one
 * open); with no `>` an already-open construct stays open. Operating on the
 * RAW source — not mdast node values — means markdown constructs that restructure
 * the character stream (code spans, emphasis, escapes) are seen exactly as
 * parse5 sees them, since only the literal `<`/`>` bytes matter.
 * @param {boolean} absorbing
 * @param {string} raw
 * @returns {boolean}
 */
function foldAbsorb(absorbing, raw) {
  if (raw.includes(">")) return UNTERMINATED_MARKUP_TAIL_RE.test(raw);
  return absorbing || UNTERMINATED_MARKUP_TAIL_RE.test(raw);
}

/**
 * Map of comment start-offset -> end-offset (exclusive) for EVERY comment the
 * HTML tokenizer finds in `value`, from a SINGLE rehype parse. Validated against
 * the real tokenizer (parse5) rather than a hand-rolled bogus-comment state
 * machine, so a bogus comment (`<!bogus>`, `<?php?>`, `<![CDATA[…]]>`) is spliced
 * to exactly the span a browser hides and a `<Foo>` element, a `<!doctype>`, or
 * visible prose never is. Replaces a per-candidate parse: the whole value is
 * tokenized once and every span read from that tree.
 * @param {string} value
 * @returns {Map<number, number>}
 */
function commentSpans(value) {
  const tree = unified().use(rehypeParse, { fragment: true }).parse(value);
  /** @type {Map<number, number>} */
  const spans = new Map();
  visit(tree, "comment", (/** @type {any} */ node) => {
    if (node.position)
      spans.set(node.position.start.offset, node.position.end.offset);
  });
  return spans;
}

/**
 * Append comment ranges found in `value` to `ranges`.
 *
 * Proper `<!--…-->` comments are located with linear indexOf scanning (a lazy
 * `<!--[\s\S]*?-->` regex backtracks polynomially on crafted input); the close
 * search starts 2 chars in so spec-abrupt closes (`<!-->`, `<!--->`) terminate
 * their own comment. Other `<!`/`<?` starts are bogus comments, spliced to the
 * exact span the HTML tokenizer assigns them so the prose branch reaches parity
 * with the HTML-source branch (which strips them via parse5).
 * @param {string} value
 * @param {number} base absolute offset of the start of `value`
 * @param {number} nodeEnd absolute offset of the end of the containing node
 * @param {Array<{start: number, end: number, kind: "comment" | "hidden"}>} ranges
 */
function collectCommentRanges(value, base, nodeEnd, ranges) {
  BOGUS_COMMENT_OPEN_RE.lastIndex = 0;
  // Tokenized bogus-comment spans, parsed once on first need (many values carry
  // a proper `<!--` handled below without ever touching the tree).
  /** @type {Map<number, number> | null} */
  let spans = null;
  for (let match; (match = BOGUS_COMMENT_OPEN_RE.exec(value));) {
    const open = match.index;
    if (value.startsWith("<!--", open)) {
      const close = value.indexOf("-->", open + 2);
      /* c8 ignore start -- micromark only tokenizes inline comments WITH a
         terminator (an unterminated `<!--` in phrasing context stays literal
         text, visible to a human reader), so this is fail-closed
         defense-in-depth against a future tokenizer change. Unterminated
         comments in flow blocks are covered — parse5 handles them in
         scanHtmlFragment. */
      if (close === -1) {
        ranges.push({ start: base + open, end: nodeEnd, kind: "comment" });
        break;
      }
      /* c8 ignore stop */
      ranges.push({
        start: base + open,
        end: base + close + 3,
        kind: "comment",
      });
      BOGUS_COMMENT_OPEN_RE.lastIndex = close + 3;
      continue;
    }
    if (!spans) spans = commentSpans(value);
    const end = spans.get(open);
    // Not a comment (a `<Foo>` element, a `<!doctype>`, visible prose): leave
    // it untouched and resume scanning just past this `<`.
    if (end === undefined) continue;
    ranges.push({ start: base + open, end: base + end, kind: "comment" });
    BOGUS_COMMENT_OPEN_RE.lastIndex = end;
  }
}

/**
 * Update hidden-region state for one html node while inside a tracked region.
 *
 * Mutates `state` in place. A closing tag for the tracked element decrements
 * depth; reaching zero closes the range. A nested open of the same tag
 * increments depth. Any other close is swallowed inside the region.
 * @param {{ tag: string | null, depth: number, regionStart: number }} state
 * @param {string} value
 * @param {number} nodeEnd absolute end offset of this node
 * @param {Array<{start: number, end: number, kind: "comment" | "hidden"}>} ranges
 */
function updateHiddenState(state, value, nodeEnd, ranges) {
  if (value.startsWith("</")) {
    if (closingTagName(value) !== state.tag) return;
    state.depth--;
    if (state.depth === 0) {
      ranges.push({ start: state.regionStart, end: nodeEnd, kind: "hidden" });
      state.tag = null;
    }
    return;
  }
  const el = parseHtmlTag(value);
  if (el && el.tagName === state.tag) state.depth++;
}

// The block-level phrasing containers whose inline html the balance walk owns.
// (Nested phrasing — emphasis, links — is reached by recursing from these; html
// directly under a flow parent like listItem/blockquote is owned by the flow
// branch instead.)
const PHRASING_ROOTS = new Set(["paragraph", "heading", "tableCell"]);

/**
 * Yield the `html` leaf nodes of a phrasing subtree in document order,
 * descending through nested inline containers (emphasis, links, …) but NOT into
 * flow parents (their html belongs to the flow/source branch).
 * @param {any} node
 * @returns {Generator<any>}
 */
function* inlineHtmlLeaves(node) {
  for (const child of node.children) {
    if (child.type === "html") yield child;
    else if (
      Array.isArray(child.children) &&
      !FLOW_HTML_PARENTS.has(child.type)
    )
      yield* inlineHtmlLeaves(child);
  }
}

/** @param {any} node @returns {boolean} */
function hasHtmlLeaf(node) {
  for (const _ of inlineHtmlLeaves(node)) return true;
  return false;
}

/**
 * Balance-walk a markdown phrasing root's html leaves in document order: a
 * hidden open tag starts a removal region that runs to its matching close (or
 * the container's end when unbalanced — fail-closed), comments become
 * single-node ranges, and preserved tags are counted. Inline html is tokenized
 * per TAG (an element's content sits in sibling text nodes), which is why this
 * walk exists instead of handing the value to rehype.
 *
 * The absorb state is folded from the RAW source between html nodes (not from
 * mdast node values), so markdown constructs that reshuffle the character
 * stream — code spans, emphasis, escapes — are seen exactly as parse5 sees
 * them. The root is walked in full document order (descending through nested
 * emphasis/links) so an unterminated tag in one node absorbs markup in a
 * sibling/nested node the way it does in the flat token stream.
 * @param {any} node
 * @param {string} text the full document source, for raw-slice absorb folding
 * @param {Array<{start: number, end: number, kind: "comment" | "hidden"}>} ranges
 * @param {ReturnType<typeof newWarned>} warned
 */
function scanInlineChildren(node, text, ranges, warned) {
  const state =
    /** @type {{ tag: string | null, depth: number, regionStart: number }} */ ({
      tag: null,
      depth: 0,
      regionStart: 0,
    });
  // "Inside an unterminated tag / bogus comment" — parse5 absorbs following
  // markup into it until the next `>`.
  let absorbing = false;
  // Non-null while inside a raw-text element (its lowercased tag name); content
  // is opaque until the matching end tag.
  let rawText = /** @type {string | null} */ (null);
  // End offset of the last html node processed; the raw slice from here to the
  // next html node is what parse5 tokenizes between them.
  let prevEnd = node.position.start.offset;
  for (const child of inlineHtmlLeaves(node)) {
    const value = child.value;
    const base = child.position.start.offset;
    const end = child.position.end.offset;
    // Fold the inter-node source (markdown text, code spans, emphasis markers)
    // into the absorb state before deciding what to do with this html node.
    absorbing = foldAbsorb(absorbing, text.slice(prevEnd, base));

    if (rawText) {
      // Raw-text content is opaque; only the matching end tag ends the region.
      if (new RegExp(`</${rawText}(?![a-z0-9-])`, "i").test(value))
        rawText = null;
    } else if (state.depth > 0) {
      updateHiddenState(state, value, end, ranges);
    } else if (!absorbing) {
      // Not absorbed into a preceding unterminated tag — scan normally.
      // Comments can share an inline html node with neighboring constructs
      // (e.g. in a list item, `<!-- c -->!` is ONE node), so comment spans are
      // located within the value and spliced individually rather than assuming
      // the node IS the comment.
      collectCommentRanges(value, base, end, ranges);
      const tagName = isHiddenOpen(value);
      if (tagName) {
        // A void element never emits a matching close, so a balance region
        // would extend to the container end and splice out following visible
        // text. Emit a single-node range instead (the source branch does too).
        // A self-closed FOREIGN element behaves the same way: in SVG/MathML
        // content the HTML spec honours the `/>` flag, so the element closes
        // immediately and everything after it renders.
        if (VOID_ELEMENTS.has(tagName) || isSelfClosedForeign(tagName, value))
          ranges.push({ start: base, end, kind: "hidden" });
        else {
          state.tag = tagName;
          state.depth = 1;
          state.regionStart = base;
        }
      } else if (!value.startsWith("</")) {
        const el = parseHtmlTag(value);
        if (el) {
          // A raw-text open tag starts an opaque region (a self-closing `/>`
          // does not apply to these in HTML — they always open).
          if (RAW_TEXT_ELEMENTS.has(el.tagName)) rawText = el.tagName;
          if (REPORTED_TAGS.has(el.tagName)) countTag(warned, el.tagName);
          if (hasDataSrc(el)) warned.dataSrc += 1;
        }
      }
    }
    // else: absorbed into a preceding unterminated tag — parse5 treats it as
    // tag soup, not a comment/element, so leave it untouched (fail open).

    absorbing = foldAbsorb(absorbing, value);
    prevEnd = end;
  }
  if (state.depth > 0) {
    ranges.push({
      start: state.regionStart,
      end: node.position.end.offset,
      kind: "hidden",
    });
  }
}

// Containers whose direct html children are flow BLOCKS (complete markup —
// tags and content in one node value), as opposed to the phrasing containers
// (paragraph, heading, tableCell, emphasis, …) whose html children are
// per-tag fragments needing the balance walk.
const FLOW_HTML_PARENTS = new Set([
  "root",
  "blockquote",
  "listItem",
  "footnoteDefinition",
]);

/**
 * @param {string} text
 * @returns {{ ranges: Array<{start: number, end: number, kind: "comment" | "hidden"}>, warned: ReturnType<typeof newWarned> }}
 */
function scanMarkdown(text) {
  const tree = mdParser.parse(text);
  /** @type {Array<{start: number, end: number, kind: "comment" | "hidden"}>} */
  const ranges = [];
  const warned = newWarned();

  // Flow html blocks carry complete markup, so rehype locates comments/hidden
  // elements precisely within them; block-local offsets are shifted to
  // document coordinates.
  visit(tree, "html", (/** @type {any} */ node, _index, parent) => {
    if (!FLOW_HTML_PARENTS.has(parent?.type)) return;
    const base = node.position.start.offset;
    const sub = scanHtmlFragment(text.slice(base, node.position.end.offset));
    for (const range of sub.ranges) {
      ranges.push({
        start: base + range.start,
        end: base + range.end,
        kind: range.kind,
      });
    }
    mergeWarned(warned, sub.warned);
  });

  // Every phrasing ROOT that holds inline html (paragraph, heading, tableCell,
  // …) gets the balance walk — not just paragraphs, so a hidden span inside a
  // heading cannot slip through. Nested inline containers (emphasis, links, …)
  // are walked as part of their root in document order, so the walk is skipped
  // for them here to avoid double-scanning and to keep the absorb state flowing
  // across those boundaries.
  visit(tree, (/** @type {any} */ node) => {
    if (!PHRASING_ROOTS.has(node.type)) return;
    if (!hasHtmlLeaf(node)) return;
    scanInlineChildren(node, text, ranges, warned);
  });

  return { ranges, warned };
}

// 30%-of-lines heuristic: HTML *source* gets scanned as one rehype fragment;
// inline tags scattered in prose go through the markdown branch instead.
/**
 * @param {string} text
 * @returns {boolean}
 */
export function looksLikeHtmlSource(text) {
  const lines = text.split("\n");
  if (lines.length < 5) return false;
  let htmlLines = 0;
  for (const line of lines) {
    if (/<\/?[a-zA-Z][^<>]*>/.test(line)) htmlLines++;
  }
  return htmlLines / lines.length > 0.3;
}

/**
 * Layer 2 over web-ingress text: splice out HTML comments and hidden elements
 * (placeholders mark the cuts; all other bytes are preserved verbatim) and
 * count preserved scripting/resource tags for the caller's warning. Returns
 * null when there is nothing to strip and nothing to report.
 * @param {string} text
 * @returns {{ text: string, removed: { comments: number, hidden: number }, warned: { tags: Record<string, number>, dataSrc: number } } | null}
 */
export function sanitizeHtml(text) {
  if (!HTML_TAG_PRESENT.test(text)) return null;
  /** @type {{ ranges: Array<{start: number, end: number, kind: "comment" | "hidden"}>, warned: ReturnType<typeof newWarned> }} */
  let scan;
  try {
    scan = looksLikeHtmlSource(text)
      ? scanHtmlFragment(text)
      : scanMarkdown(text);
  } catch {
    // The parse/visit blew up (stack overflow on pathological nesting, or any
    // other parser error). Fail CLOSED at this boundary so `sanitize`/
    // `sanitizeText` keep their never-throw contract: withhold the whole input
    // behind a placeholder and report it as hidden content removed.
    return {
      text: UNPARSEABLE_PLACEHOLDER,
      removed: { comments: 0, hidden: 1 },
      warned: newWarned(),
    };
  }
  const { ranges, warned } = scan;
  if (ranges.length === 0 && !hasWarned(warned)) return null;
  const removed = { comments: 0, hidden: 0 };
  for (const range of ranges)
    removed[range.kind === "comment" ? "comments" : "hidden"]++;
  return {
    text: ranges.length > 0 ? spliceRanges(text, ranges) : text,
    removed,
    warned,
  };
}

// ─── Layer 3: markdown/URL exfiltration detection ────────────────────────────

// Template-injection indicators, applied to the whole URL so they fire even
// when it is too malformed for `new URL()` to parse (e.g. a non-ASCII host).
// These are name-independent shapes — server-/client-side template syntax that
// only appears in a URL when something is interpolating untrusted data — so
// they carry signal on their own and need no value-shape gate.
//
// Keyword-PARAM detection (`?token=…`, `…#secret=…`) was REMOVED from this list
// (finding #20): firing on the parameter NAME alone flagged every `?session=ok`
// / `?key=pk_public_mapkey` / `?d=3`, drowning the real signal. A keyword
// param is now flagged only when its VALUE is payload-shaped, via the
// value-gated raw scan below (rawUrlKeywordExfil) which reuses the same
// blob/credential shape test as the post-parse param walk — see
// paramExfilReason. The raw scan keeps the pre-parse / fragment coverage the
// old name arm had (an unparseable host means `new URL()` throws and the
// post-parse walk never runs).
const EXFIL_INDICATORS = [/\$\{[^{}]+\}/, /\{\{[^{}]+\}\}/];

// Parameter NAMES whose presence used to flag on sight; now they only gate
// WHICH raw params the value-shape test is applied to before the URL is parsed.
// Kept narrow (the historically over-eager set) so the raw pre-parse pass stays
// cheap; any non-keyword param is still value-gated post-parse by the walk.
const KEYWORD_PARAM_NAME_RE =
  /^(?:data|d|payload|exfil|leak|steal|secret|token|key|env|password|pwd|cookie|session|auth)$/i;

const LONG_QUERY_THRESHOLD = 200;

// A `data:` URI carries its payload inline instead of pointing at a host, so
// the query/credential/fragment checks below never fire on it. Active-content
// types (HTML, SVG, JS) are a script-injection vector; an oversized blob of any
// type is an inline exfil/injection payload. A small inline image (icon) is
// left alone so the common case isn't drowned in noise.
const DATA_URI_ACTIVE_RE =
  /^\s*data:(?:text\/html|image\/svg\+xml|application\/(?:javascript|ecmascript|xhtml\+xml))[;,]/i;
export const DATA_URI_LENGTH_THRESHOLD = 4096;

// javascript:/vbscript: URIs execute on navigation/load, never a legitimate
// link target in fetched content — flagged regardless of payload.
const SCRIPT_URI_RE = /^\s*(?:javascript|vbscript):/i;

const RELATIVE_URL_BASE = "http://relative.invalid";

// Parameter NAMES that legitimately carry a LONG opaque (base64/hex) value, so
// a blob in one of them is NOT exfil: CDN request-signing (AWS SigV4 /
// CloudFront `X-Amz-*`/`Signature`/`Policy`/`Key-Pair-Id`, GCS `X-Goog-*`,
// Azure SAS `sv/sr/sig/se/sp/st/spr/skoid/sktid`), pagination cursors /
// continuation tokens, and the long analytics click-IDs. Matched
// case-insensitively against the exact (lowercased) parameter name. Scope is
// deliberately limited to names whose benign value is genuinely a long token —
// generic short params (`page`, `limit`, `v`, `t`, `cb`, …) are NOT listed,
// since their values never reach the blob threshold anyway and listing them
// would only widen the rename-dodge surface. A blob or credential-shaped value
// in any OTHER parameter still fires — this allowlist trades a narrow dodge
// (`?sig=<stolen>`) for not drowning the model in false positives on ordinary
// fetched pages.
const BENIGN_BLOB_PARAM_RE =
  /^(?:x-(?:amz|goog|ms|oss|obs)-[a-z0-9-]+|amz-[a-z0-9-]+|utm_[a-z]+|sig|signature|hmac|policy|credential|expires|key-pair-id|se|sp|sr|sv|st|spr|si|skoid|sktid|cursor|after|before|continuation|continuationtoken|continuation_token|pagetoken|page_token|nexttoken|next_token|gclid|fbclid|dclid|msclkid|gbraid|wbraid|_ga|_gl|mc_eid|mc_cid)$/i;

// matchesSecretHint is a deliberately broad PRE-gate whose bare-keyword arms
// (`token`, `secret`, `authorization`, …) also match ordinary hyphen/word
// delimited prose, and with no secret-redaction engine to refine the verdict
// here a weak digit proxy isn't enough: `login-authenticate-2024` and
// `the-secret-recipe-2024` clear "has a digit." A leaked credential is an
// OPAQUE, separator-free token, so the value must additionally contain a
// contiguous 20+ char `[A-Za-z0-9_]` run (no hyphen/space — that's what splits
// the prose runs below the bar) AND a digit before it counts as one.
const OPAQUE_TOKEN_RE = /[A-Za-z0-9_]{20,}/g;
const VALUE_HAS_DIGIT_RE = /\d/;

// A value that is ENTIRELY a long base64 (40+ chars, optional `=` padding) or
// hex (32+ chars) run. Anchored to the whole value (operating on the RAW,
// un-decoded query so a `+` in base64 is not turned into a space), so a benign
// short value with an incidental hex word never trips it. Both arms are linear.
const BLOB_VALUE_B64_RE = /^[A-Za-z0-9+/]{40,}={0,2}$/;
const BLOB_VALUE_HEX_RE = /^[A-Fa-f0-9]{32,}$/;

// RFC 4648 §5 url-safe base64 substitutes `-`/`_` for `+`/`/`, so a payload
// encoded url-safe escapes the `[A-Za-z0-9+/]` arms above. Adding `-`/`_` to the
// charset would re-admit a long hyphenated word-slug (`the-secret-history-of-…`)
// as a "blob", so this arm distinguishes the two by CHARACTER MIX rather than a
// contiguous run: bulk-encoded bytes drawn from base64url's 64-symbol alphabet
// almost always carry BOTH an uppercase letter and a digit, whereas a human slug
// is lowercase dictionary words joined by separators and shows neither. The
// earlier contiguous-40-run gate was fragile — ordinary base64url scatters a
// `-`/`_` roughly every ~30 chars, breaking any 40-char run, so a real beacon
// (`?d=<200-char base64url of cookies>`) routinely dodged it. The mix test keeps
// the slug benign (no uppercase) while catching the scattered-separator blob the
// run gate missed. Anchored to the whole value for the same RAW-query reason.
const BLOB_VALUE_B64URL_RE = /^[A-Za-z0-9_-]{40,}={0,2}$/;
const B64URL_MIXED_RE = /(?=.*[A-Z])(?=.*[0-9])/;

// A path segment whose whole value is a base64/hex run longer than any standard
// content hash (SHA-512 hex is 128, base64 88; SHA-256 hex 64) is bulk encoded
// data — a beacon URL that smuggles its payload in the path to dodge the query
// walk — rather than an asset fingerprint. The threshold sits just above the
// SHA-512-hex ceiling so every real fingerprint clears it while a ~150-char
// base64 of stolen cookies does not. Hyphens/underscores are excluded from the
// standard arm so a long word-slug (`the-secret-history-of-…`) is not mistaken
// for a payload; the url-safe arm re-admits `-`/`_` but, like the query arm
// above, gates on a contiguous 40+ alphanumeric run to keep the slug benign.
const PATH_BLOB_RE = /^(?:[A-Za-z0-9+/]+={0,2}|[A-Fa-f0-9]+)$/;
const PATH_BLOB_MIN_LEN = 128;

/**
 * True for an entirely-url-safe-base64 value (≥40 chars) whose character mix —
 * at least one uppercase letter AND one digit — marks it as bulk-encoded bytes
 * rather than a lowercase hyphenated word-slug. Shared by the query and path
 * blob detectors. Precision-first: a value missing either class is treated as a
 * benign slug and passes (a false negative, per the detection-layer doctrine).
 * @param {string} value
 * @returns {boolean}
 */
function isBase64UrlBlob(value) {
  return BLOB_VALUE_B64URL_RE.test(value) && B64URL_MIXED_RE.test(value);
}

/** @param {string} value @returns {boolean} */
function isBlobValue(value) {
  return (
    BLOB_VALUE_B64_RE.test(value) ||
    BLOB_VALUE_HEX_RE.test(value) ||
    isBase64UrlBlob(value)
  );
}

/**
 * True when the percent-DECODED form of `value` is blob-shaped, even though
 * the raw value isn't (e.g. `A%41A%41…` decodes to a run of `A`s). This is a
 * REPORT-ONLY check — `paramExfilReason` never rewrites the URL, it only
 * names a reason for the caller's warning — so the false-positive cost of
 * decoding is much lower than it would be in the splicing layer. Applied IN
 * ADDITION to the raw-value test (never instead of it): the raw scan stays
 * the primary signal since `URLSearchParams`-style decoding elsewhere in this
 * file is deliberately avoided (it mangles `+` in base64). A malformed
 * percent-sequence throws in `decodeURIComponent`; that failure is not a
 * blob shape either way, so it fails open (skip the decoded check).
 * @param {string} value
 * @returns {boolean}
 */
function decodedBlobMatch(value) {
  let decoded;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return false;
  }
  return isBlobValue(decoded);
}

/**
 * RAW (un-decoded) `name=value` pairs of a query/fragment string, split on `&`
 * and `;`. URLSearchParams is avoided on purpose: it percent-/`+`-decodes
 * values, turning a `+`-bearing base64 blob into a space-broken string that the
 * anchored blob regexes would miss.
 * @param {string} qs
 * @returns {Array<[string, string]>}
 */
function rawParams(qs) {
  /** @type {Array<[string, string]>} */
  const pairs = [];
  for (const pair of qs.split(/[&;]/)) {
    if (!pair) continue;
    const eq = pair.indexOf("=");
    const name = eq === -1 ? pair : pair.slice(0, eq);
    const value = eq === -1 ? "" : pair.slice(eq + 1);
    pairs.push([name.toLowerCase(), value]);
  }
  return pairs;
}

/**
 * Exfil reason for one URL parameter, or null. A credential-shaped value in any
 * non-allowlisted parameter (reusing the secret-shape gate), or a long
 * base64/hex blob in one. Allowlisted signing/pagination/analytics parameters
 * are skipped entirely (see BENIGN_BLOB_PARAM_RE).
 * @param {string} name  lowercased parameter name
 * @param {string} value RAW (un-decoded) value
 * @returns {string | null}
 */
function paramExfilReason(name, value) {
  if (BENIGN_BLOB_PARAM_RE.test(name)) return null;
  // A leaked credential is an OPAQUE, separator-free token. Gate the
  // secret-shape/digit test on the CONTIGUOUS opaque run(s) of the value, not on
  // the whole prose value: a benign path-like value (`?redirect=/authorization-
  // service/…abcdefghij1234567890`) otherwise matches "authorization" in one
  // place and a 20-char run in another and false-fires. Requiring both on the
  // SAME run keeps `ghp_…`-style contiguous tokens firing while dropping prose.
  const opaqueRuns = value.match(OPAQUE_TOKEN_RE);
  if (
    opaqueRuns?.some(
      (run) => VALUE_HAS_DIGIT_RE.test(run) && matchesSecretHint(run),
    )
  )
    return "credential-shaped token in URL parameter";
  if (isBlobValue(value) || decodedBlobMatch(value))
    return "suspicious query parameter";
  return null;
}

/**
 * Pre-parse, value-GATED keyword-parameter scan over the RAW URL string. Splits
 * off the query (`?…`) and fragment (`#…`) and applies the same blob/credential
 * value-shape test as the post-parse walk, but only to keyword-named params
 * (KEYWORD_PARAM_NAME_RE). This is the precision fix for finding #20: a keyword
 * param flags only when its value is actually payload-shaped, so `?session=ok`
 * and `?key=pk_public_mapkey` no longer fire. It runs BEFORE `new URL()` so a
 * blob in an unparseable-host URL (which the post-parse walk never reaches) is
 * still caught, preserving the coverage the old name-only arm had.
 * @param {string} url
 * @returns {string | null}
 */
function rawUrlKeywordExfil(url) {
  // Strip the scheme+authority+path prefix: everything up to the first `?`/`#`.
  const qIdx = url.search(/[?#]/);
  if (qIdx === -1) return null;
  for (const segment of url.slice(qIdx + 1).split("#")) {
    for (const [name, value] of rawParams(segment)) {
      if (!KEYWORD_PARAM_NAME_RE.test(name)) continue;
      const reason = paramExfilReason(name, value);
      if (reason) return reason;
    }
  }
  return null;
}

/**
 * True when every parameter of the parsed URL's query is in the benign
 * allowlist. Used to suppress the coarse long-query-string heuristic for
 * signed-CDN links, which are long by design. Only ever called once the query
 * is known to be long (and thus non-empty), so the vacuous-true empty case
 * cannot arise here.
 * @param {URL} parsed
 * @returns {boolean}
 */
function allParamsBenign(parsed) {
  return rawParams(parsed.search.slice(1)).every(([name]) =>
    BENIGN_BLOB_PARAM_RE.test(name),
  );
}

/**
 * Walk the query and fragment parameters of a parsed URL for an exfil reason.
 * @param {URL} parsed
 * @returns {string | null}
 */
function checkUrlParams(parsed) {
  for (const [name, value] of rawParams(parsed.search.slice(1))) {
    const reason = paramExfilReason(name, value);
    if (reason) return reason;
  }
  // The fragment carries the same `key=value` channel (`#token=…`); a bare
  // anchor (`#section-2`) yields one empty-value param that trips nothing.
  for (const [name, value] of rawParams(parsed.hash.slice(1))) {
    const reason = paramExfilReason(name, value);
    if (reason) return reason;
  }
  return null;
}

/**
 * A bulk encoded-data blob smuggled in a path segment (a beacon URL that avoids
 * query strings entirely), or null.
 * @param {URL} parsed
 * @returns {string | null}
 */
function checkUrlPath(parsed) {
  for (const segment of parsed.pathname.split("/")) {
    if (
      segment.length > PATH_BLOB_MIN_LEN &&
      (PATH_BLOB_RE.test(segment) || isBase64UrlBlob(segment))
    )
      return "encoded data blob in path segment";
  }
  return null;
}

/**
 * @param {string} url
 * @returns {string | null}
 */
export function checkExfilUrl(url) {
  // A browser strips tab/newline/CR ANYWHERE in a URL before resolving its
  // scheme, so `java\tscript:alert(1)` navigates as `javascript:`. Strip them
  // for the scheme tests (the payload/length checks below keep the raw string).
  const schemeUrl = url.replace(/[\t\n\r]/g, "");
  if (/^\s*data:/i.test(schemeUrl)) {
    if (DATA_URI_ACTIVE_RE.test(schemeUrl)) return "active-content data: URI";
    if (url.length > DATA_URI_LENGTH_THRESHOLD)
      return "oversized inline data: payload";
    return null;
  }
  if (SCRIPT_URI_RE.test(schemeUrl)) return "script-executing URI";
  // Template-injection shapes (`${…}`, `{{…}}`) only in the query/fragment: a
  // brace in the PATH or host is a legitimate templated doc URL
  // (`/api/{{version}}/guide`), and flagging it both false-positives and
  // mislabels the location. Sliced from the raw string so an unparseable-host
  // URL is still covered before `new URL()` would throw.
  const qfIdx = url.search(/[?#]/);
  const queryAndFragment = qfIdx === -1 ? "" : url.slice(qfIdx);
  if (
    queryAndFragment &&
    EXFIL_INDICATORS.some((pattern) => pattern.test(queryAndFragment))
  )
    return "suspicious query parameter";
  // Value-gated keyword params, scanned on the RAW string so a blob in an
  // unparseable-host URL is caught before `new URL()` would throw.
  const keywordReason = rawUrlKeywordExfil(url);
  if (keywordReason) return keywordReason;
  // Userinfo and an oversized fragment are exfil channels the param walk misses:
  // credentials smuggled as `user:secret@host`, or a payload tucked in `#<blob>`.
  // Parse against a sentinel base so relative URLs don't throw.
  let parsed;
  try {
    parsed = new URL(url, RELATIVE_URL_BASE);
  } catch {
    return null;
  }
  if (parsed.username || parsed.password) return "embedded credentials";
  // A long query string is only suspicious when it carries a non-allowlisted
  // parameter — a signed-CDN URL is long by design (all `X-Amz-*`/SAS params).
  // Measure the query from `parsed.search` (the parser's query span), NOT a raw
  // indexOf("?") into the whole URL: a `?` inside the FRAGMENT (`/p#a?<blob>`)
  // would otherwise be read as the query start, leaving `parsed.search` empty so
  // `allParamsBenign` runs `[].every(...)` → vacuously true and suppresses the
  // flag. The fragment is length-checked separately just below.
  if (parsed.search.length > LONG_QUERY_THRESHOLD && !allParamsBenign(parsed))
    return "unusually long query string";
  if (parsed.hash.length > LONG_QUERY_THRESHOLD)
    return "unusually long fragment";
  return checkUrlParams(parsed) || checkUrlPath(parsed);
}

/**
 * Host of a flagged URL — enough for the warning to name the destination
 * without echoing the payload-bearing query/fragment.
 * @param {string} url
 * @returns {string}
 */
export function urlHost(url) {
  // A `data:` URI has no host; name the channel rather than echoing the payload.
  if (/^\s*data:/i.test(url)) return "(inline data: URI)";
  let parsed;
  try {
    parsed = new URL(url, RELATIVE_URL_BASE);
  } catch {
    // checkExfilUrl flags via regex before parsing, so it can hand us a URL
    // WHATWG rejects (e.g. a non-ASCII host).
    return "(unparsable URL)";
  }
  if (
    parsed.origin === RELATIVE_URL_BASE &&
    !url.startsWith(RELATIVE_URL_BASE)
  ) {
    return "(relative URL)";
  }
  return parsed.host;
}

/**
 * True when `url` is an absolute, off-origin target (an authority that is not
 * the relative-resolution sentinel). Used for form `action`/`formaction` and
 * `meta refresh` URLs, where pointing off the page's own origin is the
 * exfil/redirect signal regardless of the query shape.
 * @param {string} url
 * @returns {boolean}
 */
function isOffOrigin(url) {
  let parsed;
  try {
    parsed = new URL(url, RELATIVE_URL_BASE);
  } catch {
    return false;
  }
  return (
    parsed.origin !== RELATIVE_URL_BASE || url.startsWith(RELATIVE_URL_BASE)
  );
}

/**
 * The redirect URL of a `<meta http-equiv="refresh">` content value
 * (`"5; url=https://…"`), or null when it carries no `url=` target.
 * @param {string} content
 * @returns {string | null}
 */
function metaRefreshUrl(content) {
  // Do NOT exclude `;` from the URL run: the `;` separates the timeout from
  // `url=` BEFORE the target, while WITHIN the target it is a legal query
  // sub-delimiter — excluding it truncated a `?a=1;b=<blob>` exfil tail. The
  // optional leading quote is consumed and the run then stops at the closing
  // quote (quoted) or at whitespace (unquoted); a single group keeps both forms
  // without an unreachable no-match arm.
  const match = /** @type {{ groups: { url: string } } | null} */ (
    content.match(/url\s*=\s*['"]?(?<url>[^'"\s]+)/i)
  );
  return match ? match.groups.url : null;
}

// HTML whitespace per the `srcset` grammar (ASCII whitespace).
const SRCSET_WS_RE = /[ \t\n\f\r]/;

/**
 * URLs of a `srcset` value, parsed per the WHATWG "parse a srcset attribute"
 * grammar rather than a naive `split(",")`: a candidate's URL is a run of
 * non-whitespace characters, so a URL that itself contains commas (a `data:`
 * URI, or a query with `,`) is kept intact. A comma only separates candidates
 * when it trails the URL run or follows the (paren-aware) descriptor. Trailing
 * commas on the URL run mark a candidate with no descriptor.
 * @param {string} value
 * @returns {string[]}
 */
function parseSrcset(value) {
  /** @type {string[]} */ const urls = [];
  let i = 0;
  const n = value.length;
  while (i < n) {
    while (i < n && (SRCSET_WS_RE.test(value[i]) || value[i] === ",")) i++;
    const start = i;
    while (i < n && !SRCSET_WS_RE.test(value[i])) i++;
    const run = value.slice(start, i);
    const url = run.replace(/,+$/, "");
    if (url) urls.push(url);
    // A URL run ending in a comma is a bare candidate (no descriptor); the
    // comma already delimits the next one, so skip descriptor parsing.
    if (run.endsWith(",")) continue;
    // Otherwise consume the descriptor up to the first unparenthesized comma.
    let depth = 0;
    while (i < n) {
      const c = value[i];
      if (c === "(") depth++;
      else if (c === ")" && depth > 0) depth--;
      else if (c === "," && depth === 0) {
        i++;
        break;
      }
      i++;
    }
  }
  return urls;
}

/**
 * Candidate URLs of a `srcset` (a "url descriptor" string parsed per the HTML
 * grammar) or `ping` (a space-separated url list rehype delivers as an array)
 * attribute. An absent attribute (neither string nor array) yields none.
 * @param {unknown} value
 * @returns {string[]}
 */
function multiUrlAttr(value) {
  if (Array.isArray(value))
    return value
      .map((candidate) => String(candidate).trim().split(/\s+/)[0])
      .filter(Boolean);
  if (typeof value === "string") return parseSrcset(value);
  return [];
}

/**
 * URL-bearing attributes of every HTML element in `text`, parsed with rehype so
 * quoting/casing/entities are handled correctly (no hand-rolled tag regex).
 * `context` selects the per-URL check the caller applies: resource URLs get the
 * exfil-shape test; form-submission and meta-refresh targets additionally flag
 * any absolute off-origin destination.
 * @param {string} text
 * @returns {Array<{ url: string, isImage: boolean, context: "resource" | "form" | "refresh" }>}
 */
function extractHtmlUrls(text) {
  const tree = unified().use(rehypeParse, { fragment: true }).parse(text);
  /** @type {Array<{ url: string, isImage: boolean, context: "resource" | "form" | "refresh" }>} */
  const urls = [];
  visit(tree, "element", (/** @type {any} */ node) => {
    // hast element nodes always carry a `properties` object (parse5 sets it).
    const props = node.properties;
    const isImage = node.tagName === "img";
    for (const key of ["src", "href", "background"])
      if (typeof props[key] === "string")
        urls.push({ url: props[key], isImage, context: "resource" });
    for (const key of ["srcSet", "ping"])
      for (const url of multiUrlAttr(props[key]))
        urls.push({ url, isImage, context: "resource" });
    for (const key of ["action", "formAction"])
      if (typeof props[key] === "string")
        urls.push({ url: props[key], isImage: false, context: "form" });
    // rehype delivers `http-equiv` as an array (comma-separated); join it back
    // so a `refresh` directive is matched regardless of how it was tokenized.
    const httpEquiv = Array.isArray(props.httpEquiv)
      ? props.httpEquiv.join(",").toLowerCase()
      : "";
    if (
      node.tagName === "meta" &&
      httpEquiv.includes("refresh") &&
      typeof props.content === "string"
    ) {
      const url = metaRefreshUrl(props.content);
      if (url) urls.push({ url, isImage: false, context: "refresh" });
    }
  });
  return urls;
}

// Reason for an off-origin submission/redirect target by context; null leaves
// the URL to the exfil-shape check alone.
const OFF_ORIGIN_REASON = {
  form: "off-origin form action",
  refresh: "off-origin meta-refresh redirect",
};

/**
 * Layer 3: report data-exfil-shaped URLs in markdown links/images/definitions
 * and HTML attributes (src/href/background/srcset/ping, form action/formaction,
 * meta-refresh). Detection only — the text is never modified; the caller
 * surfaces the threats as a warning.
 * @param {string} text
 * @returns {Array<{ isImage: boolean, reason: string, target: string }> | null}
 */
export function detectExfil(text) {
  if (!MD_LINK_HINT.test(text) && !HTML_TAG_PRESENT.test(text)) return null;

  /** @type {Array<{ isImage: boolean, reason: string, target: string }>} */
  const threats = [];

  try {
    // Remark AST handles markdown links/images/definitions (balanced parens,
    // reference links) correctly, unlike a hand-rolled regex.
    const tree = mdParser.parse(text);
    visit(tree, (node) => {
      if (
        node.type !== "link" &&
        node.type !== "image" &&
        node.type !== "definition"
      )
        return;
      const reason = checkExfilUrl(node.url);
      if (!reason) return;
      threats.push({
        isImage: node.type === "image",
        reason,
        target: urlHost(node.url),
      });
    });

    // HTML attributes (not AST nodes in remark).
    for (const { url, isImage, context } of extractHtmlUrls(text)) {
      const reason =
        checkExfilUrl(url) ||
        (context !== "resource" && isOffOrigin(url)
          ? OFF_ORIGIN_REASON[context]
          : null);
      if (!reason) continue;
      threats.push({ isImage, reason, target: urlHost(url) });
    }
  } catch {
    // The parse/visit blew up (stack overflow on pathological nesting). Fail
    // CLOSED so the never-throw contract holds: report one sentinel threat so
    // the caller still warns rather than crashing, since an input too nested to
    // scan could itself be hiding an exfil URL.
    return [
      {
        isImage: false,
        reason: "input too deeply nested to scan for exfil URLs",
        target: "(unparseable HTML)",
      },
    ];
  }

  return threats.length > 0 ? threats : null;
}
