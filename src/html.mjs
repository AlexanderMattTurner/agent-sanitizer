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
 * Every splice is ROUND-TRIPPABLE: the placeholder carries a content-addressed
 * key (see {@link layer2Placeholder}) and `sanitizeHtml` returns a `splices`
 * array pairing each placeholder with the original bytes it replaced, so a
 * caller that must write the text back (an agent editing a PR body whose
 * comments were spliced) can rehydrate instead of persisting the loss —
 * comments are ubiquitous legitimate content (PR templates, tooling markers),
 * and an earlier lossy splice corrupted real documents (#244). The splice
 * itself stays: comments hide content from a human reading the rendered page,
 * which is the exact channel this layer exists to close.
 *
 * Layer 3 reports data-exfil-shaped URLs (suspicious query params, oversized
 * payloads, embedded credentials) without modifying them; the caller surfaces
 * the report as a warning.
 *
 * Split into its own module so it can be lazy-loaded: pulling in the
 * remark/rehype/unified graph costs ~200ms of module-load time, so the main
 * entry `await import()`s this module only when its cheap regex gates match.
 */
import { createHash } from "node:crypto";
// @ts-ignore -- css-tree ships no bundled types and @types/css-tree lags the 3.x
// API (e.g. `ident.decode`); the value AST is walked with local `any` types.
import * as csstree from "css-tree";
import { unified } from "unified";
import remarkParse from "remark-parse";
import remarkGfm from "remark-gfm";
import rehypeParse from "rehype-parse";
import { SKIP, EXIT } from "unist-util-visit";
import {
  HTML_TAG_PRESENT,
  MD_LINK_HINT,
  SECRET_HINT,
  SECRET_HINT_EXT,
  matchesSecretHint,
  needsUrlScan,
} from "./gates.mjs";
import { confusableHost, describeConfusableHost } from "./confusable-host.mjs";
import { SEVERITY } from "./severity.mjs";

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
//
// Every ident in a value — keyword, function name, dimension unit — is
// escape-decoded and lowercased ONCE at the parse boundary (see
// {@link canonicalizeValue}), so the detectors below compare canonical tokens
// against literals. Doing it per-site is what let `left:-9999PX` through: CSS
// units are ASCII case-insensitive, and every site that forgot `.toLowerCase()`
// was a one-keystroke bypass of the whole layer.

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
    // Function names, units and idents arrive lowercased and escape-decoded
    // from parseDeclarations, so a literal compare is correct by construction.
    const name = fn.name;
    const args = valueTokens(fn);
    if (/^(?:scale|scale3d|scalex|scaley|matrix|matrix3d)$/.test(name)) {
      // scale/matrix collapse to nothing when EITHER axis factor is (near-)zero:
      // `scale(1,0)` collapses the Y axis, as does `matrix(1,0,0,0,…)` (d=0).
      // A factor sits at a fixed ARGUMENT position, so the comma-separated
      // argument list is what carries it — indexing a Number-filtered token list
      // instead drops an unresolvable `var()`/`calc()` argument and slides a
      // later benign 0 into a factor slot, splicing VISIBLE text.
      // Factor positions per function:
      //   scale/scale3d/scaleX/scaleY: scaleX=0, scaleY=1 (a lone scaleX(0) or
      //     scaleY(0) argument sits at 0)
      //   matrix(a,b,c,d,…): scaleX=a (0), scaleY=d (3)
      //   matrix3d(m11,…): scaleX=m11 (0), scaleY=m22 (5) — index 3 is m14,
      //     which the identity matrix leaves at 0 (a false positive)
      const groups = functionArgs(fn);
      const factorIdx =
        name === "matrix" ? [0, 3] : name === "matrix3d" ? [0, 5] : [0, 1];
      // css-tree reads the exponent form (`1e-3`) at full value; scale()/matrix()
      // factors are <number>s (never lengths). An argument that is not one Number
      // token — `var(--x)`, `calc(…)`, a missing slot — is unresolvable and fails
      // OPEN: it yields no hidden verdict.
      if (
        factorIdx.some((/** @type {number} */ i) => {
          const group = groups[i];
          const factor = group && group.length === 1 ? group[0] : null;
          return (
            factor !== null &&
            factor.type === "Number" &&
            Math.abs(parseFloat(factor.value)) < NEAR_ZERO_EPSILON
          );
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
      if (a && a.type === "Dimension" && ANGLE_UNITS.has(a.unit)) {
        const degrees = hueDegrees(`${a.value}${a.unit}`);
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
    if (fn.type !== "Function" || fn.name !== "opacity") continue;
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
    (t) => t.type === "Function" && t.name === "rect",
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
 * Fold one hex color body — 3, 4, 6 or 8 digits, `#` already stripped — to
 * `#rrggbb`, or to `transparent` when its alpha byte is zero. `#RGB`/`#RGBA`
 * expand by doubling each digit, exactly as a browser reads them.
 *
 * A PARTIAL alpha (neither `00` nor `ff`) drops out and leaves the color, which
 * is what {@link canonicalizeColorFunction} already does with `rgba(…, .5)`:
 * the caller compares this color against the backdrop it is painted on, and a
 * color blended over its own value renders that value at every alpha. Keeping
 * the two spellings apart here would leave `#ffffff80` a bypass of a hide that
 * `rgba(255,255,255,.5)` is caught for.
 * @param {string} digits
 * @returns {string}
 */
function canonicalizeHex(digits) {
  const expanded =
    digits.length <= 4
      ? [...digits].map((digit) => digit + digit).join("")
      : digits;
  if (expanded.slice(6) === "00") return "transparent";
  return `#${expanded.slice(0, 6)}`;
}

/**
 * Canonicalize a CSS color to lowercase `#rrggbb` (or the `transparent`
 * sentinel) so `white`, `#FFF`, `#ffffff`, `#ffffffff`, `rgb(255, 255, 255)`,
 * `rgb(255 255 255)`, `rgb(100% 100% 100%)`, and `hsl(0 0% 100%)` all compare
 * equal — as do `transparent`, `#0000`, `#00000000` and `rgba(0,0,0,0)`.
 * Returns the trimmed lowercased input unchanged when it is not a form we
 * recognize; callers gate the same-color compare on isConcreteColor so an
 * unresolved token (`var()`, `inherit`) never falsely reads as a same-color
 * hide.
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
  // All four hex notations in one match: reading only #RGB and #RRGGBB left
  // `#0000` and `#00000000` — exact synonyms of `transparent`, which IS a hide —
  // unresolved, so invisible text reached the model.
  const hex = value.match(/^#([0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$/);
  if (hex) return canonicalizeHex(hex[1]);
  return canonicalizeColorFunction(value) ?? value;
}

// True when a value node paints — or cannot be proven NOT to paint — a
// background IMAGE layer: a `url()`, a `*-gradient()` or an `image-set()`
// anywhere in the value. The value AST is walked rather than a re-serialized
// string regexed: an escaped function name (`\49 mage-set(…)`, which a browser
// reads as `image-set(…)`) survives serialization escaped and slipped past the
// regex, so the image layer went unseen and same-colored text painted over an
// image was spliced as hidden. A `Raw` node — a value css-tree could not parse,
// which is also what an escaped `url(` degrades to — is unresolvable and so
// counts as an image layer (fail OPEN: no same-color hide).
/** @param {any} node value node, or null @returns {boolean} */
function paintsImageLayer(node) {
  if (!node) return false;
  let found = false;
  csstree.walk(node, {
    enter(/** @type {any} */ child) {
      if (child.type === "Url" || child.type === "Raw") found = true;
      // Names are canonicalized at the parse boundary, so a suffix test covers
      // every gradient (`linear-`/`radial-`/`conic-`/`repeating-`/`-webkit-`)
      // and both `image-set` spellings. `url` appears as a Function (not a Url)
      // node when its name carried an escape — the very case the old regex on
      // the re-serialized text missed.
      if (
        child.type === "Function" &&
        (child.name === "url" ||
          child.name.endsWith("gradient") ||
          child.name.endsWith("image-set"))
      )
        found = true;
    },
  });
  return found;
}

// The leading color token of a `background` shorthand (the first token that
// canonicalizes to a real color), so `background:#fff` still compares. Returns
// "" (fail open, no same-color hide) when the shorthand carries an IMAGE layer:
// the painted image can make same-colored text perfectly readable over it (and
// if it fails to load the element's own background shows through), so the flat
// color token is not provably the rendered backdrop.
/** @param {any} node value node for `background`, or null @returns {string} */
function backgroundColor(node) {
  if (!node || paintsImageLayer(node)) return "";
  for (const token of valueTokens(node)) {
    const color = canonicalizeColor(tokenText(token));
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
    if (token.type === "Identifier" && token.name === "round") break;
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
    const name = fn.name;
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

/** True when a value is exactly the keyword `none`.
 * @param {any} node @returns {boolean} */
function isNoneKeyword(node) {
  const token = soleToken(node);
  return Boolean(token && token.type === "Identifier" && token.name === "none");
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
/** @param {(key: string) => any} nodeOf @returns {boolean} */
function hasImageLayer(nodeOf) {
  const img = nodeOf("background-image");
  // Only the single keyword `none` proves the longhand paints nothing; any
  // other value (an unresolvable `var()` included) counts as a layer.
  if (img && !isNoneKeyword(img)) return true;
  return paintsImageLayer(nodeOf("background"));
}

// The declarations that add to an axis's BORDER box beyond its content-box
// length, per axis. Shorthands are listed alongside the longhands they can set,
// because a shorthand this checker cannot resolve must fail OPEN rather than be
// ignored — ignoring it is what let `height:0; padding-bottom:56.25%` read as
// invisible.
// Logical spellings are listed beside their physical twins: `padding-block-end`
// IS the aspect-ratio idiom in a logical stylesheet, so omitting it would leave
// the exact false positive this checker exists to close.
const BLOCK_AXIS_EXTENT_PROPS = [
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
const INLINE_AXIS_EXTENT_PROPS = [
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

// The shorthands that can set a width alongside a style and a color. An omitted
// width computes to `medium`, so these need an explicit numeric width before
// the declaration can be called zero-extent.
const BORDER_SHORTHANDS = new Set([
  "border",
  "border-top",
  "border-bottom",
  "border-left",
  "border-right",
  "border-block",
  "border-inline",
  "border-block-start",
  "border-block-end",
  "border-inline-start",
  "border-inline-end",
]);

// `border-width`'s keyword values. They are LENGTHS, so a border shorthand that
// names one (or names none at all, defaulting to `medium`) has real extent.
const BORDER_WIDTH_KEYWORDS = new Set(["thin", "medium", "thick"]);

/**
 * True when a declared axis-additive property provably contributes NO extent.
 *
 * Deliberately conservative: every numeric token must be near zero, no
 * border-width keyword may appear, and a `border*` shorthand must carry an
 * explicit numeric width (an omitted width computes to `medium`, i.e. 3px). A
 * `calc()`, a `var()`, or any unit this cannot resolve leaves a non-numeric
 * token behind and returns false — the fail-open the module's own policy
 * requires, since an unresolvable value may well paint a visible box.
 * @param {string} prop @param {any} node @returns {boolean}
 */
function contributesNoExtent(prop, node) {
  const tokens = valueTokens(node);
  if (tokens.length === 0) return false;
  const isBorderShorthand = BORDER_SHORTHANDS.has(prop);
  let sawNumeric = false;
  for (const token of tokens) {
    if (
      token.type === "Number" ||
      token.type === "Dimension" ||
      token.type === "Percentage"
    ) {
      if (Math.abs(parseFloat(token.value)) >= NEAR_ZERO_EPSILON) return false;
      sawNumeric = true;
      continue;
    }
    // A hex color is a `Hash` node, never a length — accepting it keeps
    // `border:0 solid #ccc` resolvable without weakening the fail-open below.
    if (token.type === "Hash") continue;
    // A style/color identifier (`solid`, `red`) adds no length, but a
    // width keyword does — and anything else (a function node, `var()`) is
    // unresolvable and must fail open.
    if (token.type !== "Identifier") return false;
    if (BORDER_WIDTH_KEYWORDS.has(String(token.name).toLowerCase()))
      return false;
  }
  return isBorderShorthand ? sawNumeric : true;
}

/**
 * True when every declaration that could add to `axisProps`' axis is either
 * absent or provably zero, so a near-zero content-box length really does mean
 * the rendered border box is empty.
 * @param {(key: string) => any} nodeOf @param {string[]} axisProps
 * @returns {boolean}
 */
function axisExtentProvablyZero(nodeOf, axisProps) {
  for (const prop of axisProps) {
    const node = nodeOf(prop);
    if (!node) continue; // undeclared: contributes its initial value, 0
    if (!contributesNoExtent(prop, node)) return false;
  }
  return true;
}

/**
 * @param {(key: string) => any} nodeOf value node for a property, or null
 * @param {(key: string) => string} textOf decoded/lowercased text for a property
 * @returns {boolean}
 */
function isOverflowHidden(nodeOf, textOf) {
  if (textOf("overflow") !== "hidden") return false;
  for (const [dim, axisProps] of /** @type {[string, string[]][]} */ ([
    ["height", BLOCK_AXIS_EXTENT_PROPS],
    ["width", INLINE_AXIS_EXTENT_PROPS],
    ["max-height", BLOCK_AXIS_EXTENT_PROPS],
    ["max-width", INLINE_AXIS_EXTENT_PROPS],
  ]))
    // Near-zero (epsilon band), not exact 0, so `height:0.0001px` still counts —
    // matching the standalone size checks a browser renders as invisible.
    // The content box being empty is necessary but NOT sufficient: the universal
    // aspect-ratio wrapper (`height:0; padding-bottom:56.25%; overflow:hidden` —
    // Bootstrap's `.ratio`, and every hand-pasted padding-bottom hack) renders
    // at 56.25% of its container with everything inside it on screen. Reading
    // the content-box length alone spliced that visible content out.
    if (
      isNearZeroLength(nodeOf(dim)) &&
      axisExtentProvablyZero(nodeOf, axisProps)
    )
      return true;
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
 * One value token as text. An Identifier's `name` is already the decoded,
 * lowercased ident (see {@link canonicalizeValue}), so it is used verbatim
 * rather than round-tripped through the serializer; every other token is
 * re-serialized from its (canonicalized) node fields.
 * @param {any} token
 * @returns {string}
 */
function tokenText(token) {
  return token.type === "Identifier" ? token.name : csstree.generate(token);
}

/**
 * Reconstruct a declaration's canonicalized value as a string for keyword/color
 * comparisons. Escapes and letter case were resolved at the parse boundary, so
 * `no\6e e`, `NONE` and `none` all render as `none` here. A whole-value `Raw`
 * (an unparsed value) is returned verbatim — it never matches a hiding keyword,
 * so it fails open.
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
      parts.push(tokenText(child)),
    );
  return parts.join(" ");
}

/**
 * Canonicalize a parsed value subtree IN PLACE so every downstream comparison
 * against a literal (`ABSOLUTE_UNITS`, `"rect"`, `"none"`) is correct by
 * construction instead of depending on each call site remembering to decode and
 * lowercase. CSS idents — keywords, function names and dimension units — are
 * escape-decodable and ASCII case-insensitive for every keyword this module
 * matches, so a browser reads `left:-9999PX`, `left:-9999p\78` and
 * `left:-9999px` identically; the ad-hoc per-site `.toLowerCase()` did not, and
 * a single uppercased unit walked straight past the detector.
 *
 * `Url.value` is deliberately NOT touched: css-tree already decodes url escapes,
 * and a second decode would eat a legitimately backslash-bearing path.
 * @param {any} valueNode
 * @returns {void}
 */
function canonicalizeValue(valueNode) {
  csstree.walk(valueNode, {
    enter(/** @type {any} */ node) {
      // ident.decode is pure string iteration and cannot throw on a token the
      // tokenizer already produced.
      if (node.type === "Identifier" || node.type === "Function")
        node.name = csstree.ident.decode(node.name).toLowerCase();
      else if (node.type === "Dimension")
        node.unit = csstree.ident.decode(node.unit).toLowerCase();
    },
  });
}

/**
 * Parse a style string into a map of decoded lowercase property name -> parsed
 * and canonicalized value node, via css-tree's tolerant declaration-list
 * parser. This replaces the hand-rolled declaration splitter, per-declaration
 * salvage, escape decoder, and `!important` stripper in one pass: css-tree
 * recovers per-declaration exactly as a browser does (a bogus declaration is
 * dropped, the rest kept), keeps a `;` inside a string/`url()`/paren as part of
 * the value, and exposes `!important` as `node.important` (so an escaped
 * spelling `none!\69mportant` is stripped for free). Property names are
 * escape-decoded and gated to real CSS idents; anything else is dropped (fail
 * open). Later declarations win, per the cascade.
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
      canonicalizeValue(node.value);
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
    backgroundColor(nodeOf("background"));
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
    !hasImageLayer(nodeOf)
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

// One shared fragment parser for every HTML parse in this module (mirroring
// `mdParser` below): all of them must agree on the tokenizer's verdict, so
// there is exactly one parser configuration to reason about.
const htmlParser = unified().use(rehypeParse, { fragment: true });

/**
 * Preorder depth-first walk of a unist tree, calling `visitor(node, index,
 * parent)` on every node whose `type` is `test` (or on every node when `test` is
 * null). `EXIT` ends the walk, `SKIP` leaves the node's children unvisited —
 * the `unist-util-visit` contract, which is what the call sites here are
 * written against.
 *
 * Spelled out rather than imported because `unist-util-visit` allocates a fresh
 * ancestors array and a closure per node, and on a document that is one long
 * flat sibling list — 32k `<p>` elements per megabyte of ordinary HTML — that
 * turns a linear walk super-linear: 3480 ms against this walk's 62 ms over the
 * same 4 MB tree. The three parallel arrays are the stack, so the walk itself
 * allocates nothing per node.
 * @param {any} tree
 * @param {string | null} test
 * @param {(node: any, index: number | undefined, parent: any) => unknown} visitor
 */
function walk(tree, test, visitor) {
  /** @type {any[]} */
  const nodes = [tree];
  /** @type {Array<number | undefined>} */
  const indices = [undefined];
  /** @type {any[]} */
  const parents = [undefined];
  while (nodes.length > 0) {
    const node = nodes.pop();
    const index = indices.pop();
    const parent = parents.pop();
    const result =
      test === null || node.type === test
        ? visitor(node, index, parent)
        : undefined;
    if (result === EXIT) return;
    if (result === SKIP) continue;
    const children = node.children;
    if (children === undefined) continue;
    for (let i = children.length - 1; i >= 0; i--) {
      nodes.push(children[i]);
      indices.push(i);
      parents.push(node);
    }
  }
}

/**
 * `parse` with its most recent (input, tree) pair remembered.
 *
 * Layers 2 and 3 each parse the SAME tool output: `sanitizeHtml` tokenizes it to
 * decide the source-vs-markdown branch, and `detectExfil` tokenizes it again to
 * read `src`/`href` off the elements — two full parse5 runs and two full
 * micromark runs over one document, which is most of what the HTML layer costs
 * on ordinary prose. Every consumer only READS the tree (the sole AST mutation
 * in this module is over a css-tree value parsed per style string), so one tree
 * is safe to hand to both.
 *
 * One entry, replaced on every miss, so the retained footprint is one tree for
 * the document most recently sanitized — the tree that call had allocated
 * anyway. A miss re-parses and answers identically, so the cache can never
 * change a verdict, only what one costs.
 * @param {(text: string) => any} parse
 * @returns {(text: string) => any}
 */
function lastParseCached(parse) {
  /** @type {string | null} */
  let cachedText = null;
  /** @type {any} */
  let cachedTree = null;
  return (text) => {
    if (cachedText === text) return cachedTree;
    // The key is recorded only AFTER the parse returns. A parse that throws —
    // which is how a pathologically nested fragment reaches the fail-closed
    // withhold — must leave the entry untouched, or the next call for that same
    // text hits a key whose tree came from a DIFFERENT document and gets a
    // verdict about the wrong input instead of the withhold.
    const tree = parse(text);
    cachedText = text;
    cachedTree = tree;
    return tree;
  };
}

/**
 * Parse `html` as an HTML fragment with the real tokenizer (parse5, via rehype).
 * @param {string} html
 * @returns {any}
 */
const parseFragment = lastParseCached((html) => htmlParser.parse(html));

/**
 * @param {string} htmlValue
 * @returns {any}
 */
function parseHtmlTag(htmlValue) {
  const tree = parseFragment(htmlValue);
  /** @type {any} */
  let firstElement = null;
  walk(tree, "element", (node) => {
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

/**
 * @typedef {"comment" | "hidden"} SpliceKind
 * @typedef {{ start: number, end: number, kind: SpliceKind }} SpliceRange
 * @typedef {{ placeholder: string, original: string, start: number }} SplicePair
 *   One splice: the keyed placeholder now in the output text, the ORIGINAL
 *   bytes it replaced, and the placeholder's start offset in the RETURNED text.
 *   All offsets in this module — unist positions and these — are plain JS
 *   string indices, i.e. UTF-16 code units.
 */

// The kind-specific prose of a Layer-2 placeholder. The full placeholder is
// built by {@link layer2Placeholder} and matched by {@link LAYER2_PLACEHOLDER_RE};
// keep all three in sync — they are ONE grammar shared with the rehydrating
// hooks and the tests.
const PLACEHOLDER_LABEL = Object.freeze({
  hidden: "hidden HTML",
  comment: "HTML comment",
});

// How many lowercase-hex chars of the sha256 make the placeholder key. 48 bits
// is far past accidental-collision range for the handful of splices one
// document carries, while keeping the placeholder short enough to read.
const PLACEHOLDER_KEY_LEN = 12;

/**
 * The keyed, content-addressed placeholder for one Layer-2 splice:
 * `[hidden HTML removed #<key>]` / `[HTML comment removed #<key>]`, where
 * `<key>` is the first 12 lowercase-hex chars of sha256 over the UTF-8
 * encoding of the ORIGINAL spliced text. Content-addressed on purpose:
 * identical spliced content yields the identical placeholder, so a rehydrator
 * can match placeholder → original by key alone, and duplicated content never
 * produces conflicting keys.
 * @param {SpliceKind} kind
 * @param {string} original the exact text the splice removed
 * @returns {string}
 */
export function layer2Placeholder(kind, original) {
  const key = createHash("sha256")
    .update(original, "utf8")
    .digest("hex")
    .slice(0, PLACEHOLDER_KEY_LEN);
  return `[${PLACEHOLDER_LABEL[kind]} removed #${key}]`;
}

/**
 * The single grammar definition for keyed Layer-2 placeholders — the exact
 * output of {@link layer2Placeholder}, capture group 1 = the key. Global so
 * callers can scan a document for every placeholder; reset `lastIndex` (or
 * use `matchAll`) between uses.
 */
export const LAYER2_PLACEHOLDER_RE =
  /\[(?:hidden HTML|HTML comment) removed #([0-9a-f]{12})\]/g;

// DEPRECATED un-keyed placeholder PREFIXES, kept exported for callers that
// match "some Layer-2 placeholder of this kind" without knowing the key. The
// full placeholder is keyed — build it with {@link layer2Placeholder}, match it
// with {@link LAYER2_PLACEHOLDER_RE}.
export const HIDDEN_PLACEHOLDER = "[hidden HTML removed";
export const COMMENT_PLACEHOLDER = "[HTML comment removed";
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
 * `ranges` sorted by start with every overlap unioned — one entry per
 * placeholder {@link spliceRanges} emits, in the same order as its `pairs`.
 * @param {SpliceRange[]} ranges
 * @returns {SpliceRange[]}
 */
function mergeRanges(ranges) {
  const sorted = [...ranges].sort(
    (left, right) => left.start - right.start || left.end - right.end,
  );
  /** @type {SpliceRange[]} */
  const merged = [];
  for (const range of sorted) {
    const last = merged[merged.length - 1];
    if (last && range.start < last.end) {
      if (range.end > last.end) last.end = range.end;
      // A hidden range absorbed into a comment range (the comment sorts first
      // on a tie) must keep the hidden label — hidden content placeholdered as
      // an "[HTML comment removed …]" would understate what was stripped.
      // Hidden dominates: if either side is hidden, the union is hidden.
      if (range.kind === "hidden") last.kind = "hidden";
    } else {
      merged.push({ ...range });
    }
  }
  return merged;
}

/**
 * Replace each range of `text` with its kind's keyed placeholder, preserving
 * every byte outside the ranges verbatim. Overlapping/nested ranges are merged
 * (defense-in-depth — the scanners emit disjoint ranges).
 *
 * Returns the spliced text plus `pairs`, one per emitted placeholder in output
 * order, each pairing the placeholder with the ORIGINAL bytes it replaced and
 * its start offset in the RETURNED text (UTF-16 code-unit string indices, the
 * same space as `ranges`) — everything a rehydrator needs to undo the splice.
 * @param {string} text
 * @param {SpliceRange[]} ranges
 * @returns {{ text: string, pairs: SplicePair[] }}
 */
export function spliceRanges(text, ranges) {
  const merged = mergeRanges(ranges);
  let out = "";
  let cursor = 0;
  /** @type {SplicePair[]} */
  const pairs = [];
  for (const range of merged) {
    out += text.slice(cursor, range.start);
    const original = text.slice(range.start, range.end);
    const placeholder = layer2Placeholder(range.kind, original);
    pairs.push({ placeholder, original, start: out.length });
    out += placeholder;
    cursor = range.end;
  }
  return { text: out + text.slice(cursor), pairs };
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
 * @returns {{ ranges: SpliceRange[], warned: ReturnType<typeof newWarned> }}
 */
export function scanHtmlFragment(html) {
  return scanFragmentTree(html, parseFragment(html));
}

/**
 * `scanHtmlFragment` for a caller that already has the fragment tree — the
 * dispatch in `sanitizeHtml` parses to decide the branch, so re-parsing there
 * would tokenize the same input twice. `tree` MUST be the parse of `html`;
 * the ranges are offsets into `html`, read from that tree's positions.
 * @param {string} html
 * @param {any} tree
 * @returns {{ ranges: SpliceRange[], warned: ReturnType<typeof newWarned> }}
 */
function scanFragmentTree(html, tree) {
  /** @type {SpliceRange[]} */
  const ranges = [];
  const warned = newWarned();
  // @ts-ignore -- visit callback returns EXIT/SKIP only on matches; implicit undefined return is intentional
  // eslint-disable-next-line consistent-return
  walk(tree, null, (/** @type {any} */ node) => {
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

/** The markdown tree for `text`, cached the same way {@link parseFragment} is.
 * @type {(text: string) => any} */
const parseMarkdown = lastParseCached((text) => mdParser.parse(text));

// A `code` node is a FENCED or INDENTED block and nothing else, so either a
// three-run of backticks/tildes or a line opening on a four-column indent must
// appear somewhere in the text for one to exist. CommonMark expands a tab to
// the next four-column tab stop, so fewer than four spaces followed by a tab is
// an indent too ("  \tfoo" is a code block) — hence ` *\t` rather than `\t`.
// Read over the whole document and deliberately loose (a stray ``` anywhere is
// enough to parse), because the only sound direction to be wrong in here is
// towards parsing.
const MARKDOWN_CODE_HINT = /```|~~~|^(?: {4}| *\t)/m;

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
  const tree = parseFragment(value);
  /** @type {Map<number, number>} */
  const spans = new Map();
  walk(tree, "comment", (/** @type {any} */ node) => {
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
 * @param {SpliceRange[]} ranges
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
 * @param {SpliceRange[]} ranges
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
 * @param {SpliceRange[]} ranges
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
 * @returns {{ ranges: SpliceRange[], warned: ReturnType<typeof newWarned> }}
 */
function scanMarkdown(text) {
  const tree = parseMarkdown(text);
  /** @type {SpliceRange[]} */
  const ranges = [];
  const warned = newWarned();

  // Flow html blocks carry complete markup, so rehype locates comments/hidden
  // elements precisely within them; block-local offsets are shifted to
  // document coordinates.
  walk(tree, "html", (/** @type {any} */ node, _index, parent) => {
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
  walk(tree, null, (/** @type {any} */ node) => {
    if (!PHRASING_ROOTS.has(node.type)) return;
    if (!hasHtmlLeaf(node)) return;
    scanInlineChildren(node, text, ranges, warned);
  });

  return { ranges, warned };
}

/**
 * True when remark finds a code block — fenced or indented — in `text`.
 *
 * Asked before the HTML tokenizer because "no character data outside the
 * markup" cannot see an INDENTED code block: its four leading spaces are
 * whitespace, so a document that is nothing but one indented block
 * (`"    <div hidden>x</div>\n"`) satisfies the rule and takes the source
 * branch, and the hidden element gets spliced out of a block the renderer
 * displays as literal text. A fence escapes only incidentally, because the
 * backticks are non-whitespace character data. Code blocks are markdown-ONLY
 * syntax, so their presence settles the question the same way the tokenizer
 * does — by parsing, not by counting.
 * @param {string} text
 * @returns {boolean}
 */
function hasMarkdownCode(text) {
  if (!MARKDOWN_CODE_HINT.test(text)) return false;
  let found = false;
  walk(parseMarkdown(text), "code", () => {
    found = true;
    return EXIT;
  });
  return found;
}

/**
 * The parsed fragment tree for `text` when `text` is HTML *source*, else null.
 *
 * "HTML source" means the markup accounts for the WHOLE document: the real
 * tokenizer (parse5, via rehype) places every element there is, and the only
 * character data it leaves OUTSIDE all of them is whitespace. That is exactly
 * the property the source branch needs — it hands the whole input to
 * `scanHtmlFragment` as one fragment, which is faithful only when there is no
 * non-HTML syntax around the markup for that parse to misread.
 *
 * Everything else fails OPEN to the markdown branch, which parses with remark
 * and scans only the spans remark itself calls HTML. That is the conservative
 * direction: markdown-only constructs (fenced/indented code, tables, lists)
 * keep their meaning, so an HTML sample inside a code fence is displayed
 * rather than spliced. The dispatch this replaces counted tag-shaped LINES and
 * took the source branch above 30% of them, which got that case wrong — it
 * spliced hidden-element examples out of documentation code blocks.
 *
 * Character data is judged by its DECODED value, as a renderer sees it: the
 * ignored `<html>`/`<head>`/`<body>` tags of a full page leave their
 * surrounding newlines merged into one text node, and `&nbsp;` between two
 * elements is whitespace on the page.
 * @param {string} text
 * @returns {any}
 */
function htmlSourceTree(text) {
  if (hasMarkdownCode(text)) return null;
  const tree = parseFragment(text);
  let sawElement = false;
  // Only ROOT children can hold character data outside an element; everything
  // deeper is by construction inside one.
  for (const node of tree.children) {
    if (node.type === "element") sawElement = true;
    // Comments and the doctype are markup, not character data.
    else if (node.type === "text" && node.value.trim() !== "") return null;
  }
  return sawElement ? tree : null;
}

/**
 * True when `text` is HTML source rather than markdown that merely contains
 * tags — see `htmlSourceTree` for the definition and the fail-open rationale.
 * @param {string} text
 * @returns {boolean}
 */
export function looksLikeHtmlSource(text) {
  return htmlSourceTree(text) !== null;
}

// How many scan/splice rounds one `sanitizeHtml` call may spend before it
// withholds the document instead. Every input measured settles in at most 2;
// the headroom is for a shape the measurement did not reach, and the ceiling is
// what keeps a crafted reveal-chain from buying one whole reparse per node.
const MAX_SPLICE_ROUNDS = 8;

/**
 * `ranges`, which index a text spliced at `merged` (with the resulting
 * `pairs`), translated back into coordinates of the source that was spliced.
 *
 * Every offset outside a placeholder maps by the length the splices before it
 * removed. No offset ever falls INSIDE one: a placeholder holds neither `<`
 * nor `>`, and a scanner range always opens on a `<` and closes after a `>` or
 * at the end of the text — so a placeholder edge is the closest an offset gets,
 * and the same shift is exact there.
 * @param {SpliceRange[]} ranges
 * @param {SpliceRange[]} merged  the spliced spans, sorted, one per pair
 * @param {SplicePair[]} pairs
 * @returns {SpliceRange[]}
 */
function toSourceRanges(ranges, merged, pairs) {
  // Placeholder ends ascend across `pairs`, so the splices before an offset are
  // found by bisection. Walking `pairs` per offset instead costs the product of
  // the two lists, which on a document of 10k hidden elements is 10^8 steps.
  const ends = pairs.map((pair) => pair.start + pair.placeholder.length);
  const shifts = merged.map((range, index) => range.end - ends[index]);
  /** @param {number} offset @returns {number} */
  const toSource = (offset) => {
    let low = 0;
    let high = ends.length;
    while (low < high) {
      const mid = Math.floor((low + high) / 2);
      if (ends[mid] <= offset) low = mid + 1;
      else high = mid;
    }
    return low === 0 ? offset : offset + shifts[low - 1];
  };
  return ranges.map((range) => ({
    start: toSource(range.start),
    end: toSource(range.end),
    kind: range.kind,
  }));
}

/**
 * Layer 2 over web-ingress text: splice out HTML comments and hidden elements
 * (keyed placeholders mark the cuts; all other bytes are preserved verbatim)
 * and count preserved scripting/resource tags for the caller's warning. Returns
 * null when there is nothing to strip and nothing to report.
 *
 * `splices` pairs every emitted placeholder with the original bytes it
 * replaced (see {@link spliceRanges}), so a caller can rehydrate the text —
 * nothing is lost, only hidden behind an identity-carrying placeholder.
 *
 * `unparseable` is set (true) only on the fail-closed path below, where the
 * whole input was withheld behind {@link UNPARSEABLE_PLACEHOLDER} rather than
 * spliced — the caller's warning must describe a whole-output withhold, not a
 * splice. There `splices` is `[]`: the parser blew up before any span could be
 * located, so nothing is recoverable per-splice (the caller's pre-splice
 * `reveal` is the only copy).
 *
 * Idempotent over its own output, and by CONSTRUCTION rather than by argument:
 * the scan is re-run over the spliced text until it finds nothing more, so the
 * returned text is a fixed point. One pass is not enough on its own, because
 * removing an element changes how parse5 reparents the bytes around it, which
 * can flip {@link htmlSourceTree}'s markdown/source verdict for the next run.
 * A document that has not settled within {@link MAX_SPLICE_ROUNDS} rounds is
 * withheld whole, on the same fail-closed path a parser blow-up takes.
 * @param {string} text
 * @returns {{ text: string, removed: { comments: number, hidden: number }, warned: { tags: Record<string, number>, dataSrc: number }, splices: SplicePair[], unparseable?: true } | null}
 */
export function sanitizeHtml(text) {
  if (!HTML_TAG_PRESENT.test(text)) return null;
  /** @type {SpliceRange[]} Every span found so far, in SOURCE coordinates. */
  let ranges = [];
  let spliced = { text, pairs: /** @type {SplicePair[]} */ ([]) };
  const removed = { comments: 0, hidden: 0 };
  /** @type {ReturnType<typeof newWarned>} */
  let warned;
  // Each round splices at least one more span of `text`, so the covered length
  // grows strictly and the loop terminates. A placeholder holds no `<`, so no
  // round can find a span inside one and re-cover ground already covered.
  for (let round = 0; ; round++) {
    // Termination alone is not a cost bound: each round is a whole reparse, so
    // an input that reveals one more node per round would pay one per node.
    // This refuses past the ceiling instead, the way MAX_DEPTH in output.mjs
    // refuses past a nesting depth.
    /* c8 ignore start -- no input is known to reach round MAX_SPLICE_ROUNDS:
       370k adversarial draws over the shapes that DO chain (a stray `<td>` the
       source branch drops, a bogus comment, the adoption-agency reparent that
       flips the branch) settle in at most 2. Defense in depth on the
       web-ingress boundary, not a path with a fixture. */
    if (round === MAX_SPLICE_ROUNDS)
      return {
        text: UNPARSEABLE_PLACEHOLDER,
        removed: { comments: 0, hidden: 1 },
        warned: newWarned(),
        splices: [],
        unparseable: true,
      };
    /* c8 ignore stop */
    /** @type {{ ranges: SpliceRange[], warned: ReturnType<typeof newWarned> }} */
    let scan;
    try {
      // One parse decides the branch AND feeds it, so the source branch does not
      // tokenize the input twice.
      const sourceTree = htmlSourceTree(spliced.text);
      scan = sourceTree
        ? scanFragmentTree(spliced.text, sourceTree)
        : scanMarkdown(spliced.text);
    } catch {
      // The parse/visit blew up (stack overflow on pathological nesting, or any
      // other parser error). Fail CLOSED at this boundary so `sanitize`/
      // `sanitizeText` keep their never-throw contract: withhold the whole input
      // behind a placeholder and report it as hidden content removed.
      return {
        text: UNPARSEABLE_PLACEHOLDER,
        removed: { comments: 0, hidden: 1 },
        warned: newWarned(),
        splices: [],
        unparseable: true,
      };
    }
    // The last scan saw exactly the text being returned, so its tag counts are
    // the ones that describe that text.
    warned = scan.warned;
    if (scan.ranges.length === 0) break;
    // Re-splice from the SOURCE every round: pairs then carry original bytes
    // and offsets into the returned text, never a nested earlier placeholder.
    const grown = mergeRanges([
      ...ranges,
      ...toSourceRanges(scan.ranges, ranges, spliced.pairs),
    ]);
    const next = spliceRanges(text, grown);
    /* c8 ignore next 4 -- unreachable: every range holds a `<` and no
       placeholder does, so each round covers source bytes the last one did
       not and the text must change. Kept because the alternative to this
       stop is a hook that spins on untrusted input. */
    if (next.text === spliced.text) break;
    for (const range of scan.ranges)
      removed[range.kind === "comment" ? "comments" : "hidden"]++;
    ranges = grown;
    spliced = next;
  }
  if (ranges.length === 0 && !hasWarned(warned)) return null;
  return {
    text: spliced.text,
    removed,
    warned,
    splices: spliced.pairs,
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
// fetched pages. The OAuth callback pair (`code`, `state`) is listed for that
// same trade: a redirect URL is one of the most common things a fetched page or
// a browser tool prints, and both values are opaque by design (an authorization
// code, a signed CSRF nonce), so the value shape cannot separate them from a
// payload.
const BENIGN_BLOB_PARAM_RE =
  /^(?:x-(?:amz|goog|ms|oss|obs)-[a-z0-9-]+|amz-[a-z0-9-]+|utm_[a-z]+|sig|signature|hmac|policy|credential|expires|key-pair-id|se|sp|sr|sv|st|spr|si|skoid|sktid|code|state|cursor|after|before|continuation|continuationtoken|continuation_token|pagetoken|page_token|nexttoken|next_token|gclid|fbclid|dclid|msclkid|gbraid|wbraid|_ga|_gl|mc_eid|mc_cid)$/i;

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
 * @returns {Array<[string, string, string]>} [lowercased name, value, RAW (case-preserved) name]
 */
function rawParams(qs) {
  /** @type {Array<[string, string, string]>} */
  const pairs = [];
  for (const pair of qs.split(/[&;]/)) {
    if (!pair) continue;
    const eq = pair.indexOf("=");
    const rawName = eq === -1 ? pair : pair.slice(0, eq);
    const value = eq === -1 ? "" : pair.slice(eq + 1);
    pairs.push([rawName.toLowerCase(), value, rawName]);
  }
  return pairs;
}

/**
 * Exfil reason for one URL parameter, or null. A credential-shaped or
 * blob-shaped run in EITHER half of the pair — the value, or the name — in any
 * non-allowlisted parameter. Testing the name too (not just the value) is what
 * catches a payload that lands on the wrong side of the `=`: `?<blob>`,
 * `?<blob>=`, `?<blob>==` (trailing `=`s read as padding) and `?<blob>=x` (any
 * non-padding tail) are one channel, since the server reads the query string
 * either way. Allowlisted signing/pagination/analytics parameters are skipped
 * entirely (see BENIGN_BLOB_PARAM_RE).
 * @param {string} name    lowercased parameter name, for the allowlist gate
 * @param {string} value   RAW (un-decoded) value
 * @param {string} rawName RAW (case-preserved, un-decoded) name
 * @returns {string | null}
 */
function paramExfilReason(name, value, rawName) {
  if (BENIGN_BLOB_PARAM_RE.test(name)) return null;
  for (const candidate of [rawName, value]) {
    if (!candidate) continue;
    // A leaked credential is an OPAQUE, separator-free token. Gate the
    // secret-shape/digit test on the CONTIGUOUS opaque run(s), not on the whole
    // prose candidate: a benign path-like value (`?redirect=/authorization-
    // service/…abcdefghij1234567890`) otherwise matches "authorization" in one
    // place and a 20-char run in another and false-fires. Requiring both on the
    // SAME run keeps `ghp_…`-style contiguous tokens firing while dropping prose.
    const opaqueRuns = candidate.match(OPAQUE_TOKEN_RE);
    if (
      opaqueRuns?.some(
        (run) => VALUE_HAS_DIGIT_RE.test(run) && matchesSecretHint(run),
      )
    )
      return "credential-shaped token in URL parameter";
    if (isBlobValue(candidate) || decodedBlobMatch(candidate))
      return "suspicious query parameter";
  }
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
    for (const [name, value, rawName] of rawParams(segment)) {
      if (!KEYWORD_PARAM_NAME_RE.test(name)) continue;
      const reason = paramExfilReason(name, value, rawName);
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
  for (const [name, value, rawName] of rawParams(parsed.search.slice(1))) {
    const reason = paramExfilReason(name, value, rawName);
    if (reason) return reason;
  }
  // The fragment carries the same `key=value` channel (`#token=…`); a bare
  // anchor (`#section-2`) yields one empty-value param that trips nothing.
  for (const [name, value, rawName] of rawParams(parsed.hash.slice(1))) {
    const reason = paramExfilReason(name, value, rawName);
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
 *
 * `autoFetched` says whether reaching this URL takes a deliberate act. Exactly
 * one attribute here does: `href` on an `<a>`, which somebody has to follow.
 * Every other one is fetched by the renderer on sight (`src`, `srcset`,
 * `background`, and `href` on a `<link>`), fires on a click aimed at something
 * else (`ping`), or navigates on its own (a form action, a meta refresh). The
 * distinction is the caller's severity line, not a detection line — the URL is
 * reported either way (see the exfil tier in ../src/output.mjs).
 * @param {string} text
 * @returns {Array<{ url: string, isImage: boolean, autoFetched: boolean, context: "resource" | "form" | "refresh" }>}
 */
function extractHtmlUrls(text) {
  const tree = parseFragment(text);
  /** @type {Array<{ url: string, isImage: boolean, autoFetched: boolean, context: "resource" | "form" | "refresh" }>} */
  const urls = [];
  walk(tree, "element", (/** @type {any} */ node) => {
    // hast element nodes always carry a `properties` object (parse5 sets it).
    const props = node.properties;
    const isImage = node.tagName === "img";
    const isAnchor = node.tagName === "a";
    for (const key of ["src", "href", "background"])
      if (typeof props[key] === "string")
        urls.push({
          url: props[key],
          isImage,
          autoFetched: !(key === "href" && isAnchor),
          context: "resource",
        });
    for (const key of ["srcSet", "ping"])
      for (const url of multiUrlAttr(props[key]))
        urls.push({ url, isImage, autoFetched: true, context: "resource" });
    for (const key of ["action", "formAction"])
      if (typeof props[key] === "string")
        urls.push({
          url: props[key],
          isImage: false,
          autoFetched: true,
          context: "form",
        });
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
      if (url)
        urls.push({
          url,
          isImage: false,
          autoFetched: true,
          context: "refresh",
        });
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
 * @typedef {{ url: string, isImage: boolean, autoFetched: boolean, context: "resource" | "form" | "refresh" }} CollectedUrl
 */

/**
 * Every URL a Layer-3 detector reads: markdown links/images/definitions plus the
 * URL-bearing HTML attributes `extractHtmlUrls` covers. Both detectors below
 * consume this rather than deciding for themselves what counts as a URL, so a
 * node type is either in scope for all of them or for none — a second walk is
 * how one detector silently stops covering a shape the other still does.
 * `parseMarkdown` memoizes its last tree, so the detectors running back to back
 * over one document share the parse as well as the definition.
 *
 * A markdown node is reported with `context: "resource"`, which is the context
 * that applies no off-origin rule — markdown carries no form or refresh target.
 * @param {string} text
 * @returns {CollectedUrl[]}
 */
function collectUrls(text) {
  /** @type {CollectedUrl[]} */
  const urls = [];
  // Remark AST handles markdown links/images/definitions (balanced parens,
  // reference links, GFM autolink literals) correctly, unlike a hand-rolled
  // regex.
  walk(parseMarkdown(text), null, (node) => {
    if (
      node.type !== "link" &&
      node.type !== "image" &&
      node.type !== "definition"
    )
      return;
    urls.push({
      url: node.url,
      isImage: node.type === "image",
      // A markdown image is fetched the moment the document renders; a link
      // (or a definition, which only names one) is not.
      autoFetched: node.type === "image",
      context: "resource",
    });
  });
  // HTML attributes (not AST nodes in remark).
  urls.push(...extractHtmlUrls(text));
  return urls;
}

/**
 * Layer 3: report data-exfil-shaped URLs in markdown links/images/definitions
 * and HTML attributes (src/href/background/srcset/ping, form action/formaction,
 * meta-refresh). Detection only — the text is never modified; the caller
 * surfaces the threats as a warning.
 *
 * `autoFetched` marks a threat that needs no deliberate act to fire — a
 * rendered image, a stylesheet, a form target, a meta refresh — as opposed to a
 * link somebody has to follow. Both are reported; the caller uses it to decide
 * how loudly (see the exfil tier in ./output.mjs).
 * @param {string} text
 * @returns {Array<{ isImage: boolean, autoFetched: boolean, reason: string, target: string }> | null}
 */
export function detectExfil(text) {
  if (!needsUrlScan(text)) return null;

  /** @type {Array<{ isImage: boolean, autoFetched: boolean, reason: string, target: string }>} */
  const threats = [];

  try {
    for (const { url, isImage, autoFetched, context } of collectUrls(text)) {
      const reason =
        checkExfilUrl(url) ||
        (context !== "resource" && isOffOrigin(url)
          ? OFF_ORIGIN_REASON[context]
          : null);
      if (!reason) continue;
      threats.push({ isImage, autoFetched, reason, target: urlHost(url) });
    }
  } catch {
    // The parse/visit blew up (stack overflow on pathological nesting). Fail
    // CLOSED so the never-throw contract holds: report one sentinel threat so
    // the caller still warns rather than crashing, since an input too nested to
    // scan could itself be hiding an exfil URL.
    return [
      {
        isImage: false,
        // Fail closed on the severity tier too: an input the scanner could not
        // read is not evidence that what it hides is harmless.
        autoFetched: true,
        reason: "input too deeply nested to scan for exfil URLs",
        target: "(unparseable HTML)",
      },
    ];
  }

  return threats.length > 0 ? threats : null;
}

/**
 * Layer 3, second detector: report URLs whose HOST is a confusable of an ASCII
 * name (`аpple.com`). Detection only, and deliberately independent of the
 * exfil-shape test above — a homoglyph domain needs no suspicious query to be
 * the whole attack, so `https://аpple.com/docs` is reported while
 * {@link detectExfil} stays silent on it.
 *
 * Fails CLOSED on a parse blow-up for the same reason detectExfil does.
 * @param {string} text
 * @returns {Array<{ severity: string, description: string }> | null}
 */
export function detectConfusableHosts(text) {
  if (!needsUrlScan(text)) return null;

  /** @type {Array<{ severity: string, description: string }>} */
  const threats = [];
  /** @type {Set<string>} */
  const seen = new Set();

  try {
    for (const { url } of collectUrls(text)) {
      const found = confusableHost(url);
      // One host repeated across a document is one deception, not N.
      if (!found || seen.has(found.ascii)) continue;
      seen.add(found.ascii);
      threats.push({
        severity: found.severity,
        description: describeConfusableHost(found),
      });
    }
  } catch {
    return [
      {
        severity: SEVERITY.WARNING,
        description: "input too deeply nested to scan for confusable hosts",
      },
    ];
  }

  return threats.length > 0 ? threats : null;
}
