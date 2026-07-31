/**
 * Layer 1: ANSI + invisible-character stripping. The zero-dependency core shared
 * by the convenience `sanitize` (index.mjs), the tool-output pipeline
 * (output.mjs), and the Edit-repair rehydrator (rehydrate.mjs) — a single
 * implementation so every consumer derives the EXACT view the model was shown (a
 * re-implementation would drift, and rehydration's soundness gate depends on
 * re-cleaning reproducing the view).
 *
 * Lone-surrogate normalization is NOT applied by {@link applyLayer1} itself: it
 * is exported as {@link LONE_SURROGATE_RE} for consumers to apply at the boundary
 * that needs a well-formed string (the redactor input in output.mjs's
 * processLayer1 / re-redact, and before the HTML tokenizer), because that is the
 * point where a lone surrogate would otherwise corrupt a match or a parse.
 */
import { stripInvisibleWithReport, CATEGORY } from "./invisible.mjs";

// Raw control introducers that must not survive: 7-bit ESC (U+001B) and the
// entire 8-bit C1 control block (U+0080–U+009F) — which includes CSI (U+009B),
// the string introducers DCS/SOS/OSC/PM/APC (U+0090/0098/009D/009E/009F), and ST
// (U+009C). All are category Cc, so the invisible-char pass (which targets Cf /
// variation / blank fillers) never removes them; this residual sweep is the
// guarantee that none survives. Sweeping the whole C1 block — not just the
// introducers the ANSI grammar above names — fails closed: a DCS/SOS/PM/APC
// string the grammar does not consume still loses its introducer and terminator
// here, so no terminal can hide-render its body as a control payload.
// eslint-disable-next-line no-control-regex -- matching the raw introducers is the point
const CONTROL_INTRODUCER_RE = /[\u001b\u0080-\u009f]/g;

// An OSC (Operating System Command) string is `<introducer> … <terminator>`.
// Introducer: 7-bit `ESC]` or 8-bit C1 OSC (U+009D). Terminator: ST (`ESC\` or
// 8-bit C1 ST U+009C) OR the legacy BEL (U+0007). The body is everything up to
// the terminator — a title, a clickable-hyperlink URL, a clipboard write — i.e.
// attacker-controlled PAYLOAD TEXT. Matching the introducer alone (leaving the
// body) would let that payload survive into the model's view, so the OSC branch
// consumes the introducer, the whole body, AND the terminator as one unit.
//
// Three alternatives, tried in order:
//   1. a properly TERMINATED string — a body of bytes that no terminator can
//      start with (the negated class makes that run unambiguous and
//      backtrack-free), then a terminator (ST or BEL).
//   2. an ABORTED string — the body runs up to (but does NOT consume) an
//      interior bare ESC or a nested C1-OSC introducer (U+009D) that is not
//      itself part of a valid terminator. Per ECMA-48/xterm, a bare ESC (one
//      not immediately followed by `\` to form ST) aborts the OSC string in
//      progress — the terminal drops back to processing that ESC as the start
//      of a NEW sequence, and everything after it is normal text/escapes, not
//      part of this OSC's payload. Consuming only up to the lookahead (not
//      the ESC/U+009D itself) leaves it for the next position in this same
//      `.replace(ANSI_RE, ...)` scan to match as its own sequence (or, if it
//      doesn't complete one, for the residual C1 sweep in applyLayer1 to
//      remove just that one introducer byte) — so an interior ESC can no
//      longer delete the rest of the document (it used to fall through to
//      alternative 3 below and consume everything to EOS).
//   3. anything else from the introducer to END-OF-STRING (`[\s\S]*$`) — the
//      fail-closed catch-all for a GENUINELY unterminated string: no ST, BEL,
//      interior ESC, or nested OSC intro anywhere in the remainder, so there
//      is truly nothing left to hand to a later position. Reached only when
//      alternatives 1 and 2 both fail to find their respective triggers.
// All three are linear (bounded lookahead / no nested quantifiers), so the
// branch stays linear.
const OSC_INTRO = "(?:\\u001b\\]|\\u009d)";
const OSC_TERM = "(?:\\u001b\\\\|\\u009c|\\u0007)";
const OSC_BODY = "[^\\u0007\\u001b\\u009c\\u009d]";
const OSC_BRANCH = `${OSC_INTRO}(?:${OSC_BODY}*${OSC_TERM}|${OSC_BODY}*(?=[\\u001b\\u009d])|${OSC_BODY}*$)`;

// CSI / two-byte ESC sequences (cursor moves, erase, SGR color, charset/DEC
// selectors): an introducer, a bounded private-intro run, optional numeric
// params, and a single final byte. Not an enforcement boundary on its own — any
// introducer this declines to match is still removed by the residual sweep in
// applyLayer1 — but matching the whole sequence keeps the common case one clean
// deletion (and avoids a lone-ESC residual on every styled line).
//
// The private-intro class is BOUNDED ({0,12}, not *) on purpose: ; and # live
// in both this class and the parameter group that follows, so an unbounded *
// here lets a ;#;#... run be split between the two quantifiers — O(n^2)
// backtracking on an ESC;#;#... string that never completes a sequence
// (CodeQL js/polynomial-redos). A constant bound makes the intro a constant
// factor, so the whole match is linear; a real sequence never carries more than
// a couple of intro bytes.
//
// Params allow BOTH `;` (standard parameter separator) and `:` (ITU T.416
// colon-separated SGR sub-parameters, e.g. truecolor `ESC[38:2:255:0:0m` as
// emitted by tmux/kitty/mintty) — legitimate, display-only ANSI that must not
// leave a colon-parameter residue behind.
//
// The final-byte class deliberately excludes `\d`: per ECMA-48, CSI final
// bytes occupy 0x40–0x7E (letters and a handful of punctuation) while digits
// are PARAMETER bytes and can never terminate a sequence — an unterminated
// `ESC[` therefore must not be allowed to eat trailing visible digits (e.g.
// `ESC[2024 report` is NOT `ESC[` + final-byte `2` + literal `024 report`; it
// is an incomplete CSI intro that the residual sweep in applyLayer1 cleans up,
// leaving "2024 report" intact). `=`, `<`, `>` are excluded for the same
// reason: 0x3C–0x3F (`<=>?`) are private PARAMETER-prefix bytes, not final
// bytes, per ECMA-48 § 5.4 — `?` already lives in the private-intro class
// above; `<=>` were never valid finals and including them let a private-marker
// sequence terminate one byte too early. `~` (0x7E) IS a real final byte (vt220
// function-key sequences, e.g. `ESC[3~` for Delete) and is kept.
const CSI_BRANCH =
  "[\\u001b\\u009b][[()#;?]{0,12}(?:(?:\\d{1,4}(?:[;:]\\d{0,4})*)?[A-PR-TZcf-ntqry~])";

// Full ANSI escape grammar (OSC first so `ESC]` / C1-OSC is consumed as a whole
// string, not split by the CSI branch), not just SGR: the Layer-1 guarantee is
// that no control introducer and no OSC payload survives, and a cursor-move or
// erase sequence is as much a display-spoofing hazard as a color one. Built from
// `\uXXXX`-escaped string parts via `new RegExp`, so no raw control byte sits in
// the source (no no-control-regex disable needed).
const ANSI_RE = new RegExp(`(?:${OSC_BRANCH}|${CSI_BRANCH})`, "gu");

// Unpaired UTF-16 surrogates (high not followed by low, or low not preceded by
// high). Normalized before any HTML parser, which throws on a stray byte —
// which would otherwise let a single malformed code unit suppress all output.
export const LONE_SURROGATE_RE =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

const MAX_ANSI_PASSES = 3;

/**
 * Strip ANSI escape sequences to a fixed point. Removing one sequence can
 * reconstitute another around it (a lone ESC left of `ESC[32m[0m` gains the
 * trailing `[0m` once the inner sequence is removed, forming a brand-new valid
 * sequence the single pass would miss), so iterate — but only a fixed few
 * times. Bounding by the input's ESC count is quadratic on attacker-controlled
 * text: `("\x1b[").repeat(n) + "m".repeat(n)` reconstitutes exactly ONE
 * sequence per pass, so n full O(n) scans run, and 48 KB already costs seconds.
 * The passes are not what makes Layer 1 safe — applyLayer1's residual
 * CONTROL_INTRODUCER_RE sweep is, and it removes every ESC/C1 byte whatever
 * survives here. Past the bound a reconstituted sequence therefore degrades to
 * VISIBLE text rather than a hidden control, which is the fail-open direction.
 * @param {string} input
 * @returns {string}
 */
export function stripAnsiFully(input) {
  let prev = input;
  let out = prev.replace(ANSI_RE, "");
  for (let pass = 1; pass < MAX_ANSI_PASSES && out !== prev; pass++) {
    prev = out;
    out = prev.replace(ANSI_RE, "");
  }
  return out;
}

/**
 * Layer 1: ANSI + invisible-char strip with a result guaranteed free of every
 * raw ANSI control introducer (7-bit ESC U+001B and the whole 8-bit C1 control
 * block U+0080–U+009F: CSI, the DCS/SOS/OSC/PM/APC string introducers, and ST).
 *
 * Removing an invisible character can reconstitute an escape its split hid from
 * the ANSI pass (`ESC`<ZWSP>`[32m` → `ESC[32m`), so strip ANSI again after the
 * invisible pass — but only when stripInvisible changed something, since
 * reconstitution is impossible otherwise and the re-strip is a wasted pass on
 * the hot clean path. The ANSI strip still cannot match an *incomplete*
 * reconstituted sequence (a lone `ESC[` left when an inner complete sequence is
 * removed from a nested split), so a final sweep removes every residual raw
 * introducer outright — that sweep, not the regex matching, is the guarantee
 * that no control introducer survives. `deAnsi` is the ANSI strip of the
 * original (invisible runs intact), the scope a LONG_RUN payload check needs.
 * @param {string} text
 * @returns {{ cleaned: string, deAnsi: string, found: string[] }}
 */
export function applyLayer1(text) {
  const deAnsi = stripAnsiFully(text);
  // stripInvisibleWithReport returns `found` for exactly the categories it
  // removed — so a ZWNJ/ZWJ the carve-out PRESERVES never registers as a strip,
  // and the leading-BOM exception is already handled inside it. Pass the ORIGINAL
  // `text` so a BOM that was interior before the ANSI strip (`ESC[m + interior U+FEFF`, now at
  // index 0 of `deAnsi`) is treated as interior and stripped, not preserved.
  const { cleaned: afterInvis, found } = stripInvisibleWithReport(deAnsi, text);
  let ansiFound = deAnsi.length !== text.length;

  let cleaned = afterInvis;
  if (afterInvis !== deAnsi) {
    const reStripped = stripAnsiFully(afterInvis);
    if (reStripped.length !== afterInvis.length) ansiFound = true;
    cleaned = reStripped;
  }
  const swept = cleaned.replace(CONTROL_INTRODUCER_RE, "");
  if (swept !== cleaned) {
    cleaned = swept;
    ansiFound = true;
  }

  if (ansiFound) found.push(CATEGORY.ANSI);
  return { cleaned, deAnsi, found };
}
