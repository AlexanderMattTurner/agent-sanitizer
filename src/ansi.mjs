/**
 * The ONE ANSI grammar: the raw control-introducer charset and the tokenizer
 * every consumer scans with.
 *
 * Two modules need this grammar and they cannot import each other —
 * `layer1.mjs` imports `invisible.mjs`, so `invisible.mjs` (which owns the
 * public `isSgrOnly` / `SGR_RE`) must not import back. Before this module the
 * grammar was therefore written out twice with DIFFERENT param rules
 * (`invisible.mjs`'s SGR regex accepted any digit run, `layer1.mjs`'s CSI
 * branch capped each parameter at four digits), and the introducer charset
 * three times. The looser copy suppressed the operator warning for a sequence
 * the stripper could not match: `ESC[12345m` read as "display-only colour"
 * while `[12345m` was spliced into the model's view as visible text. One
 * tokenizer, one charset, consumed by both — the disagreement cannot recur.
 *
 * Same precedent (and same reason) as `cf-charset.mjs`: a dependency-free leaf
 * module both layers read from.
 */

// Raw control introducers that must not survive Layer 1: 7-bit ESC (U+001B) and
// the entire 8-bit C1 control block (U+0080-U+009F) — which includes CSI
// (U+009B), the string introducers DCS/SOS/OSC/PM/APC
// (U+0090/0098/009D/009E/009F), and ST (U+009C). Gating the whole C1 block, not
// just the introducers the sequence grammar below names, fails closed: a
// DCS/SOS/PM/APC string the grammar does not consume still loses its introducer
// and terminator, so no terminal can hide-render its body as a control payload.
//
// A SOURCE STRING, not a literal: three call sites need it with different flags
// (`g` for the Layer-1 sweep, unflagged for the prompt gate, `g` again to drive
// the scan below), and spelling the class out at each site is how the three
// copies came to spell the same byte two different ways — which defeats a
// grep-based drift check as well. Building from `\uXXXX` escapes keeps every
// raw control byte out of the source (no `no-control-regex` disable needed).
export const CONTROL_INTRODUCER_SOURCE = "[\\u001b\\u0080-\\u009f]";

// SGR (Select Graphic Rendition): colors, bold, reset. The grammar is closed:
// params are [0-9;:]* and the final byte is `m`, so a match can only restyle
// text — never reposition the cursor, erase, or smuggle an OSC string. `:` is
// included alongside `;` because ITU T.416 colon-separated SGR sub-parameters
// (truecolor `ESC[38:2:255:0:0m`, as emitted by tmux/kitty/mintty) are pure
// display-only SGR too. A SGR sequence has TWO encodings: the 7-bit `ESC [ … m`
// and the 8-bit C1 form where a single U+009B (CSI) replaces `ESC [`; both must
// be recognized, or a C1-introduced `U+009B 31m … 0m` is pure color yet is
// misread as a non-SGR payload.
const SGR_SOURCE = "(?:\\u001b\\[|\\u009b)[0-9;:]*m";

/**
 * Public alias kept for compatibility (re-exported by `invisible.mjs` and the
 * package root). It is now DERIVED: {@link scanAnsi} classifies a token as SGR
 * by testing the token's own text against this exact source, so the predicate
 * and the regex can no longer describe different languages.
 */
export const SGR_RE = new RegExp(SGR_SOURCE, "g");

// The same language, anchored — the SGR/CSI discriminator for a token the
// scanner has already delimited.
const SGR_ANCHORED_RE = new RegExp(`^${SGR_SOURCE}$`);

// Private parameter-prefix and intermediate bytes that may follow an
// introducer before the parameters (`ESC[?25h`, `ESC(B`, `ESC#8`). Also covers
// the 7-bit `ESC [` CSI introducer's bracket itself.
const CSI_INTRO_RE = /[[()#;?]/;

// ECMA-48 parameter bytes.
const CSI_PARAM_RE = /[0-9;:]/;

// ECMA-48 final bytes, minus the ones a terminal never accepts here. Digits are
// PARAMETER bytes and can never terminate a sequence — an unterminated `ESC[`
// must not eat trailing visible digits (`ESC[2024 report` is NOT `ESC[` +
// final-byte `2`; it is an incomplete intro whose ESC the residual sweep
// removes, leaving "2024 report" intact). `<=>?` (0x3C-0x3F) are private
// PARAMETER-prefix bytes per ECMA-48 § 5.4, not finals — including them let a
// private-marker sequence terminate one byte too early. `~` (0x7E) IS a real
// final byte (vt220 function keys, `ESC[3~` for Delete) and is kept.
const CSI_FINAL_RE = /[A-PR-TZcf-nqrty~]/;

const ESC = 0x1b;
const CSI_C1 = 0x9b;
const ST_C1 = 0x9c;
const OSC_C1 = 0x9d;
const BEL = 0x07;

/** The four things an introducer can turn out to be. */
export const TOKEN_KIND = Object.freeze({
  /** A display-only `ESC[…m` / `U+009B…m` colour sequence. */
  SGR: "sgr",
  /** Any other complete CSI / two-byte escape (cursor move, erase, charset). */
  CSI: "csi",
  /** An OSC string: introducer, body and terminator as one unit. */
  OSC: "osc",
  /** An introducer that starts no sequence the grammar recognizes. */
  ORPHAN: "orphan-introducer",
});

/**
 * @typedef {object} AnsiToken
 * @property {number} start Index of the introducer.
 * @property {number} end Index one past the last character of the token.
 * @property {string} kind One of {@link TOKEN_KIND}.
 */

/**
 * End index of the OSC string starting at `start`, or -1 if no OSC introducer
 * is there.
 *
 * An OSC (Operating System Command) string is `<introducer> body <terminator>`:
 * a title, a clickable-hyperlink URL, a clipboard write — i.e. attacker-
 * controlled PAYLOAD TEXT. Consuming the introducer alone would leave that
 * payload in the model's view, so the whole string is one token. Three ways it
 * can end:
 *   1. a real terminator — ST (`ESC\` or the 8-bit C1 ST U+009C) or the legacy
 *      BEL — which is consumed with the body.
 *   2. an ABORT: per ECMA-48/xterm a bare ESC (one not forming ST) drops the
 *      terminal out of the OSC string, and a nested C1 OSC introducer likewise
 *      starts something new. The token ends BEFORE that byte so the scan
 *      re-reads it as its own sequence — without this, an interior ESC deleted
 *      the rest of the document via case 3.
 *   3. end of input, for a genuinely unterminated string: fail closed and drop
 *      everything from the introducer on, so no OSC body survives.
 * @param {string} text
 * @param {number} start
 * @returns {number}
 */
function scanOsc(text, start) {
  const code = text.charCodeAt(start);
  let i = -1;
  if (code === OSC_C1) i = start + 1;
  if (code === ESC && text[start + 1] === "]") i = start + 2;
  if (i < 0) return -1;
  for (; i < text.length; i++) {
    const byte = text.charCodeAt(i);
    if (byte === BEL || byte === ST_C1) return i + 1;
    if (byte === ESC) return text[i + 1] === "\\" ? i + 2 : i;
    if (byte === OSC_C1) return i;
  }
  return text.length;
}

/**
 * End index of the CSI / two-byte escape sequence starting at `start`, or -1
 * when the introducer completes no sequence.
 *
 * Single-pass and greedy: intro bytes, then parameter bytes, then exactly one
 * final byte. The previous regex form had to BOUND the intro run ({0,12})
 * because `;` lives in both the intro and parameter classes, so an unbounded
 * run let a `;#;#…` string be split between the two quantifiers — quadratic
 * backtracking (CodeQL js/polynomial-redos). A hand-written scanner never
 * backtracks, so the bound is gone and the scan is linear by construction.
 * @param {string} text
 * @param {number} start
 * @returns {number}
 */
function scanCsi(text, start) {
  const code = text.charCodeAt(start);
  if (code !== ESC && code !== CSI_C1) return -1;
  let i = start + 1;
  while (i < text.length && CSI_INTRO_RE.test(text[i])) i++;
  while (i < text.length && CSI_PARAM_RE.test(text[i])) i++;
  if (i < text.length && CSI_FINAL_RE.test(text[i])) return i + 1;
  return -1;
}

// Drives the scan: jumping introducer-to-introducer keeps the common case (text
// with no escapes at all) a single native regex scan rather than a per-character
// JS loop.
const INTRODUCER_SCAN_RE = new RegExp(CONTROL_INTRODUCER_SOURCE, "g");

/**
 * Tokenize every raw control introducer in `text`.
 *
 * Every introducer yields exactly one token — an ORPHAN when it starts nothing
 * the grammar recognizes — so "which introducers are in this text" and "which
 * sequences are in this text" are answered by the same scan. That is what lets
 * the stripper (splice every non-orphan token, then sweep) and the SGR-only
 * predicate (every token is SGR) agree by construction.
 *
 * Tokens are disjoint and ordered by `start`; each `end` is strictly greater
 * than its `start`, so the scan always advances.
 * @param {string} text
 * @returns {AnsiToken[]}
 */
export function scanAnsi(text) {
  /** @type {AnsiToken[]} */
  const tokens = [];
  INTRODUCER_SCAN_RE.lastIndex = 0;
  let match;
  while ((match = INTRODUCER_SCAN_RE.exec(text)) !== null) {
    const start = match.index;
    const oscEnd = scanOsc(text, start);
    const csiEnd = oscEnd < 0 ? scanCsi(text, start) : -1;
    let end = start + 1;
    /** @type {string} */
    let kind = TOKEN_KIND.ORPHAN;
    if (oscEnd >= 0) {
      end = oscEnd;
      kind = TOKEN_KIND.OSC;
    } else if (csiEnd >= 0) {
      end = csiEnd;
      kind = SGR_ANCHORED_RE.test(text.slice(start, csiEnd))
        ? TOKEN_KIND.SGR
        : TOKEN_KIND.CSI;
    }
    tokens.push({ start, end, kind });
    INTRODUCER_SCAN_RE.lastIndex = end;
  }
  return tokens;
}
