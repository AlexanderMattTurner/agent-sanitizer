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
// just the introducers the sequence grammar below names, fails closed: a C1 byte
// the grammar recognizes no sequence for still loses that byte, so no terminal
// can hide-render what follows it as a control payload.
//
// The introducer set as DATA, so a non-JS consumer can share it: the generator
// (scripts/gen-invisible-charset.mjs) pins these code points into
// data/invisible-charset.json's `control_introducers`, which the Python port
// (python/agent_sanitizer/textstrip.py) sweeps. Before that, the Python side
// hand-wrote `\x1b` alone and the whole C1 block survived its strip — the exact
// fork this module's header says must not recur, one language over.
export const CONTROL_INTRODUCER_CODEPOINTS = Object.freeze([
  0x1b,
  ...Array.from({ length: 0x9f - 0x80 + 1 }, (_, i) => 0x80 + i),
]);

// A SOURCE STRING, not a literal: three call sites need it with different flags
// (`g` for the Layer-1 sweep, unflagged for the prompt gate, `g` again to drive
// the scan below), and spelling the class out at each site is how the three
// copies came to spell the same byte two different ways — which defeats a
// grep-based drift check as well. Derived from the code-point list above so the
// regex and the exported data cannot disagree; `\uXXXX` escapes keep every raw
// control byte out of the source (no `no-control-regex` disable needed).
export const CONTROL_INTRODUCER_SOURCE = charClass(
  CONTROL_INTRODUCER_CODEPOINTS,
);

/** A code point as a `\uXXXX` escape — the one spelling of a control byte that
 * both this module's regexes and the generated Python pattern use, so no raw
 * control byte ever lands in either source.
 * @param {number} cp
 * @returns {string} */
function unicodeEscape(cp) {
  return `\\u${cp.toString(16).padStart(4, "0")}`;
}

/** A character class matching exactly the given code points.
 * @param {readonly number[]} cps
 * @returns {string} */
function charClass(cps) {
  return `[${cps.map(unicodeEscape).join("")}]`;
}

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
// The `[` is escaped though neither engine requires it: Python's `re` warns
// `FutureWarning: Possible nested set` on a bare one, and this class ships as
// the generated pattern a Python consumer compiles.
const CSI_INTRO_CLASS = "[\\[()#;?]";
const CSI_INTRO_RE = new RegExp(CSI_INTRO_CLASS);

// ECMA-48 parameter bytes.
const CSI_PARAM_CLASS = "[0-9;:]";
const CSI_PARAM_RE = new RegExp(CSI_PARAM_CLASS);

// ECMA-48 final bytes, minus the ones a terminal never accepts here. Digits are
// PARAMETER bytes and can never terminate a sequence — an unterminated `ESC[`
// must not eat trailing visible digits (`ESC[2024 report` is NOT `ESC[` +
// final-byte `2`; it is an incomplete intro whose ESC the residual sweep
// removes, leaving "2024 report" intact). `<=>?` (0x3C-0x3F) are private
// PARAMETER-prefix bytes per ECMA-48 § 5.4, not finals — including them let a
// private-marker sequence terminate one byte too early. `~` (0x7E) IS a real
// final byte (vt220 function keys, `ESC[3~` for Delete) and is kept.
const CSI_FINAL_CLASS = "[A-PR-TZcf-nqrty~]";
const CSI_FINAL_RE = new RegExp(CSI_FINAL_CLASS);

const ESC = 0x1b;
const CSI_C1 = 0x9b;
const ST_C1 = 0x9c;
const BEL = 0x07;
// THE ABORT SET — the four controls that end a control string short of its
// terminator, and the whole of it. Every other C0 control and DEL is
// deliberately consumed as body, because that is what a terminal does with
// them: DEC's parser (vt100.net/emu/dec_ansi_parser) IGNORES C0 other than
// CAN/SUB/ESC in `osc_string` and `sos_pm_apc_string` and `put`s them in
// `dcs_passthrough`, so aborting on `VT`/`FF`/`NUL`/`DEL` would end the token
// early and splice the rest of a payload the terminal swallows back into the
// model's view — the under-strip this layer exists to close.
//   CAN/SUB — ECMA-48 and that same parser cancel the string here.
//   LF/CR   — NOT terminal behavior, a fail-closed blast-radius limit: they
//             are the only two controls that cross a line, and a body running
//             past one blinds a reader who consumes the strip as a RECORD
//             rather than rendering it (see scanControlString).
const CAN = 0x18;
const SUB = 0x1a;
const LF = 0x0a;
const CR = 0x0d;

// PROBLEM CLASS — a control string whose body the grammar leaves as visible
// text. ECMA-48 opens FIVE strings, not one: OSC (`ESC ]` / U+009D), DCS
// (`ESC P` / U+0090), SOS (`ESC X` / U+0098), PM (`ESC ^` / U+009E) and APC
// (`ESC _` / U+009F). All five share one grammar — introducer, body, ST — and
// every body is attacker-controlled payload text, so all five are consumed as
// one token. Recognizing OSC alone left the other four's bodies in the model's
// view: `ESC _ hidden ESC \` reduced to the visible text `_hidden\`, and at the
// prompt gate the two bare `ESC`s tokenized as inert orphans, which is the
// benign kind, so the gate answered `note` instead of `block`.
// The second byte of the 7-bit form, keyed by introducer. `P` also happens to
// be a CSI final byte, so without this table `ESC P` completed a two-byte CSI
// and the DCS body survived that way instead.
const STRING_INTRO_7BIT = "]PX^_";
const OSC_7BIT = "]";
const OSC_C1 = 0x9d;
// The 8-bit C1 introducers for the same five. This doubles as the set a nested
// introducer aborts on (see scanControlString case 2) — the two ARE the same
// set: opening a string is exactly what ends the one already open.
const STRING_INTRO_C1 = new Set([0x90, 0x98, OSC_C1, 0x9e, 0x9f]);

/**
 * The same grammar {@link scanAnsi} implements, as a REGEX SOURCE — the shipped
 * artifact for a consumer that cannot run this module.
 *
 * The scanner below is AUTHORITATIVE and this is derived from its own constants,
 * never the other way round: the scanner emits token KINDS a regex cannot, and
 * it is linear by construction where the regex form has to carry an explicit
 * guard to stay linear (see the CSI arm's lookahead). What a regex CAN be is data —
 * a stdlib-only Python filter on an uncontrolled host, with no install path for
 * this package, can read a pattern string but cannot import a tokenizer. So the
 * generator pins this into `data/invisible-charset.json` beside the introducer
 * set, `agent_sanitizer.textstrip` compiles it, and the two ports stop being two
 * hand-written spellings of one grammar.
 *
 * Every construct here is common to JS and Python `re` with NO flags —
 * `\uXXXX`, `(?:)`, `(?=)`, `(?!)`, and `(?![\s\S])` for end-of-input (Python's
 * `$` also matches before a trailing newline, JS's does not; `\Z` is Python-only)
 * — so ONE pattern string is what both engines read.
 * `test/ansi-pattern-parity.test.mjs` runs it against the scanner over a fuzz
 * corpus; `tests/test_textstrip.py` asserts it compiles under plain `re`.
 */
export const ESCAPE_SEQUENCE_SOURCE = (() => {
  const introducer7Bit = `${unicodeEscape(ESC)}${charClass(
    [...STRING_INTRO_7BIT].map((ch) => ch.charCodeAt(0)),
  )}`;
  const c1Introducers = [...STRING_INTRO_C1].sort((a, b) => a - b);
  // Consumed with the body, vs the bytes the token ends BEFORE (zero-width) so
  // the scan re-reads them — the split scanControlString makes byte for byte.
  const consumed = [BEL, CAN, SUB, ST_C1].sort((a, b) => a - b);
  const abortBefore = [ESC, ...c1Introducers, LF, CR].sort((a, b) => a - b);
  const body = `[^${[...new Set([...consumed, ...abortBefore])]
    .sort((a, b) => a - b)
    .map(unicodeEscape)
    .join("")}]*`;
  // `ESC \` is the 7-bit ST, the one two-byte terminator.
  const escapeSt = `${unicodeEscape(ESC)}${unicodeEscape(0x5c)}`;
  const terminator =
    `(?:${charClass(consumed)}|${escapeSt}` +
    `|(?=${charClass(abortBefore)})|(?![\\s\\S]))`;
  const stringArm = `(?:${introducer7Bit}|${charClass(c1Introducers)})${body}${terminator}`;
  // The negative lookahead pins the intro run MAXIMAL — which is what the
  // scanner's `while` loop does — and in doing so removes the only place the
  // two quantifiers could repartition (`;` is in both classes), so this cannot
  // backtrack super-linearly the way an unbounded `[…;…]*[…;…]*` would.
  const csiArm =
    `${charClass([ESC, CSI_C1])}${CSI_INTRO_CLASS}*(?!${CSI_INTRO_CLASS})` +
    `${CSI_PARAM_CLASS}*${CSI_FINAL_CLASS}`;
  // The string arm runs FIRST for the same reason it does in scanAnsi: `P` is
  // also a CSI final byte, so a CSI-first alternation takes `ESC P` alone and
  // leaves the DCS body as visible text.
  return `(?:${stringArm}|${csiArm})`;
})();

/** The seven things an introducer can turn out to be. */
export const TOKEN_KIND = Object.freeze({
  /** A display-only `ESC[…m` / `U+009B…m` colour sequence. */
  SGR: "sgr",
  /** Any other complete CSI / two-byte escape (cursor move, erase, charset). */
  CSI: "csi",
  /** An OSC string: introducer, body and terminator as one unit. */
  OSC: "osc",
  /**
   * One of the other four ECMA-48 control strings — DCS, SOS, PM or APC —
   * introducer, body and terminator as one unit, exactly like
   * {@link TOKEN_KIND.OSC}. Split from it only so a warning can name what it
   * found; both are payload-carrying strings and neither is benign.
   */
  CONTROL_STRING: "control-string",
  /**
   * A 7-bit `ESC` that starts no sequence the grammar recognizes — a truncated
   * write, a log fragment cut mid-escape, a stray byte living in a file.
   */
  ORPHAN: "orphan-introducer",
  /**
   * A 7-bit `ESC` that OPENS a CSI (`ESC [`) it never completes. Split from
   * {@link TOKEN_KIND.ORPHAN} because a terminal's CSI parser is STATEFUL: it
   * keeps consuming what follows as parameters and intermediates until a final
   * byte (0x40-0x7E) arrives, so `hello ESC[12 world` renders as `hello orld`
   * — the ` w` is eaten as the sequence's intermediate and final. That is the
   * model-sees/human-sees divergence the gate exists for, so consumers that
   * downgrade an inert strip to a note must keep warning on this one; only a
   * lone `ESC` that opens nothing is inert.
   */
  ORPHAN_CSI: "orphan-csi-introducer",
  /**
   * A RAW C1 byte (U+0080-U+009F) that starts no sequence the grammar
   * recognizes. Split from {@link TOKEN_KIND.ORPHAN} because the two carry very
   * different weight: a lone `ESC` is ordinary debris in terminal output, while
   * a raw C1 byte is not something legitimate UTF-8 text produces. The five
   * string introducers in the block open a {@link TOKEN_KIND.OSC} or
   * {@link TOKEN_KIND.CONTROL_STRING} token instead, so a byte that reaches
   * here is one the grammar recognizes no sequence for at all — and a terminal
   * may still act on it. Consumers that downgrade an inert strip to a note (see
   * `isBenignAnsiKinds` in ./layer1.mjs) must keep warning on this one.
   */
  ORPHAN_C1: "orphan-c1-introducer",
});

/**
 * True for either orphan kind — the tokens {@link scanAnsi} emits for an
 * introducer that completes no sequence, which the stripper must leave in place
 * for the residual sweep rather than splice (see stripAnsiOnce).
 * @param {string} kind one of {@link TOKEN_KIND}
 * @returns {boolean}
 */
export function isOrphanKind(kind) {
  return (
    kind === TOKEN_KIND.ORPHAN ||
    kind === TOKEN_KIND.ORPHAN_CSI ||
    kind === TOKEN_KIND.ORPHAN_C1
  );
}

/**
 * The orphan kind for the introducer character `ch`, given the character `next`
 * that follows it: a raw C1 byte, an `ESC` that opened an incomplete CSI, or a
 * lone `ESC`. The one place that split is decided, shared by the tokenizer and
 * by Layer 1's residual sweep (which sees bare characters, not tokens).
 *
 * `[` is the only lookahead that matters. The five string introducers — `ESC ]`,
 * `ESC P`, `ESC X`, `ESC ^`, `ESC _` — are consumed whole by
 * {@link scanControlString}, to the end of input if unterminated, so they never
 * reach here; every other second byte (`ESC (`, `ESC #`) bounds what a terminal
 * swallows to a byte or two rather than running until a final byte arrives.
 * @param {string} ch
 * @param {string} [next]  the following character, or undefined at end of input
 * @returns {string}
 */
export function orphanKindFor(ch, next) {
  if (ch.charCodeAt(0) !== ESC) return TOKEN_KIND.ORPHAN_C1;
  return next === "[" ? TOKEN_KIND.ORPHAN_CSI : TOKEN_KIND.ORPHAN;
}

/**
 * @typedef {object} AnsiToken
 * @property {number} start Index of the introducer.
 * @property {number} end Index one past the last character of the token.
 * @property {string} kind One of {@link TOKEN_KIND}.
 */

/**
 * The control string starting at `start`, or null when no string introducer is
 * there.
 *
 * A control string is `<introducer> body <terminator>`: an OSC window title, a
 * clickable-hyperlink URL, a clipboard write, a DCS device payload, an APC
 * application command — i.e. attacker-controlled PAYLOAD TEXT in every case.
 * Consuming the introducer alone would leave that payload in the model's view,
 * so the whole string is one token. Three ways it can end:
 *   1. a real terminator — ST (`ESC\` or the 8-bit C1 ST U+009C), the legacy
 *      BEL, or the CAN/SUB (U+0018/U+001A) that ECMA-48 and xterm cancel a
 *      string on — which is consumed with the body.
 *   2. an ABORT: per ECMA-48/xterm a bare ESC (one not forming ST) drops the
 *      terminal out of the string, and a nested C1 string introducer likewise
 *      starts something new. The token ends BEFORE that byte so the scan
 *      re-reads it as its own sequence — without this, an interior ESC deleted
 *      the rest of the document via case 4.
 *   3. a line break (LF/CR) BOUNDS the body, before the break. This is a fail-
 *      closed blast-radius limit, NOT terminal behavior: a real terminal ignores
 *      an interior LF and keeps collecting to a true terminator. Without the
 *      bound one stray `ESC ]` deleted every later line to end of input, so on a
 *      consumer that reads the strip as a RECORD (a model, not a display) one
 *      introducer blinded the whole tail behind a clean-looking prefix. The
 *      break survives; the payload after it on the same line is dropped. This is
 *      what makes the layer-wide invariant hold — no token of any kind spans a
 *      line break, so a strip NEVER removes a newline (test/layer1-ansi).
 *   4. end of input, for a genuinely unterminated string with no line break:
 *      fail closed and drop everything from the introducer on, so no body
 *      survives.
 *
 * BEL terminates every arm here, not just OSC. Only xterm's OSC parser accepts
 * it, so a DCS ending at BEL over-consumes by the width of one body — the
 * fail-closed direction, and the alternative (a per-introducer terminator set)
 * makes a terminal that does accept it an under-strip.
 * @param {string} text
 * @param {number} start
 * @returns {{ end: number, kind: string } | null}
 */
function scanControlString(text, start) {
  const code = text.charCodeAt(start);
  const second = code === ESC ? text[start + 1] : undefined;
  const sevenBit = second !== undefined && STRING_INTRO_7BIT.includes(second);
  if (!sevenBit && !STRING_INTRO_C1.has(code)) return null;
  const kind =
    second === OSC_7BIT || code === OSC_C1
      ? TOKEN_KIND.OSC
      : TOKEN_KIND.CONTROL_STRING;
  let i = sevenBit ? start + 2 : start + 1;
  for (; i < text.length; i++) {
    const byte = text.charCodeAt(i);
    if (byte === BEL || byte === ST_C1 || byte === CAN || byte === SUB)
      return { end: i + 1, kind };
    if (byte === ESC) return { end: text[i + 1] === "\\" ? i + 2 : i, kind };
    if (STRING_INTRO_C1.has(byte) || byte === LF || byte === CR)
      return { end: i, kind };
  }
  return { end: text.length, kind };
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
 * Every introducer yields exactly one token — an orphan kind (see
 * {@link orphanKindFor}) when it starts nothing the grammar recognizes — so
 * "which introducers are in this text" and "which
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
    // The string arms run FIRST: `ESC P` also completes a two-byte CSI (`P` is a
    // final byte), so letting scanCsi answer first would take the DCS
    // introducer alone and leave its body as visible text.
    const string = scanControlString(text, start);
    const csiEnd = string ? -1 : scanCsi(text, start);
    let end = start + 1;
    /** @type {string} */
    let kind = orphanKindFor(text[start], text[start + 1]);
    if (string) {
      end = string.end;
      kind = string.kind;
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
