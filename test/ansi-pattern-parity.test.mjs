/**
 * The shipped escape GRAMMAR describes the same language the scanner accepts.
 *
 * `src/ansi.mjs` holds two things now: `scanAnsi`, the authoritative tokenizer,
 * and `ESCAPE_SEQUENCE_SOURCE`, the regex the generator pins into
 * `data/invisible-charset.json` for a consumer that cannot import a tokenizer (a
 * bare `python3` filter on an uncontrolled host). Both are built from the same
 * constants, but "built from the same constants" is not agreement — so this
 * DIFFERENTIALS them: strip with the regex, strip with the scanner, demand the
 * same bytes.
 *
 * That is what the cross-language equivalence corpus could not do. The corpus
 * discriminated only where a case existed, so a control-string body that met a
 * newline — a case nobody wrote — was wrong IDENTICALLY in both ports and no
 * assertion anywhere could see it. A property over a generated corpus can.
 *
 * Compiling the pattern here also pins the half of its contract Python cannot:
 * a Python-only construct (`\Z`, `(?P<…>`) fails at `new RegExp` in this file,
 * where `tests/test_textstrip.py` catches the JS-only ones.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import {
  ESCAPE_SEQUENCE_SOURCE,
  isOrphanKind,
  scanAnsi,
} from "../src/ansi.mjs";
import { fcRunOptions, cp } from "./test-helpers.mjs";

const ESC = cp(0x1b);
const CSI = cp(0x9b);
const OSC = cp(0x9d);
const DCS = cp(0x90);
const APC = cp(0x9f);
const ST = cp(0x9c);
const BEL = cp(0x07);
const CAN = cp(0x18);
const SUB = cp(0x1a);

/** The strip the pattern gives a stdlib-only consumer: one pass, splice every
 * match. The Python port runs exactly this (`ANSI_RE.sub("", text)`). */
function stripWithPattern(text) {
  return text.replace(new RegExp(ESCAPE_SEQUENCE_SOURCE, "g"), "");
}

/** The same strip via the authoritative tokenizer: splice every non-orphan
 * token, leaving orphans to the residual sweep (`stripAnsiOnce`'s body). */
function stripWithScanner(text) {
  let out = "";
  let last = 0;
  for (const token of scanAnsi(text)) {
    if (isOrphanKind(token.kind)) continue;
    out += text.slice(last, token.start);
    last = token.end;
  }
  return last === 0 ? text : out + text.slice(last);
}

// Drawn as PIECES, biased hard toward escape bytes: a uniform draw over text
// reaches an ESC essentially never, and the shapes that discriminate the two
// implementations are torn introducers, doubled terminators, and bodies that
// run into a line break.
const grammarByte = fc.constantFrom(
  ESC,
  CSI,
  OSC,
  DCS,
  APC,
  ST,
  BEL,
  CAN,
  SUB,
  cp(0x98),
  cp(0x9e),
  cp(0x00),
  cp(0x0b),
  cp(0x7f),
  "[",
  "]",
  "P",
  "X",
  "^",
  "_",
  "\\",
  "m",
  "0",
  "1",
  ";",
  ":",
  "?",
  "(",
  "#",
  "~",
  "J",
  "B",
  "2",
  " ",
  "a",
  "\n",
  "\r",
);

const grammarText = fc
  .array(grammarByte, { maxLength: 24 })
  .map((parts) => parts.join(""));

// Every way a control string can end, plus both CSI encodings — the arms the
// pattern has to reproduce one for one.
const ARMS = [
  ["real terminator (BEL)", `${ESC}]0;title${BEL}`],
  ["ESC \\ terminator", `${ESC}]0;title${ESC}\\`],
  ["C1 ST terminator", `${OSC}0;title${ST}`],
  ["DCS + ESC \\", `${ESC}Pq#payload${ESC}\\`],
  ["C1 APC + C1 ST", `${APC}command${ST}`],
  ["CAN abort", `${ESC}]title${CAN}rest`],
  ["SUB abort", `${ESC}]title${SUB}rest`],
  ["nested-introducer abort", `${OSC}first${OSC}second${BEL}`],
  ["ESC abort", `${ESC}]title${ESC}[0mrest`],
  ["newline abort", `${ESC}]title\nrest`],
  ["unterminated at EOF", `${ESC}]dangling`],
  ["CSI", `${ESC}[2J`],
  ["C1 CSI", `${CSI}31m`],
];

describe("the shipped escape pattern and the scanner are one grammar", () => {
  it("strips every arm identically, with a newline before, inside and after", () => {
    for (const [name, sequence] of ARMS)
      for (const [placement, input] of [
        ["bare", `A${sequence}Z`],
        ["before", `A\n${sequence}Z`],
        ["inside", `A${sequence.slice(0, 3)}\n${sequence.slice(3)}Z`],
        ["after", `A${sequence}\nZ`],
      ]) {
        const viaPattern = stripWithPattern(input);
        assert.equal(
          viaPattern,
          stripWithScanner(input),
          `${name} / ${placement}`,
        );
        // Non-vacuity: the case reached the grammar at all, rather than passing
        // because both implementations left the input alone. Exempt `inside` —
        // a break planted mid-INTRODUCER is meant to leave a match-nothing
        // fragment, and that fragment is itself a case the two must agree on.
        if (placement !== "inside")
          assert.notEqual(
            viaPattern,
            input,
            `${name} / ${placement} matched nothing`,
          );
      }
  });

  it("leaves a truncated CSI to the residual sweep in both implementations", () => {
    // The row the two ports actually disagreed on before the pattern was
    // generated: no final byte means no sequence, so the introducer alone goes
    // (in the sweep, not here) and `[12` stays VISIBLE. The Python port's own
    // general arm used to eat the bracket — deleting a byte the authoritative
    // layer keeps.
    for (const input of [`A${ESC}[12`, `A${ESC}[12\nZ`]) {
      assert.equal(stripWithPattern(input), input);
      assert.equal(stripWithScanner(input), input);
    }
  });

  it("agrees with the scanner over generated escape-dense text", () => {
    fc.assert(
      fc.property(grammarText, (text) => {
        assert.equal(stripWithPattern(text), stripWithScanner(text));
      }),
      fcRunOptions(),
    );
  });

  it("carries no capturing group, so a consumer's splice cannot reinsert one", () => {
    // `re.sub` / `String.replace` with a capturing group changes what `\1` and
    // `$1` mean in a replacement, and `findall` starts returning groups instead
    // of matches — a contract break for a consumer that only wants deletion.
    const match = new RegExp(ESCAPE_SEQUENCE_SOURCE).exec(`${ESC}[0m`);
    assert.equal(match.length, 1);
  });
});
