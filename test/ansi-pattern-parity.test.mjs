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
  // The CSI bytes outside the old grammar: private parameter markers,
  // intermediates, and finals the old class left out.
  "<",
  "=",
  ">",
  "!",
  "/",
  "@",
  "`",
  "{",
  "|",
  "}",
  "q",
  "s",
  "u",
);

// A whole CSI drawn from ECMA-48 § 5.4 itself, so the corpus reaches every
// parameter, intermediate and final byte rather than only the ones listed above.
const byteIn = (lo, hi) =>
  fc.integer({ min: lo, max: hi }).map((code) => String.fromCharCode(code));
const validCsi = fc
  .tuple(
    fc.constantFrom(`${ESC}[`, CSI),
    fc.array(byteIn(0x30, 0x3f), { maxLength: 4 }),
    fc.array(byteIn(0x20, 0x2f), { maxLength: 2 }),
    byteIn(0x40, 0x7e),
  )
  .map(([intro, params, intermediates, final]) =>
    [intro, ...params, ...intermediates, final].join(""),
  );

const grammarText = fc
  .array(fc.oneof({ weight: 4, arbitrary: grammarByte }, validCsi), {
    maxLength: 24,
  })
  .map((parts) => parts.join(""));

// The spec's CSI language, spelled from ECMA-48 § 5.4 rather than imported, so
// it is an oracle for the shipped grammar and not a second copy of it.
const SPEC_CSI_RE = new RegExp(
  `(?:${ESC}\\[|${CSI})[\\x30-\\x3f]*[\\x20-\\x2f]*[\\x40-\\x7e]`,
);

/** Apply one strip until it changes nothing. Unbounded on purpose: the
 * property below is about the grammar, not about Layer 1's pass cap. */
function toFixedPoint(strip, text) {
  let previous = text;
  let next = strip(previous);
  while (next !== previous) {
    previous = next;
    next = strip(previous);
  }
  return next;
}

// Valid CSI sequences the grammar used to miss: a private parameter marker
// (`<=>`), an intermediate byte, and finals outside the old final class.
const WIDENED_CSI = [
  ["xterm modifyOtherKeys", `${ESC}[>4;1m`],
  ["private `=` marker", `${ESC}[=5h`],
  ["DECSCUSR (space intermediate)", `${ESC}[1 q`],
  ["SGR mouse report", `${ESC}[<0;1;1M`],
  ["save cursor", `${ESC}[s`],
  ["restore cursor", `${ESC}[u`],
  ["insert char `@`", `${ESC}[4@`],
  ["HPA backtick", `${ESC}[5\``],
  ["DECSLE `{`", `${ESC}[1{`],
  ["`|` final", `${ESC}[2|`],
  ["DECERA `}`", `${ESC}[1}`],
  ["C1 private marker", `${CSI}>4;1m`],
];

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
  ...WIDENED_CSI,
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

  it("removes every ECMA-48 CSI whole, as one `csi` token", () => {
    for (const [name, sequence] of WIDENED_CSI) {
      const input = `A${sequence}Z`;
      assert.equal(stripWithPattern(input), "AZ", `${name} / pattern`);
      assert.equal(stripWithScanner(input), "AZ", `${name} / scanner`);
      assert.deepEqual(
        scanAnsi(sequence),
        [{ start: 0, end: sequence.length, kind: "csi" }],
        name,
      );
    }
  });

  it("leaves no spec-valid CSI in a fixed point of either strip", () => {
    fc.assert(
      fc.property(grammarText, (text) => {
        for (const [name, strip] of [
          ["pattern", stripWithPattern],
          ["scanner", stripWithScanner],
        ]) {
          const residue = SPEC_CSI_RE.exec(toFixedPoint(strip, text));
          assert.equal(
            residue,
            null,
            `${name} left ${JSON.stringify(residue)}`,
          );
        }
      }),
      fcRunOptions(),
    );
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
