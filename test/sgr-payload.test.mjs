/**
 * `sgrCarriesPayload` — the question a consumer that PRESERVES escapes has to
 * answer, and the one the rest of the engine never had to: not "is this SGR"
 * (isSgrOnly answers that) but "is this SGR still just styling".
 *
 * Two arms, and both are here with their false-positive twins, because the cost
 * of a wrong yes is a colourized file losing its colour:
 *
 *   CONCEAL — parameter 8 blanks what follows for a human while the bytes stay
 *     readable to a model. The twin is the extended-colour form: `ESC[38;5;8m`
 *     is bright-black foreground, and a reader that scans for the digit instead
 *     of parsing the parameters calls it conceal. The whole reason the parameter
 *     semantics live in ansi.mjs (which owns the SGR grammar) is that this is
 *     the second place they would otherwise be written down.
 *   RUN — sequences back to back with nothing between them render as nothing at
 *     all. The twin is the same count of sequences with text between them, which
 *     is exactly what a styling emitter produces.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { sgrCarriesPayload, SGR_RUN_THRESHOLD } from "../src/ansi.mjs";
import { cp } from "./test-helpers.mjs";

const ESC = cp(0x1b);
const CSI = cp(0x9b);

/** @type {ReadonlyArray<[string, string, boolean]>} name, text, expected */
const CONCEAL_CASES = [
  ["conceal alone", `${ESC}[8m`, true],
  ["conceal among attributes", `${ESC}[0;8;31m`, true],
  ["conceal with a leading zero", `${ESC}[08m`, true],
  ["conceal after an omitted parameter", `${ESC}[;8m`, true],
  ["conceal in the C1 encoding", `${CSI}8m`, true],
  ["conceal inside prose", `visible${ESC}[8mhidden${ESC}[28m`, true],

  ["reset", `${ESC}[m`, false],
  ["explicit reset", `${ESC}[0m`, false],
  ["red", `${ESC}[31m`, false],
  ["reveal, which is 28 and not 8", `${ESC}[28m`, false],
  ["256-colour index 8 (bright black)", `${ESC}[38;5;8m`, false],
  ["truecolor with an 8 component", `${ESC}[48;2;0;0;8m`, false],
  ["underline colour with an 8 component", `${ESC}[58;2;0;0;8m`, false],
  ["colon-form 256-colour index 8", `${ESC}[38:5:8m`, false],
  ["colon-form truecolor with an 8 component", `${ESC}[38:2:0:0:8m`, false],
  // An unknown colour-space selector is malformed and what a terminal makes of
  // the rest is undefined; the parser stops rather than reading the argument
  // after it as a parameter, which is the answer that keeps the content.
  ["unknown colour selector followed by 8", `${ESC}[38;9;8m`, false],
  ["a parameter run with no introducer", "8m", false],
  ["an erase, which is not SGR at all", `${ESC}[2J`, false],
  ["plain text", "plain", false],
];

describe("sgrCarriesPayload: conceal", () => {
  for (const [name, text, expected] of CONCEAL_CASES)
    it(`${name} -> ${expected}`, () => {
      assert.equal(sgrCarriesPayload(text), expected);
    });
});

describe("sgrCarriesPayload: runs", () => {
  const colour = `${ESC}[31m`;

  it("a run at the threshold is a channel", () => {
    assert.equal(sgrCarriesPayload(colour.repeat(SGR_RUN_THRESHOLD)), true);
  });

  it("one sequence short of the threshold is not", () => {
    assert.equal(
      sgrCarriesPayload(colour.repeat(SGR_RUN_THRESHOLD - 1)),
      false,
    );
  });

  it("the same sequences with text between them are styling", () => {
    assert.equal(
      sgrCarriesPayload(`${colour}x`.repeat(SGR_RUN_THRESHOLD * 5)),
      false,
    );
  });

  it("one character breaks the run, and the count restarts", () => {
    const short = colour.repeat(SGR_RUN_THRESHOLD - 1);
    assert.equal(sgrCarriesPayload(`${short}x${short}`), false);
  });

  it("a run in the C1 encoding counts the same", () => {
    assert.equal(
      sgrCarriesPayload(`${CSI}31m`.repeat(SGR_RUN_THRESHOLD)),
      true,
    );
  });

  it("a run of non-SGR sequences is not this predicate's finding", () => {
    // The layers above strip those outright; answering true here would make the
    // run threshold look like what caught them.
    assert.equal(
      sgrCarriesPayload(`${ESC}[2J`.repeat(SGR_RUN_THRESHOLD)),
      false,
    );
  });
});
