/**
 * `sgrCarriesPayload` — the question a consumer that PRESERVES escapes has to
 * answer, and the one the rest of the engine never had to: not "is this SGR"
 * (isSgrOnly answers that) but "is this SGR still just styling".
 *
 * Three arms, and all are here with their false-positive twins, because the
 * cost of a wrong yes is a colourized file losing its colour:
 *
 *   CONCEAL — parameter 8 blanks what follows for a human while the bytes stay
 *     readable to a model. It is terminal STATE, so the cases below cover the
 *     transitions, not one token shape: a reveal or reset in the same token
 *     cancels it, an erase between two tokens does not, and an extended-colour
 *     index of 8 (`ESC[38;5;8m`) was never conceal at all.
 *   COLOUR — a foreground painted in its own background hides the same text by
 *     other means. The twins are what ANSI art does with matching colours
 *     (spaces, one block element repeated) and the cases a terminal may render differently
 *     (bold over a basic colour, the unknown default colours).
 *   RUN — sequences with nothing that RENDERS between them put no glyph on the
 *     screen, so past a threshold they carry data. The twin is the same count of
 *     sequences separated by spaces, which is exactly what an ANSI-art colour
 *     bar looks like.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { sgrCarriesPayload, SGR_RUN_THRESHOLD } from "../src/layer1.mjs";
import { cp } from "./test-helpers.mjs";

const ESC = cp(0x1b);
const CSI = cp(0x9b);
const ZWSP = cp(0x200b);
const VARIATION_SELECTOR = cp(0xfe00);

/** @type {ReadonlyArray<[string, string, boolean]>} name, text, expected */
const CONCEAL_CASES = [
  ["conceal alone", `${ESC}[8m`, true],
  ["conceal among attributes", `${ESC}[0;8;31m`, true],
  ["conceal with a leading zero", `${ESC}[08m`, true],
  ["conceal after an omitted parameter", `${ESC}[;8m`, true],
  ["conceal in the C1 encoding", `${CSI}8m`, true],
  ["conceal inside prose", `visible${ESC}[8mhidden${ESC}[28m`, true],
  // Parameter scanning RESUMES after an extended colour's arguments: a reader
  // that stopped at the colour selector instead of sizing its arguments would
  // hand this one a pass.
  ["conceal after an extended colour", `${ESC}[38;5;1;8m`, true],
  // The parameters apply in order, so `8` is live until something later in the
  // SAME token clears it.
  ["conceal set after a reset in one token", `${ESC}[0;8m`, true],
  // An unknown colour-space selector sizes no arguments, so the scan continues
  // from the next parameter rather than skipping bytes it cannot measure.
  ["conceal behind an unknown colour selector", `${ESC}[38;9;8m`, true],
  // Conceal is terminal state: a cursor/erase sequence between two SGR tokens
  // leaves it exactly where it was.
  ["conceal surviving an erase", `${ESC}[8m${ESC}[2Jhidden${ESC}[28m`, true],

  ["reset", `${ESC}[m`, false],
  ["explicit reset", `${ESC}[0m`, false],
  ["red", `${ESC}[31m`, false],
  ["reveal, which is 28 and not 8", `${ESC}[28m`, false],
  ["conceal revealed later in the same token", `${ESC}[8;28;31m`, false],
  ["conceal reset later in the same token", `${ESC}[8;0m`, false],
  ["256-colour index 8 (bright black)", `${ESC}[38;5;8m`, false],
  ["truecolor with an 8 component", `${ESC}[48;2;0;0;8m`, false],
  ["underline colour with an 8 component", `${ESC}[58;2;0;0;8m`, false],
  ["CMY with an 8 component", `${ESC}[38;3;0;0;8m`, false],
  ["CMYK with an 8 component", `${ESC}[38;4;0;0;0;8m`, false],
  ["implementation-defined colour selector 0", `${ESC}[38;0m`, false],
  ["colon-form 256-colour index 8", `${ESC}[38:5:8m`, false],
  ["colon-form truecolor with an 8 component", `${ESC}[38:2:0:0:8m`, false],
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

const BLOCK = cp(0x2588);

/** @type {ReadonlyArray<[string, string, boolean]>} name, text, expected */
const COLOUR_CASES = [
  ["basic black on black", `${ESC}[30;40mhidden`, true],
  ["256-colour index on itself", `${ESC}[38;5;7;48;5;7mhidden`, true],
  ["truecolor on itself", `${ESC}[38;2;1;2;3;48;2;1;2;3mhidden`, true],
  ["colon-form truecolor on itself", `${ESC}[38:2::1:2:3;48:2::1:2:3mx`, true],
  // One colour, two spellings: basic 37 IS palette index 7.
  ["basic foreground on its indexed twin", `${ESC}[37;48;5;7mhidden`, true],
  ["bright basic on itself", `${ESC}[97;107mx`, true],
  ["set across two tokens", `${ESC}[30m${ESC}[40mhidden`, true],
  ["hidden span inside prose", `shown ${ESC}[30;40mhidden${ESC}[0m`, true],
  // A non-SGR token between the colour and the reset changes no rendition, so
  // the text before it is still drawn in matching colours.
  [
    "hidden span before an erase",
    `${ESC}[30;40mhidden${ESC}[2J${ESC}[0m`,
    true,
  ],
  [
    "hidden span before a cursor move",
    `${ESC}[30;40mhidden${ESC}[H${ESC}[0m`,
    true,
  ],
  // Bold brightens only the 8 basic colours, so it disambiguates nothing here.
  ["bold over truecolor", `${ESC}[1;38;2;0;0;0;48;2;0;0;0mx`, true],

  ["whitespace painted in its own colour", `${ESC}[30;40m   ${ESC}[0m`, false],
  [
    "whitespace before an erase in its own colour",
    `${ESC}[30;40m  ${ESC}[K${ESC}[0m`,
    false,
  ],
  ["ANSI-art block elements", `${ESC}[31;41m${BLOCK}${BLOCK}${ESC}[0m`, false],
  // In matching colours every Block Element is the same solid cell, so a
  // second distinct one is a hidden choice: the channel is the glyph identity.
  ["two distinct block elements in one span", `${ESC}[31;41m▀▄${ESC}[0m`, true],
  [
    "a base-32 block-element stream",
    `${ESC}[31;41m▀▁▂▃▄▅▆▇█▉▊▋▌▍▎▏${ESC}[0m`,
    true,
  ],
  // `seen` spans the text: one glyph per sequence still spells the stream.
  [
    "one distinct block element per sequence",
    `${ESC}[31;41m▀${ESC}[31;41m▄${ESC}[0m`,
    true,
  ],
  [
    "distinct block elements under two matching colours",
    `${ESC}[31;41m▀${ESC}[0m ${ESC}[34;44m▄${ESC}[0m`,
    true,
  ],
  // Half-block image renderers (catimg-style): top pixel as foreground, bottom
  // as background, so a flat region repeats ONE glyph in matching colours.
  [
    "a half-block image with a flat region",
    `${ESC}[38;5;1;48;5;1m▀${ESC}[38;5;1;48;5;2m▀${ESC}[38;5;1;48;5;1m▀${ESC}[38;5;3;48;5;3m▀${ESC}[0m\n`,
    false,
  ],
  [
    "distinct block elements in different colours",
    `${ESC}[31;40m▀▄█▌▐░▒▓${ESC}[0m`,
    false,
  ],
  [
    "distinct block elements, only one in matching colours",
    `${ESC}[31;41m█${ESC}[32;40m▀▄${ESC}[0m`,
    false,
  ],
  ["bold over a basic colour", `${ESC}[1;30;40mtext`, false],
  ["bold over a low palette index", `${ESC}[1;38;5;0;48;5;0mtext`, false],
  ["default colours, which are unknown", `${ESC}[39;49mtext`, false],
  ["different colours", `${ESC}[31;40mtext`, false],
  ["a reset before the text", `${ESC}[30;40m${ESC}[0mtext`, false],
  ["foreground reset to default", `${ESC}[30;40;39mtext`, false],
  // Rendition outlives the text: a file left black-on-black blanks whatever
  // the terminal prints after it, exactly as a trailing CONCEAL does.
  ["matching colours with nothing after", `text${ESC}[30;40m`, true],
  ["matching colours with only whitespace after", `text${ESC}[30;40m \n`, true],
  [
    "matching colours set by the last of two tokens",
    `${ESC}[30m${ESC}[40m`,
    true,
  ],
  [
    "matching colours reset before the end",
    `text${ESC}[30;40m${ESC}[0m`,
    false,
  ],
  ["different colours left active at the end", `text${ESC}[32;40m`, false],
  ["bold basic match left active at the end", `text${ESC}[1;30;40m`, false],
  ["foreground alone left active at the end", `${ESC}[32mok`, false],
  ["only zero-width characters hidden", `${ESC}[30;40m${ZWSP}${ESC}[0m`, false],
];

describe("sgrCarriesPayload: foreground on its own background", () => {
  for (const [name, text, expected] of COLOUR_CASES)
    it(`${name} -> ${expected}`, () => {
      assert.equal(sgrCarriesPayload(text), expected);
    });
});

describe("sgrCarriesPayload: runs", () => {
  const colour = `${ESC}[31m`;
  const run = (separator) =>
    Array.from({ length: SGR_RUN_THRESHOLD }, () => colour).join(separator);

  it("a run at the threshold is a channel", () => {
    assert.equal(sgrCarriesPayload(run("")), true);
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

  // A zero-width separator renders nothing, so the run it hides is still a run
  // that puts no glyph on the screen — and a handful of them sits under the
  // invisible layer's own thresholds, so they survive to be written.
  it("a run separated by zero-width characters still counts", () => {
    assert.equal(sgrCarriesPayload(run(ZWSP)), true);
  });

  it("a run separated by variation selectors still counts", () => {
    assert.equal(sgrCarriesPayload(run(VARIATION_SELECTOR)), true);
  });

  // The false-positive twin: colour bars separate their codes with SPACES, and
  // a space renders.
  it("colour codes separated by spaces are styling at any length", () => {
    const bar = Array.from({ length: SGR_RUN_THRESHOLD * 5 }, () => colour);
    assert.equal(sgrCarriesPayload(bar.join(" ")), false);
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

// Precision corpus: what real tools print. Every entry is styling, so every
// arm above must answer no for all of them — a yes here costs a colourized
// file or a pasted log its colour.
const ORDINARY_TERMINAL_OUTPUT = [
  ["test runner pass line", `${ESC}[32m✔ parses input${ESC}[0m (1.2ms)\n`],
  [
    "test runner failure",
    `${ESC}[31m✖ fails${ESC}[39m\n${ESC}[2mat foo.js:1${ESC}[22m\n`,
  ],
  [
    "git diff hunk",
    `${ESC}[1mdiff --git a/x b/x${ESC}[m\n${ESC}[36m@@ -1 +1 @@${ESC}[m\n${ESC}[31m-old${ESC}[m\n${ESC}[32m+new${ESC}[m\n`,
  ],
  [
    "ls --color",
    `${ESC}[0m${ESC}[01;34msrc${ESC}[0m  ${ESC}[01;32mrun.sh${ESC}[0m\n`,
  ],
  ["inverse status bar", `${ESC}[7m NORMAL ${ESC}[27m main.c\n`],
  [
    "256-colour prompt",
    `${ESC}[38;5;33muser${ESC}[0m@${ESC}[38;5;208mhost${ESC}[0m $ `,
  ],
  ["truecolor highlight", `${ESC}[38;2;255;100;0;48;2;30;30;30mwarn${ESC}[0m`],
  ["colour left active at the end", `${ESC}[33mtrailing yellow`],
  ["background-only banner", `${ESC}[44m  deploy  ${ESC}[0m`],
  ["block-element progress bar", `${ESC}[32;40m████████▌   ${ESC}[0m 71%\n`],
  ["shaded meter", `${ESC}[36m▕▓▓▓▒▒░░  ▏${ESC}[0m`],
  ["sparkline", `${ESC}[33m▁▂▃▅▇█▇▅▃▂${ESC}[0m`],
  [
    "box-drawing table",
    `${ESC}[2m┌──────┬────┐${ESC}[0m\n${ESC}[2m│${ESC}[0m ${ESC}[1mname${ESC}[0m ${ESC}[2m│${ESC}[0m ok ${ESC}[2m│${ESC}[0m\n${ESC}[2m└──────┴────┘${ESC}[0m\n`,
  ],
  [
    "coloured box on a background",
    `${ESC}[37;44m╔══╗${ESC}[0m\n${ESC}[37;44m╚══╝${ESC}[0m`,
  ],
];

describe("sgrCarriesPayload: ordinary terminal output is styling", () => {
  for (const [name, text] of ORDINARY_TERMINAL_OUTPUT)
    it(name, () => {
      assert.equal(sgrCarriesPayload(text), false);
    });
});
