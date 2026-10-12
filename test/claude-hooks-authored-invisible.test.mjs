/**
 * The INVISIBLE half of the write path: when an authored field counts as a
 * covert channel, and what the layer reports when it acts.
 *
 * A field the strip leaves byte for byte must come back as no rewrite at all
 * (a phantom report made the pipeline re-run until it ran out of passes), and
 * the rewrite it does make is a fixed point.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { sanitizeAuthoredContent } from "../claude-hooks/lib/authored-content.mjs";
import { LONG_RUN_THRESHOLD } from "../src/invisible.mjs";
import { cp } from "./test-helpers.mjs";

const ESC = cp(0x1b);
const ZWSP = cp(0x200b);
const ZWNJ = cp(0x200c);
const VS1 = cp(0xfe00);
const BEH = cp(0x628);
const PROSE = "This is a perfectly ordinary sentence of prose. ";
const FAMILY = [0x1f468, 0x1f469, 0x1f467, 0x1f466].map(cp).join(cp(0x200d));
const CHECKED = `- ${cp(0x2714)}${cp(0xfe0f)} done\n`;

/** @param {string} content */
const authored = (content) => sanitizeAuthoredContent("Write", { content });

test("a field the strip leaves byte for byte reports no rewrite (regression)", () => {
  // Thirty-plus joiners or selectors, every one of them rendering an emoji:
  // over the raw scattered threshold, so a raw count called them a payload and
  // recorded an action for a strip that removed nothing.
  for (const content of [
    PROSE.repeat(5) + `${PROSE}${FAMILY} `.repeat(10),
    CHECKED.repeat(30),
  ])
    assert.equal(authored(content), null);
});

test("a ZWNJ between every Persian letter is stripped and reported", () => {
  const chain = `${BEH}${ZWNJ}`.repeat(200) + BEH;
  const result = authored(chain);
  assert.ok(result, "the joiner chain was left in the file");
  assert.deepEqual(result.changed, ["content (invisible characters)"]);
  // Only the excess goes: what remains is the letters plus the joiners the
  // carve-out's budget still allows, never a letter fewer.
  const cleaned = /** @type {string} */ (result.updatedInput.content);
  assert.equal(cleaned.replaceAll(ZWNJ, ""), BEH.repeat(201));
  assert.ok(cleaned.length < chain.length);
});

test("the rewrite is a fixed point of the layer", () => {
  const inputs = [
    `keep${ESC}[${ZWSP}2J${ZWSP.repeat(LONG_RUN_THRESHOLD + 2)}tail`,
    `${ESC}[`.repeat(6) + "m".repeat(6) + " tail",
    (ESC + ZWSP).repeat(5) + "[2J".repeat(5) + ZWSP.repeat(LONG_RUN_THRESHOLD),
    `${BEH}${ZWNJ}`.repeat(200) + BEH,
    `${ESC}[8m${ZWSP.repeat(40)}hidden${ESC}[28m`,
  ];
  for (let stages = 1; stages <= 6; stages++)
    for (const prefix of [0, 15, 40])
      for (const pad of [0, 75, 195])
        inputs.push(
          `0${VS1} `.repeat(prefix) +
            "x".repeat(pad) +
            `${ESC}${ZWSP}[0;0;0m` +
            `${ESC}[0;0;0${VS1}m`.repeat(stages) +
            ZWSP.repeat(12),
        );
  let rewritten = 0;
  for (const input of inputs) {
    const result = authored(input);
    if (result === null) continue;
    rewritten++;
    const cleaned = /** @type {string} */ (result.updatedInput.content);
    assert.equal(authored(cleaned), null, JSON.stringify(input));
  }
  assert.equal(rewritten, inputs.length);
});

// SGR parameter bytes render nothing, so they are no visible cover: the verdict
// reads the de-ANSI'd view, as the prompt gate does. One SGR of a thousand
// parameters used to buy the preserve budget for fifty hidden selectors.
const SGR_COVER = `${ESC}[${"0;".repeat(1000)}0m`;

test("SGR parameter bytes do not fund preserved selectors (regression)", () => {
  const content = SGR_COVER + `0${VS1} `.repeat(50);
  const result = authored(content);
  assert.ok(result, "fifty selectors under SGR cover were left in the file");
  assert.deepEqual(result.changed, [
    "content (terminal-control sequences, invisible characters)",
  ]);
  const cleaned = /** @type {string} */ (result.updatedInput.content);
  // The strip judged the same view the verdict did: no escape is left to buy
  // cover on a second pass, and the selectors are cut to the view's budget.
  assert.equal(cleaned.includes(ESC), false);
  assert.ok(cleaned.split(VS1).length - 1 < 50);
  assert.equal(cleaned.replaceAll(VS1, ""), "0 ".repeat(50));
  assert.equal(authored(cleaned), null);
});

test("coloured text whose invisibles do rendering work keeps its colour and bytes (precision)", () => {
  const PERSIAN = `ما می${ZWNJ}خواهیم این کتاب${ZWNJ}ها را بخوانیم. `;
  for (const content of [
    `${ESC}[32m${CHECKED}${ESC}[0m`.repeat(10),
    `${ESC}[1;34m${PERSIAN}${ESC}[0m\n`.repeat(20),
    `${ESC}[33m${FAMILY} family${ESC}[0m `.repeat(5),
    SGR_COVER + `0${VS1} `.repeat(5),
    `${ESC}[32m✔ ok${ESC}[0m\n${ESC}[31m✖ failed${ESC}[0m\n`.repeat(20),
  ])
    assert.equal(authored(content), null, JSON.stringify(content));
});
