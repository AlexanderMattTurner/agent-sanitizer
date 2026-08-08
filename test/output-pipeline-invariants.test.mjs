/**
 * Whole-pipeline INVARIANTS for src/output.mjs — the properties the module
 * promises about everything it returns, rather than about one layer's output.
 * Each suite here is a class-level guard: it holds for any input and any option
 * combination, so a future layer that re-establishes some invariants and forgets
 * the rest fails here even though every per-layer example test still passes.
 *
 *   1. Layer-4 closure — every string reachable from a result has been through
 *      the injected redactor, not just `cleaned`.
 *   2. Post-mutation invariants — `cleaned` never carries a lone surrogate, and
 *      `sgrNote` never survives a mutation that was not the SGR strip, for every
 *      point of the option matrix.
 *   3. Walk path-independence — a shared node's sanitized/suppressed form
 *      depends on the node and its depth, never on which path reached it first.
 *
 * Invisible/surrogate inputs are built from \uXXXX escapes (never literal
 * control bytes; see CLAUDE.md > Code Style).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  sanitizeText,
  sanitizeValue,
  suppressToolOutput,
  MAX_DEPTH,
} from "../src/output.mjs";
import { LONE_SURROGATE_RE } from "../src/layer1.mjs";

// LONE_SURROGATE_RE is /g, so `.test` advances lastIndex between calls. Derive a
// stateless copy from the SAME source rather than hand-copying the pattern.
const HAS_LONE_SURROGATE = new RegExp(LONE_SURROGATE_RE.source, "u");

const ESC = "\u001B";
const REPLACEMENT_CHAR = "\uFFFD";
const SECRET = "sk-live-ABCDEF1234567890";
// Two regexes rather than one /g reused for both roles: `.test` on a /g regex
// advances lastIndex, so a shared instance would silently skip matches.
const SECRET_RE = /sk-live-[A-Za-z0-9]+/;
const SECRET_RE_G = /sk-live-[A-Za-z0-9]+/g;

/** Mask the corpus's secret shape, nothing else. */
const maskSecrets = (/** @type {string} */ text) =>
  text.replace(SECRET_RE_G, "[REDACTED:KEY]");

/** Stand-in Layer-4 engine. */
const redactor = (/** @type {string} */ text) =>
  SECRET_RE.test(text) ? { text: maskSecrets(text), found: ["key"] } : null;

/** Every string reachable from a sanitizeText result, including the warnings. */
function reachableStrings(result) {
  const out = [result.cleaned, ...result.warnings];
  if (result.reveal !== undefined) out.push(result.reveal);
  return out;
}

// ─── 1. Layer-4 closure over the whole result object ─────────────────────────

// Each case hides the secret somewhere Layer 2 SPLICES OUT, so the pre-Layer-2
// stage value (`reveal`) is the only place it survives — which is exactly the
// value a caller is invited to persist to a log or sidecar file.
const HIDDEN_SECRET_CASES = [
  ["HTML comment", `visible<!-- token=${SECRET} -->`],
  [
    "display:none element",
    `visible<div style="display:none">token=${SECRET}</div>`,
  ],
  ["comment inside a paragraph", `<p>intro<!-- ${SECRET} -->tail</p>`],
];

describe("invariant: no string leaves sanitizeText unvetted by Layer 4", () => {
  for (const [label, input] of HIDDEN_SECRET_CASES)
    it(`redacts the secret hidden in a spliced ${label} before returning it`, async () => {
      const r = await sanitizeText(input, {
        html: true,
        exfilScan: true,
        redact: redactor,
      });
      // Non-vacuity: the splice really did fire and really did hand back a
      // reveal, so the assertions below inspect the risky path.
      assert.equal(r.modified, true);
      assert.equal(typeof r.reveal, "string");
      for (const text of reachableStrings(r))
        assert.ok(
          !text.includes(SECRET),
          `unredacted secret in a returned string: ${JSON.stringify(text)}`,
        );
      // The reveal still shows WHAT was hidden — only the secret is masked, so
      // the field keeps its purpose (inspecting the removed markup).
      assert.equal(r.reveal, maskSecrets(input));
    });

  it("carries the same closure through sanitizeValue's `reveals`", async () => {
    /** @type {string[]} */
    const reveals = [];
    await sanitizeValue(
      { body: `visible<!-- token=${SECRET} -->` },
      { html: true, redact: redactor },
      [],
      reveals,
    );
    assert.equal(reveals.length, 1);
    assert.ok(!reveals[0].includes(SECRET));
  });

  it("withholds the reveal (and says so) when it cannot be vetted, keeping `cleaned`", async () => {
    // Throws only on the PRE-splice text, so Layer 4's pass over `cleaned`
    // succeeds and only the side channel is unvettable.
    const redact = (/** @type {string} */ text) => {
      if (text.includes("<!--")) throw new Error("redactor unreachable");
      return null;
    };
    const r = await sanitizeText(`visible<!-- token=${SECRET} -->`, {
      html: true,
      redact,
    });
    assert.equal(r.cleaned, "visible[HTML comment removed]");
    assert.ok(!("reveal" in r));
    assert.ok(
      r.warnings.includes(
        "Withheld the pre-splice copy of the removed HTML: it could not be vetted for secrets",
      ),
    );
  });

  it("leaves a legitimate reveal byte-identical when the redactor finds nothing", async () => {
    // Precision: vetting must not rewrite content that holds no secret.
    const input = "docs <!-- TODO: rewrite this paragraph --> end";
    const r = await sanitizeText(input, { html: true, redact: redactor });
    assert.equal(r.reveal, input);
  });

  it("returns the raw reveal when no redactor is configured (nothing to vet with)", async () => {
    const input = "intro <!-- secret --> tail";
    const r = await sanitizeText(input, { html: true });
    assert.equal(r.reveal, input);
  });
});

// ─── 2. Post-mutation invariants across the option matrix ────────────────────

// Layer 5 asks for the LOW surrogate of an emoji: deleting it joins the bytes
// around it and leaves the HIGH surrogate stranded. The repair for that belongs
// to Layer 1's "always normalized" contract, so it must not depend on whether a
// redactor, the HTML pipeline, or the SGR carve-out happens to be switched on.
const SPLITS_A_SURROGATE_PAIR = {
  filterInjection: () => ({ removeSpans: ["\uDE00"] }),
};
const OPTION_MATRIX = [
  ["bare", {}],
  ["redact", { redact: () => null }],
  ["html", { html: true }],
  ["exfilScan", { exfilScan: true }],
  ["sgrCarveOut", { sgrCarveOut: true }],
  ["html+redact", { html: true, redact: () => null }],
  [
    "html+redact+exfil+sgr",
    { html: true, exfilScan: true, sgrCarveOut: true, redact: () => null },
  ],
];

describe("invariant: a byte mutation always restores the stage invariants", () => {
  for (const [label, options] of OPTION_MATRIX)
    it(`normalizes the lone surrogate a Layer-5 deletion strands (${label})`, async () => {
      const r = await sanitizeText("hi \u{1F600} <b>there</b>", {
        ...options,
        ...SPLITS_A_SURROGATE_PAIR,
      });
      // Non-vacuity: the deletion fired, so the surrogate really was stranded.
      assert.equal(r.modified, true);
      assert.ok(
        !HAS_LONE_SURROGATE.test(r.cleaned),
        `lone surrogate in cleaned (${label}): ${JSON.stringify(r.cleaned)}`,
      );
      assert.ok(r.cleaned.includes(REPLACEMENT_CHAR));
    });

  // `sgrNote` downgrades the caller's banner to "display-only color stripped",
  // so it may only survive when that strip was the SOLE change.
  const SGR_INPUT = `${ESC}[31mred${ESC}[0m`;
  // [label, options, input, expected cleaned]. The expected text is asserted
  // too: it proves the named layer is what actually mutated the bytes, so the
  // sgrNote assertion cannot pass because the layer silently no-opped.
  const MUTATIONS_AFTER_LAYER1 = [
    [
      "Layer 2 splice",
      { html: true },
      `${SGR_INPUT}<!-- x -->`,
      "red[HTML comment removed]",
    ],
    [
      "Layer 4 redaction",
      {
        redact: (/** @type {string} */ t) => ({ text: `${t}!`, found: ["k"] }),
      },
      SGR_INPUT,
      "red!",
    ],
    [
      "Layer 5 deletion",
      { filterInjection: () => ({ removeSpans: ["red"] }) },
      SGR_INPUT,
      "",
    ],
  ];

  it("keeps sgrNote true when the SGR strip really is the only change", async () => {
    // Positive marker: without it the assertions below could pass vacuously on
    // an sgrNote that is never true in the first place.
    const r = await sanitizeText(SGR_INPUT, { sgrCarveOut: true });
    assert.equal(r.sgrNote, true);
    assert.equal(r.modified, true);
  });

  for (const [label, options, input, expected] of MUTATIONS_AFTER_LAYER1)
    it(`clears sgrNote when ${label} also changes bytes`, async () => {
      const r = await sanitizeText(input, { sgrCarveOut: true, ...options });
      assert.equal(r.cleaned, expected);
      assert.equal(r.modified, true);
      assert.equal(r.sgrNote, false);
    });
});

// ─── 3. Walk path-independence ───────────────────────────────────────────────

/** `depth` nested wrappers around `node`. */
function chainTo(node, depth) {
  let cur = node;
  for (let i = 0; i < depth; i++) cur = { n: cur };
  return cur;
}

const sharedNode = () => ({ level2: { payload: "REAL CONTENT" } });

describe("invariant: a shared node's result does not depend on the path that reached it first", () => {
  // The range straddles the depth cap: below it nothing truncates, above it the
  // shared node itself truncates on the deep path (and a placeholder is never
  // cached). In between, the node's CHILD truncates — and caching the node by
  // identity alone propagated that truncation to every other path, withholding
  // real tool output from the model.
  for (let extra = -5; extra <= 2; extra++) {
    const deep = MAX_DEPTH + extra;
    it(`sanitizeValue: shallow occurrence is intact when a deep path (depth ${deep}) reaches it first`, async () => {
      const shared = sharedNode();
      const withDeep = await sanitizeValue(
        { deep: chainTo(shared, deep), shallow: shared },
        {},
        [],
      );
      const alone = await sanitizeValue({ shallow: sharedNode() }, {}, []);
      assert.deepEqual(withDeep.value.shallow, alone.value.shallow);
      assert.deepEqual(withDeep.value.shallow, {
        level2: { payload: "REAL CONTENT" },
      });
    });

    it(`suppressToolOutput: shallow occurrence keeps its shape when a deep path (depth ${deep}) reaches it first`, () => {
      const shared = sharedNode();
      const out = suppressToolOutput(
        { deep: chainTo(shared, deep), shallow: shared },
        "[suppressed]",
      );
      assert.deepEqual(out.shallow, { level2: { payload: "[suppressed]" } });
    });
  }

  it(
    "still bounds an UNBALANCED diamond DAG, where one node is reached at many depths",
    { timeout: 10_000 },
    async () => {
      // Each level reaches the same child through a 1-hop and a 2-hop branch, so
      // a node sits at a RANGE of depths and the per-depth cache cannot collapse
      // it to one entry. 2^28 root->leaf paths: only a memo that is still
      // effective per (node, depth) finishes this at all.
      let node = { leaf: "x" };
      for (let i = 0; i < 28; i++) node = { a: node, b: { pad: node } };
      const r = await sanitizeValue(node, {}, []);
      let walk = r.value;
      for (let i = 0; i < 28; i++) walk = walk.a;
      assert.equal(walk.leaf, "x");
    },
  );
});
