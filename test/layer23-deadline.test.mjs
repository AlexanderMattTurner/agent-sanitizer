/**
 * Layers 2 and 3 refuse to start on a spent budget.
 *
 * `sanitizeHtml` and `detectExfil` each parse the whole document in ONE
 * synchronous call, so a caller cannot interrupt them once they begin. A host
 * that runs this pipeline inside a hook kills that hook at its own timeout and
 * reads the kill as a non-blocking error, which shows the model the RAW text —
 * the fail-open Layers 2/3 exist to prevent. Layer 4's injected redactor
 * already refuses on a spent budget; these cases pin the same posture for the
 * two layers that had none, and pin that it costs nothing where no work runs.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { sanitizeText } from "../src/output.mjs";

const SPENT = { remainingMs: () => 0 };
const LIVE = { remainingMs: () => 5_000 };

/** Text the Layer-2/3 pre-gate accepts, carrying a comment Layer 2 removes. */
const HTML_DOC = "<p>visible</p><!-- hidden instruction -->";
/** Text the pre-gate accepts through its markdown-link arm, for Layer 3 alone. */
const LINK_DOC = "see [report](https://drop.example/collect?d=secret)";
/** Text the pre-gate declines: no tag, no link, so neither layer would run. */
const PLAIN_DOC = "an ordinary line of tool output";

const SPENT_MESSAGE = /time budget was spent before Layers 2\/3/;

describe("a spent deadline before Layers 2/3", () => {
  it("refuses the whole call rather than skipping the HTML splice", async () => {
    await assert.rejects(
      () => sanitizeText(HTML_DOC, { html: true, deadline: SPENT }),
      SPENT_MESSAGE,
    );
  });

  it("refuses on the exfil-scan route too, which Layer 2 never gates", async () => {
    await assert.rejects(
      () => sanitizeText(LINK_DOC, { exfilScan: true, deadline: SPENT }),
      SPENT_MESSAGE,
    );
  });

  it("refuses BEFORE Layer 4, so no redactor call rides a spent budget", async () => {
    let redactCalls = 0;
    await assert.rejects(
      () =>
        sanitizeText(HTML_DOC, {
          html: true,
          deadline: SPENT,
          redact: () => {
            redactCalls += 1;
            return null;
          },
        }),
      SPENT_MESSAGE,
    );
    assert.equal(redactCalls, 0);
  });

  it("still returns normally when the pre-gate runs neither layer", async () => {
    // The refusal is scoped to work that would actually spend time. A call the
    // pre-gate declines costs nothing, so refusing it would withhold output for
    // no reason — the false-positive direction this package rejects.
    const out = await sanitizeText(PLAIN_DOC, { html: true, deadline: SPENT });

    assert.equal(out.cleaned, PLAIN_DOC);
  });
});

describe("a budget that is not spent", () => {
  it("lets Layer 2 splice, so the refusal above is not vacuous", async () => {
    const out = await sanitizeText(HTML_DOC, { html: true, deadline: LIVE });

    assert.ok(!out.cleaned.includes("hidden instruction"));
    assert.ok(out.cleaned.includes("visible"));
  });

  it("leaves a caller that passes no deadline unbounded, as before", async () => {
    const out = await sanitizeText(HTML_DOC, { html: true });

    assert.ok(!out.cleaned.includes("hidden instruction"));
  });
});
