/**
 * The blocking entry points survive a payload longer than a regex can match.
 *
 * V8 pushes one backtrack entry per iteration of an unbounded quantifier onto a
 * regexp stack capped at 64 MB, so `LONG_RUN_RE.exec` throws `RangeError:
 * Maximum call stack size exceeded` once a single run passes ~8.4 M code
 * points. Every consumer of "long run" scanned with that regex, so an 8 MB
 * paste of zero-widths — the exact payload the scan exists to catch — took out
 * the SessionStart scanner (scanText), the prompt gate (classifyPrompt) and the
 * tool-output pipeline (sanitizeText) alike: the layer failed by throwing
 * rather than by reporting.
 *
 * The fixture has to be that big to reach the bound, so this suite costs ~20
 * seconds and ~16 MB of fixture. It lives in its own file for that reason, and
 * stands down under Stryker, where the tap runner would re-run it once per
 * mutant that touches these modules — for a verdict the differential suites
 * already reach on inputs a thousand times smaller.
 */
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";

import {
  LONG_RUN_RE,
  findLongRuns,
  hasLongRun,
  payloadLongRunSample,
} from "../src/invisible.mjs";
import { scanText } from "../src/instructions.mjs";
import { classifyPrompt } from "../src/prompt.mjs";
import { sanitizeText } from "../src/output.mjs";

const MUTATION_RUN = process.env.STRYKER_NAMESPACE
  ? "an 8 MB fixture re-run per mutant costs hours; the differential suites cover these paths"
  : null;

const ZWSP = "\u200B";
// Deliberately NOT a multiple of the scan's chunk bound: an aligned length
// lands every stitched match exactly on the end of the run, so a final tail
// shorter than the bound — what RUN_TAIL_RE's lower bound is for — would never
// be exercised by anything (the property draws top out at 14 code points).
const RUN_LENGTH = 8 * 1024 * 1024 + 7;
/** Built in `before` so a stood-down run allocates nothing. */
let RUN = "";

before(() => {
  if (!MUTATION_RUN) RUN = ZWSP.repeat(RUN_LENGTH);
});

/** An `it` that stands down under Stryker (see the header). */
const huge = (name, fn) =>
  it(name, async (t) => {
    if (MUTATION_RUN) {
      t.skip(MUTATION_RUN);
      return;
    }
    await fn(t);
  });

describe("a run past the regexp engine's limit", () => {
  // The pin on RUN_LENGTH: below the bound this whole suite would pass on the
  // unbounded regex it exists to retire. A V8 that lifts the bound turns this
  // red, which is the signal to re-measure it — not to shrink the fixture.
  huge("is a run LONG_RUN_RE itself cannot match", () => {
    LONG_RUN_RE.lastIndex = 0;
    assert.throws(() => LONG_RUN_RE.exec(RUN), RangeError);
  });

  huge("findLongRuns reports it as one run", () =>
    assert.deepEqual(
      [...findLongRuns(RUN)].map((run) => [run.index, run.charCount]),
      [[0, RUN_LENGTH]],
    ),
  );

  huge("hasLongRun sees it", () => assert.equal(hasLongRun(RUN), true));

  huge("payloadLongRunSample returns the whole run", () =>
    assert.equal(payloadLongRunSample(RUN)?.length, RUN_LENGTH),
  );

  huge("scanText reports one finding on it", () => {
    const findings = scanText(RUN);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].charCount, RUN_LENGTH);
    assert.equal(findings[0].method, "zero-width binary encoding");
  });

  huge("classifyPrompt blocks it", () =>
    assert.equal(classifyPrompt(RUN).action, "block"),
  );

  huge("sanitizeText strips it", async () => {
    const { cleaned, found } = await sanitizeText(RUN);
    assert.equal(cleaned, "");
    assert.deepEqual(found, ["cf-format"]);
  });
});
