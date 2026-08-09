/**
 * Unit test for the shard-report aggregator's dedup/tally.
 *
 * The big source files are sharded by LINE RANGE, so a mutant whose span
 * straddles a tile boundary is instrumented by BOTH adjacent shards; the
 * per-shard incremental cache can likewise re-emit a mutant from an earlier
 * tiling. Either way the SAME mutant lands in more than one `mutation.json`.
 * Summing the raw statuses double-counts it — and because the neighbour shard
 * only clips the mutant's edge, its copy frequently reports NoCoverage/Survived,
 * deflating the project score below the true unsharded value. `tallyMutants`
 * collapses duplicates to one verdict per unique mutant, keeping the strongest.
 *
 * These tests pin that behaviour with hand-built reports; the end-to-end score
 * over the real 28 shard reports is exercised by running the script in CI.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { describe, it } from "node:test";

import {
  gatedScopes,
  tallyMutants,
} from "../.github/scripts/aggregate-mutation.mjs";
import { mutatedSources } from "../scripts/shipped-sources.mjs";

/** Build a mutant with a distinct-by-default location so tests opt IN to
 * collisions by passing the same `loc`, rather than colliding by accident. */
let seq = 0;
const mutant = (status, loc) => {
  const line = loc ?? ++seq;
  return {
    status,
    mutatorName: "ArithmeticOperator",
    replacement: "-",
    location: {
      start: { line, column: 1 },
      end: { line, column: 9 },
    },
  };
};

/** One shard report: { files: { path: { mutants: [...] } } }. */
const report = (...mutants) => ({ files: { "src/a.mjs": { mutants } } });

/** A report spanning several files, optionally keyed by absolute path. */
const multiFileReport = (byFile, projectRoot) => ({
  ...(projectRoot === undefined ? {} : { projectRoot }),
  files: Object.fromEntries(
    Object.entries(byFile).map(([file, mutants]) => [file, { mutants }]),
  ),
});

describe("tallyMutants", () => {
  it("scores a single report exactly as Stryker would (detected / covered)", () => {
    const r = report(
      mutant("Killed"),
      mutant("Timeout"),
      mutant("Survived"),
      mutant("NoCoverage"),
      mutant("RuntimeError"), // excluded from the score entirely
      mutant("Ignored"), // excluded from the score entirely
    );
    const { total, detected, undetected, score, counts } = tallyMutants([r]);
    assert.equal(total, 6);
    assert.equal(detected, 2); // Killed + Timeout
    assert.equal(undetected, 2); // Survived + NoCoverage
    // 2 detected / 4 scored = 50%; RuntimeError + Ignored are not scored.
    assert.equal(score, 50);
    assert.deepEqual(counts, {
      Killed: 1,
      Timeout: 1,
      Survived: 1,
      NoCoverage: 1,
      RuntimeError: 1,
      Ignored: 1,
    });
  });

  it("counts a mutant instrumented by two shards once, keeping the strongest verdict", () => {
    // Same identity (same loc/mutator/replacement) in two shard reports: the
    // owning shard Killed it; the neighbour that only clipped its span reports
    // NoCoverage. It must count once, as Killed — the raw sum would score it as
    // 1 detected + 1 undetected = 50%, the bug this dedup fixes.
    const shardA = report(mutant("Killed", 42));
    const shardB = report(mutant("NoCoverage", 42));
    const { total, detected, undetected, score, counts } = tallyMutants([
      shardA,
      shardB,
    ]);
    assert.equal(total, 1, "the duplicated mutant must collapse to one");
    assert.equal(detected, 1);
    assert.equal(undetected, 0);
    assert.equal(score, 100);
    assert.deepEqual(counts, { Killed: 1 });
  });

  it("keeps the strongest verdict regardless of shard order", () => {
    // Weaker verdict seen FIRST must still lose to the later stronger one, and
    // vice versa — the resolution is order-independent, not last-write-wins.
    const strongFirst = tallyMutants([
      report(mutant("Survived", 7)),
      report(mutant("Killed", 7)),
    ]);
    const strongLast = tallyMutants([
      report(mutant("Killed", 7)),
      report(mutant("Survived", 7)),
    ]);
    assert.deepEqual(strongFirst.counts, { Killed: 1 });
    assert.deepEqual(strongLast.counts, { Killed: 1 });
  });

  it("resolves Survived over NoCoverage for the same mutant (covered beats unreached)", () => {
    // Both undetected, but Survived means the suite RAN the mutant and missed
    // it (a real gap) while NoCoverage means a neighbour never reached it. The
    // owning shard's Survived is the true verdict.
    const { counts, undetected, score } = tallyMutants([
      report(mutant("NoCoverage", 3)),
      report(mutant("Survived", 3)),
    ]);
    assert.deepEqual(counts, { Survived: 1 });
    assert.equal(undetected, 1);
    assert.equal(score, 0);
  });

  it("treats mutants at different locations as distinct (no false collapse)", () => {
    // Guard against the dedup over-merging: same status/mutator but different
    // lines are different mutants and must both count.
    const { total } = tallyMutants([
      report(mutant("Survived", 10), mutant("Survived", 20)),
    ]);
    assert.equal(total, 2);
  });

  it("scores each gated scope independently", () => {
    // The library and the newly-gated hook layer are two populations with very
    // different mutation histories. A blended score would let the weaker one
    // drag src/'s long-standing floor down, so the aggregator tallies per scope.
    const reports = [
      multiFileReport({
        "src/a.mjs": [mutant("Killed", 1), mutant("Killed", 2)],
        "claude-hooks/lib/hook-io.mjs": [
          mutant("Killed", 3),
          mutant("Survived", 4),
        ],
      }),
    ];
    const isSrc = (/** @type {string} */ f) => f.startsWith("src/");
    assert.equal(tallyMutants(reports, isSrc).score, 100);
    assert.equal(tallyMutants(reports, (f) => !isSrc(f)).score, 50);
    // Unfiltered, the hook layer's miss would show up as a 75% library score.
    assert.equal(tallyMutants(reports).score, 75);
  });

  it("scopes absolute report paths by relativizing against projectRoot", () => {
    // Stryker keys `files` relative to projectRoot, but the field is optional
    // and an absolute key must not silently land in the wrong scope (or dedup
    // against nothing when a sibling shard emitted the relative form).
    const relative = multiFileReport({ "src/a.mjs": [mutant("Killed", 5)] });
    const absolute = multiFileReport(
      { "/build/repo/src/a.mjs": [mutant("Survived", 5)] },
      "/build/repo",
    );
    const isSrc = (/** @type {string} */ f) => f.startsWith("src/");
    const scoped = tallyMutants([relative, absolute], isSrc);
    assert.equal(scoped.total, 1, "both keys name the same mutant");
    assert.equal(scoped.score, 100);
    assert.equal(
      tallyMutants([absolute], (f) => !isSrc(f)).total,
      0,
      "an absolute src/ path must not fall into the hook scope",
    );
  });

  it("scores 0 when no mutant produced a scorable verdict", () => {
    // Only errored/ignored mutants: scored denominator is 0, guard the div.
    const { score, detected, undetected } = tallyMutants([
      report(mutant("RuntimeError"), mutant("Ignored")),
    ]);
    assert.equal(detected, 0);
    assert.equal(undetected, 0);
    assert.equal(score, 0);
  });
});

describe("gatedScopes", () => {
  it("partitions every mutated file into exactly one gated scope", () => {
    // Each scope applies its own break threshold to whatever it claims. A file
    // claimed twice is gated twice — the library's floor applied to tooling it
    // was never measured against — and a file claimed by nothing is scored by
    // no threshold at all, which is the silent ungating the split exists to
    // prevent. Run over the LIVE mutated set, so a new directory that fits none
    // of the prefixes fails here rather than at the next aggregate run.
    const scopes = gatedScopes({
      breakThreshold: 83,
      hookScopeBreak: 30,
      toolingScopeBreak: 1,
    });
    const files = mutatedSources(
      execFileSync("git", ["rev-parse", "--show-toplevel"], {
        encoding: "utf8",
      }).trim(),
    );
    assert.ok(files.length > 0, "the mutated set must not be empty");
    for (const file of files) {
      const claimed = scopes.filter((scope) => scope.inScope(file));
      assert.equal(
        claimed.length,
        1,
        `${file} is claimed by ${claimed.length} scope(s): ${claimed.map((s) => s.name).join(", ") || "none"}`,
      );
    }
    // Every scope must claim something, or its threshold gates an empty set —
    // the vacuous pass the aggregator's own empty-scope check also refuses.
    for (const scope of scopes)
      assert.ok(
        files.some((file) => scope.inScope(file)),
        `scope "${scope.name}" claims no mutated file`,
      );
  });
});
