/**
 * The budget helper is the sole verdict for every cost gate, so its own
 * polarity is pinned here: a run inside its ceiling passes, one over it throws
 * with the label and the reading, and a mutation run stands down.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { assertUnderBudget, grow } from "./budget.mjs";

/** A `TestContext` stand-in recording what the helper reports. */
function recorder() {
  const seen = { diagnostics: [], skipped: null };
  return {
    seen,
    t: {
      diagnostic: (msg) => seen.diagnostics.push(msg),
      skip: (msg) => {
        seen.skipped = msg;
      },
    },
  };
}

/** Enough work that the timed run reads a non-zero CPU figure. */
const work = (n) => {
  let acc = 0;
  for (let i = 0; i < n; i++) acc = (acc + i * 31) % 1_000_003;
  return acc;
};

describe("assertUnderBudget", () => {
  it("passes inside its ceiling and reports the reading", async () => {
    const { seen, t } = recorder();
    const inputs = [];
    await assertUnderBudget(
      t,
      "label",
      60_000,
      (attempt) => {
        inputs.push(attempt);
        return 1e5 + attempt;
      },
      work,
    );
    assert.deepEqual(inputs, [0, 1]);
    assert.equal(seen.skipped, null);
    assert.equal(seen.diagnostics.length, 1);
    assert.match(
      seen.diagnostics[0],
      /^label: [\d.]+ms CPU \(ceiling 60000ms\)$/,
    );
  });

  it("throws over its ceiling, naming the label and the reading", async () => {
    const { t } = recorder();
    await assert.rejects(
      assertUnderBudget(t, "slow path", 0, () => 5e6, work),
      (err) => {
        assert.ok(err instanceof assert.AssertionError);
        assert.match(
          err.message,
          /^slow path took [\d.]+ms of CPU, over its 0ms ceiling/,
        );
        return true;
      },
    );
  });

  it("stands down under a Stryker run without calling the code", async () => {
    const saved = process.env.STRYKER_NAMESPACE;
    process.env.STRYKER_NAMESPACE = "__stryker__";
    try {
      // A fresh module instance, so MUTATION_RUN is read with the env set.
      const fresh = await import(`./budget.mjs?stryker=${Date.now()}`);
      const { seen, t } = recorder();
      let calls = 0;
      await fresh.assertUnderBudget(
        t,
        "label",
        0,
        () => 1,
        () => {
          calls++;
        },
      );
      assert.equal(calls, 0);
      assert.equal(seen.skipped, fresh.MUTATION_RUN);
      assert.match(seen.skipped, /Stryker/);
    } finally {
      if (saved === undefined) delete process.env.STRYKER_NAMESPACE;
      else process.env.STRYKER_NAMESPACE = saved;
    }
  });
});

describe("grow", () => {
  it("repeats a unit to exactly n code units", () => {
    assert.equal(grow("abc", 7), "abcabca");
    assert.equal(grow("abc", 0), "");
  });
});
