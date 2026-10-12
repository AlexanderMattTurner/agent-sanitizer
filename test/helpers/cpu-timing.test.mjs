/**
 * The verdict helpers of the cost-gate harness. Every gate that stopped
 * comparing a clock reading itself now delegates to one of these, so each must
 * both pass a reading inside its limit and throw, descriptively, outside it.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  assertCalibrated,
  assertDearerThan,
  assertWithinBudget,
  assertWithinCeiling,
} from "./cpu-timing.mjs";

describe("cost-gate verdict helpers", () => {
  it("assertWithinBudget passes at the budget and names the overrun beyond it", () => {
    assertWithinBudget("x", 15, 15, 3);
    assert.throws(
      () => assertWithinBudget("x", 15.04, 15, 3.2),
      /x ran in 15\.0 units \(3\.2ms CPU\), budget 15/u,
    );
  });

  it("assertWithinCeiling passes at the ceiling and names the overrun beyond it", () => {
    assertWithinCeiling("y", 40, 40);
    assert.throws(
      () => assertWithinCeiling("y", 40.5, 40),
      /y took 40\.5ms of CPU at best, ceiling 40ms/u,
    );
  });

  it("assertCalibrated rejects a unit that is timer noise", () => {
    assertCalibrated(0.11);
    assert.throws(() => assertCalibrated(0.1), /too fast to divide by/u);
  });

  it("assertDearerThan is strict and carries the reason", () => {
    assertDearerThan("z", 2, 1, "unused");
    assert.throws(
      () => assertDearerThan("z", 1, 1, "it is a no-op"),
      /z \(1\.0ms CPU\) no longer costs more than the baseline \(1\.0ms CPU\) — it is a no-op/u,
    );
  });
});
