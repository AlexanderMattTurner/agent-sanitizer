/**
 * Contract test for the SSOT guard-pair map (.hooks/guard-pairs.json)
 * that the pre-commit hook uses to run a source's paired contract test in the
 * same commit as the source. A pair pointing at a moved/renamed file would
 * make the hook a silent no-op for exactly the SSOT it was added to protect,
 * so every path is asserted to exist, and the two pairings that actually broke
 * main are pinned by name (non-vacuity: an emptied map cannot pass).
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";
import { describe, it } from "node:test";

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();

const { pairs } = JSON.parse(
  readFileSync(join(repoRoot, ".hooks", "guard-pairs.json"), "utf8"),
);

describe("SSOT guard-pair map", () => {
  it("is non-empty and every mapped path exists in the repo", () => {
    const entries = Object.entries(pairs);
    assert.ok(entries.length > 0, "pair map must not be empty");
    for (const [source, tests] of entries) {
      assert.ok(
        existsSync(join(repoRoot, source)),
        `mapped SSOT source does not exist: ${source}`,
      );
      assert.ok(
        Array.isArray(tests) && tests.length > 0,
        `${source} must map to at least one guard test`,
      );
      for (const test of tests) {
        assert.ok(
          existsSync(join(repoRoot, test)),
          `guard test for ${source} does not exist: ${test}`,
        );
        assert.match(
          test,
          /\.test\.mjs$/,
          `guard test for ${source} must be a node --test file: ${test}`,
        );
      }
    }
  });

  it("pins the pairings that actually broke main (release-token + instructions guards)", () => {
    assert.deepEqual(pairs[".github/workflows/auto-version.yaml"], [
      "scripts/version-bump.test.mjs",
      // The workflow's six PyPI-publish steps gate on `steps.release.outputs`,
      // and a sync once dropped the `id: release` that defines it — an unknown
      // step id renders empty rather than erroring, so the whole coupled half
      // no-opped silently. The step-ref guard is what catches that.
      ".github/scripts/workflow-step-refs.test.mjs",
    ]);
    assert.deepEqual(pairs["src/instructions.mjs"], [
      "test/instructions.test.mjs",
    ]);
    assert.ok(
      pairs["src/invisible.mjs"].includes("test/invisible-charset.test.mjs"),
      "invisible.mjs must pair with its charset drift guard",
    );
  });
});
