/**
 * Contract test for the sandbox climb-out.
 *
 * Every case here is one a plain local run cannot reach: outside Stryker the
 * helper is the identity, so a broken `unsandbox` would look perfectly healthy
 * until a mutation shard read the wrong tree. The paths below are therefore
 * synthesised rather than observed.
 */
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join, sep } from "node:path";
import { describe, it } from "node:test";

import { SANDBOX_MARKER, repoRoot, unsandbox } from "./repo-root.mjs";

const ROOT = join(sep, "home", "dev", "repo");
const SANDBOX = `${ROOT}${SANDBOX_MARKER}a1b2c3`;

describe("unsandbox", () => {
  it("returns a path outside a sandbox unchanged", () => {
    assert.equal(unsandbox(ROOT), ROOT);
    assert.equal(
      unsandbox(join(ROOT, "src", "index.mjs")),
      join(ROOT, "src", "index.mjs"),
    );
  });

  it("maps the sandbox root back to the repo root", () => {
    assert.equal(unsandbox(SANDBOX), ROOT);
  });

  it("maps a file INSIDE the sandbox back onto the real tree", () => {
    // The case that matters and that truncation gets wrong: everything below
    // the sandbox segment has to survive, or a resolved module path becomes the
    // repo root and stops matching anything.
    assert.equal(
      unsandbox(join(SANDBOX, "src", "index.mjs")),
      join(ROOT, "src", "index.mjs"),
    );
  });

  it("removes only the sandbox segment, not a later lookalike", () => {
    const nested = join(
      SANDBOX,
      "fixtures",
      ".stryker-tmp",
      "sandbox-zzz",
      "a.mjs",
    );
    assert.equal(
      unsandbox(nested),
      join(ROOT, "fixtures", ".stryker-tmp", "sandbox-zzz", "a.mjs"),
    );
  });

  it("leaves `.stryker-tmp` alone when no sandbox directory follows it", () => {
    const reports = join(ROOT, ".stryker-tmp", "reports", "x.json");
    assert.equal(unsandbox(reports), reports);
  });
});

describe("repoRoot", () => {
  it("names a real checkout, with no trailing separator", () => {
    assert.ok(existsSync(join(repoRoot, "package.json")), repoRoot);
    assert.ok(!repoRoot.endsWith(sep), repoRoot);
  });

  it("is not inside a sandbox, wherever this suite is running from", () => {
    assert.ok(!repoRoot.includes(SANDBOX_MARKER), repoRoot);
  });
});
