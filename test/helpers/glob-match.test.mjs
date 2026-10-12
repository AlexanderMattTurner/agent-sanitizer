import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  MATCHES_GLOB_MIN_NODE,
  matchesGlob,
  requireMatchesGlob,
} from "./glob-match.mjs";

describe("test/helpers/glob-match", () => {
  it("hands back Node's own matcher, matching and refusing", () => {
    assert.equal(matchesGlob("test/a.test.mjs", "test/*.test.mjs"), true);
    assert.equal(matchesGlob("test/a.mjs", "test/*.test.mjs"), false);
  });

  it("fails with the required Node version where the matcher is missing", () => {
    assert.throws(
      () => requireMatchesGlob({}, "v22.4.0"),
      new RegExp(
        `path\\.matchesGlob is missing on Node v22\\.4\\.0.*>= ${MATCHES_GLOB_MIN_NODE.replaceAll(".", "\\.")}`,
      ),
    );
  });

  it("returns the injected matcher untouched when present", () => {
    const stub = () => true;
    assert.equal(requireMatchesGlob({ matchesGlob: stub }), stub);
  });
});
