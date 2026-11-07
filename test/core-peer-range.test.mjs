/**
 * The agent-control-plane-core version CI tests against must sit inside the
 * peer range consumers resolve against.
 *
 * The exact devDependencies pin is the only core version the suite, the type
 * build and the plugin bundle ever run; the peerDependencies range is what a
 * published install accepts. Renovate bumps the pin and never the range, so
 * without this check a pin bumped past the range ceiling (or a floor raised past
 * the pin) ships a range that excludes the one version it was tested with, and
 * npm 7+ consumers on that version get ERESOLVE.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import semver from "semver";

import { repoRoot } from "./helpers/repo-root.mjs";

const CORE = "agent-control-plane-core";
const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));

test("the core dev pin is exact and inside the published peer range", () => {
  const pin = pkg.devDependencies?.[CORE];
  const range = pkg.peerDependencies?.[CORE];
  assert.ok(
    semver.valid(pin),
    `devDependencies.${CORE} must be one exact version, got ${pin}`,
  );
  assert.ok(
    semver.validRange(range),
    `peerDependencies.${CORE} must be a semver range, got ${range}`,
  );
  assert.ok(
    semver.satisfies(pin, range),
    `devDependencies.${CORE} ${pin} is outside peerDependencies.${CORE} ` +
      `"${range}": the release would publish a range excluding the only core ` +
      `version CI tested. Move the pin and the range together.`,
  );
  // An exact pin here as well re-couples every core release to a sanitizer
  // release, which is what the peer range exists to undo.
  assert.equal(pkg.dependencies?.[CORE], undefined);
});
