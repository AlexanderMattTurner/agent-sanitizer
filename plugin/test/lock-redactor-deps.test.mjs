/**
 * When `lock-redactor-deps.mjs --if-stale` (the step CI's plugin-dist-autofix
 * runs) must re-lock. Offline: the lock records the digest of the
 * requirements.in it was compiled from, so staleness is a comparison, never a
 * resolution.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  REQUIREMENTS_IN_PATH,
  REQUIREMENTS_LOCK_PATH,
  redactorRequirements,
} from "../scripts/build-plugin.mjs";
import {
  lockIsStale,
  requirementsInDigest,
  stampLockInput,
} from "../scripts/lock-redactor-deps.mjs";

const LOCK = readFileSync(REQUIREMENTS_LOCK_PATH, "utf-8");
const REQUIREMENTS_IN = readFileSync(REQUIREMENTS_IN_PATH, "utf-8");

/** A lock exactly as uv writes it, before the input digest is stamped in. */
const UNSTAMPED = LOCK.replace(/^# requirements\.in sha256: .*\n/m, "");

test("the committed lock was compiled from the committed requirements.in", () => {
  // The one state --if-stale may skip. Red here means a dependency change in
  // the `secrets` extra never reached the pins the plugin ships.
  assert.equal(lockIsStale(LOCK, REQUIREMENTS_IN), false);
});

test("a raised floor in the secrets extra makes the lock stale", () => {
  // The extra as python/pyproject.toml declares it, with detect-secrets'
  // floor raised past the version the lock pins.
  const pyproject = readFileSync(
    new URL("../../python/pyproject.toml", import.meta.url),
    "utf-8",
  );
  const raised = pyproject.replace(
    /"detect-secrets>=[^"]+"/,
    '"detect-secrets>=99.0.0"',
  );
  assert.notEqual(raised, pyproject, "the fixture raised nothing");
  assert.equal(lockIsStale(LOCK, redactorRequirements(raised)), true);
});

test("a dependency added to the secrets extra makes the lock stale", () => {
  assert.equal(lockIsStale(LOCK, `${REQUIREMENTS_IN}left-pad-py>=1.0\n`), true);
});

test("a lock with no recorded input digest is stale", () => {
  assert.equal(lockIsStale(UNSTAMPED, REQUIREMENTS_IN), true);
});

test("a lock that pins the published engine is stale whatever its digest", () => {
  const pinned = LOCK.replace(
    /^certifi==/m,
    "agent-sanitizer==1.2.3 \\\n    --hash=sha256:" +
      "0".repeat(64) +
      "\ncertifi==",
  );
  assert.equal(lockIsStale(pinned, REQUIREMENTS_IN), true);
});

test("stamping writes the digest under uv's header, where the committed lock has it", () => {
  const stamped = stampLockInput(UNSTAMPED, REQUIREMENTS_IN);
  assert.equal(stamped, LOCK);
  assert.match(
    stamped,
    new RegExp(
      `^#\\s+node plugin/scripts/lock-redactor-deps\\.mjs\\n# requirements\\.in sha256: ${requirementsInDigest(REQUIREMENTS_IN)}$`,
      "m",
    ),
  );
  assert.throws(
    () => stampLockInput("certifi==1 \\\n", REQUIREMENTS_IN),
    /wrote no header/,
  );
});
