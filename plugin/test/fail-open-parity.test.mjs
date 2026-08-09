/**
 * `plugin/scripts/lib/fail-open.sh` is GENERATED from `FAIL_CLOSED_VALUES` in
 * `claude-hooks/lib/hook-io.mjs`, so the shell shims and the JS cannot disagree
 * about which spellings of `AGENT_SANITIZER_FAIL_OPEN` mean "fail closed".
 *
 * Two halves, and neither alone is enough:
 *
 *   - ROUND TRIP. The committed bytes are what the generator still produces —
 *     an edit to the closed set that never reached the committed file, or a
 *     hand-edit of the file, fails here rather than at a user's next incident.
 *   - BEHAVIOUR. The generated function, actually sourced and run by bash, and
 *     `failOpenEnabled()`, actually run by node, agree on every posture value.
 *     A generator that emitted syntactically valid nonsense would pass the
 *     round trip alone.
 *
 * The remaining hand-written implementations (the repo's own
 * `.claude/hooks/safe-launch.sh` and the `.claude/settings.json` bootstrap,
 * neither of which can reach this file) are pinned against the same values in
 * tests/test_safe_launch.py.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  FAIL_CLOSED_VALUES,
  FAIL_OPEN_ENV,
  failOpenEnabled,
  failOpenShellLib,
} from "../../claude-hooks/lib/hook-io.mjs";

const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const LIB_PATH = join(ROOT, "plugin", "scripts", "lib", "fail-open.sh");

// The knob values both implementations must agree on. `null` means unset.
// Split here rather than derived from FAIL_CLOSED_VALUES on both sides: a
// derivation would make the two agree by construction and prove nothing.
const CLOSED_VALUES = ["0", "false"];
const OPEN_VALUES = [null, "1", "", "no", "off", "true", "FALSE", "0 "];

test("the split under test is populated and disjoint (non-vacuity)", () => {
  assert.deepEqual([...FAIL_CLOSED_VALUES], CLOSED_VALUES);
  assert.equal(
    OPEN_VALUES.filter((v) => v !== null && CLOSED_VALUES.includes(v)).length,
    0,
  );
  assert.ok(OPEN_VALUES.length >= 2);
});

test("the committed shell lib is exactly what the generator produces", () => {
  assert.equal(
    readFileSync(LIB_PATH, "utf8"),
    failOpenShellLib(),
    `${LIB_PATH} is stale or hand-edited — regenerate it (the command is in its header)`,
  );
});

test("the generated shell function decides exactly as failOpenEnabled()", () => {
  for (const value of [...CLOSED_VALUES, ...OPEN_VALUES]) {
    const env = { PATH: process.env.PATH };
    if (value !== null) env[FAIL_OPEN_ENV] = value;
    const res = spawnSync(
      "bash",
      [
        "-c",
        `. "$1"; if agent_sanitizer_fail_open; then echo open; else echo closed; fi`,
        "bash",
        LIB_PATH,
      ],
      { encoding: "utf8", env },
    );
    assert.equal(res.status, 0, res.stderr);
    const expected = failOpenEnabled(
      value === null ? {} : { [FAIL_OPEN_ENV]: value },
    )
      ? "open"
      : "closed";
    assert.equal(
      res.stdout.trim(),
      expected,
      `bash and JS disagree on ${JSON.stringify(value)}`,
    );
  }
});

test("a mutated closed set is caught by the round trip (the guard can fail)", () => {
  // The round-trip assertion is only worth its line if a divergence trips it.
  // Mutated in memory, never on disk: a killed test run must not leave the
  // committed posture lib rewritten.
  const mutated = readFileSync(LIB_PATH, "utf8").replace(
    "0 | false)",
    "0 | false | no)",
  );
  assert.notEqual(mutated, failOpenShellLib());
});
