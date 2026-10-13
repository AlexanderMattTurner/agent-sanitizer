/**
 * `plugin/scripts/lib/fail-open.sh` is GENERATED from `FAIL_CLOSED_VALUES` in
 * `claude-hooks/lib/hook-io.mjs` (by `pnpm build:plugin`, and by the release
 * bake that ships it), so the shell shims and the JS cannot disagree about
 * which spellings of `AGENT_SANITIZER_FAIL_OPEN` mean "fail closed".
 *
 * What is left to prove is BEHAVIOUR: the generated function, actually sourced
 * and run by bash, and `failOpenEnabled()`, actually run by node, agree on
 * every posture value. A generator that emitted syntactically valid nonsense
 * would otherwise ship.
 *
 * The remaining hand-written implementations (the repo's own
 * `.claude/hooks/safe-launch.sh` and the `.claude/settings.json` bootstrap,
 * neither of which can reach this file) are pinned against the same values in
 * tests/test_safe_launch.py.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  FAIL_CLOSED_VALUES,
  FAIL_OPEN_ENV,
  failOpenEnabled,
} from "../../claude-hooks/lib/hook-io.mjs";
import { failOpenShellLib } from "../../scripts/gen-fail-open-lib.mjs";

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

test("the generated shell function decides exactly as failOpenEnabled()", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "agent-sanitizer-fail-open-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const lib = join(dir, "fail-open.sh");
  writeFileSync(lib, failOpenShellLib());
  for (const value of [...CLOSED_VALUES, ...OPEN_VALUES]) {
    const env = { PATH: process.env.PATH };
    if (value !== null) env[FAIL_OPEN_ENV] = value;
    const res = spawnSync(
      "bash",
      [
        "-c",
        `. "$1"; if agent_sanitizer_fail_open; then echo open; else echo closed; fi`,
        "bash",
        lib,
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
