/**
 * `plugin/scripts/lib/node-floor.sh` is GENERATED from `engines.node` in
 * `package.json`, so the launcher's runtime diagnosis and the floor npm
 * enforces cannot disagree about which node versions this package supports.
 *
 * Two halves, and neither alone is enough:
 *
 *   - ROUND TRIP. The committed bytes are what the generator still produces —
 *     a raised `engines.node` that never reached the committed file, or a
 *     hand-edit of the file, fails here rather than in an operator's transcript
 *     as a version fault named against the wrong floor.
 *   - BEHAVIOUR. The generated functions, actually sourced and run by bash,
 *     classify real `node --version` answers the way the declared range does. A
 *     generator that emitted syntactically valid nonsense would pass the round
 *     trip alone.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  nodeFloorShellLib,
  nodeMajorFloor,
  parseNodeMajorFloor,
} from "../../scripts/gen-node-floor-lib.mjs";

const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const LIB_PATH = join(ROOT, "plugin", "scripts", "lib", "node-floor.sh");

/** A stub `node` whose `--version` answers `reported`. */
function stubNode(t, reported) {
  const dir = mkdtempSync(join(tmpdir(), "agent-sanitizer-node-floor-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const bin = join(dir, "node");
  writeFileSync(bin, `#!/bin/sh\nprintf '%s\\n' ${JSON.stringify(reported)}\n`);
  chmodSync(bin, 0o755);
  return bin;
}

/** `{ major, meetsFloor }` as the generated shell functions answer for `bin`. */
function askShell(bin) {
  const res = spawnSync(
    "bash",
    [
      "-c",
      'set -uo pipefail; . "$1"; printf "%s\\n" "$(agent_sanitizer_node_major "$2")"; ' +
        'if agent_sanitizer_node_meets_floor "$2"; then echo meets; else echo below; fi',
      "bash",
      LIB_PATH,
      bin,
    ],
    { encoding: "utf8" },
  );
  assert.equal(res.status, 0, res.stderr);
  const [major, verdict] = res.stdout.split("\n");
  assert.ok(["meets", "below"].includes(verdict), res.stdout);
  return { major, meetsFloor: verdict === "meets" };
}

test("the committed shell lib is exactly what the generator produces", () => {
  assert.equal(
    readFileSync(LIB_PATH, "utf8"),
    nodeFloorShellLib(),
    `${LIB_PATH} is stale or hand-edited — regenerate it (the command is in its header)`,
  );
});

test("the rendered floor is the one package.json declares", () => {
  const declared = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"))
    .engines.node;
  assert.equal(parseNodeMajorFloor(declared), nodeMajorFloor());
  assert.match(
    nodeFloorShellLib(),
    new RegExp(`^AGENT_SANITIZER_NODE_MAJOR_FLOOR=${nodeMajorFloor()}$`, "m"),
  );
});

test("a range the generator cannot render as one floor fails the build", () => {
  // Anything the parser would have to APPROXIMATE — a caret, an upper bound, a
  // wildcard, nothing at all — throws, because a guessed floor reaches an
  // operator as a confident, wrong "upgrade node" instruction.
  for (const declared of ["^22.0.0", ">=20 <23", "22.x", "22", "", undefined])
    assert.throws(
      () => parseNodeMajorFloor(declared),
      /cannot render as a single major-version floor/,
      `${declared} was rendered rather than rejected`,
    );
  // Non-vacuity: the spellings it DOES accept, including the padded forms.
  assert.equal(parseNodeMajorFloor(">=22"), 22);
  assert.equal(parseNodeMajorFloor(">= 22.11.0"), 22);
});

test("the shell classifies real version strings against the declared floor", (t) => {
  const floor = nodeMajorFloor();
  for (const major of [floor - 4, floor - 1, floor, floor + 1, floor + 10])
    assert.deepEqual(
      askShell(stubNode(t, `v${major}.3.1`)),
      { major: String(major), meetsFloor: major >= floor },
      `v${major}.3.1`,
    );
});

test("an unreadable version is UNKNOWN, and unknown never claims a fault", (t) => {
  // Precision over recall at the one place this feeds: a wrong version
  // diagnosis sends an operator to replace a runtime that was fine.
  for (const reported of ["", "not a version", "22.1.0", "vX.Y.Z"])
    assert.deepEqual(
      askShell(stubNode(t, reported)),
      { major: "", meetsFloor: true },
      `${JSON.stringify(reported)} was read as a version`,
    );
  // A binary that cannot be executed at all is unknown too, not "too old".
  assert.deepEqual(askShell(join(tmpdir(), "agent-sanitizer-no-such-node")), {
    major: "",
    meetsFloor: true,
  });
});
