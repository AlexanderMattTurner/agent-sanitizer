/**
 * `_AGENT_SANITIZER_REDACTOR_PYZ` is the launcher's hand-off of the committed
 * zipapp to the compiled hook binary, whose module-relative path names no file
 * on disk. These cases drive the real `spawnDaemon` default command against a
 * stand-in python3 that records its argv, so the variable is shown to change
 * what gets spawned rather than merely to be set.
 */
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { setTimeout as sleep } from "node:timers/promises";

import { spawnDaemon } from "../claude-hooks/lib/redactor-client.mjs";

/** [name, whether the named zipapp exists, the argv the stand-in records]. */
const CASES = [
  [
    "runs the zipapp the variable names when it exists",
    true,
    "python3 PYZ /sock",
  ],
  [
    "falls through to the PATH console script when the named file is missing",
    false,
    "agent-secret-redactor-daemon /sock",
  ],
];

for (const [name, exists, want] of CASES)
  test(`_AGENT_SANITIZER_REDACTOR_PYZ ${name}`, async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "redactor-pyz-"));
    const saved = { ...process.env };
    t.after(() => {
      process.env = saved;
      rmSync(dir, { recursive: true, force: true });
    });
    // Both candidate launchers record their argv; which one runs is the result.
    // The rename makes `argv` appear only once it holds the line: `>` creates
    // the file before echo writes, so the poll below could read it empty.
    for (const bin of ["python3", "agent-secret-redactor-daemon"]) {
      writeFileSync(
        join(dir, bin),
        `#!/bin/sh\necho "${bin} $*" > "${dir}/argv.tmp" && mv "${dir}/argv.tmp" "${dir}/argv"\n`,
      );
      chmodSync(join(dir, bin), 0o755);
    }
    const pyz = join(dir, "chosen.pyz");
    if (exists) writeFileSync(pyz, "");
    process.env.PATH = `${dir}:${saved.PATH}`;
    process.env._AGENT_SANITIZER_REDACTOR_PYZ = pyz;

    spawnDaemon("/sock");
    for (let i = 0; i < 200 && !existsSync(join(dir, "argv")); i++)
      await sleep(25);
    assert.ok(existsSync(join(dir, "argv")), "nothing was spawned");
    assert.equal(
      readFileSync(join(dir, "argv"), "utf8").trim(),
      want.replace("PYZ", pyz),
    );
  });
