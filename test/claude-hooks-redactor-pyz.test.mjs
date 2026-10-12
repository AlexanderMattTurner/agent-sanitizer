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
import { afterEach, beforeEach, describe, it } from "node:test";
import { setTimeout as sleep } from "node:timers/promises";

import { spawnDaemon } from "../claude-hooks/lib/redactor-client.mjs";

const ENV_KEYS = ["PATH", "_AGENT_SANITIZER_REDACTOR_PYZ"];

describe("_AGENT_SANITIZER_REDACTOR_PYZ selects the zipapp the daemon spawns from", () => {
  /** @type {string} */
  let dir;
  /** @type {Record<string, string | undefined>} */
  let saved;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "redactor-pyz-"));
    saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
    // Both candidate launchers record their argv; which one runs is the result.
    for (const name of ["python3", "agent-secret-redactor-daemon"]) {
      const bin = join(dir, name);
      writeFileSync(bin, `#!/bin/sh\necho "${name} $*" > "${dir}/argv"\n`);
      chmodSync(bin, 0o755);
    }
    process.env.PATH = `${dir}:${saved.PATH}`;
  });

  afterEach(() => {
    for (const k of ENV_KEYS)
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    rmSync(dir, { recursive: true, force: true });
  });

  /** The argv the spawned stand-in recorded. */
  async function spawned() {
    spawnDaemon("/sock");
    for (let i = 0; i < 200 && !existsSync(join(dir, "argv")); i++)
      await sleep(25);
    assert.ok(existsSync(join(dir, "argv")), "nothing was spawned");
    return readFileSync(join(dir, "argv"), "utf8").trim();
  }

  it("runs the zipapp the variable names when it exists", async () => {
    const pyz = join(dir, "chosen.pyz");
    writeFileSync(pyz, "");
    process.env._AGENT_SANITIZER_REDACTOR_PYZ = pyz;
    assert.equal(await spawned(), `python3 ${pyz} /sock`);
  });

  it("falls through to the PATH console script when the named file is missing", async () => {
    process.env._AGENT_SANITIZER_REDACTOR_PYZ = join(dir, "absent.pyz");
    assert.equal(await spawned(), "agent-secret-redactor-daemon /sock");
  });
});
