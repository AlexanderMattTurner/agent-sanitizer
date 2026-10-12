/**
 * The committed redactor zipapp's `__main__.py` extracts the engine to a cache
 * directory with a predictable name and imports from it. These cases run the
 * REAL stub (the exact text the build writes into daemon.pyz) inside a minimal
 * archive whose engine `main` just reports where it was imported from, and pin
 * that the stub only ever imports from a directory no other uid can write: a
 * squatted, shared-writable, or symlinked cache is refused before any planted
 * module runs.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { PYZ_MAIN } from "../plugin/scripts/build-redactor-pyz.mjs";

const UID = /** @type {() => number} */ (process.getuid)();

/** A daemon module that reports the file it was imported from. */
const REPORTING_DAEMON = 'def main():\n    print("RAN " + __file__)\n';
const PLANTED_DAEMON = 'def main():\n    print("PLANTED")\n';

/** @param {import("node:test").TestContext} t */
function scratch(t) {
  const dir = mkdtempSync(join(tmpdir(), "pyz-stub-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/**
 * Write a zipapp holding the real stub plus a stand-in engine; return its path
 * and the digest the stub keys its cache on.
 * @param {string} dir
 */
function buildArchive(dir) {
  const pyz = join(dir, "daemon.pyz");
  const res = spawnSync(
    "python3",
    [
      "-c",
      `import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as zf:
    zf.writestr("__main__.py", sys.argv[2])
    zf.writestr("agent_sanitizer/__init__.py", "")
    zf.writestr("agent_sanitizer/secrets/__init__.py", "")
    zf.writestr("agent_sanitizer/secrets/daemon.py", sys.argv[3])`,
      pyz,
      PYZ_MAIN,
      REPORTING_DAEMON,
    ],
    { encoding: "utf8" },
  );
  assert.equal(res.status, 0, res.stderr);
  const digest = createHash("sha256")
    .update(readFileSync(pyz))
    .digest("hex")
    .slice(0, 16);
  return { pyz, digest };
}

/**
 * Plant an attacker's engine tree at `tree` (what a co-tenant would pre-create
 * at the predictable digest path).
 * @param {string} tree
 */
function plant(tree) {
  mkdirSync(join(tree, "agent_sanitizer", "secrets"), { recursive: true });
  writeFileSync(join(tree, "agent_sanitizer", "__init__.py"), "");
  writeFileSync(join(tree, "agent_sanitizer", "secrets", "__init__.py"), "");
  writeFileSync(
    join(tree, "agent_sanitizer", "secrets", "daemon.py"),
    PLANTED_DAEMON,
  );
}

/**
 * Run the archive the way the client does (`python3 daemon.pyz`), with the temp
 * dir pointed at `tmp`. `uid` makes the stub see a different `os.getuid()`, the
 * only way to drive the foreign-owner arm without root.
 * @param {string} pyz
 * @param {{tmp: string, pluginData?: string, uid?: number}} opts
 */
function runStub(pyz, { tmp, pluginData, uid }) {
  const env = { ...process.env, TMPDIR: tmp };
  delete env.CLAUDE_PLUGIN_DATA;
  if (pluginData) env.CLAUDE_PLUGIN_DATA = pluginData;
  const args =
    uid === undefined
      ? [pyz]
      : [
          "-c",
          `import os, runpy, sys
os.getuid = lambda: int(sys.argv[2])
runpy.run_path(sys.argv[1], run_name="__main__")`,
          pyz,
          String(uid),
        ];
  return spawnSync("python3", args, { encoding: "utf8", env });
}

describe("the zipapp stub imports only from a cache no other uid can write", () => {
  it("extracts into an owner-only temp-dir cache and runs the engine from it", (t) => {
    const dir = scratch(t);
    const { pyz, digest } = buildArchive(dir);
    const base = join(dir, `agent-sanitizer-pyz-${UID}`);
    const res = runStub(pyz, { tmp: dir });
    assert.equal(res.status, 0, res.stderr);
    assert.equal(
      res.stdout.trim(),
      `RAN ${join(base, digest, "agent_sanitizer", "secrets", "daemon.py")}`,
    );
    assert.equal(statSync(base).mode & 0o777, 0o700);
    assert.deepEqual(readdirSync(base), [digest]);
  });

  it("extracts under CLAUDE_PLUGIN_DATA when Claude Code supplies it", (t) => {
    const dir = scratch(t);
    const { pyz, digest } = buildArchive(dir);
    const data = join(dir, "plugin-data");
    const res = runStub(pyz, { tmp: dir, pluginData: data });
    assert.equal(res.status, 0, res.stderr);
    assert.equal(
      res.stdout.trim(),
      `RAN ${join(data, "redactor-pyz", digest, "agent_sanitizer", "secrets", "daemon.py")}`,
    );
    assert.ok(
      !readdirSync(dir).some((name) => name.startsWith("agent-sanitizer-pyz-")),
    );
  });

  it("falls back to the temp-dir cache when CLAUDE_PLUGIN_DATA cannot hold one", (t) => {
    const dir = scratch(t);
    const { pyz, digest } = buildArchive(dir);
    // A plain file where the directory should be: the cache base cannot be
    // created under it, whatever uid runs this (a 0500 directory would not
    // stop root).
    const data = join(dir, "plugin-data");
    writeFileSync(data, "");
    const res = runStub(pyz, { tmp: dir, pluginData: data });
    assert.equal(res.status, 0, res.stderr);
    assert.equal(
      res.stdout.trim(),
      `RAN ${join(dir, `agent-sanitizer-pyz-${UID}`, digest, "agent_sanitizer", "secrets", "daemon.py")}`,
    );
  });

  it("does NOT fall back from a plugin-data cache that exists but is untrusted", (t) => {
    // The fallback is for an unwritable base, never for a hostile one: moving
    // to the temp dir would hide the squat that trusted_dir exists to report.
    const dir = scratch(t);
    const { pyz, digest } = buildArchive(dir);
    const data = join(dir, "plugin-data");
    const base = join(data, "redactor-pyz");
    plant(join(base, digest));
    chmodSync(base, 0o777);
    const res = runStub(pyz, { tmp: dir, pluginData: data });
    assert.notEqual(res.status, 0);
    assert.match(res.stderr, /refusing .*: writable by group or other/);
    assert.ok(!res.stdout.includes("PLANTED"), res.stdout);
  });

  it("refuses a cache base writable by group or other", (t) => {
    const dir = scratch(t);
    const { pyz, digest } = buildArchive(dir);
    const base = join(dir, `agent-sanitizer-pyz-${UID}`);
    plant(join(base, digest));
    chmodSync(base, 0o777);
    const res = runStub(pyz, { tmp: dir });
    assert.notEqual(res.status, 0);
    assert.match(res.stderr, /refusing .*: writable by group or other/);
    assert.ok(!res.stdout.includes("PLANTED"), res.stdout);
  });

  it("refuses a cache base owned by another uid", (t) => {
    const dir = scratch(t);
    const { pyz, digest } = buildArchive(dir);
    const otherUid = UID + 1;
    const base = join(dir, `agent-sanitizer-pyz-${otherUid}`);
    plant(join(base, digest));
    chmodSync(base, 0o700);
    const res = runStub(pyz, { tmp: dir, uid: otherUid });
    assert.notEqual(res.status, 0);
    assert.match(
      res.stderr,
      new RegExp(`refusing .*: owned by uid ${UID}, not ${otherUid}`),
    );
    assert.ok(!res.stdout.includes("PLANTED"), res.stdout);
  });

  it("refuses a symlinked cache base", (t) => {
    const dir = scratch(t);
    const { pyz, digest } = buildArchive(dir);
    const decoy = join(dir, "decoy");
    plant(join(decoy, digest));
    chmodSync(decoy, 0o700);
    symlinkSync(decoy, join(dir, `agent-sanitizer-pyz-${UID}`));
    const res = runStub(pyz, { tmp: dir });
    assert.notEqual(res.status, 0);
    assert.match(res.stderr, /refusing .*: not a real directory/);
    assert.ok(!res.stdout.includes("PLANTED"), res.stdout);
  });

  it("refuses a symlinked digest tree inside a trusted base", (t) => {
    const dir = scratch(t);
    const { pyz, digest } = buildArchive(dir);
    const base = join(dir, `agent-sanitizer-pyz-${UID}`);
    mkdirSync(base, { mode: 0o700 });
    const decoy = join(dir, "decoy");
    plant(decoy);
    symlinkSync(decoy, join(base, digest));
    const res = runStub(pyz, { tmp: dir });
    assert.notEqual(res.status, 0);
    assert.match(res.stderr, new RegExp(`refusing .*${digest}: not a real`));
    assert.ok(!res.stdout.includes("PLANTED"), res.stdout);
  });
});
