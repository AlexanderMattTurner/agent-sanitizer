/**
 * The redactor zipapp's `__main__.py` extracts the engine to a predictable cache
 * directory and imports from it. These cases run the REAL stub in a minimal
 * archive whose engine reports where it was imported from, and pin that it only
 * imports from a directory no other uid can write: a squatted, shared-writable
 * or symlinked cache is refused before any planted module runs.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
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
const ENGINE = join("agent_sanitizer", "secrets", "daemon.py");
const ZIP = `import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as zf:
    zf.writestr("__main__.py", sys.argv[2])
    zf.writestr("agent_sanitizer/__init__.py", "")
    zf.writestr("agent_sanitizer/secrets/__init__.py", "")
    zf.writestr("agent_sanitizer/secrets/daemon.py", 'def main():\\n    print("RAN " + __file__)\\n')`;
// os.getuid is patched so the stub sees another uid: the only way to drive the
// foreign-owner arm without root.
const AS_UID = `import os, runpy, sys
os.getuid = lambda: int(sys.argv[2])
runpy.run_path(sys.argv[1], run_name="__main__")`;

/** A scratch dir (the stub's TMPDIR) holding a zipapp of the real stub. */
function fixture(/** @type {import("node:test").TestContext} */ t) {
  const dir = mkdtempSync(join(tmpdir(), "pyz-stub-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const pyz = join(dir, "daemon.pyz");
  const zip = spawnSync("python3", ["-c", ZIP, pyz, PYZ_MAIN], {
    encoding: "utf8",
  });
  assert.equal(zip.status, 0, zip.stderr);
  const digest = createHash("sha256")
    .update(readFileSync(pyz))
    .digest("hex")
    .slice(0, 16);
  const tmpBase = (uid = UID) => join(dir, `agent-sanitizer-pyz-${uid}`);
  /** Run the archive as the client does; `uid` impersonates another user. */
  const run = (/** @type {{pluginData?: string, uid?: number}} */ o = {}) => {
    const env = { ...process.env, TMPDIR: dir };
    delete env.CLAUDE_PLUGIN_DATA;
    if (o.pluginData) env.CLAUDE_PLUGIN_DATA = o.pluginData;
    const args =
      o.uid === undefined ? [pyz] : ["-c", AS_UID, pyz, String(o.uid)];
    return spawnSync("python3", args, { encoding: "utf8", env });
  };
  return { dir, digest, tmpBase, run };
}

/** What a co-tenant pre-creates at the predictable path: an attacker's engine in `base/digest`, `base` set to `mode`. */
function squat(
  /** @type {string} */ base,
  /** @type {string} */ digest,
  mode = 0o777,
) {
  plant(join(base, digest));
  chmodSync(base, mode);
}
function plant(/** @type {string} */ tree) {
  mkdirSync(join(tree, "agent_sanitizer", "secrets"), { recursive: true });
  writeFileSync(join(tree, "agent_sanitizer", "__init__.py"), "");
  writeFileSync(join(tree, "agent_sanitizer", "secrets", "__init__.py"), "");
  writeFileSync(join(tree, ENGINE), 'def main():\n    print("PLANTED")\n');
}

describe("the zipapp stub imports only from a cache no other uid can write", () => {
  it("extracts into an owner-only temp-dir cache and runs the engine from it", (t) => {
    const { digest, tmpBase, run } = fixture(t);
    const res = run();
    assert.equal(res.status, 0, res.stderr);
    assert.equal(res.stdout.trim(), `RAN ${join(tmpBase(), digest, ENGINE)}`);
    assert.equal(statSync(tmpBase()).mode & 0o777, 0o700);
  });

  it("prefers CLAUDE_PLUGIN_DATA, falling back to the temp dir only when it cannot hold a cache", (t) => {
    const { dir, digest, tmpBase, run } = fixture(t);
    const data = join(dir, "plugin-data");
    let res = run({ pluginData: data });
    assert.equal(res.status, 0, res.stderr);
    assert.equal(
      res.stdout.trim(),
      `RAN ${join(data, "redactor-pyz", digest, ENGINE)}`,
    );
    // A plain file where the directory should be: the base cannot be created
    // under it whatever uid runs this (a 0500 directory would not stop root).
    rmSync(data, { recursive: true });
    writeFileSync(data, "");
    res = run({ pluginData: data });
    assert.equal(res.status, 0, res.stderr);
    assert.equal(res.stdout.trim(), `RAN ${join(tmpBase(), digest, ENGINE)}`);
  });

  // Each row arranges a hostile cache and names the refusal; none may fall back
  // or run the planted tree.
  /** @type {[string, (f: ReturnType<typeof fixture>) => {pluginData?: string, uid?: number}, (digest: string) => RegExp][]} */
  const refusals = [
    [
      "a plugin-data cache that exists but is untrusted (no fallback to temp)",
      ({ dir, digest }) => {
        squat(join(dir, "plugin-data", "redactor-pyz"), digest);
        return { pluginData: join(dir, "plugin-data") };
      },
      () => /refusing .*: writable by group or other/,
    ],
    [
      "a cache base writable by group or other",
      ({ digest, tmpBase }) => {
        squat(tmpBase(), digest);
        return {};
      },
      () => /refusing .*: writable by group or other/,
    ],
    [
      "a cache base owned by another uid",
      ({ digest, tmpBase }) => {
        squat(tmpBase(UID + 1), digest, 0o700);
        return { uid: UID + 1 };
      },
      () => new RegExp(`refusing .*: owned by uid ${UID}, not ${UID + 1}`),
    ],
    [
      "a symlinked cache base",
      ({ dir, digest, tmpBase }) => {
        squat(join(dir, "decoy"), digest, 0o700);
        symlinkSync(join(dir, "decoy"), tmpBase());
        return {};
      },
      () => /refusing .*: not a real directory/,
    ],
    [
      "a symlinked digest tree inside a trusted base",
      ({ dir, digest, tmpBase }) => {
        plant(join(dir, "decoy"));
        mkdirSync(tmpBase(), { mode: 0o700 });
        symlinkSync(join(dir, "decoy"), join(tmpBase(), digest));
        return {};
      },
      (digest) => new RegExp(`refusing .*${digest}: not a real`),
    ],
  ];
  for (const [name, arrange, refusal] of refusals)
    it(`refuses ${name}`, (t) => {
      const f = fixture(t);
      const res = f.run(arrange(f));
      assert.notEqual(res.status, 0);
      assert.match(res.stderr, refusal(f.digest));
      assert.ok(!res.stdout.includes("PLANTED"), res.stdout);
    });
});
