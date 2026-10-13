/**
 * Where the redactor client looks for its daemon socket. DEFAULT_SOCKET_PATH is
 * fixed at module load, so the wiring cases run a fresh process; the root-trust
 * cases call resolveSocketPath directly over one shared fixture of roots.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import { resolveSocketPath } from "../claude-hooks/lib/redactor-client.mjs";

const CLIENT = new URL(
  "../claude-hooks/lib/redactor-client.mjs",
  import.meta.url,
).href;
const UID = /** @type {() => number} */ (process.getuid)();
const SUFFIX = join("agent-sanitizer-redactor", "redactor.sock");
/** @param {number} uid */
const fallback = (uid) =>
  join(tmpdir(), `agent-sanitizer-redactor-${uid}`, "redactor.sock");

const dir = mkdtempSync(join(tmpdir(), "redactor-paths-"));
after(() => rmSync(dir, { recursive: true, force: true }));
/** A directory with exactly `mode`, bypassing the umask. */
const root = (/** @type {string} */ name, /** @type {number} */ mode) => {
  const path = join(dir, name);
  mkdirSync(path);
  chmodSync(path, mode);
  return path;
};
const priv = root("priv", 0o700);
const open = root("open", 0o777);
const data = root("data", 0o755);
const link = join(dir, "link");
symlinkSync(priv, link);
// The daemon binds "." + 16 hex digits before renaming onto redactor.sock, four
// bytes longer, so that longer name is what must fit sun_path (103 bytes).
/** A private root whose published socket path is exactly `bytes` long. */
const sized = (/** @type {number} */ bytes) =>
  root("r".repeat(bytes - Buffer.byteLength(join(dir, SUFFIX)) - 1), 0o700);
const fits = sized(99);
const tooLong = sized(100);
assert.equal(Buffer.byteLength(join(fits, SUFFIX)), 99, "fixture drifted");

/** DEFAULT_SOCKET_PATH in a fresh process under `env`. */
function resolvedSocket(/** @type {Record<string, string>} */ env) {
  const base = { ...process.env };
  for (const name of [
    "_AGENT_SANITIZER_REDACTOR_SOCKET",
    "XDG_RUNTIME_DIR",
    "CLAUDE_PLUGIN_DATA",
  ])
    delete base[name];
  const res = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `process.stdout.write((await import(${JSON.stringify(CLIENT)})).DEFAULT_SOCKET_PATH);`,
    ],
    { encoding: "utf8", env: { ...base, ...env } },
  );
  assert.equal(res.status, 0, res.stderr);
  return res.stdout;
}

describe("the default redactor socket lives in a per-user directory", () => {
  it("uses an explicit override verbatim, else a uid-named temp-dir socket", () => {
    assert.equal(
      resolvedSocket({ _AGENT_SANITIZER_REDACTOR_SOCKET: "/x/y.sock" }),
      "/x/y.sock",
    );
    assert.equal(resolvedSocket({}), fallback(UID));
  });

  /** @type {[string, Record<string, string>, number, string][]} */
  const rows = [
    [
      "prefers a private XDG_RUNTIME_DIR over CLAUDE_PLUGIN_DATA",
      { XDG_RUNTIME_DIR: priv, CLAUDE_PLUGIN_DATA: data },
      UID,
      join(priv, SUFFIX),
    ],
    [
      "skips a group/other-writable XDG_RUNTIME_DIR",
      { XDG_RUNTIME_DIR: open, CLAUDE_PLUGIN_DATA: data },
      UID,
      join(data, SUFFIX),
    ],
    [
      "skips a missing root",
      { XDG_RUNTIME_DIR: join(dir, "absent") },
      UID,
      fallback(UID),
    ],
    [
      "skips a symlinked root even when its target is private",
      { XDG_RUNTIME_DIR: link, CLAUDE_PLUGIN_DATA: link },
      UID,
      fallback(UID),
    ],
    [
      "skips a private root owned by another uid",
      { XDG_RUNTIME_DIR: priv },
      UID + 1,
      fallback(UID + 1),
    ],
    [
      "takes a root whose daemon temp bind fits sun_path (99 bytes)",
      { XDG_RUNTIME_DIR: fits },
      UID,
      join(fits, SUFFIX),
    ],
    [
      "skips a root whose daemon temp bind overflows sun_path (100 bytes)",
      { XDG_RUNTIME_DIR: tooLong },
      UID,
      fallback(UID),
    ],
  ];
  for (const [name, env, uid, expected] of rows)
    it(name, () => assert.equal(resolveSocketPath(env, uid), expected));
});
