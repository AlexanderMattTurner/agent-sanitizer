/**
 * Where the redactor client looks for its daemon: the socket path it dials and
 * the zipapp it spawns. Both are resolved from the environment the hook runs
 * in, so these cases drive the real module under controlled environments and
 * assert the path it settles on (the socket) or the process it actually starts
 * (the zipapp).
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
import { describe, it } from "node:test";

import { resolveSocketPath } from "../claude-hooks/lib/redactor-client.mjs";

const CLIENT = new URL(
  "../claude-hooks/lib/redactor-client.mjs",
  import.meta.url,
).href;
const UID = /** @type {() => number} */ (process.getuid)();
const SOCKET_ENV = [
  "_AGENT_SANITIZER_REDACTOR_SOCKET",
  "XDG_RUNTIME_DIR",
  "CLAUDE_PLUGIN_DATA",
];

/** @param {import("node:test").TestContext} t */
function scratch(t) {
  const dir = mkdtempSync(join(tmpdir(), "redactor-paths-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/**
 * DEFAULT_SOCKET_PATH as a fresh process resolves it under `env` (it is fixed
 * at module load, so each environment needs its own process).
 * @param {Record<string, string>} env
 */
function resolvedSocket(env) {
  const base = { ...process.env };
  for (const name of SOCKET_ENV) delete base[name];
  const res = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `const m = await import(${JSON.stringify(CLIENT)});
process.stdout.write(m.DEFAULT_SOCKET_PATH);`,
    ],
    { encoding: "utf8", env: { ...base, ...env } },
  );
  assert.equal(res.status, 0, res.stderr);
  return res.stdout;
}

/**
 * A directory with exactly `mode`, bypassing the umask.
 * @param {string} path
 * @param {number} mode
 */
function dirWithMode(path, mode) {
  mkdirSync(path);
  chmodSync(path, mode);
  return path;
}

describe("the default redactor socket lives in a per-user directory", () => {
  it("uses an explicit socket override verbatim", () => {
    assert.equal(
      resolvedSocket({ _AGENT_SANITIZER_REDACTOR_SOCKET: "/x/y.sock" }),
      "/x/y.sock",
    );
  });

  it("prefers a private XDG_RUNTIME_DIR", (t) => {
    const dir = scratch(t);
    const runtime = dirWithMode(join(dir, "run"), 0o700);
    const data = dirWithMode(join(dir, "data"), 0o755);
    assert.equal(
      resolvedSocket({ XDG_RUNTIME_DIR: runtime, CLAUDE_PLUGIN_DATA: data }),
      join(runtime, "agent-sanitizer-redactor", "redactor.sock"),
    );
  });

  it("skips a group/other-writable XDG_RUNTIME_DIR for CLAUDE_PLUGIN_DATA", (t) => {
    const dir = scratch(t);
    const runtime = dirWithMode(join(dir, "run"), 0o777);
    const data = dirWithMode(join(dir, "data"), 0o755);
    assert.equal(
      resolvedSocket({ XDG_RUNTIME_DIR: runtime, CLAUDE_PLUGIN_DATA: data }),
      join(data, "agent-sanitizer-redactor", "redactor.sock"),
    );
  });

  it("skips a missing root and one whose socket path overflows sun_path", (t) => {
    const dir = scratch(t);
    const deep = join(dir, "d".repeat(80));
    dirWithMode(deep, 0o700);
    assert.equal(
      resolvedSocket({
        XDG_RUNTIME_DIR: join(dir, "absent"),
        CLAUDE_PLUGIN_DATA: deep,
      }),
      join(tmpdir(), `agent-sanitizer-redactor-${UID}`, "redactor.sock"),
    );
  });

  it("skips a symlinked root even when its target is private", (t) => {
    const dir = scratch(t);
    const target = dirWithMode(join(dir, "target"), 0o700);
    const link = join(dir, "link");
    symlinkSync(target, link);
    assert.equal(
      resolvedSocket({ XDG_RUNTIME_DIR: link, CLAUDE_PLUGIN_DATA: link }),
      join(tmpdir(), `agent-sanitizer-redactor-${UID}`, "redactor.sock"),
    );
  });

  it("skips roots owned by another uid", (t) => {
    const dir = scratch(t);
    const runtime = dirWithMode(join(dir, "run"), 0o700);
    const env = { XDG_RUNTIME_DIR: runtime, CLAUDE_PLUGIN_DATA: runtime };
    // Positive pair: the same roots are taken by their own uid, so the
    // foreign-uid result below is the owner clause and nothing else.
    assert.equal(
      resolveSocketPath(env, UID),
      join(runtime, "agent-sanitizer-redactor", "redactor.sock"),
    );
    assert.equal(
      resolveSocketPath(env, UID + 1),
      join(tmpdir(), `agent-sanitizer-redactor-${UID + 1}`, "redactor.sock"),
    );
  });

  // The daemon binds "." + 16 hex digits before renaming onto redactor.sock,
  // four bytes longer, so the longer name is what must fit sun_path.
  for (const [pathBytes, taken] of [
    [99, true],
    [100, false],
    [103, false],
  ]) {
    it(`takes a root only if the daemon's temp bind fits (socket path ${pathBytes} bytes)`, (t) => {
      const dir = scratch(t);
      const suffix = join("agent-sanitizer-redactor", "redactor.sock");
      // join(dir, "r" * k, suffix) is len(join(dir, suffix)) + 1 + k bytes.
      const fill = pathBytes - Buffer.byteLength(join(dir, suffix)) - 1;
      const root = dirWithMode(join(dir, "r".repeat(fill)), 0o700);
      assert.equal(
        Buffer.byteLength(join(root, suffix)),
        pathBytes,
        "fixture sizing drifted",
      );
      const expected = taken
        ? join(root, suffix)
        : join(tmpdir(), `agent-sanitizer-redactor-${UID}`, "redactor.sock");
      assert.equal(resolveSocketPath({ XDG_RUNTIME_DIR: root }, UID), expected);
    });
  }

  it("falls back to a uid-named temp-dir socket, never a shared name", () => {
    assert.equal(
      resolvedSocket({}),
      join(tmpdir(), `agent-sanitizer-redactor-${UID}`, "redactor.sock"),
    );
  });
});
