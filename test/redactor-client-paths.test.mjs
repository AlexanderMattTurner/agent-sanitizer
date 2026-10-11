/**
 * Where the redactor client looks for its daemon: the socket path it dials and
 * the zipapp it spawns. Both are resolved from the environment the hook runs
 * in, so these cases drive the real module under controlled environments and
 * assert the path it settles on (the socket) or the process it actually starts
 * (the zipapp).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

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

  it("falls back to a uid-named temp-dir socket, never a shared name", () => {
    assert.equal(
      resolvedSocket({}),
      join(tmpdir(), `agent-sanitizer-redactor-${UID}`, "redactor.sock"),
    );
  });
});
