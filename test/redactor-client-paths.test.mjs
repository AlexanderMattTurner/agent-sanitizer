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
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { setTimeout as sleep } from "node:timers/promises";

import {
  resolveSocketPath,
  spawnDaemon,
} from "../claude-hooks/lib/redactor-client.mjs";

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

describe("the daemon spawn honours the launcher-exported zipapp path", () => {
  it("runs _AGENT_SANITIZER_REDACTOR_PYZ under python3 with the socket path", async (t) => {
    // A compiled hook binary resolves import.meta.url inside its virtual
    // filesystem, so the exported path is the only route to the zipapp there.
    // The stand-in records the argv python3 handed it.
    const dir = scratch(t);
    const marker = join(dir, "argv.json");
    const pyz = join(dir, "daemon.pyz");
    writeFileSync(
      pyz,
      [
        "import json, os, sys",
        `marker = ${JSON.stringify(marker)}`,
        'with open(marker + ".tmp", "w") as fh:',
        "    json.dump(sys.argv, fh)",
        'os.replace(marker + ".tmp", marker)',
        "",
      ].join("\n"),
    );
    const saved = {
      daemon: process.env._AGENT_SANITIZER_REDACTOR_DAEMON,
      pyz: process.env._AGENT_SANITIZER_REDACTOR_PYZ,
    };
    t.after(() => {
      for (const [name, value] of [
        ["_AGENT_SANITIZER_REDACTOR_DAEMON", saved.daemon],
        ["_AGENT_SANITIZER_REDACTOR_PYZ", saved.pyz],
      ]) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    });
    delete process.env._AGENT_SANITIZER_REDACTOR_DAEMON;
    process.env._AGENT_SANITIZER_REDACTOR_PYZ = pyz;
    const socketPath = join(dir, "r.sock");
    spawnDaemon(socketPath);
    for (let i = 0; i < 100 && !existsSync(marker); i++) await sleep(50);
    assert.deepEqual(JSON.parse(readFileSync(marker, "utf8")), [
      pyz,
      socketPath,
    ]);
  });
});
