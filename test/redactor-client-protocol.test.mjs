/**
 * The redactor client's side of the wire: which sockets it will hand live
 * credentials to (classifySocket), which requests it will send, and which
 * responses it accepts. Every case runs against a real Unix socket served by a
 * stand-in daemon that speaks the framing and answers what the case dictates.
 */
import assert from "node:assert/strict";
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  FRAME_CAP,
  classifySocket,
  connectAndRequest,
  redactViaDaemon,
} from "../claude-hooks/lib/redactor-client.mjs";
import {
  FrameReader,
  encodeFrame,
} from "../claude-hooks/lib/redactor-wire.mjs";
import { startStandInDaemon } from "./redactor-stand-in.mjs";

const UID = /** @type {() => number} */ (process.getuid)();

/** @param {import("node:test").TestContext} t */
function privateDir(t) {
  const dir = mkdtempSync(join(tmpdir(), "rp-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/**
 * A stand-in daemon on `socketPath` answering every request with `reply`
 * (called with the parsed request). Resolves once listening; records each
 * request it received.
 * @param {import("node:test").TestContext} t
 * @param {string} socketPath
 * @param {(request: any) => unknown} reply
 */
async function standIn(t, socketPath, reply) {
  /** @type {unknown[]} */
  const received = [];
  let connections = 0;
  const server = await startStandInDaemon(socketPath, (request) => {
    received.push(request);
    return reply(request);
  });
  server.on("connection", () => {
    connections += 1;
  });
  t.after(() => server.close());
  return { received, connections: () => connections };
}

const REQUEST = { text: "x", map: false, web_ingress: true, env_secrets: {} };

describe("classifySocket", () => {
  it("accepts our listening socket under a 0700 dir we own", async (t) => {
    const dir = privateDir(t);
    const socketPath = join(dir, "r.sock");
    await standIn(t, socketPath, () => null);
    assert.equal(classifySocket(socketPath), "ok");
  });

  it("reports a missing socket as absent, so the caller spawns its own", (t) => {
    assert.equal(classifySocket(join(privateDir(t), "r.sock")), "absent");
  });

  it("refuses a regular file at the socket path", (t) => {
    const socketPath = join(privateDir(t), "r.sock");
    writeFileSync(socketPath, "");
    assert.equal(classifySocket(socketPath), "untrusted");
  });

  it("refuses a symlink to a real socket", async (t) => {
    const dir = privateDir(t);
    const real = join(dir, "real.sock");
    await standIn(t, real, () => null);
    const link = join(dir, "r.sock");
    symlinkSync(real, link);
    assert.equal(classifySocket(link), "untrusted");
  });

  it("refuses a socket whose directory others can write", async (t) => {
    const dir = privateDir(t);
    const shared = join(dir, "shared");
    mkdirSync(shared);
    const socketPath = join(shared, "r.sock");
    await standIn(t, socketPath, () => null);
    chmodSync(shared, 0o777);
    assert.equal(classifySocket(socketPath), "untrusted");
  });

  it("refuses a socket bound by another uid", async (t) => {
    const socketPath = join(privateDir(t), "r.sock");
    await standIn(t, socketPath, () => null);
    assert.equal(classifySocket(socketPath, { uid: UID + 1 }), "untrusted");
  });

  it("accepts our socket under a root-owned dir no one else can write", async (t) => {
    // The test cannot chown to root, so the parent's stat is substituted.
    const socketPath = join(privateDir(t), "r.sock");
    await standIn(t, socketPath, () => null);
    /** @param {number} mode a root-owned directory's permission bits */
    const rootDir = (mode) =>
      /** @type {typeof lstatSync} */ (
        /** @type {unknown} */ (
          (/** @type {string} */ path) =>
            path === socketPath
              ? lstatSync(path)
              : { isDirectory: () => true, uid: 0, mode: 0o40000 | mode }
        )
      );
    assert.equal(classifySocket(socketPath, { lstat: rootDir(0o755) }), "ok");
    assert.equal(
      classifySocket(socketPath, { lstat: rootDir(0o775) }),
      "untrusted",
    );
  });
});

describe("connectAndRequest sends only what the protocol accepts", () => {
  it("never connects to a socket that fails classification", async (t) => {
    const shared = join(privateDir(t), "shared");
    mkdirSync(shared);
    const socketPath = join(shared, "r.sock");
    const daemon = await standIn(t, socketPath, () => null);
    chmodSync(shared, 0o777);
    await assert.rejects(
      connectAndRequest(socketPath, REQUEST, 2000),
      /failed the ownership check/u,
    );
    assert.equal(daemon.connections(), 0);
    // Non-vacuity: the same socket is dialed once its directory is private.
    chmodSync(shared, 0o700);
    assert.equal(await connectAndRequest(socketPath, REQUEST, 2000), null);
    assert.equal(daemon.connections(), 1);
  });

  it("refuses a request missing a protocol field without dialing", async (t) => {
    const socketPath = join(privateDir(t), "r.sock");
    const daemon = await standIn(t, socketPath, () => null);
    /** @type {Record<string, unknown>} */
    const partial = { ...REQUEST };
    delete partial.env_secrets;
    await assert.rejects(
      connectAndRequest(socketPath, partial, 2000),
      /does not match the wire protocol/u,
    );
    assert.equal(daemon.connections(), 0);
    // Positive marker: the complete request is sent and answered.
    assert.equal(await connectAndRequest(socketPath, REQUEST, 2000), null);
    assert.deepEqual(daemon.received, [REQUEST]);
  });

  it("refuses an over-cap request without dialing, so it is not respawned for", async (t) => {
    const socketPath = join(privateDir(t), "r.sock");
    const daemon = await standIn(t, socketPath, () => null);
    const error = await connectAndRequest(
      socketPath,
      { ...REQUEST, text: "x".repeat(FRAME_CAP) },
      2000,
    ).catch((/** @type {Error & {code?: string}} */ err) => err);
    assert.match(String(error), /exceeds the 16777216-byte frame cap/u);
    assert.equal(/** @type {{code?: string}} */ (error).code, undefined);
    assert.equal(daemon.connections(), 0);
  });

  it("names the daemon's reason and its log for an error response", async (t) => {
    const dir = privateDir(t);
    const socketPath = join(dir, "r.sock");
    await standIn(t, socketPath, () => ({ error: "malformed request" }));
    await assert.rejects(connectAndRequest(socketPath, REQUEST, 2000), {
      message: `daemon reported redaction failure: malformed request; its log is ${join(dir, "daemon.log")}`,
    });
  });
});

describe("an error response quotes only plain printable-ASCII text", () => {
  // A newline forges a report line; ESC opens a terminal sequence; tag
  // characters spell an instruction; a bidi override reorders the line.
  const HOSTILE = "x\u001b]0;pwned\u0007\u{e006f}\u202e\nLine 1: fake";

  it("drops hostile text but keeps the failure and the log path", async (t) => {
    const dir = privateDir(t);
    const socketPath = join(dir, "r.sock");
    await standIn(t, socketPath, () => ({ error: HOSTILE }));
    await assert.rejects(connectAndRequest(socketPath, REQUEST, 2000), {
      message: `daemon reported redaction failure; its log is ${join(dir, "daemon.log")}`,
    });
  });

  it("drops an over-long reason", async (t) => {
    const dir = privateDir(t);
    const socketPath = join(dir, "r.sock");
    await standIn(t, socketPath, () => ({ error: "x".repeat(201) }));
    await assert.rejects(connectAndRequest(socketPath, REQUEST, 2000), {
      message: `daemon reported redaction failure; its log is ${join(dir, "daemon.log")}`,
    });
  });
});

describe("redactViaDaemon accepts only the response shapes its mode allows", () => {
  /**
   * @param {boolean} map
   * @param {unknown} response
   */
  const outcome = (map, response) =>
    redactViaDaemon("x", {
      map,
      webIngress: true,
      connect: async () => /** @type {any} */ (response),
    }).then(
      (value) => ({ ok: value }),
      (/** @type {Error} */ err) => ({ error: err.message }),
    );

  const pair = { placeholder: "[REDACTED]", original: "s", start: 0 };
  for (const [label, map, response] of [
    ["plain null", false, null],
    ["plain redaction", false, { text: "[REDACTED]", found: ["T"] }],
    [
      "map redaction",
      true,
      { text: "[REDACTED]", pairs: [pair], found: ["T"] },
    ],
    ["map with no pairs", true, { text: "x", pairs: [], found: [] }],
    ["unmappable", true, { unmappable: "reserved characters" }],
  ])
    it(`accepts ${label}`, async () => {
      assert.deepEqual(await outcome(/** @type {boolean} */ (map), response), {
        ok: response,
      });
    });

  for (const [label, map, response] of [
    ["plain without found", false, { text: "x" }],
    ["plain with a non-string finding", false, { text: "x", found: [1] }],
    ["plain with an extra field", false, { text: "x", found: [], extra: 1 }],
    ["plain as an array", false, ["x"]],
    ["map null", true, null],
    ["map without found", true, { text: "x", pairs: [] }],
    [
      "map with a malformed pair",
      true,
      { text: "x", pairs: [{ ...pair, start: -1 }], found: [] },
    ],
    [
      "map with a boolean offset",
      true,
      { text: "x", pairs: [{ ...pair, start: true }], found: [] },
    ],
    ["unmappable with a non-string reason", true, { unmappable: true }],
  ])
    it(`refuses ${label}`, async () => {
      const result = await outcome(/** @type {boolean} */ (map), response);
      assert.match(
        /** @type {{error?: string}} */ (result).error ?? "",
        /^secret redaction unavailable \(redactor returned a malformed (plain|map) response/u,
      );
    });
});

describe("the wire codec every Node party frames through", () => {
  it("encodes a 4-byte big-endian UTF-8 body length, then the JSON body", () => {
    // The byte layout the Python daemon's _read_frame decodes; its own suite
    // pins the same layout from the other side.
    const body = Buffer.from('{"text":"é"}', "utf8");
    assert.deepEqual(
      encodeFrame({ text: "é" }),
      Buffer.concat([Buffer.from([0, 0, 0, body.length]), body]),
    );
  });

  it("reassembles a frame delivered one byte at a time", () => {
    const value = { text: "x".repeat(300), found: ["T"] };
    const reader = new FrameReader();
    const frame = encodeFrame(value);
    const results = [...frame].map((byte) => reader.push(Buffer.from([byte])));
    assert.deepEqual(results.at(-1), { value });
    assert.deepEqual(
      results.slice(0, -1),
      Array(frame.length - 1).fill(undefined),
    );
  });

  it("refuses a header over the frame cap before buffering the body", () => {
    const header = Buffer.allocUnsafe(4);
    header.writeUInt32BE(FRAME_CAP + 1, 0);
    assert.throws(
      () => new FrameReader().push(header),
      /over the 16777216-byte frame cap/u,
    );
    // Non-vacuity: a header AT the cap is accepted and waits for its body.
    header.writeUInt32BE(FRAME_CAP, 0);
    assert.equal(new FrameReader().push(header), undefined);
  });

  it("refuses to encode a body over the frame cap", () => {
    assert.throws(
      () => encodeFrame("x".repeat(FRAME_CAP)),
      /exceeds the 16777216-byte frame cap/u,
    );
  });
});
