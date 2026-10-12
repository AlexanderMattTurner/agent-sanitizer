/**
 * A stand-in redactor daemon for the hook suites, framed through the client's
 * own codec (claude-hooks/lib/redactor-wire.mjs), so no suite carries a copy of
 * the wire format that can drift from it.
 */
import { createServer } from "node:net";

import {
  FrameReader,
  encodeFrame,
} from "../claude-hooks/lib/redactor-wire.mjs";

/**
 * Serve `socketPath`, answering each request frame with `reply(request)`.
 * @param {string} socketPath
 * @param {(request: any) => unknown} reply
 * @returns {Promise<import("node:net").Server>}
 */
export function startStandInDaemon(socketPath, reply) {
  const server = createServer((sock) => {
    // Without a handler a socket 'error' is re-thrown and takes down the test
    // runner with an unattributable stack.
    sock.on("error", () => {});
    const reader = new FrameReader();
    sock.on("data", (chunk) => {
      const frame = reader.push(chunk);
      if (frame !== undefined) sock.end(encodeFrame(reply(frame.value)));
    });
  });
  return new Promise((resolve) =>
    server.listen(socketPath, () => resolve(server)),
  );
}
