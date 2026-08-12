/**
 * Contract test for the stdout capture.
 *
 * Two properties, and the second is the one a `process.stdout.write` patch gets
 * wrong: the callee's bytes are captured, AND a consumer that already holds the
 * real stream — which is exactly what `node:test`'s tap reporter is — keeps
 * writing to it throughout. A helper that satisfies only the first passes every
 * assertion about capture while silently eating the TAP lines its own suite is
 * being judged on.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { withCapturedStdout } from "./capture-stdout.mjs";

describe("withCapturedStdout", () => {
  it("captures what the callee wrote, and returns its value", async () => {
    const captured = await withCapturedStdout(() => {
      process.stdout.write('{"hookSpecificOutput":{}}');
      process.stdout.write("tail");
      return "returned";
    });
    assert.deepEqual(captured, {
      result: "returned",
      stdout: '{"hookSpecificOutput":{}}tail',
    });
  });

  it("catches an async callee's write after the first tick", async () => {
    const { stdout } = await withCapturedStdout(async () => {
      await Promise.resolve();
      process.stdout.write("late");
    });
    assert.equal(stdout, "late");
  });

  it("leaves a consumer holding the real stream writing to it", async () => {
    // The tap reporter's shape: bind the stream ONCE, then keep writing across
    // the capture window and past its end. Every one of those writes must still
    // reach the stream it bound, or the suite's own TAP output loses lines.
    //
    // The tripwire FORWARDS rather than swallows, and the markers are distinct
    // from anything a reporter emits: a recording stub that dropped what it saw
    // would be this very bug, wearing an assertion.
    const realStream = process.stdout;
    /** @type {string[]} */
    const seen = [];
    const realWrite = realStream.write.bind(realStream);
    // @ts-expect-error -- narrower than the overloaded write signature.
    realStream.write = (chunk) => {
      if (String(chunk).startsWith("capture-probe")) seen.push(String(chunk));
      return realWrite(chunk);
    };
    /** @type {string | undefined} */
    let stdout;
    try {
      realStream.write("capture-probe: before\n");
      ({ stdout } = await withCapturedStdout(async () => {
        realStream.write("capture-probe: during\n");
        process.stdout.write("HOOK-ENVELOPE");
        await Promise.resolve();
        realStream.write("capture-probe: after a tick\n");
      }));
      realStream.write("capture-probe: after\n");
    } finally {
      realStream.write = realWrite;
    }
    assert.deepEqual(seen, [
      "capture-probe: before\n",
      "capture-probe: during\n",
      "capture-probe: after a tick\n",
      "capture-probe: after\n",
    ]);
    // The separation, stated both ways: the callee's envelope was captured, and
    // it never reached the bound stream.
    assert.equal(stdout, "HOOK-ENVELOPE");
    assert.ok(!seen.some((chunk) => chunk.includes("HOOK-ENVELOPE")));
  });

  it("restores process.stdout when the callee throws", async () => {
    const realStream = process.stdout;
    await assert.rejects(
      () =>
        withCapturedStdout(() => {
          process.stdout.write("before the throw");
          throw new Error("hook blew up");
        }),
      /hook blew up/,
    );
    assert.equal(process.stdout, realStream);
  });
});
