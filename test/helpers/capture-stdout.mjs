/**
 * Run something that writes to `process.stdout`, and keep those bytes off the
 * test runner's own output stream. A hook entry point writes its response
 * envelope to stdout, and under `--test-reporter=tap` — how Stryker's tap runner
 * executes every file — that stream IS the TAP stream.
 *
 * Swapping the `process.stdout` PROPERTY is what makes the separation exact, and
 * the reason is the whole point of this module: `process.stdout.write = …`
 * around an AWAITED call swallows more than the callee's bytes, because
 * `node:test`'s reporter pipes into `process.stdout` asynchronously and every
 * reporter line flushing inside the window is discarded too. That leaves a TAP
 * stream missing its head, which parses as not-ok with ZERO failing tests and
 * exit code 0 — Stryker then names the file with an empty failure message and
 * aborts every mutation shard, telling nobody which test or why. Patching the
 * property instead reaches only the callee: the reporter bound the real stream
 * when it piped, while `emitHookResponse` resolves `process.stdout` per call.
 *
 * The bytes are returned rather than dropped so a caller can assert on an
 * envelope a hook legitimately emitted.
 */
import { Writable } from "node:stream";

/**
 * @template T
 * @param {() => T | Promise<T>} fn
 * @returns {Promise<{ result: T, stdout: string }>}
 */
export async function withCapturedStdout(fn) {
  /** @type {string[]} */
  const chunks = [];
  const real = /** @type {PropertyDescriptor} */ (
    Object.getOwnPropertyDescriptor(process, "stdout")
  );
  Object.defineProperty(process, "stdout", {
    configurable: true,
    value: new Writable({
      write(chunk, _encoding, done) {
        chunks.push(String(chunk));
        done();
      },
    }),
  });
  try {
    return { result: await fn(), stdout: chunks.join("") };
  } finally {
    Object.defineProperty(process, "stdout", real);
  }
}
