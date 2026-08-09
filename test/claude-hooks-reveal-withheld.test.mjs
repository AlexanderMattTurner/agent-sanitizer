/**
 * The reveal-persistence loop in sanitize-output must never drop a reveal
 * SILENTLY. The Layer-2 splice warning promises the model a sidecar it can Read
 * back; when the pre-splice text cannot be re-vetted (the redactor daemon dies
 * between the seam's vet call and the persistence loop), the loop skips the
 * write — and without a warning that promise dangles: the model is told hidden
 * content was preserved for inspection while nothing was written anywhere.
 *
 * Like claude-hooks-extensions.test.mjs, the Layer-4 seam is driven through a
 * STUB daemon over the real socket protocol (4-byte BE length + JSON): the hook
 * builds its redactor callback internally, so the socket is the only seam a
 * test can reach. The daemon here is CONTENT-keyed so the two redaction calls
 * one tool output triggers diverge deterministically: the seam's vet of the
 * pre-splice text (which still carries the `<!--` comment markers) succeeds,
 * while the loop's re-vet of the vetted text (markers gone) fails exactly when
 * the fixture plants its failure marker — the transient-death shape, with no
 * ordering assumptions.
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { mkdtempSync, rmSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// mkdtemp yields a 0700 dir owned by us — what both the client's socket check
// and the reveal store's dir check demand. Set BEFORE importing the hook: both
// paths are resolved once, at module load.
const socketDir = mkdtempSync(join(tmpdir(), "sanitizer-reveal-withheld-"));
const socketPath = join(socketDir, "redactor.sock");
process.env._AGENT_SANITIZER_REDACTOR_SOCKET = socketPath;
const revealDir = mkdtempSync(join(tmpdir(), "sanitizer-reveal-store-"));
process.env._AGENT_SANITIZER_REVEAL_DIR = revealDir;

const { evaluateToolOutput, REVEAL_WITHHELD_WARNING } =
  await import("../claude-hooks/sanitize-output.mjs");

// `token` trips the SECRET_HINT pre-gate on every call, so both the vet and the
// loop reach the daemon. `poison` is the failure marker the withheld case
// plants; the daemon reports a scan failure only once the comment markers are
// gone (i.e. only on the loop's re-vet of already-vetted text), so the reveal
// SURVIVES the seam and the loop's catch is the code path under test.
const FAIL_MARKER = "poison";

/**
 * A daemon speaking the real wire protocol whose reply is keyed on the request
 * text: `{error}` for post-vet text carrying the failure marker, otherwise a
 * "redaction" that rewrites the comment markers (so its output is
 * distinguishable from a pass-through AND no longer matches the `<!--` key).
 */
function startStubDaemon() {
  const server = createServer((sock) => {
    /** @type {Buffer[]} */
    const chunks = [];
    sock.on("data", (chunk) => {
      chunks.push(chunk);
      const buf = Buffer.concat(chunks);
      if (buf.length < 4) return;
      const expected = buf.readUInt32BE(0);
      if (buf.length < 4 + expected) return;
      const { text } = JSON.parse(
        buf.subarray(4, 4 + expected).toString("utf8"),
      );
      const reply =
        text.includes(FAIL_MARKER) && !text.includes("<!--")
          ? { error: "scan failed" }
          : {
              text: text.replaceAll("<!--", "(c:").replaceAll("-->", ":c)"),
              found: ["FakeDetector"],
            };
      const body = Buffer.from(JSON.stringify(reply), "utf8");
      const header = Buffer.allocUnsafe(4);
      header.writeUInt32BE(body.length, 0);
      sock.end(Buffer.concat([header, body]));
    });
  });
  return new Promise((resolve) => {
    server.listen(socketPath, () => resolve(server));
  });
}

/** @type {import("node:net").Server} */
let daemon;
before(async () => {
  daemon = await startStubDaemon();
});
after(() => {
  daemon.close();
  rmSync(socketDir, { recursive: true, force: true });
  rmSync(revealDir, { recursive: true, force: true });
});

describe("sanitize-output: reveal-persistence loop failure is not silent", () => {
  it("warns (fixed prose) when the reveal redaction throws, keeping the sanitized output", async () => {
    const fields = await evaluateToolOutput({
      tool_name: "WebFetch",
      tool_response: `visible<!-- token ${FAIL_MARKER} -->`,
    });
    assert.ok(fields !== null);
    // The primary output is untouched by the side channel's failure.
    assert.equal(fields.mutated_output, "visible[HTML comment removed]");
    const context = String(fields.additional_context);
    assert.ok(
      context.includes(REVEAL_WITHHELD_WARNING),
      `missing withheld warning in: ${context}`,
    );
    // The warning REPLACES the sidecar hint — advertising a file that was
    // never written would be worse than the silent drop this test closes.
    assert.ok(!context.includes("was saved to"));
    assert.deepEqual(readdirSync(revealDir), []);
  });

  it("non-vacuity: a vettable reveal is persisted with a hint and no withheld warning", async () => {
    const fields = await evaluateToolOutput({
      tool_name: "WebFetch",
      tool_response: "visible<!-- token benign -->",
    });
    assert.ok(fields !== null);
    const context = String(fields.additional_context);
    assert.ok(context.includes("was saved to"));
    assert.ok(!context.includes(REVEAL_WITHHELD_WARNING));
    assert.equal(readdirSync(revealDir).length, 1);
  });
});
