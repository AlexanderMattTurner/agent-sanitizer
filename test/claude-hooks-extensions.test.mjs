/**
 * The host-extension seams on the sanitize-output hook: `postText`, `redactNote`,
 * and `audit`, plus the operator-declared secret vars the redaction set unions in.
 *
 * Two properties are asserted throughout, because they are the ones a composer is
 * relying on:
 *
 *   - INERT BY DEFAULT. Every seam left unsupplied must produce byte-identical
 *     results to the same call with no bag at all — an extension point that
 *     changes a shipped verdict when nobody uses it is a regression wearing a
 *     feature's clothes. Each seam has an explicit no-op comparison here.
 *   - THROWS PROPAGATE. A callback that throws must not be swallowed: it reaches
 *     the CLI's fail-closed catch, which suppresses the tool output. Swallowing
 *     would degrade a broken extension into showing unvetted output.
 *
 * The Layer-4 tests drive a STUB daemon over the real socket protocol (4-byte BE
 * length + JSON) rather than a stubbed `redactViaDaemon`: the hook builds its
 * redactor callback internally, so the socket is the only seam a test can reach,
 * and going through it also proves the note survives the real response path.
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// mkdtemp yields a 0700 dir owned by us, which is exactly what the client's
// socket-ownership check demands. Set BEFORE importing the hook: the client
// resolves DEFAULT_SOCKET_PATH once, at module load.
const socketDir = mkdtempSync(join(tmpdir(), "sanitizer-ext-"));
const socketPath = join(socketDir, "redactor.sock");
process.env._AGENT_SANITIZER_REDACTOR_SOCKET = socketPath;

const { sanitizeText, sanitizeValue, evaluateToolOutput, judgeSanitizeOutput } =
  await import("../claude-hooks/sanitize-output.mjs");
const { extraSecretVars, envBoundSecretVars } =
  await import("../claude-hooks/lib/env-config.mjs");

// What the stub daemon claims to have redacted. `token` trips the SECRET_HINT
// pre-gate, so text containing it reaches the daemon at all.
const SECRET_TEXT = "here is a token: abc";
const REDACTED_TEXT = "here is a token: [REDACTED]";

/** A daemon that replies to every request with one fixed redaction. */
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
      const body = Buffer.from(
        JSON.stringify({ text: REDACTED_TEXT, found: ["FakeDetector"] }),
        "utf8",
      );
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
});

describe("postText", () => {
  it("is inert when unsupplied", async () => {
    const bare = await sanitizeText("plain output", "Bash");
    const empty = await sanitizeText("plain output", "Bash", undefined, {});
    assert.deepEqual(empty, bare);
    assert.equal(bare.cleaned, "plain output");
    assert.equal(bare.modified, false);
  });

  it("leaves the result untouched when the callback declines", async () => {
    const bare = await sanitizeText("plain output", "Bash");
    for (const declined of [null, undefined, {}]) {
      const result = await sanitizeText("plain output", "Bash", undefined, {
        postText: () => declined,
      });
      assert.deepEqual(result, bare);
    }
  });

  it("replaces the model-facing text and marks it modified", async () => {
    const result = await sanitizeText("plain output", "Bash", undefined, {
      postText: (cleaned) => ({ cleaned: `${cleaned}!` }),
    });
    assert.equal(result.cleaned, "plain output!");
    assert.equal(result.modified, true);
  });

  it("appends a warning without claiming the bytes changed", async () => {
    const result = await sanitizeText("plain output", "Bash", undefined, {
      postText: () => ({ warning: "host says hello" }),
    });
    assert.deepEqual(result.warnings, ["host says hello"]);
    assert.equal(result.cleaned, "plain output");
    assert.equal(result.modified, false);
  });

  it("receives the cleaned text, the tool, the ingress class, and the deadline", async () => {
    /** @type {any[]} */
    const seen = [];
    // A trailing SGR reset is stripped by Layer 1, so `cleaned` differs from the
    // raw input — proving the callback runs AFTER the seam, not before it.
    const postText = (
      /** @type {string} */ cleaned,
      /** @type {any} */ ctx,
    ) => {
      seen.push([cleaned, ctx.toolName, ctx.webIngress, ctx.deadline]);
      return null;
    };
    await sanitizeText("hi[0m", "Bash", undefined, { postText });
    await sanitizeText("hi", "WebFetch", undefined, { postText });
    assert.equal(seen[0][0], "hi");
    assert.deepEqual(
      seen.map((s) => s.slice(1, 3)),
      [
        ["Bash", false],
        ["WebFetch", true],
      ],
    );
    assert.equal(typeof seen[0][3].remainingMs(), "number");
  });

  it("drops the display-only-SGR note when it rewrites the bytes", async () => {
    const colored = "[31mred[0m";
    const bare = await sanitizeText(colored, "Bash");
    assert.equal(bare.sgrNote, true, "fixture must be an SGR-only strip");

    const noted = await sanitizeText(colored, "Bash", undefined, {
      postText: () => ({ warning: "no rewrite" }),
    });
    assert.equal(
      noted.sgrNote,
      true,
      "a warning alone must not clear the note",
    );

    const rewritten = await sanitizeText(colored, "Bash", undefined, {
      postText: (cleaned) => ({ cleaned: `${cleaned}?` }),
    });
    assert.equal(rewritten.sgrNote, false);
  });

  it("runs on value leaves but not on field names", async () => {
    /** @type {string[]} */
    const seen = [];
    /** @type {string[]} */
    const warnings = [];
    const result = await sanitizeValue(
      { fieldName: ["leaf", 7] },
      "Bash",
      warnings,
      undefined,
      undefined,
      {
        postText: (cleaned) => {
          seen.push(cleaned);
          return null;
        },
      },
    );
    assert.deepEqual(seen, ["leaf"]);
    assert.deepEqual(result.value, { fieldName: ["leaf", 7] });
  });

  it("propagates a throw instead of swallowing it", async () => {
    await assert.rejects(
      sanitizeText("plain output", "Bash", undefined, {
        postText: () => {
          throw new Error("host callback exploded");
        },
      }),
      /host callback exploded/u,
    );
  });

  it("reaches the model through evaluateToolOutput", async () => {
    const fields = await evaluateToolOutput(
      { tool_name: "Bash", tool_response: "plain output" },
      { postText: () => ({ warning: "host says hello" }) },
    );
    assert.match(String(fields?.additional_context), /host says hello/u);
  });
});

describe("redactNote", () => {
  const secretEvent = { tool_name: "Bash", tool_response: SECRET_TEXT };

  it("is inert when unsupplied: the redaction warning carries no note", async () => {
    const fields = await evaluateToolOutput(secretEvent);
    assert.equal(fields?.mutated_output, REDACTED_TEXT);
    assert.match(
      String(fields?.additional_context),
      /API keys\/secrets redacted: FakeDetector/u,
    );
    assert.doesNotMatch(String(fields?.additional_context), /provenance/u);
  });

  it("appends the note to that leaf's redaction warning", async () => {
    const fields = await evaluateToolOutput(secretEvent, {
      redactNote: () => " (provenance: host)",
    });
    assert.match(
      String(fields?.additional_context),
      /API keys\/secrets redacted: FakeDetector \(provenance: host\)/u,
    );
  });

  it("is handed the PRE-redaction text", async () => {
    /** @type {string[]} */
    const seen = [];
    await evaluateToolOutput(secretEvent, {
      redactNote: (raw) => {
        seen.push(raw);
        return undefined;
      },
    });
    assert.deepEqual(seen, [SECRET_TEXT]);
  });

  it("never fires on text the secret pre-gate did not match", async () => {
    let calls = 0;
    await evaluateToolOutput(
      { tool_name: "Bash", tool_response: "nothing of interest" },
      {
        redactNote: () => {
          calls += 1;
          return "x";
        },
      },
    );
    assert.equal(calls, 0);
  });
});

describe("audit", () => {
  /** @param {any} response @param {any} ext */
  const judge = (response, ext) =>
    judgeSanitizeOutput(
      { event: "PostToolUse", tool: "Bash", input: {}, response },
      ext,
    );

  it("is handed the original output when nothing was rewritten", async () => {
    /** @type {any[]} */
    const records = [];
    await judge("plain output", { audit: (r) => records.push(r) });
    assert.equal(records.length, 1);
    assert.deepEqual(records[0], {
      tool: "Bash",
      modified: false,
      output: "plain output",
      context: undefined,
    });
  });

  it("is handed the mutated output the model will actually see", async () => {
    /** @type {any[]} */
    const records = [];
    const verdict = await judge(SECRET_TEXT, { audit: (r) => records.push(r) });
    assert.equal(records[0].modified, true);
    assert.equal(records[0].output, REDACTED_TEXT);
    assert.equal(records[0].output, verdict.mutated_output);
    assert.match(String(records[0].context), /redacted/u);
  });

  it("does not fire when the event carried no tool response", async () => {
    /** @type {any[]} */
    const records = [];
    for (const response of [null, undefined])
      await judge(response, { audit: (r) => records.push(r) });
    assert.deepEqual(records, []);
  });

  it("is awaited, so a rejecting recorder fails the judge closed", async () => {
    await assert.rejects(
      judge("plain output", {
        audit: async () => {
          throw new Error("audit sink down");
        },
      }),
      /audit sink down/u,
    );
  });

  it("is inert when unsupplied", async () => {
    const withBag = await judge("plain output", {});
    const without = await judgeSanitizeOutput({
      event: "PostToolUse",
      tool: "Bash",
      input: {},
      response: "plain output",
    });
    assert.deepEqual(withBag, without);
  });
});

describe("_AGENT_SANITIZER_EXTRA_SECRET_VARS", () => {
  it("is empty when unset or blank", () => {
    for (const env of [
      {},
      { _AGENT_SANITIZER_EXTRA_SECRET_VARS: "" },
      { _AGENT_SANITIZER_EXTRA_SECRET_VARS: "  " },
    ])
      assert.deepEqual(extraSecretVars(env), []);
  });

  it("parses a comma-separated list, trimming each name", () => {
    assert.deepEqual(
      extraSecretVars({
        _AGENT_SANITIZER_EXTRA_SECRET_VARS: "GLOVEBOX_SEED, AWS_S3_KEY2",
      }),
      ["GLOVEBOX_SEED", "AWS_S3_KEY2"],
    );
  });

  it("throws on a malformed name rather than silently dropping it", () => {
    // Dropping any of these silently would leave the operator believing a
    // forwarded credential is masked while its value reaches the model verbatim.
    for (const raw of ["lower_case", "HAS SPACE", "HAS-DASH", "A,,B", "A;B"])
      assert.throws(
        () => extraSecretVars({ _AGENT_SANITIZER_EXTRA_SECRET_VARS: raw }),
        /_AGENT_SANITIZER_EXTRA_SECRET_VARS/u,
        `expected ${raw} to be refused`,
      );
  });

  it("unions into the env-bound redaction set without displacing it", () => {
    const base = envBoundSecretVars({});
    const widened = envBoundSecretVars({
      _AGENT_SANITIZER_EXTRA_SECRET_VARS: "GLOVEBOX_SEED",
    });
    assert.ok(base.length > 0, "curated floor must be non-empty");
    assert.equal(base.includes("GLOVEBOX_SEED"), false);
    assert.deepEqual(widened, [...base, "GLOVEBOX_SEED"]);
  });

  it("does not duplicate a name the curated floor already carries", () => {
    const existing = envBoundSecretVars({})[0];
    const widened = envBoundSecretVars({
      _AGENT_SANITIZER_EXTRA_SECRET_VARS: existing,
    });
    assert.deepEqual(widened, envBoundSecretVars({}));
  });
});
