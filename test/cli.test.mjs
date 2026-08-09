/**
 * Contract tests for the stdin/stdout CLI (`bin/sanitize-cli.mjs`), the
 * single-source-of-truth bridge for non-JS pipelines.
 *
 * The CLI must be a faithful pass-through to `sanitize`: its JSON response has
 * to equal what an in-process `sanitize` call returns for the same input, in
 * both one-shot and worker modes. So `sanitize` itself is the oracle here —
 * these tests pin the I/O envelope and the worker's stay-alive-on-bad-input
 * contract, not the sanitization verdicts (those are owned by sanitize.test.mjs).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { Buffer } from "node:buffer";
import { fileURLToPath } from "node:url";
import { mkdtempSync, writeFileSync, readFileSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import fc from "fast-check";

import { sanitize } from "../src/index.mjs";
import { classifyPrompt } from "../src/prompt.mjs";
import { sanitizeText } from "../src/output.mjs";
import { scanInstructionFiles } from "../src/instructions.mjs";
import {
  createLineSplitter,
  parseArgs,
  USAGE,
  OPS,
} from "../bin/sanitize-cli.mjs";
import { fcRunOptions, unicodeChar, loneSurrogate } from "./test-helpers.mjs";

const ESC = "\u001b";

const ZWS = "\u200b";
const HIDDEN_HTML = '<div style="display:none">leak</div>';

const CLI = fileURLToPath(new URL("../bin/sanitize-cli.mjs", import.meta.url));

/** Run the CLI with `input` on stdin, returning trimmed stdout. */
const run = (args, input) =>
  execFileSync("node", [CLI, ...args], { input, encoding: "utf8" });

/** The wire response shape, for comparing CLI output against the sanitize oracle. */
// The identity, deliberately. This used to re-project `sanitize()`'s result
// down to a hand-written four-field list, which meant these "mirrors
// sanitize()" assertions could not see a field the CLI failed to forward — and
// one had already gone missing (`splices`). Comparing the whole object is what
// makes the oracle a real oracle. Kept as a named function so the intent is
// legible at the call sites rather than looking like a forgotten refactor.
const envelope = (result) => result;

// Inputs spanning every layer: a Cf char (Layer 1), clean passthrough, a hidden
// element + an exfil-shaped URL (Layers 2/3, html mode). Each carries the html
// flag it needs so the oracle comparison covers both code paths.
const CASES = [
  { name: "strips invisible (Layer 1)", text: "a​b", html: false },
  { name: "clean passthrough", text: "hello world", html: false },
  { name: "empty input", text: "", html: false },
  {
    name: "hidden HTML + exfil (Layers 2/3)",
    text: '<div style="display:none">leak</div>[x](https://evil.test/?d=SECRET)',
    html: true,
  },
];

describe("CLI: invoked through a symlinked bin (published-package shape)", () => {
  // npm installs the `sanitize-cli` bin as a symlink under node_modules/.bin,
  // so a consumer launches the CLI via a path that is NOT this module's real
  // file. The script-detection guard must resolve real paths; a raw URL compare
  // makes `invokedAsScript` false and the CLI emits nothing (silent break).
  it("runs and returns a response when launched through a symlink", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "ais-cli-bin-"));
    const link = path.join(dir, "sanitize-cli");
    symlinkSync(CLI, link);
    const out = execFileSync("node", [link], {
      input: '{"text":"a​b"}',
      encoding: "utf8",
    });
    assert.deepEqual(JSON.parse(out), {
      cleaned: "ab",
      found: ["cf-format"],
      warnings: [
        "Stripped: Format chars (Cf) — inspect the removed bytes with a hex dump (xxd / od -c), which survives sanitization",
      ],
      notes: [],
    });
  });
});

describe("CLI: one-shot mode mirrors sanitize()", () => {
  for (const { name, text, html } of CASES) {
    it(name, async () => {
      const expected = await sanitize(text, { html });
      const got = JSON.parse(run([], JSON.stringify({ text, html })));
      assert.deepEqual(got, envelope(expected));
    });
  }
});

describe("CLI: worker mode", () => {
  it("answers newline-delimited requests in order, matching sanitize()", async () => {
    const input = CASES.map((c) =>
      JSON.stringify({ text: c.text, html: c.html }),
    ).join("\n");
    const lines = run(["--worker"], `${input}\n`).trim().split("\n");
    assert.equal(lines.length, CASES.length);
    for (const [i, { text, html }] of CASES.entries()) {
      assert.deepEqual(
        JSON.parse(lines[i]),
        envelope(await sanitize(text, { html })),
      );
    }
  });

  it("reports a bad request as an error line and keeps serving the next", () => {
    const input = `${JSON.stringify({ text: 123 })}\n${JSON.stringify({ text: "ok" })}\n`;
    const lines = run(["--worker"], input).trim().split("\n");
    assert.match(JSON.parse(lines[0]).error, /text must be a string/);
    assert.deepEqual(JSON.parse(lines[1]), {
      cleaned: "ok",
      found: [],
      warnings: [],
      notes: [],
    });
  });

  it("treats a string-encoded newline in the payload as one request", async () => {
    const text = "line1\nline2​";
    const out = run(["--worker"], `${JSON.stringify({ text })}\n`).trim();
    assert.equal(out.split("\n").length, 1);
    assert.deepEqual(JSON.parse(out), envelope(await sanitize(text)));
  });

  it("emits exactly one error line for a blank line, keeping framing", () => {
    // A blank/whitespace request line must NOT be silently skipped: a skip emits
    // zero responses for one input line and desyncs every later response against
    // a one-response-per-request client. We assert one response PER input line
    // and that the following real request still answers correctly.
    const input = `\n   \n${JSON.stringify({ text: "ok" })}\n`;
    const lines = run(["--worker"], input).trim().split("\n");
    assert.equal(lines.length, 3); // blank, whitespace, real → 3 responses
    assert.ok(JSON.parse(lines[0]).error);
    assert.ok(JSON.parse(lines[1]).error);
    assert.deepEqual(JSON.parse(lines[2]), {
      cleaned: "ok",
      found: [],
      warnings: [],
      notes: [],
    });
  });
});

describe("CLI: input-size cap (DoS guard)", () => {
  const overLimit = JSON.stringify({ text: "A".repeat(200) });
  const underLimit = JSON.stringify({ text: "ok" });

  it("one-shot rejects an oversized request with a non-zero exit", () => {
    assert.throws(
      () =>
        execFileSync("node", [CLI], {
          input: overLimit,
          encoding: "utf8",
          env: { ...process.env, AGENT_SANITIZER_MAX_INPUT_BYTES: "50" },
        }),
      (err) => {
        assert.equal(err.status, 1);
        assert.match(String(err.stderr), /request too large/);
        assert.match(String(err.stderr), /AGENT_SANITIZER_MAX_INPUT_BYTES/);
        return true;
      },
    );
  });

  it("worker returns an error line for an oversized request and keeps serving", () => {
    const out = execFileSync("node", [CLI, "--worker"], {
      input: `${overLimit}\n${underLimit}\n`,
      encoding: "utf8",
      env: { ...process.env, AGENT_SANITIZER_MAX_INPUT_BYTES: "50" },
    });
    const lines = out.trim().split("\n");
    assert.equal(lines.length, 2);
    assert.match(JSON.parse(lines[0]).error, /request too large/);
    assert.deepEqual(JSON.parse(lines[1]), {
      cleaned: "ok",
      found: [],
      warnings: [],
      notes: [],
    });
  });

  it("ignores a non-positive / non-numeric limit, using the default", () => {
    // A bogus override must not disable the cap or set it to zero (which would
    // reject everything); it falls back to the generous default, so a small
    // request still succeeds.
    for (const bogus of ["0", "-1", "notanumber", ""]) {
      const out = execFileSync("node", [CLI], {
        input: underLimit,
        encoding: "utf8",
        env: { ...process.env, AGENT_SANITIZER_MAX_INPUT_BYTES: bogus },
      });
      assert.deepEqual(JSON.parse(out), {
        cleaned: "ok",
        found: [],
        warnings: [],
        notes: [],
      });
    }
  });
});

describe("CLI: one-shot fails loudly on a bad request", () => {
  it("exits non-zero with the reason on stderr", () => {
    assert.throws(
      () => run([], JSON.stringify({ text: 123 })),
      (err) => {
        assert.equal(err.status, 1);
        assert.match(String(err.stderr), /text must be a string/);
        return true;
      },
    );
  });

  it("exits non-zero on empty stdin (no request at all)", () => {
    assert.throws(
      () => run([], ""),
      (err) => {
        assert.equal(err.status, 1);
        return true;
      },
    );
  });
});

// ─── Transport faithfulness (fuzz) ───────────────────────────────────────────
//
// The fixed CASES above pin known shapes; this fuzzes the NEW surface the CLI
// adds — the JSON request/response envelope and the worker's newline framing —
// to prove it transports arbitrary text without altering the verdict. The
// sanitizer itself is already fuzzed elsewhere, so `sanitize` is the oracle:
// the only thing under test is that `cli(text)` === `sanitize(text)` for inputs
// that stress the encoding (lone surrogates, ANSI/ESC, invisibles, structural
// tokens, line/paragraph separators). A framing bug — a payload byte read as a
// request boundary, or a surrogate mangled by the JSON round-trip — shows up as
// a mismatch or a response-count drift that the hand-picked cases would miss.

const FRAMING_TOKENS = [
  "\n",
  "\r",
  "\r\n",
  "\u2028", // line separator — valid in JSON, must NOT split a worker request
  "\u2029", // paragraph separator
  "\u0000", // NUL
  "\u001b[31m", // 7-bit ANSI/ESC
  "\u009b6n", // 8-bit C1 CSI
  "\u200b", // zero-width space
  "\ufeff", // BOM
  '<div style="display:none">x</div>',
  "[t](https://evil.test/?d=SECRET)",
];

const fuzzText = fc
  .array(
    fc.oneof(unicodeChar, loneSurrogate, fc.constantFrom(...FRAMING_TOKENS)),
    {
      maxLength: 80,
    },
  )
  .map((parts) => parts.join(""));

describe("CLI: transport faithfulness (fuzz)", () => {
  it("one-shot mode equals sanitize() for arbitrary input", async () => {
    await fc.assert(
      fc.asyncProperty(fuzzText, fc.boolean(), async (text, html) => {
        const got = JSON.parse(run([], JSON.stringify({ text, html })));
        assert.deepEqual(got, envelope(await sanitize(text, { html })));
      }),
      fcRunOptions({ numRuns: 60 }),
    );
  });

  it("worker mode batches arbitrary requests, one faithful response each", async () => {
    // Batch a whole array of inputs through ONE worker process: this is where a
    // framing bug bites — a payload that smuggles a newline would split one
    // request into two and desync every response after it.
    await fc.assert(
      fc.asyncProperty(
        fc.array(fuzzText, { minLength: 1, maxLength: 15 }),
        async (texts) => {
          const input = texts
            .map((text) => JSON.stringify({ text }))
            .join("\n");
          const lines = run(["--worker"], `${input}\n`).trim().split("\n");
          assert.equal(lines.length, texts.length);
          for (const [i, text] of texts.entries()) {
            assert.deepEqual(
              JSON.parse(lines[i]),
              envelope(await sanitize(text)),
            );
          }
        },
      ),
      fcRunOptions({ numRuns: 40 }),
    );
  });
});

describe("CLI: large input", () => {
  it("transports a payload larger than the OS pipe buffer in both modes", async () => {
    const text = `${"A".repeat(200_000)}\u200b${"B".repeat(200_000)}`;
    const expected = envelope(await sanitize(text));
    assert.deepEqual(JSON.parse(run([], JSON.stringify({ text }))), expected);
    const out = run(["--worker"], `${JSON.stringify({ text })}\n`).trim();
    assert.equal(out.split("\n").length, 1);
    assert.deepEqual(JSON.parse(out), expected);
  });
});

// \u2500\u2500\u2500 Op dispatch: the other self-contained entry points \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
//
// Beyond `sanitize`, the CLI bridges every data-in/data-out entry point through
// an `op` field. Same contract as above \u2014 the in-process function is the oracle,
// and these pin only that the CLI relays its result faithfully in both modes.
// The injected-callback seams (confusables, redact, io) have no wire form and are
// deliberately absent.

/** Build one request line and assert the CLI's response equals `expected`, in
 * both one-shot and (single-request) worker mode. */
const assertOpMirrors = (request, expected) => {
  const line = JSON.stringify(request);
  assert.deepEqual(JSON.parse(run([], line)), expected);
  const out = run(["--worker"], `${line}\n`).trim();
  assert.equal(out.split("\n").length, 1);
  assert.deepEqual(JSON.parse(out), expected);
};

describe("CLI: op dispatch mirrors the in-process entry point", () => {
  it("classifyPrompt: pass / SGR-note / block all relay faithfully", () => {
    for (const text of [
      "hello world",
      `${ESC}[31mred${ESC}[0m`,
      `${ESC}[2Jwipe`,
    ])
      assertOpMirrors({ op: "classifyPrompt", text }, classifyPrompt(text));
  });

  it("sanitizeText: Layers 1\u20133 relay the full shape", async () => {
    for (const { text, html } of [
      { text: `a${ZWS}b`, html: false },
      { text: "hello", html: false },
      { text: HIDDEN_HTML, html: true },
    ]) {
      const { cleaned, warnings, notes, modified, sgrNote } =
        await sanitizeText(text, { html });
      assertOpMirrors(
        { op: "sanitizeText", text, html },
        { cleaned, warnings, notes, modified, sgrNote },
      );
    }
  });

  it("scanInstructionFiles + cleanFile: scan, clean, re-scan clean", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "ais-cli-"));
    const notes = path.join(dir, "NOTES.md");
    writeFileSync(notes, `intro ${ZWS.repeat(100)} outro\n`, "utf8");
    writeFileSync(path.join(dir, "CLEAN.md"), "nothing hidden\n", "utf8");

    assertOpMirrors(
      { op: "scanInstructionFiles", globs: ["*.md"], cwd: dir },
      { findings: scanInstructionFiles(["*.md"], { cwd: dir }) },
    );

    // cleanFile mutates the file, so the oracle can't run on the same path after
    // the CLI already cleaned it. Drive the CLI first, then assert the on-disk
    // effect and that a second clean is a no-op.
    const clean = (p) =>
      JSON.parse(run([], JSON.stringify({ op: "cleanFile", path: p }))).changed;
    assert.equal(clean(notes), true);
    assert.ok(!readFileSync(notes, "utf8").includes(ZWS));
    assert.equal(clean(notes), false);
    assert.equal(clean(path.join(dir, "CLEAN.md")), false);
    assert.deepEqual(scanInstructionFiles(["*.md"], { cwd: dir }), []);
  });

  it("scanInstructionFiles rejects a present-but-non-string cwd loudly", () => {
    assert.throws(
      () =>
        run(
          [],
          JSON.stringify({
            op: "scanInstructionFiles",
            globs: ["*.md"],
            cwd: 5,
          }),
        ),
      (err) => {
        assert.equal(err.status, 1);
        assert.match(String(err.stderr), /request\.cwd must be a string/);
        return true;
      },
    );
  });
});

describe("CLI: unknown op fails loudly", () => {
  it("one-shot exits non-zero naming the op", () => {
    assert.throws(
      () => run([], JSON.stringify({ op: "nope", text: "x" })),
      (err) => {
        assert.equal(err.status, 1);
        assert.match(String(err.stderr), /unknown op: nope/);
        return true;
      },
    );
  });

  it("worker reports the bad op and keeps serving", () => {
    const input = `${JSON.stringify({ op: "nope" })}\n${JSON.stringify({ text: "ok" })}\n`;
    const lines = run(["--worker"], input).trim().split("\n");
    assert.match(JSON.parse(lines[0]).error, /unknown op: nope/);
    assert.deepEqual(JSON.parse(lines[1]), {
      cleaned: "ok",
      found: [],
      warnings: [],
      notes: [],
    });
  });
});

// ─── Worker per-line memory cap (streaming) ─────────────────────────
//
// The header docstring promises the worker rejects an oversized request "rather
// than buffering an unbounded payload into memory." A `readline`-based loop
// can't honor that: it buffers a whole newline-less line before the size check
// runs. These tests pin the streaming behavior — an oversize line is discarded
// AS IT STREAMS (peak buffering bounded by the cap), the worker emits one error
// line for it, and the framing resyncs so the NEXT request still answers.

/**
 * Drive the worker by streaming raw chunks on stdin, collecting response lines.
 * @param {Buffer[]} chunks   written in order, then stdin is closed
 * @param {number} capBytes   AGENT_SANITIZER_MAX_INPUT_BYTES for the child
 * @returns {Promise<{ lines: string[], peakRssBytes: number }>}
 */
const runWorkerStreaming = (chunks, capBytes) =>
  new Promise((resolve, reject) => {
    const child = spawn("node", [CLI, "--worker"], {
      env: {
        ...process.env,
        AGENT_SANITIZER_MAX_INPUT_BYTES: String(capBytes),
      },
    });
    let out = "";
    let peakRssBytes = 0;
    child.stdout.on("data", (d) => (out += d));
    child.on("error", reject);
    // Sample the child's resident set so the test can assert the oversize line
    // never made it into memory whole. /proc is Linux-only; elsewhere the RSS
    // assertion is skipped and only the functional framing checks run.
    const sample = () => {
      try {
        const statm = readFileSync(`/proc/${child.pid}/statm`, "utf8");
        peakRssBytes = Math.max(
          peakRssBytes,
          Number(statm.split(" ")[1]) * 4096,
        );
      } catch {
        // child gone or non-Linux /proc absent — nothing to sample
      }
    };
    const sampler = setInterval(sample, 5);
    child.on("close", () => {
      clearInterval(sampler);
      resolve({
        lines: out.length === 0 ? [] : out.trim().split("\n"),
        peakRssBytes,
      });
    });

    (async () => {
      for (const chunk of chunks) {
        if (!child.stdin.write(chunk))
          await new Promise((r) => child.stdin.once("drain", r));
      }
      child.stdin.end();
    })().catch(reject);
  });

describe("CLI: worker bounds per-line buffering to the input cap", () => {
  it("discards an oversized no-newline line, errors once, and resyncs", async () => {
    const cap = 1024;
    const okBefore = Buffer.from(`${JSON.stringify({ text: "a" })}\n`);
    // A single line FAR larger than Node's interpreter baseline, NO interior
    // newline, streamed in 1 MiB chunks: a buffering implementation must hold the
    // whole payload before the cap fires, so its peak RSS rises by ~payloadBytes.
    // The bound code discards each chunk past the cap, so RSS stays near baseline.
    const payloadBytes = 256 * 1024 * 1024;
    const chunkSize = 1024 * 1024;
    const bigChunk = Buffer.from("X".repeat(chunkSize));
    const bigChunks = Array.from(
      { length: payloadBytes / chunkSize },
      () => bigChunk,
    );
    const okAfter = Buffer.from(`\n${JSON.stringify({ text: "b" })}\n`);

    // Baseline: peak RSS of a worker that only handles two tiny requests. The
    // streaming run's peak must not exceed this by anything close to payloadBytes.
    const baseline = await runWorkerStreaming(
      [okBefore, Buffer.from(`${JSON.stringify({ text: "b" })}\n`)],
      cap,
    );
    const { lines, peakRssBytes } = await runWorkerStreaming(
      [okBefore, ...bigChunks, okAfter],
      cap,
    );

    // Exactly one response per input line, framing intact across the discard.
    assert.equal(lines.length, 3);
    assert.deepEqual(JSON.parse(lines[0]), {
      cleaned: "a",
      found: [],
      warnings: [],
      notes: [],
    });
    assert.match(JSON.parse(lines[1]).error, /request too large/);
    assert.match(JSON.parse(lines[1]).error, /AGENT_SANITIZER_MAX_INPUT_BYTES/);
    // The resync proof: the request AFTER the discarded line still answers.
    assert.deepEqual(JSON.parse(lines[2]), {
      cleaned: "b",
      found: [],
      warnings: [],
      notes: [],
    });

    // Memory proof: peak RSS over baseline must stay a small fraction of the
    // 256 MiB payload. A buffering impl would add ~payloadBytes here; the bound
    // adds only the cap plus transient chunk/GC slack. The 1/4-payload ceiling
    // sits far below a buffering peak yet comfortably above GC headroom, so the
    // assertion separates the two implementations without flaking. /proc is
    // Linux-only, so a genuinely /proc-less host (non-Linux) legitimately
    // reports 0 for both and skips the bound. On Linux, /proc IS expected to
    // be available, so a zero-sample run there is a broken sampler, not a
    // legitimate skip — assert loudly rather than silently no-op the entire
    // memory-bound claim this test exists to make.
    if (process.platform === "linux")
      assert.ok(
        baseline.peakRssBytes > 0 && peakRssBytes > 0,
        "RSS sampler landed no samples on Linux (baseline=" +
          `${baseline.peakRssBytes}, payload=${peakRssBytes}) — the memory-bound ` +
          "assertion below did not run",
      );
    if (peakRssBytes > 0 && baseline.peakRssBytes > 0)
      assert.ok(
        peakRssBytes - baseline.peakRssBytes < payloadBytes / 4,
        `peak RSS grew by ${peakRssBytes - baseline.peakRssBytes} bytes over ` +
          `baseline ${baseline.peakRssBytes}; a bounded worker stays well under ` +
          `${payloadBytes / 4} for a ${payloadBytes}-byte streamed line`,
      );
  });

  it("a line exactly at the cap succeeds; one byte over errors", async () => {
    // The request is `{"text":"<pad>"}`; size the pad so the whole line lands
    // exactly on / one past the cap, pinning the boundary.
    const make = (capExact) => {
      const envelopeBytes = Buffer.byteLength('{"text":""}');
      const text = "a".repeat(capExact - envelopeBytes);
      return JSON.stringify({ text });
    };
    const cap = 256;
    const atCap = make(cap);
    assert.equal(Buffer.byteLength(atCap), cap);
    const overCap = make(cap + 1);
    assert.equal(Buffer.byteLength(overCap), cap + 1);

    const input = Buffer.from(`${atCap}\n${overCap}\n`);
    const { lines } = await runWorkerStreaming([input], cap);
    assert.equal(lines.length, 2);
    assert.ok(!("error" in JSON.parse(lines[0])), "at-cap line should succeed");
    assert.match(JSON.parse(lines[1]).error, /request too large/);
  });
});

// ─── Splitter unit + property tests ────────────────────────────────────
//
// `createLineSplitter` is the pure heart of the fix — it decides, byte by byte,
// which line is in-cap (a `line` event) and which overflowed (an `oversize`
// event), independent of how stdin chunks the bytes. Unit-test it directly so a
// member-drop (CRLF handling, the at-cap boundary, mid-chunk overflow, the EOF
// flush) is caught without spawning a process.

/** Feed `input` to a fresh splitter as the given `chunkSize` (or all at once),
 * returning every event including the EOF flush. */
const splitAll = (input, cap, chunkSize) => {
  const split = createLineSplitter(cap);
  const buf = Buffer.from(input, "utf8");
  const events = [];
  if (chunkSize === undefined) events.push(...split(buf));
  else
    for (let i = 0; i < buf.length; i += chunkSize)
      events.push(...split(buf.subarray(i, i + chunkSize)));
  events.push(...split.end());
  return events;
};

describe("createLineSplitter", () => {
  it("emits one in-cap line per newline, text decoded", () => {
    assert.deepEqual(splitAll("hi\nthere\n", 100), [
      { kind: "line", text: "hi" },
      { kind: "line", text: "there" },
    ]);
  });

  it("strips a trailing CR (CRLF frames like LF)", () => {
    assert.deepEqual(splitAll("a\r\nb\r\n", 100), [
      { kind: "line", text: "a" },
      { kind: "line", text: "b" },
    ]);
  });

  it("emits a blank line for an empty input line (no skip)", () => {
    assert.deepEqual(splitAll("\n \n", 100), [
      { kind: "line", text: "" },
      { kind: "line", text: " " },
    ]);
  });

  it("flushes an unterminated final line at EOF", () => {
    assert.deepEqual(splitAll("done", 100), [{ kind: "line", text: "done" }]);
    assert.deepEqual(splitAll("", 100), []);
    assert.deepEqual(splitAll("x\n", 100), [{ kind: "line", text: "x" }]);
  });

  it("a line exactly at the cap is in-cap; one over is oversize", () => {
    assert.deepEqual(splitAll("AAAA\n", 4), [{ kind: "line", text: "AAAA" }]);
    assert.deepEqual(splitAll("AAAAA\n", 4), [{ kind: "oversize" }]);
  });

  it("discards an oversize line then resyncs on the next", () => {
    assert.deepEqual(splitAll("AAAAAAAA\nok\n", 4), [
      { kind: "oversize" },
      { kind: "line", text: "ok" },
    ]);
  });

  it("flushes an unterminated oversize tail as one oversize event", () => {
    assert.deepEqual(splitAll("AAAAAAAA", 4), [{ kind: "oversize" }]);
  });

  it("detects overflow mid-chunk, not only at the trailing edge", () => {
    // Whole input in ONE chunk: the oversize MIDDLE line must still be caught
    // (the bug the fix targets — size-checking only the chunk's tail misses it).
    assert.deepEqual(splitAll("a\nBBBBBBBB\nc\n", 4), [
      { kind: "line", text: "a" },
      { kind: "oversize" },
      { kind: "line", text: "c" },
    ]);
  });

  it("classification is identical however the bytes are chunked", () => {
    // The same logical lines fed as one chunk vs. byte-by-byte vs. odd splits
    // must yield the SAME event sequence — chunk boundaries are not request
    // boundaries. (Decoded text can differ when a split lands mid-UTF-8 char, so
    // compare the kind/oversize structure, which is what framing depends on.)
    const cap = 8;
    const input = "ok\nWAYTOOLONGLINE\n\nfin";
    const kinds = (cs) =>
      splitAll(input, cap, cs).map((e) =>
        e.kind === "oversize" ? "oversize" : "line",
      );
    const oneShot = kinds(undefined);
    assert.deepEqual(oneShot, ["line", "oversize", "line", "line"]);
    for (const cs of [1, 2, 3, 5, 7, 13]) assert.deepEqual(kinds(cs), oneShot);
  });

  it("reassembles a multi-slice line byte-for-byte", () => {
    // The line spans thousands of 1-byte chunks, so the splitter holds it as a
    // LIST of slices and joins them once at the newline (the O(n) accumulation
    // that replaced a per-segment Buffer.concat). Pin that the join reconstructs
    // the exact bytes — ASCII only, so no chunk boundary lands mid-codepoint.
    const line = "x".repeat(5000);
    assert.deepEqual(splitAll(`${line}\n`, 1_000_000, 1), [
      { kind: "line", text: line },
    ]);
  });

  it("strips a trailing CR delivered as its own chunk", () => {
    // CRLF fed byte-by-byte: the CR is the final slice, so the trailing-CR strip
    // must inspect the JOINED line's last byte, not a single accumulator's.
    assert.deepEqual(splitAll("abc\r\n", 100, 1), [
      { kind: "line", text: "abc" },
    ]);
  });

  it("property: # line events == # in-cap lines; framing chunk-invariant", () => {
    // Domain: random lines (some > cap), joined by \\n, fed at random chunk
    // sizes. INVARIANTS: (1) total events == number of input lines (one response
    // per line, no skips/dupes); (2) a line's event kind matches whether its
    // BYTE length is within the cap; (3) the event SEQUENCE is invariant to how
    // the byte stream is chunked. Never throws on any input.
    const cap = 16;
    fc.assert(
      fc.property(
        fc.array(fc.string({ maxLength: 40 }), { minLength: 1, maxLength: 12 }),
        fc.integer({ min: 1, max: 20 }),
        (rawLines, chunkSize) => {
          // A line can't contain its own delimiter; \\r is stripped, so exclude
          // both to keep the expected framing unambiguous. Terminate EVERY line
          // with \\n (trailing newline included) so each modeled line is framed —
          // an unterminated empty tail is genuinely zero lines, not one, which
          // would desync the count.
          const lines = rawLines.map((l) => l.replace(/[\n\r]/g, ""));
          const input = `${lines.join("\n")}\n`;
          const expected = lines.map((l) =>
            Buffer.byteLength(l, "utf8") > cap ? "oversize" : "line",
          );

          const kindsAt = (cs) =>
            splitAll(input, cap, cs).map((e) =>
              e.kind === "oversize" ? "oversize" : "line",
            );
          const got = kindsAt(chunkSize);
          assert.equal(got.length, lines.length);
          assert.deepEqual(got, expected);
          // Chunk-invariance: same sequence fed all-at-once.
          assert.deepEqual(kindsAt(undefined), expected);
        },
      ),
      fcRunOptions({ numRuns: 200 }),
    );
  });
});

// ─── Argument parsing: --help and unknown-flag handling ──────────────────────
// `parseArgs` is the pure resolver; the bottom-of-file dispatch only acts on its
// verdict. A bare/`--worker` invocation keeps its existing mode; the new cases
// are `--help`/`-h` (print usage, don't read stdin) and an unrecognized flag
// (usage error, exit 2) rather than the old silent fall-through that blocked on
// a TTY's stdin with no output.
describe("parseArgs", () => {
  for (const [argv, expected] of [
    [["node", "cli"], { mode: "oneshot" }],
    [["node", "cli", "--worker"], { mode: "worker" }],
    [["node", "cli", "--help"], { mode: "help" }],
    [["node", "cli", "-h"], { mode: "help" }],
    [["node", "cli", "--hepl"], { mode: "error", unknown: ["--hepl"] }],
    // an unknown flag alongside --worker is still an error (don't silently run)
    [
      ["node", "cli", "--worker", "--bogus"],
      { mode: "error", unknown: ["--bogus"] },
    ],
    // a non-flag positional arg is ignored (still one-shot)
    [["node", "cli", "somefile"], { mode: "oneshot" }],
    // --help wins even with other flags present
    [["node", "cli", "--worker", "--help"], { mode: "help" }],
  ]) {
    it(`${argv.slice(2).join(" ") || "(no args)"} → ${expected.mode}`, () =>
      assert.deepEqual(parseArgs(argv), expected));
  }
});

describe("USAGE ops list", () => {
  it("names every key of OPS, and only those, in dispatch order", () => {
    // Guards the derivation itself: if USAGE stopped being built from
    // Object.keys(OPS), this catches the drift the moment an op is added,
    // renamed, or removed.
    const sentence = USAGE.match(/Ops: ([^.]+)\./)?.[1];
    assert.ok(sentence, "USAGE must contain an 'Ops: …' sentence");
    const named = sentence
      .split(",")
      .map((name) => name.trim().replace(" (default)", ""));
    assert.deepEqual(named, Object.keys(OPS));
    // The default op stays called out as such.
    assert.ok(sentence.includes("sanitize (default)"));
  });
});

describe("CLI flag behavior (spawned)", () => {
  it("--help prints usage to stdout and exits 0 without reading stdin", () => {
    // No `input` is supplied: a help invocation must NOT block on stdin.
    const out = execFileSync("node", [CLI, "--help"], { encoding: "utf8" });
    assert.equal(out, USAGE);
  });

  it("an unknown flag exits 2 with an error on stderr, not a silent stdin hang", () => {
    let status = 0;
    let stderr = "";
    try {
      execFileSync("node", [CLI, "--nope"], {
        encoding: "utf8",
        stdio: "pipe",
      });
    } catch (err) {
      status = err.status;
      stderr = String(err.stderr);
    }
    assert.equal(status, 2);
    assert.match(stderr, /unrecognized option\(s\): --nope/);
  });
});
