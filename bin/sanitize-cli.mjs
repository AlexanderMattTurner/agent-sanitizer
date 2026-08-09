#!/usr/bin/env node
/**
 * Single-source-of-truth CLI over the sanitizer's data-in/data-out entry points,
 * for non-JS pipelines.
 *
 * The logic lives once, in `src/`. This CLI is the supported escape hatch for
 * callers that can't import the JavaScript directly (a Python pipeline, say): it
 * speaks JSON over stdin/stdout so any language drives the exact same verdicts
 * without a second implementation to keep in sync. Only the entry points with no
 * injected callback are exposed — the agent-pipeline seams that take a homoglyph
 * scanner, redactor, or file-access object have no language-agnostic wire form
 * and stay JS-only.
 *
 * Protocol — a request is a JSON object with an `op` (default `"sanitize"` so a
 * bare `{ text, html }` keeps working). Per op:
 *
 *   sanitize           { text, html? }            -> { cleaned, found, warnings, notes, splices? }
 *   sanitizeText       { text, html?, exfilScan? } -> { cleaned, warnings, notes, modified, sgrNote }
 *   classifyPrompt     { text }                    -> { action, reason? }
 *   scanInstructionFiles { globs, cwd? }           -> { findings: [{ file, findings }] }
 *   cleanFile          { path }                    -> { changed }
 *
 * A failure response is `{ "error": string }`. Two modes, same binary:
 *
 *   one-shot (default): read ONE JSON object from stdin (may span lines), write
 *     ONE response line. A malformed request propagates — non-zero exit, a
 *     one-line reason on stderr (the message, deliberately not a raw Node stack)
 *     — so a scripted caller fails loudly.
 *
 *   worker (`--worker`): read newline-delimited JSON requests until EOF, write
 *     EXACTLY one response line per input line, in order — including for a blank
 *     line (a framing slip on the caller's side), which gets an `{ "error" }`
 *     line rather than being silently skipped. Skipping a line desyncs every
 *     later response against a client that reads one response per request. A
 *     malformed request likewise yields an `{ "error" }` line and the worker
 *     keeps serving — the specific, necessary recovery that makes a long-lived
 *     process usable across independent requests (one bad line must not drop the
 *     whole pipe). JSON string-encodes every newline, so one request and one
 *     response always occupy one line each.
 *
 * Input-size cap: both modes reject a single request larger than
 * `AGENT_SANITIZER_MAX_INPUT_BYTES` (UTF-8 bytes, default 10 MiB) with a
 * structured error rather than buffering an unbounded payload into memory —
 * one-shot exits non-zero, the worker emits an `{ "error" }` line and keeps
 * serving. Raise or lower the limit via that environment variable.
 */
import { Buffer } from "node:buffer";
import { realpathSync } from "node:fs";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { sanitize } from "../src/index.mjs";

/** Largest single request accepted, in UTF-8 bytes. Caps memory per request so
 * a hostile or runaway caller can't OOM the process; override via the env var. */
const DEFAULT_MAX_INPUT_BYTES = 10 * 1024 * 1024;

/** Resolve the configured input cap, falling back to the default for an unset,
 * empty, non-numeric, or non-positive value. */
function maxInputBytes() {
  const raw = process.env.AGENT_SANITIZER_MAX_INPUT_BYTES;
  const parsed = Number(raw);
  if (
    raw === undefined ||
    raw === "" ||
    !Number.isFinite(parsed) ||
    parsed <= 0
  )
    return DEFAULT_MAX_INPUT_BYTES;
  return Math.floor(parsed);
}

/** The one-line reason reported for a caught throw. A thrown non-Error that
 * still carries a `message` keeps reporting it (the historical behaviour);
 * anything else stringifies.
 * @param {unknown} err */
const errorMessage = (err) =>
  /** @type {{ message?: string }} */ (err)?.message ?? String(err);

/** The one oversize-rejection message, for every path that enforces the cap.
 * Names the limit and the env var so a caller can act on it; `size` is included
 * when the rejecting path knows it (the streaming paths discard the input
 * unbuffered, so they only know the cap was crossed).
 * @param {number} limit @param {number} [size] */
const oversizeMessage = (limit, size) =>
  `request too large: ${size === undefined ? "input" : `${size} bytes`} ` +
  `exceeds the ${limit}-byte limit ` +
  "(raise AGENT_SANITIZER_MAX_INPUT_BYTES to accept it)";

/** Throw if `text` exceeds the configured byte cap.
 * @param {string} text */
function enforceSizeLimit(text) {
  const limit = maxInputBytes();
  const size = Buffer.byteLength(text, "utf8");
  if (size > limit) throw new Error(oversizeMessage(limit, size));
}

/** Read a required string field, throwing when it is absent or the wrong type.
 * Returns the value (rather than only asserting) so the caller carries the
 * narrowed `string` forward instead of re-reading an untyped bag.
 * @param {Record<string, unknown>} req @param {string} key
 * @returns {string} */
function requireString(req, key) {
  const value = req[key];
  if (typeof value !== "string")
    throw new Error(`request.${key} must be a string`);
  return value;
}

/** Operations the CLI exposes. Each takes the parsed request, returns the JSON
 * payload object. Non-`sanitize` modules are imported lazily so a caller that
 * only ever sanitizes never loads prompt/output/instructions code. */
export const OPS = {
  /** @param {Record<string, unknown>} req */
  async sanitize(req) {
    const text = requireString(req, "text");
    // Forwarded whole rather than re-listed field by field. A hand-picked
    // projection is a second copy of the return shape that nothing keeps in
    // sync: `splices` was part of `sanitize()`'s result and silently never
    // reached the wire, so every non-JS caller was blind to Layer 2's spliced
    // ranges. `test/cli-response-contract.test.mjs` pins this set against the
    // Python client's field list, so growing the result stays a two-file edit
    // that CI notices instead of a silent drop.
    return await sanitize(text, { html: Boolean(req.html) });
  },

  /** @param {Record<string, unknown>} req */
  async sanitizeText(req) {
    const text = requireString(req, "text");
    // Layers 1–3 only: redact (Layer 4) and filterInjection (Layer 5) are
    // injected JS callbacks with no wire form, so they're never set here.
    const { sanitizeText } = await import("../src/output.mjs");
    const { cleaned, warnings, notes, modified, sgrNote } = await sanitizeText(
      text,
      {
        html: Boolean(req.html),
        exfilScan: Boolean(req.exfilScan),
      },
    );
    return { cleaned, warnings, notes, modified, sgrNote };
  },

  /** @param {Record<string, unknown>} req */
  async classifyPrompt(req) {
    const text = requireString(req, "text");
    const { classifyPrompt } = await import("../src/prompt.mjs");
    return classifyPrompt(text);
  },

  // SECURITY (R8): `scanInstructionFiles` and `cleanFile` take filesystem
  // paths/globs straight from the request and read (and, for cleanFile, WRITE)
  // whatever they resolve to, with NO root confinement — `cwd`/`path`/`globs`
  // may escape any directory (absolute paths, `..`, symlinks). Unlike the
  // text-in/text-out ops, the request here names files on the host. The stdin
  // peer that sends these requests must therefore be FULLY TRUSTED: never wire
  // this CLI's stdin to untrusted/model-controlled input for these ops. If you
  // must accept untrusted callers, add opt-in root confinement (reject paths
  // that resolve outside an allow-listed root) before exposing them.
  /** @param {Record<string, unknown>} req */
  async scanInstructionFiles(req) {
    const globs = req.globs;
    if (
      !Array.isArray(globs) ||
      globs.some((/** @type {unknown} */ g) => typeof g !== "string")
    )
      throw new Error("request.globs must be an array of strings");
    // Fail loud on a present-but-non-string cwd rather than silently dropping it
    // and scanning process.cwd() — a wrong-scope scan is worse than a clear error
    // (matches the fail-loud contract every other typed field here follows).
    if ("cwd" in req && typeof req.cwd !== "string")
      throw new Error("request.cwd must be a string");
    const { scanInstructionFiles } = await import("../src/instructions.mjs");
    const opts = typeof req.cwd === "string" ? { cwd: req.cwd } : {};
    return { findings: scanInstructionFiles(globs, opts) };
  },

  /** @param {Record<string, unknown>} req */
  async cleanFile(req) {
    const path = requireString(req, "path");
    const { cleanFile } = await import("../src/instructions.mjs");
    return { changed: cleanFile(path) };
  },
};

/**
 * Run one request through the named `op` and serialize the response.
 * Throws on a malformed request or unknown op; the caller decides whether that
 * propagates (one-shot) or becomes an `{ error }` line (worker).
 * @param {string} payload  a single JSON request object
 * @returns {Promise<string>} a single-line JSON response
 */
async function handle(payload) {
  enforceSizeLimit(payload);
  const request = /** @type {Record<string, unknown>} */ (JSON.parse(payload));
  // Stringified so a non-string `op` (a number, an object) still reaches the
  // hasOwnProperty guard and the same "unknown op" error it always did.
  const op = String(request.op ?? "sanitize");
  const run = Object.prototype.hasOwnProperty.call(OPS, op)
    ? OPS[/** @type {keyof typeof OPS} */ (op)]
    : null;
  if (!run) throw new Error(`unknown op: ${op}`);
  return JSON.stringify(await run(request));
}

/** Read the whole stream as UTF-8, aborting as soon as the accumulated bytes
 * exceed the cap so a hostile one-shot caller can't force unbounded buffering.
 * @param {NodeJS.ReadableStream} stream */
async function readAll(stream) {
  stream.setEncoding("utf8");
  const limit = maxInputBytes();
  let text = "";
  let bytes = 0;
  for await (const chunk of stream) {
    bytes += Buffer.byteLength(chunk, "utf8");
    if (bytes > limit) throw new Error(oversizeMessage(limit));
    text += chunk;
  }
  return text;
}

/**
 * One unit of the worker's one-response-per-input-line framing.
 * @typedef {{ kind: "line", text: string } | { kind: "oversize" }} SplitEvent
 */

/**
 * Streaming newline-splitter that never buffers a line past the byte `limit`.
 *
 * Fed raw stdin chunks one at a time, it yields a sequence of events the worker
 * turns into exactly one response line each. The reason this exists instead of
 * `readline`: `readline` buffers an entire newline-less line into memory before
 * handing it over, so a hostile caller streaming a multi-gigabyte line with no
 * `\n` defeats the size cap (the cap only fires once the whole line is already
 * resident). Here the running byte length of the CURRENT unterminated line is
 * tracked as bytes arrive; the instant it exceeds `limit` the partial buffer is
 * dropped and the splitter enters a "resync" state that discards every byte up
 * to (and including) the next `\n`, so peak buffering for one line is bounded by
 * `limit` plus one chunk — never the whole line.
 *
 * Events: `{ kind: "line", text }` for a complete in-cap line (trailing `\r`
 * stripped, matching `readline`'s `crlfDelay: Infinity` CRLF handling), and
 * `{ kind: "oversize" }` for a line whose bytes crossed `limit` (emitted once,
 * at the newline that terminates the discarded line). The worker maps the
 * former through `handle` and the latter to a "request too large" error line, so
 * the one-response-per-input-line framing holds even for a dropped line.
 *
 * @param {number} limit  per-line byte cap (`maxInputBytes()`)
 * @returns {((chunk: Buffer) => SplitEvent[]) & { end: () => SplitEvent[] }}
 */
function createLineSplitter(limit) {
  // The bytes of the current line are held as a LIST of chunk slices plus their
  // running total, joined into one Buffer only when the line completes. Pushing
  // a slice is O(1), so assembling an N-byte line costs O(N) overall. The old
  // single growing `Buffer.concat([buffer, segment])` per segment re-copied the
  // whole accumulated prefix each time — O(N^2) for a line streamed as many
  // small chunks (e.g. a multi-MiB line arriving in 1-byte reads). `discarding`
  // still caps peak buffering at `limit`: once a line would breach it, the
  // pending slices are dropped and we scan only for the terminating `\n`.
  /** @type {Buffer[]} */
  let pending = [];
  let pendingLen = 0;
  let discarding = false;

  /** Drop any pending slices (line abandoned or fully consumed). */
  const reset = () => {
    pending = [];
    pendingLen = 0;
  };

  /** Join the pending slices into one line buffer (single copy) and reset. */
  const take = () => {
    const buf =
      pending.length === 1 ? pending[0] : Buffer.concat(pending, pendingLen);
    reset();
    return buf;
  };

  /** Strip one trailing `\r` so CRLF input frames identically to LF.
   * @param {Buffer} buf */
  const toLine = (buf) => {
    const stripCr = buf.length > 0 && buf[buf.length - 1] === 0x0d;
    return buf.toString("utf8", 0, stripCr ? buf.length - 1 : buf.length);
  };

  // Fold one segment (the bytes of the current line seen so far in this chunk)
  // into the pending list, flipping to `discarding` if it would breach the cap.
  // Applies identically to a newline-terminated segment and to the unterminated
  // tail, so an oversize line is caught WITHIN a chunk, not only at its edge.
  /** @param {Buffer} segment */
  const accumulate = (segment) => {
    if (discarding) return;
    if (pendingLen + segment.length > limit) {
      reset();
      discarding = true;
      return;
    }
    if (segment.length > 0) {
      pending.push(segment);
      pendingLen += segment.length;
    }
  };

  /** Feed one chunk, returning the events it completes (newline-terminated).
   * @param {Buffer} chunk
   * @returns {SplitEvent[]} */
  const push = (chunk) => {
    /** @type {SplitEvent[]} */
    const events = [];
    let start = 0;
    for (let i = 0; i < chunk.length; i++) {
      if (chunk[i] !== 0x0a) continue;
      accumulate(chunk.subarray(start, i));
      if (discarding) {
        events.push({ kind: "oversize" });
        discarding = false;
        reset();
      } else {
        events.push({ kind: "line", text: toLine(take()) });
      }
      start = i + 1;
    }
    accumulate(chunk.subarray(start));
    return events;
  };

  /**
   * Flush at EOF. A final line with no trailing `\n` is still a request, so it
   * gets a response — matching `readline`, which emits its last line on `close`.
   * An empty tail (stream ended on a `\n`, or was empty) yields nothing.
   * @returns {SplitEvent[]}
   */
  push.end = () => {
    if (discarding) {
      discarding = false;
      reset();
      return [{ kind: "oversize" }];
    }
    if (pendingLen === 0) return [];
    return [{ kind: "line", text: toLine(take()) }];
  };

  return push;
}

/** @param {number} limit */
const OVERSIZE_ERROR = (limit) =>
  JSON.stringify({ error: oversizeMessage(limit) });

async function runWorker() {
  // Stream raw bytes (no encoding) so the splitter tracks UTF-8 byte length, not
  // decoded characters, and a multi-gigabyte newline-less line is discarded as
  // it streams rather than buffered whole the way `readline` would.
  const limit = maxInputBytes();
  const split = createLineSplitter(limit);

  // EXACTLY one response line per input line. A complete in-cap line goes
  // through `handle`; its try/catch is the worker's reason to exist — a single
  // malformed request reports an error and serving continues rather than
  // tearing down a pipe other requests still use. An oversize line (its bytes
  // crossed the cap, so it was discarded unbuffered) gets the same structured
  // "request too large" error a one-shot caller sees. `response` never holds a
  // newline: `JSON.stringify` of the result or of a one-key error object is
  // single-line, so the one-line-per-request framing holds.
  /** @param {SplitEvent} event */
  const respond = async (event) => {
    if (event.kind === "oversize") {
      process.stdout.write(`${OVERSIZE_ERROR(limit)}\n`);
      return;
    }
    let response;
    try {
      response = await handle(event.text);
    } catch (err) {
      response = JSON.stringify({ error: errorMessage(err) });
    }
    process.stdout.write(`${response}\n`);
  };

  for await (const chunk of process.stdin) {
    for (const event of split(Buffer.from(chunk))) await respond(event);
  }
  for (const event of split.end()) await respond(event);
}

async function runOneShot() {
  // Fail loudly but cleanly: a bad request (or a contract-impossible `sanitize`
  // throw) exits non-zero with a one-line reason on stderr — not a raw Node
  // stack, which leaks internals and is noise for a scripted caller. The
  // message carries the sanitizer-CLI prefix so a wrapping client can attribute
  // the failure to this bridge.
  let response;
  try {
    response = await handle(await readAll(process.stdin));
  } catch (err) {
    process.stderr.write(`sanitize CLI: ${errorMessage(err)}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`${response}\n`);
}

// Run only when invoked as a script, not when imported (a unit test imports
// `createLineSplitter` directly and must not have the worker consume its stdin).
// Compare REAL paths: the published bin is launched through a
// `node_modules/.bin/sanitize-cli` symlink, so `process.argv[1]` is the symlink
// path while `import.meta.url` is this module's real file — a raw URL compare
// would be false and the CLI would silently produce no output. `realpathSync`
// resolves both to the same on-disk file. A non-existent `argv[1]` (e.g. an
// `--eval` entry) throws ENOENT and is treated as "not our script".
function invokedAsScript() {
  if (process.argv[1] === undefined) return false;
  try {
    return (
      realpathSync(process.argv[1]) ===
      realpathSync(fileURLToPath(import.meta.url))
    );
  } catch {
    return false;
  }
}
// Derived from OPS (the dispatch table is the SSOT) so adding or renaming an
// op can never leave the help text advertising a stale set.
const OPS_SENTENCE = Object.keys(OPS)
  .map((op) => (op === "sanitize" ? "sanitize (default)" : op))
  .join(", ");
export const USAGE = `sanitize-cli — sanitize untrusted text before an LLM sees it.

Reads JSON on stdin, writes one JSON response line on stdout.

Usage:
  sanitize-cli            one-shot: read ONE request object from stdin, write one response
  sanitize-cli --worker   worker: read newline-delimited requests until EOF, one response per line
  sanitize-cli --help     show this help

Request: { "op"?: string, ...fields }. Ops: ${OPS_SENTENCE}.
A failure response is { "error": string }.
`;

/**
 * Resolve argv to a run mode. `-h`/`--help` prints usage; an unrecognized `-…`
 * flag is a usage error rather than a silent fall-through to one-shot mode,
 * which would block reading stdin from a TTY with no output. The only real flag
 * is `--worker`; a bare invocation (or any non-flag arg) is one-shot.
 * @param {string[]} argv  process.argv (argv[0]=node, argv[1]=script)
 * @returns {{ mode: "help" | "worker" | "oneshot" | "error", unknown?: string[] }}
 */
export function parseArgs(argv) {
  const flags = argv.slice(2).filter((arg) => arg.startsWith("-"));
  if (flags.includes("-h") || flags.includes("--help")) return { mode: "help" };
  const unknown = flags.filter((flag) => flag !== "--worker");
  if (unknown.length > 0) return { mode: "error", unknown };
  return { mode: flags.includes("--worker") ? "worker" : "oneshot" };
}

if (invokedAsScript()) {
  const parsed = parseArgs(process.argv);
  if (parsed.mode === "help") process.stdout.write(USAGE);
  else if (parsed.mode === "error") {
    process.stderr.write(
      `sanitize CLI: unrecognized option(s): ${/** @type {string[]} */ (parsed.unknown).join(", ")}\n\n${USAGE}`,
    );
    process.exitCode = 2;
  } else if (parsed.mode === "worker") await runWorker();
  else await runOneShot();
}

export { createLineSplitter };
