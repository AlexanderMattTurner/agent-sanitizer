/**
 * Test bridge to the REAL redaction engine — the single source of truth.
 *
 * The secret redactor lives once, in Python (`agent_sanitizer.secrets`).
 * `rehydrate.mjs` consumes it through an injected `io.redactMap` callback, so a
 * JS test needs *some* implementation of that callback. Rather than hand-roll a
 * second redactor in JS (which silently drifts from the real one — e.g. emitting
 * UTF-16 offsets where the engine emits code-point offsets), this drives the
 * actual `redact_map` over a long-lived Python worker: one `uv run` process,
 * newline-delimited JSON in/out, so every fuzz iteration gets the engine's real
 * verdict at ~round-trip cost instead of a per-call interpreter spawn.
 *
 * Request  line: {"text": string, "env"?: {NAME: value}}  (env → provider_vars,
 *   redacting those exact values by name).
 * Response line: {"text", "pairs", "found"} or JSON `null` when nothing redacted.
 * `pairs[].start` is a CODE-POINT offset, exactly as the production engine emits.
 */
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..");
const pythonDir = join(repoRoot, "python");

// Persistent NDJSON worker: import the engine once, then serve one response line
// per request line. Mirrors the daemon's "pay plugin setup once" rationale.
//
// The engine is reached exactly as the pytest suite reaches it (see
// tests/secrets/conftest.py): run from the repo root's *virtual* project so
// `uv run --extra dev` resolves the engine's deps (detect-secrets is a hard
// import) from the root lock, and put `python/` on sys.path so the package
// imports from the working tree. Running under `python/` instead would pick the
// editable distribution project, forcing a hatchling build of the bundled CLI
// and minting a stray python/uv.lock — neither of which we want here.
const DRIVER = `
import sys, json
sys.path.insert(0, ${JSON.stringify(pythonDir)})
from agent_sanitizer.secrets.engine import redact_map
from agent_sanitizer.secrets.config import RedactorConfig
for line in sys.stdin:
    line = line.rstrip("\\n")
    if not line:
        continue
    req = json.loads(line)
    cfg = RedactorConfig(provider_vars=req.get("env") or {})
    sys.stdout.write(json.dumps(redact_map(req["text"], cfg)) + "\\n")
    sys.stdout.flush()
`;

let worker = null;
let buffer = "";
/** @type {{resolve: (v: unknown) => void, reject: (e: Error) => void}[]} */
const pending = [];

function fail(err) {
  while (pending.length) pending.shift().reject(err);
}

function ensureWorker() {
  if (worker) return;
  worker = spawn(
    "uv",
    ["run", "--extra", "dev", "--frozen", "python", "-c", DRIVER],
    { cwd: repoRoot },
  );
  worker.on("error", (err) =>
    fail(new Error(`real redactor worker failed to start: ${err.message}`)),
  );
  worker.on("exit", (code) => {
    if (pending.length)
      fail(new Error(`real redactor worker exited (code ${code}) mid-request`));
  });
  worker.stdout.setEncoding("utf8");
  worker.stdout.on("data", (chunk) => {
    buffer += chunk;
    let nl;
    while ((nl = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, nl);
      buffer = buffer.slice(nl + 1);
      const entry = pending.shift();
      if (entry) entry.resolve(JSON.parse(line));
    }
  });
  // uv/interpreter progress goes to stderr; surface it only on a crash via exit.
  worker.stderr.resume();
}

/**
 * Run the real engine's map mode over `text`.
 * @param {string} text
 * @param {Record<string, string>} [env] provider vars: NAME → exact value to redact
 * @returns {Promise<{text: string, pairs: {placeholder: string, original: string, start: number}[], found: string[]} | null>}
 */
export function realRedactMap(text, env) {
  ensureWorker();
  return new Promise((resolve, reject) => {
    pending.push({ resolve, reject });
    worker.stdin.write(`${JSON.stringify({ text, env: env || {} })}\n`);
  });
}

/** Plain-mode probe matching the io.redact contract: the redacted text, or null
 * when nothing was redacted (empty pairs). rehydrate uses `=== null` as its
 * cheap "any secrets present?" gate, so a clean probe MUST be null, not the
 * unchanged text. */
export async function realRedact(text, env) {
  const res = await realRedactMap(text, env);
  return res.pairs.length === 0 ? null : res.text;
}

/** Shut the worker down so the test process can exit promptly. */
export function stopRealRedactor() {
  if (!worker) return;
  worker.stdin.end();
  worker.kill();
  worker = null;
}
