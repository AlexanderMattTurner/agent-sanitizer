/**
 * Test bridge to the PYTHON credential-name matcher.
 *
 * `credential_name_matcher` (Python) and `credentialNameMatcher` (JS) are two
 * implementations of one rule over one vocabulary file. A consumer binds both on
 * the same tool call — agent-glovebox binds the Python one to its redactor daemon
 * and the JS one to the tool-output gate in front of it — so a name the two
 * answer differently is a value one path redacts and the other forwards. That
 * disagreement is the whole reason the rule was extracted into this package, and
 * nothing pins it from inside a single language: each suite tests its own copy
 * against cases a human transcribed into both, which is exactly how the copies
 * drifted before.
 *
 * So this drives the REAL Python matcher rather than restating its answers, the
 * same way `real-redactor.mjs` drives the real redaction engine: one long-lived
 * `uv run` worker, newline-delimited JSON in and out, so a 10,000-name corpus
 * costs one process spawn instead of ten thousand.
 *
 * Request  line: {"op": "match"|"parse"|"folding", ...}
 * Response line: {"ok": <result>} or {"error": "<message>"}
 *
 * Every response is plain ASCII JSON: the corpus carries lone surrogates and a
 * `match` reply that echoed a name back would be unencodable on the Python side.
 * Replies therefore carry booleans and code point NUMBERS, never the names or
 * characters they are about.
 */
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..");
const pythonDir = join(repoRoot, "python");

// Reached exactly as the pytest suite reaches it (tests/secrets/conftest.py): run
// from the repo root's virtual project so `uv run --extra dev` resolves the
// package's deps from the root lock, with `python/` on sys.path so the import
// comes from the working tree rather than an installed copy.
//
// `agent_sanitizer.secrets` is the package's PUBLIC surface, which is what a
// consumer imports; importing the private module instead would leave a broken
// re-export invisible here.
const DRIVER = `
import sys, json, re
sys.path.insert(0, ${JSON.stringify(pythonDir)})
from agent_sanitizer.secrets import credential_name_matcher, parse_credential_names

NOUN_ALPHABET = re.compile(r"[A-Z0-9_]+")

def folding():
    """Every code point whose upper-casing lands inside the noun alphabet.

    The matcher's ONLY text transform is str.upper(); the vocabulary is pure
    [A-Z0-9_]. So the two languages agree on every name exactly when they agree
    on this set and its images.
    """
    return [
        [cp, chr(cp).upper()]
        for cp in range(0x110000)
        if not 0xD800 <= cp <= 0xDFFF
        and NOUN_ALPHABET.fullmatch(chr(cp).upper())
    ]

def handle(req):
    op = req["op"]
    if op == "folding":
        return folding()
    if op == "parse":
        parse_credential_names(req["spec"])
        return True
    holds = credential_name_matcher(
        scope=req["scope"],
        decline_non_secret=req["declineNonSecret"],
        **({"spec": req["spec"]} if req.get("spec") is not None else {}),
    )
    return [holds(name) for name in req["names"]]

for line in sys.stdin:
    line = line.rstrip("\\n")
    if not line:
        continue
    try:
        reply = {"ok": handle(json.loads(line))}
    except Exception as exc:
        reply = {"error": f"{type(exc).__name__}: {exc}"}
    sys.stdout.write(json.dumps(reply) + "\\n")
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
    fail(
      new Error(`python credential matcher failed to start: ${err.message}`),
    ),
  );
  // Startup failures (a syntax error in DRIVER, a missing dependency) surface
  // only here: the worker dies before answering, and without this the test would
  // hang on a promise nobody settles rather than name what went wrong.
  let stderr = "";
  worker.stderr.setEncoding("utf8");
  worker.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  worker.on("exit", (code) => {
    if (pending.length)
      fail(
        new Error(
          `python credential matcher exited (code ${code}) mid-request: ${stderr.slice(-2000)}`,
        ),
      );
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
}

/** @param {Record<string, unknown>} request @returns {Promise<{ok?: unknown, error?: string}>} */
function ask(request) {
  ensureWorker();
  return new Promise((resolve, reject) => {
    pending.push({ resolve, reject });
    worker.stdin.write(`${JSON.stringify(request)}\n`);
  });
}

/** The Python matcher's verdict for each of `names`, under one policy.
 *
 * @param {{scope: "trailing" | "any-segment", declineNonSecret: boolean, spec?: Record<string, unknown>}} policy
 * @param {string[]} names
 * @returns {Promise<boolean[]>} */
export async function pythonHoldsCredential(policy, names) {
  const reply = await ask({
    op: "match",
    scope: policy.scope,
    declineNonSecret: policy.declineNonSecret,
    spec: policy.spec ?? null,
    names,
  });
  if (reply.error)
    throw new Error(`python matcher refused the corpus: ${reply.error}`);
  return reply.ok;
}

/** The Python validator's refusal message for `spec`, or null when it accepts.
 * @param {unknown} spec @returns {Promise<string | null>} */
export async function pythonParseRejection(spec) {
  const reply = await ask({ op: "parse", spec });
  return reply.error ?? null;
}

/** Every code point whose `str.upper()` lands in `[A-Z0-9_]`, as `[cp, image]`.
 * @returns {Promise<[number, string][]>} */
export async function pythonNounAlphabetFolding() {
  const reply = await ask({ op: "folding" });
  if (reply.error)
    throw new Error(`python folding sweep failed: ${reply.error}`);
  return reply.ok;
}

/** Shut the worker down so the test process can exit promptly. */
export function stopPythonCredentialMatcher() {
  if (!worker) return;
  worker.stdin.end();
  worker.kill();
  worker = null;
}
