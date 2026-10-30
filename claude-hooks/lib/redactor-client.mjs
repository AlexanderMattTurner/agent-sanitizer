/**
 * Client for the long-lived secret-redactor daemon (agent-secret-redactor-daemon,
 * the console script the `agent-sanitizer[secrets]` PyPI extra installs).
 *
 * The daemon pays the interpreter + detect-secrets startup cost ONCE, so each
 * request is just a scan. detect-secrets stays the one and only detection engine
 * — this module never inspects the text itself.
 *
 * Per call only: a connection/protocol/scan failure throws, and the caller
 * answers THAT output under its fault posture; it sets no session-wide state,
 * so the next call retries from scratch. If the socket is absent or dead we (re)spawn the daemon
 * once and retry — a crashed daemon self-heals on the next redaction.
 *
 * Wire protocol: python/agent_sanitizer/secrets/data/redactor-protocol.json,
 * which the daemon reads too — the framing, the frame cap, and the exact shape
 * of every request and response. A response that matches no shape the request
 * allows fails closed.
 */
import { spawn } from "node:child_process";
import {
  chargeRedactorRoundTrip,
  excludeProvisioning,
} from "./hook-timing.mjs";
import { existsSync, lstatSync } from "node:fs";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { envBoundSecretVars } from "./env-config.mjs";
import {
  FRAME_CAP,
  FrameReader,
  PROTOCOL,
  conforms,
  encodeFrame,
  isPlainObject,
} from "./redactor-wire.mjs";
import {
  currentUid,
  errMessage,
  isPrivateDir,
  ownedByCurrentUser,
  privateDirAt,
} from "./hook-io.mjs";
import { readKnob } from "./knobs.mjs";

export { FRAME_CAP };

// The only daemon error text worth quoting: one short printable-ASCII line.
const DAEMON_REASON = /^[\x20-\x7e]{1,200}$/u;

// Published here, where hosts already import it; the parser behind every
// millisecond knob lives with the knob table.
export { positiveMsOr } from "./knobs.mjs";

// sun_path is 104 bytes on macOS (108 on Linux), NUL included; a longer path
// makes the daemon's bind() fail and every call fault. The daemon binds
// "." + 16 hex digits before renaming onto "redactor.sock", so the longer
// 17-byte name is what must fit.
const SOCKET_PATH_MAX = 103;
const TEMP_BIND_NAME_LENGTH = 17;

/**
 * The redactor socket path: one per user, shared by every session of that user
 * (the daemon redacts each REQUESTER's env secrets). The daemon binds it 0600
 * under a 0700 dir AFTER priming, so its existence means "ready". In order:
 *
 * 1. `_AGENT_SANITIZER_REDACTOR_SOCKET` — explicit override.
 * 2. `$XDG_RUNTIME_DIR`, then `$CLAUDE_PLUGIN_DATA` — per-user directories no
 *    other uid can write, so a co-tenant cannot pre-create the socket dir under
 *    them. Taken only if privateDirAt passes and the path fits sun_path.
 * 3. `<tmpdir>/agent-sanitizer-redactor-<uid>` — on a shared /tmp a co-tenant
 *    can still pre-create it; the daemon then refuses to serve and the client
 *    refuses to connect (classifySocket), costing availability, never a secret.
 * @param {NodeJS.ProcessEnv} env
 * @param {number | null} uid  null where the platform has no uid model, which
 *   trusts no root (see {@link isPrivateDir})
 * @returns {string}
 */
export function resolveSocketPath(env, uid) {
  const override = readKnob("_AGENT_SANITIZER_REDACTOR_SOCKET", env);
  if (override) return override;
  for (const root of [env.XDG_RUNTIME_DIR, env.CLAUDE_PLUGIN_DATA]) {
    if (!root || !privateDirAt(root, { uid })) continue;
    const dir = join(root, "agent-sanitizer-redactor");
    if (Buffer.byteLength(dir) + 1 + TEMP_BIND_NAME_LENGTH <= SOCKET_PATH_MAX)
      return join(dir, "redactor.sock");
  }
  return join(
    tmpdir(),
    `agent-sanitizer-redactor-${uid ?? "nouid"}`,
    "redactor.sock",
  );
}

export const DEFAULT_SOCKET_PATH = resolveSocketPath(process.env, currentUid());

/**
 * The daemon command, as [argv0, ...leadingArgs]. Resolution order:
 *
 * 1. `_AGENT_SANITIZER_REDACTOR_DAEMON` — authoritative when set (the launcher
 *    sets it to the provisioned venv's console script when one exists, and
 *    tests point it at dead paths to drive the fault arm; a fallback
 *    from an explicit setting would turn those arms into silent passes).
 * 2. The shipped self-contained zipapp (`plugin/dist/redactor/daemon.pyz`) —
 *    the guaranteed floor: it needs only a python3 on PATH, so a cold start
 *    with no venv and no network still redacts instead of failing closed on
 *    every tool call. At `_AGENT_SANITIZER_REDACTOR_PYZ` when the launcher
 *    exports it (the compiled binary's module-relative path names no file on
 *    disk), else beside this bundle.
 * 3. The packaged console script from PATH — the un-bundled/dev case, where
 *    no sibling dist tree exists.
 * @returns {string[]}
 */
function daemonCommand() {
  const configured = readKnob("_AGENT_SANITIZER_REDACTOR_DAEMON");
  if (configured) return [configured];
  // Inside the built bundle import.meta.url is .../plugin/dist/hooks/<bundle>,
  // so the shipped zipapp sits one level up; from the raw sources no such
  // sibling exists and the check falls through.
  const pyz =
    readKnob("_AGENT_SANITIZER_REDACTOR_PYZ") ||
    fileURLToPath(new URL("../redactor/daemon.pyz", import.meta.url));
  if (existsSync(pyz)) return ["python3", pyz];
  return ["agent-secret-redactor-daemon"];
}
// How long to wait for a freshly-spawned daemon to start accepting. A cold start
// pays the detect-secrets import + plugin prime (~1-3s), so the default leaves
// margin; tests shorten it to exercise the give-up path quickly.
const WAIT_DEADLINE_MS = readKnob("_AGENT_SANITIZER_REDACTOR_WAIT_MS");

// A daemon that ACCEPTS the connection but then stalls — a deadlock, a
// pathological detect-secrets input, or a half-written length prefix that never
// completes — emits none of the errno codes isRespawnable reacts to and never
// closes, so without a deadline connectAndRequest's Promise never settles.
// redactViaDaemon would then hang until Claude Code kills the PostToolUse hook at
// its own timeout, and a killed hook is non-blocking — so the RAW tool output is
// shown with no warning at all. The total per-connect deadline below makes a
// stall reject, so the caller's fault posture answers it, warning included. It
// stays comfortably under the hook
// timeout (two connects + the spawn wait must fit); tests shorten it via the env
// override (read per call) or the deadlineMs parameter to exercise the path fast.
function requestDeadlineMs() {
  return readKnob("_AGENT_SANITIZER_REDACTOR_REQUEST_MS");
}

/**
 * This process's values for the configured env-bound secret vars (present ones
 * only). Their VALUES are redacted by exact match — the robust way to catch
 * opaque, shapeless keys. We send the REQUESTER's current values per request
 * rather than relying on the daemon's own environment, since a long-lived daemon
 * may serve a different session than the one that started it.
 * @returns {Record<string, string>}
 */
function collectEnvSecrets() {
  /** @type {Record<string, string>} */
  // Null-prototype accumulator so a computed out[name] write is always an own
  // property, never a prototype-chain write, regardless of the configured names.
  const out = Object.create(null);
  for (const name of envBoundSecretVars()) {
    const value = process.env[name];
    if (value) out[name] = value;
  }
  return out;
}

/** @param {number} ms */
const sleep = (ms) =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

/**
 * A connect failure we should react to by (re)spawning the daemon and retrying:
 * the socket file is missing (no daemon) or present but no one is listening (the
 * daemon crashed and left a stale socket). A protocol/scan error is NOT this — it
 * fails closed without a respawn (the daemon is alive; detection genuinely failed).
 * @param {unknown} err
 * @returns {boolean}
 */
function isRespawnable(err) {
  const errno = /** @type {{code?: string}} */ (err);
  return (
    Boolean(errno) &&
    // ENOENT/ECONNREFUSED: no socket / nobody listening. ECONNRESET/EPIPE: the
    // daemon died mid-handshake leaving a half-open socket — also a crashed
    // daemon a respawn can heal, not a genuine scan failure.
    (errno.code === "ENOENT" ||
      errno.code === "ECONNREFUSED" ||
      errno.code === "ECONNRESET" ||
      errno.code === "EPIPE")
  );
}

/**
 * The error thrown when a single redaction cannot be completed. What the caller
 * then does is its posture, not this module's — the message therefore states
 * the FACT (the output was never vetted) and no consequence, since a hook
 * running fail-open splices it into a warning that says the opposite.
 * @param {unknown} cause
 * @returns {Error}
 */
function failClosed(cause) {
  return new Error(
    `secret redaction unavailable (${errMessage(cause)}); secret-shaped output could not be vetted`,
  );
}

/**
 * The shape the redactor returns: plain mode `{text, found}`, map mode
 * `{text, pairs, found}` or `{unmappable}`. All fields optional so a consumer
 * narrows the variant it expects.
 * @typedef {object} RedactResponse
 * @property {string} [text]
 * @property {string[]} [found]
 * @property {{placeholder: string, original: string, start: number}[]} [pairs]
 * @property {string} [unmappable]
 */

/**
 * Classify the socket path before we connect and hand it live credentials.
 * The request body carries collectEnvSecrets() — plaintext key VALUES — and the
 * socket lives at a predictable, world-visible $TMPDIR path any co-tenant can
 * reach. This is the one channel in the hook suite that ships secrets, so it
 * needs the same squat defense markerIsTrusted / writeFileNoFollow apply to the
 * marker/sentinel files. lstatSync does NOT traverse a final symlink, so a
 * planted symlink reads as a symlink (isSocket() false) and a foreign daemon
 * fails the uid check.
 *   - "absent"    → nothing there yet: let createConnection ENOENT so the caller's
 *                   respawn path spawns OUR daemon (never a refuse — that would
 *                   break the cold-start spawn).
 *   - "untrusted" → something IS bound there but it is not our socket under a dir
 *                   only a trusted uid can write (a co-tenant squat): refuse, so
 *                   no secret is written.
 *   - "ok"        → our socket, our uid, under a dir isTrustedSocketDir accepts.
 * `lstat`/`uid` are injectable seams so a test can drive a stat shape the test
 * process cannot create (a dir owned by another uid); production binds the real ones.
 * @param {string} socketPath
 * @param {{lstat?: typeof lstatSync, uid?: number | null}} [deps]
 * @returns {"absent" | "untrusted" | "ok"}
 */
export function classifySocket(socketPath, deps = {}) {
  const { lstat = lstatSync, uid = currentUid() } = deps;
  let st;
  try {
    st = lstat(socketPath);
  } catch {
    return "absent";
  }
  if (!st.isSocket() || !ownedByCurrentUser(st, uid)) return "untrusted";
  let dir;
  try {
    dir = lstat(dirname(socketPath));
    /* c8 ignore start -- TOCTOU-only: the socket lstat at the top of this function
       already succeeded, so its parent dir existed then; this catch fires only if a
       concurrent process rmdir'd the parent between the two lstats — a real race the
       guard fails closed on, but not deterministically reproducible in a test. */
  } catch {
    return "untrusted";
  }
  /* c8 ignore stop */
  if (!isTrustedSocketDir(dir, uid)) return "untrusted";
  return "ok";
}

/**
 * Whether the socket's parent directory keeps every UNTRUSTED uid from replacing
 * the socket inode. Unlinking or rebinding a socket needs WRITE on its parent, so
 * write — not readability — is the property this enforces: a real directory, owned
 * by us or by root, carrying no group/other write bit.
 *
 * This refusal is what blocks a co-tenant unlinking our socket and binding their
 * own listener that answers "nothing to redact" to every payload, which would turn
 * a loud fault into a silent "nothing to redact" and leak unscrubbed secrets to
 * the transcript.
 *
 * Root ownership is trusted because it is strictly stronger than our own, not a
 * concession: a deployment may hand the socket dir to root after the daemon has
 * bound, so the de-privileged agent can traverse and connect but cannot unlink or
 * shadow the socket. Root-owned is not REQUIRED because the ordinary path has no
 * root to hand it to: there the hook spawns the daemon as the ordinary user, which
 * binds under a 0700 dir it owns, and our own uid is not the adversary.
 * @param {import("node:fs").Stats} dir
 * @param {number | null} uid
 * @returns {boolean}
 */
function isTrustedSocketDir(dir, uid) {
  return isPrivateDir(dir, { uid, rootMayOwn: true });
}

/**
 * Open one connection, send `request`, resolve with the parsed response object
 * (or null). Rejects on connect failure, a malformed/oversize/short frame, or an
 * {error} response — every one of which the caller treats as a fault. A
 * socket present but not owned by us, and a request the protocol does not
 * accept, throw WITHOUT dialing (the error carries no errno, so
 * isRespawnable is false): we never dial into a squat, and an oversize request
 * is not mistaken for a dead daemon worth respawning.
 * @param {string} socketPath
 * @param {Record<string, unknown>} request
 * @param {number} [deadlineMs] total exchange deadline; defaults to the env-tunable value
 * @returns {Promise<RedactResponse|null>}
 */
export function connectAndRequest(
  socketPath,
  request,
  deadlineMs = requestDeadlineMs(),
) {
  return new Promise((resolve, reject) => {
    if (classifySocket(socketPath) === "untrusted") {
      reject(
        new Error(
          "redactor socket failed the ownership check (possible co-tenant squat) — refusing to send secrets",
        ),
      );
      return;
    }
    if (!conforms(request, PROTOCOL.request)) {
      reject(new Error("redactor request does not match the wire protocol"));
      return;
    }
    // Encoded before dialing: an over-cap request throws here, rejecting with
    // no errno, so it is not mistaken for a dead daemon worth respawning.
    const frame = encodeFrame(request);
    const sock = createConnection(socketPath);
    const reader = new FrameReader();
    // Total deadline for the whole connect→request→response exchange, cleared by
    // finish() on the first terminal event. A stalled daemon (post-connect
    // silence) trips it and fails the call closed instead of hanging the hook.
    /** @type {ReturnType<typeof setTimeout>|null} */
    let timer = null;
    // destroy() stops further events and a settled Promise ignores a second
    // resolve/reject, so the first terminal event wins with no explicit guard.
    /** @type {(fn: (value?: any) => void, arg?: unknown) => void} */
    const finish = (fn, arg) => {
      if (timer) clearTimeout(timer);
      sock.destroy();
      fn(arg);
    };
    timer = setTimeout(
      () => finish(reject, new Error("redactor response timeout")),
      deadlineMs,
    );
    sock.on("error", (err) => finish(reject, err));
    sock.on("connect", () => sock.write(frame));
    sock.on("data", (chunk) => {
      let frameRead;
      try {
        // No setEncoding, so 'data' is always a Buffer at runtime.
        frameRead = reader.push(/** @type {Buffer} */ (chunk));
      } catch (err) {
        // Recovery: an over-cap or non-JSON frame fails THIS call closed.
        finish(reject, err);
        return;
      }
      if (frameRead === undefined) return;
      const parsed = frameRead.value;
      if (isPlainObject(parsed) && "error" in parsed) {
        // The wire types `error` only as a string, so whatever answers on the
        // socket chooses it, and this message reaches the operator and the
        // model. Quote it only as plain printable ASCII on one line; anything
        // else is dropped, not escaped: this module must not import the engine.
        const reason =
          conforms(parsed, PROTOCOL.responses.error) &&
          typeof parsed.error === "string" &&
          DAEMON_REASON.test(parsed.error)
            ? `: ${parsed.error}`
            : "";
        finish(
          reject,
          new Error(
            `daemon reported redaction failure${reason}; its log is ${join(dirname(socketPath), "daemon.log")}`,
          ),
        );
        return;
      }
      finish(resolve, parsed);
    });
    sock.on("end", () =>
      finish(reject, new Error("connection closed before a full response")),
    );
  });
}

// How much of a failed daemon's stderr is kept for the error message: the tail,
// which is where a Python traceback names its exception.
const STDERR_TAIL_CHARS = 2000;

/**
 * A spawned daemon, as far as the spawning hook can see it.
 * @typedef {object} DaemonHandle
 * @property {() => string | undefined} failure why the daemon died before it was
 *   ready (its exit status and stderr tail), or undefined while it may still bind
 * @property {() => void} release stop reading its stderr
 */

/**
 * Spawn the daemon detached so it outlives this hook process. The daemon's bind()
 * is the cross-process mutex, so a racing second spawn just exits 0 — the spawn
 * is idempotent and needs no lock here.
 *
 * Its stderr is piped back so a daemon that dies on startup (an import error, a
 * refused cache directory) fails the call at once with its own reason rather than
 * after the whole spawn wait with none. The daemon points its stderr at a log
 * file before it publishes the socket, so the pipe is only read until then.
 * @param {string} socketPath
 * @param {string[]} [command] daemon command as [argv0, ...leadingArgs]
 * (injectable so tests can drive the missing-binary arm in-process;
 * production always uses daemonCommand())
 * @returns {DaemonHandle}
 */
export function spawnDaemon(socketPath, command = daemonCommand()) {
  const [bin, ...leading] = command;
  const child = spawn(bin, [...leading, socketPath], {
    detached: true,
    stdio: ["ignore", "ignore", "pipe"],
  });
  const stderr = /** @type {import("node:net").Socket} */ (child.stderr);
  let output = "";
  /** @type {string | undefined} */
  let failure;
  stderr.setEncoding("utf8");
  stderr.on("data", (/** @type {string} */ chunk) => {
    output = (output + chunk).slice(-STDERR_TAIL_CHARS);
  });
  // A missing daemon binary surfaces as an async 'error' event; UNHANDLED it
  // kills this hook process, which the harness reads as "no objection" — the
  // tool output would pass through UNSANITIZED (fail open). Recorded instead,
  // it ends the spawn wait and fails the call CLOSED.
  child.on("error", (err) => {
    failure = err.message;
  });
  // 'close', not 'exit': it fires after stderr has drained, so the tail is whole.
  // Exit 0 is the daemon that lost the bind race to a live one.
  child.on("close", (code, signal) => {
    if (code === 0) return;
    const status = signal ? `killed by ${signal}` : `exit ${code}`;
    const tail = output.trim();
    failure ??= tail ? `${status}: ${tail}` : status;
  });
  child.unref();
  stderr.unref();
  return { failure: () => failure, release: () => stderr.destroy() };
}

/**
 * Poll until the daemon is accepting connections, the deadline passes, or
 * `abandon` reports the spawned daemon dead. Probes by connecting (not just
 * existsSync) so it waits for listen(), not merely bind().
 * @param {string} socketPath
 * @param {{deadlineMs?: number, stepMs?: number, abandon?: () => boolean}} [opts]
 * @returns {Promise<boolean>}
 */
export async function waitForSocket(
  socketPath,
  { deadlineMs = WAIT_DEADLINE_MS, stepMs = 100, abandon = () => false } = {},
) {
  const deadline = Date.now() + deadlineMs;
  while (Date.now() < deadline && !abandon()) {
    if (existsSync(socketPath) && (await canConnect(socketPath))) return true;
    await sleep(stepMs);
  }
  return false;
}

/**
 * @param {string} socketPath
 * @returns {Promise<boolean>}
 */
function canConnect(socketPath) {
  return new Promise((resolve) => {
    const sock = createConnection(socketPath);
    sock.on("connect", () => {
      sock.destroy();
      resolve(true);
    });
    sock.on("error", () => {
      sock.destroy();
      resolve(false);
    });
  });
}

/**
 * Redact `text` via the daemon. Returns the response object (`{text, found}` for
 * plain, `{text, pairs, found}` / `{unmappable}` for map) or null when nothing was
 * redacted (plain mode). Throws when the text cannot be vetted.
 *
 * `connect`/`spawn`/`waitForSocket` are injectable seams (default to the real
 * implementations) so callers can stub the daemon in-process. `deadline` is the
 * caller's shared wall-clock budget (makeDeadline): when supplied, every dial and
 * the respawn wait are bounded by the budget REMAINING at that moment, and a spent
 * budget fails CLOSED without dialing — never dial with a non-positive deadline,
 * which would race and could return the raw, unvetted secret (fail open). Omitted,
 * the redactor keeps its own per-call request deadline (the standalone default).
 *
 * `webIngress` is required: it chooses between the name-trusting heuristics for
 * local output and the stricter ones for attacker-controlled text, and a
 * default would make that choice silently for any caller that forgot it.
 * @param {string} text
 * @param {{map?: boolean, webIngress: boolean, socketPath?: string,
 *   deadline?: {remainingMs: () => number},
 *   connect?: typeof connectAndRequest,
 *   spawn?: (socketPath: string) => DaemonHandle | void,
 *   waitForSocket?: typeof waitForSocket, now?: () => number}} opts
 * @returns {Promise<RedactResponse|null>}
 */
export async function redactViaDaemon(text, opts) {
  if (typeof opts?.webIngress !== "boolean")
    throw new TypeError(
      "redactViaDaemon: opts.webIngress must be true (attacker-controlled text) or false (local output)",
    );
  const {
    map = false,
    webIngress,
    socketPath = DEFAULT_SOCKET_PATH,
    deadline,
    connect = connectAndRequest,
    spawn: spawnFn = spawnDaemon,
    waitForSocket: waitFn = waitForSocket,
    // The clock the provisioning and round-trip charges are measured on;
    // injectable alongside the seams they bracket, since a stubbed wait or
    // connect advances a test clock rather than real time.
    now = Date.now,
  } = opts;
  // Remaining shared budget in ms, or undefined when no budget was threaded (the
  // standalone default). Re-read per step so the respawn path cannot overshoot.
  const remainingMs = () => (deadline ? deadline.remainingMs() : undefined);
  const budgetSpent = () => {
    const ms = remainingMs();
    return ms !== undefined && ms <= 0;
  };
  const outOfBudget = (/** @type {string} */ where) =>
    failClosed(new Error(`sanitization time budget exhausted ${where}`));
  if (budgetSpent()) throw outOfBudget("before secret vetting");
  const request = {
    text,
    map,
    web_ingress: webIngress,
    env_secrets: collectEnvSecrets(),
  };
  // Response-contract guard — every shape the protocol does not allow for this
  // mode fails CLOSED, because a caller reading a field the daemon didn't set
  // gets `undefined` and would proceed on unvetted content (fail OPEN). Plain
  // mode: `{text, found}`, or null for nothing to redact. Map mode: a
  // `{text, pairs, found}` map or the `{unmappable}` marker — never null, since
  // the daemon always answers a map request with one of the two. Validated AFTER
  // the respawn/retry logic so a malformed response is not mistaken for a dead
  // socket worth respawning. Each throw carries the BARE cause: every call sits
  // inside a catch that wraps what it caught.
  const { responses } = PROTOCOL;
  /** @param {unknown} result @returns {RedactResponse|null} */
  const validate = (result) => {
    if (map) {
      if (
        !conforms(result, responses.map) &&
        !conforms(result, responses.unmappable)
      )
        throw new Error(
          "redactor returned a malformed map response (neither `{text, pairs, found}` nor `{unmappable}`)",
        );
      return /** @type {RedactResponse} */ (result);
    }
    if (result !== null && !conforms(result, responses.plain))
      throw new Error(
        "redactor returned a malformed plain response (neither null nor `{text, found}`)",
      );
    return /** @type {RedactResponse|null} */ (result);
  };
  // Every dial is charged to the redactor share, so the slow-hook notice can
  // place the wait in this call rather than guess at it: the daemon is a
  // separate process, so its cost appears in neither this process's
  // getrusage(RUSAGE_SELF) nor — being long-lived and never reaped here — in
  // RUSAGE_CHILDREN. The round trip is the only measurable stand-in.
  /** @param {number | undefined} deadlineMs @returns {Promise<RedactResponse|null>} */
  const dial = (deadlineMs) =>
    chargeRedactorRoundTrip(
      () => connect(socketPath, request, deadlineMs),
      now,
    );
  try {
    // undefined remaining → connectAndRequest's own default request deadline.
    return validate(await dial(remainingMs()));
  } catch (err) {
    if (!isRespawnable(err)) throw failClosed(err);
    // Socket absent or dead: (re)spawn the daemon, wait for it, retry exactly once
    // — but only if the shared budget still has room for a cold start + a scan.
    if (budgetSpent()) throw outOfBudget("before redactor respawn");
    const daemon = spawnFn(socketPath) ?? undefined;
    // Clamp the cold-start wait to what the budget still allows, so a respawn can
    // never blow it. waitForSocket returns false when the daemon never bound
    // within the deadline; surface that as the actual cause rather than the opaque
    // ENOENT/connect error the retry would otherwise throw.
    const budgetMs = remainingMs();
    const waitMs =
      budgetMs === undefined
        ? WAIT_DEADLINE_MS
        : Math.min(WAIT_DEADLINE_MS, budgetMs);
    const waitOpts = {
      deadlineMs: waitMs,
      abandon: () => daemon?.failure() !== undefined,
    };
    // The cold-start wait is PROVISIONING — a one-time detect-secrets import and
    // plugin prime (~1-3s, see WAIT_DEADLINE_MS), paid by whichever tool call
    // happens to be first and by no other. Charging it to this hook would make
    // the slow-hook notice fire once per session on a healthy install.
    const ready = await excludeProvisioning(
      () => waitFn(socketPath, waitOpts),
      now,
    );
    daemon?.release();
    const died = daemon?.failure();
    if (!ready)
      throw failClosed(
        new Error(
          died === undefined
            ? // The CLAMPED wait, since that is what actually elapsed: naming
              // WAIT_DEADLINE_MS tells an operator debugging a 200ms budget
              // that the redactor got seconds it was never given.
              `redactor daemon did not start within ${waitMs}ms`
            : `redactor daemon failed to start (${died})`,
        ),
      );
    if (budgetSpent()) throw outOfBudget("after redactor respawn");
    try {
      return validate(await dial(remainingMs()));
    } catch (err2) {
      throw failClosed(err2);
    }
  }
}
