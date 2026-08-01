/** Shared I/O helpers for the Claude Code hook scripts. */

import {
  openSync,
  closeSync,
  lstatSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { userInfo } from "node:os";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

/**
 * EVERY process-wide slot these helpers keep — the four a host can observe or
 * steer, so a second instance that adopts this object is steered in all four at
 * once. A slot left off this object is one a host must configure per instance,
 * and forgetting the second call fails silently; that is the whole failure class
 * {@link adoptHookIoSharedState} exists to remove, so the object is complete
 * rather than covering only the registry.
 *
 * - `lazyModules` — the namespaces {@link lazyImport} answers from. Empty when
 *   the hooks run from source; a build-time BUNDLE (which ships with no
 *   node_modules for the runtime `import()` to resolve) statically imports its
 *   packages and registers them here before importing the hooks that lazy-load
 *   them, so the same hook source runs unchanged in both worlds.
 * - `cliEntryClaimed` — the CLI-entry latch {@link isMain} reads.
 * - `missingPackageRemedy` — the host remedy {@link configureMissingPackageRemedy}
 *   sets; null keeps {@link DEFAULT_MISSING_PACKAGE_REMEDY}.
 * - `hookgateMarker` — the marker path {@link configureHookgateMarker} sets, and
 *   `hookgateMarkerResolved`, the latch that makes a too-late call say so.
 * @typedef {{
 *   lazyModules: Record<string, Record<string, any>>,
 *   cliEntryClaimed: boolean,
 *   missingPackageRemedy: string | null,
 *   hookgateMarker: string | null,
 *   hookgateMarkerResolved: boolean,
 * }} HookIoSharedState
 */

/**
 * A fresh state object with every slot at its default. Called per use, never
 * hoisted to one shared literal, so each caller gets its own `lazyModules`.
 * @returns {HookIoSharedState}
 */
const defaultSharedState = () => ({
  lazyModules: Object.create(null),
  cliEntryClaimed: false,
  missingPackageRemedy: null,
  hookgateMarker: null,
  hookgateMarkerResolved: false,
});

/** @type {HookIoSharedState} */
let shared = defaultSharedState();

/**
 * This instance's state object, for a host to hand to another instance.
 * @returns {HookIoSharedState}
 */
export function hookIoSharedState() {
  return shared;
}

/**
 * Route every slot of {@link HookIoSharedState} on this instance through `state`.
 *
 * A host that ships its OWN hook-io module beside the packaged hooks ends up
 * with two instances of this file's state in one process, each with its own
 * registry and its own latches. Without this seam the host configures each slot
 * twice, and a slot it sets on only one instance is invisible to the readers on
 * the other. For the registry that means those readers resolve a specifier at
 * RUNTIME, inside a bundle with no node_modules, and the gate fails closed on
 * every call. Adopting one state object removes that failure mode rather than
 * policing it.
 *
 * WHY AN API AND NOT A BUNDLER ALIAS: collapsing the two module records at build
 * time (an esbuild `alias` from the host's module to this one) is the cheaper
 * fix and needs no API — but it works only when the host's module is a COPY of
 * this one. The motivating host's is not: it exports names this module does not
 * have and lacks names this one exports, so an alias breaks every call site of
 * the difference. `test/claude-hooks-exports.test.mjs` still states the rule for
 * a true copy — share this module, never duplicate it. This seam serves the
 * other case, a host with its own module that must agree with ours on state.
 *
 * Call it before importing any module that reads a slot, for the same reason
 * {@link registerLazyModules} carries that rule: a reader binds at its own
 * module scope.
 *
 * Slots already set on EITHER side survive: this instance's registrations and
 * latches carry over, and a value already present in `state` wins, since it is
 * the adopted root's own choice. Adopting the state this instance already holds
 * is a no-op.
 *
 * CONSTRAINT: every instance must adopt the same root object, and none may adopt
 * a second, different one. `shared` is reassigned, so a later `B.adopt(C)` would
 * leave an earlier `A.adopt(B)` pointing at an abandoned object whose readers
 * nothing reaches. This is not enforced with a throw: callers are bundle entry
 * points, and a throw at their top level kills the hook before it writes a
 * response — a hook that emits nothing reads as non-blocking, which is the
 * fail-OPEN this whole module is built to avoid.
 * @param {HookIoSharedState} state
 * @returns {void}
 */
export function adoptHookIoSharedState(state) {
  if (state === shared) return;
  // Fill any slot `state` omits before anything reads it. A host builds this
  // object itself, so one written against an earlier version of this package
  // lacks the slots added since — and every reader below tests `!== null`, which
  // an ABSENT slot satisfies. Unfilled, hookgateMarkerPath returns undefined
  // instead of deriving a path; probeSetupAlive then throws internally on it and
  // reports setup alive forever, so awaitLazyDependency waits out its whole
  // ceiling, the harness kills the hook, and a killed hook is non-blocking — the
  // fail-OPEN this module exists to prevent. `??=` and not `=`: it must not
  // clobber a slot the host deliberately set, including `false`.
  const slots = /** @type {Record<string, any>} */ (state);
  for (const [slot, value] of Object.entries(defaultSharedState()))
    slots[slot] ??= value;
  for (const [specifier, namespace] of Object.entries(shared.lazyModules))
    if (state.lazyModules[specifier] === undefined)
      state.lazyModules[specifier] = namespace;
  if (shared.cliEntryClaimed) state.cliEntryClaimed = true;
  if (
    shared.missingPackageRemedy !== null &&
    state.missingPackageRemedy === null
  )
    state.missingPackageRemedy = shared.missingPackageRemedy;
  if (shared.hookgateMarker !== null && state.hookgateMarker === null)
    state.hookgateMarker = shared.hookgateMarker;
  if (shared.hookgateMarkerResolved) state.hookgateMarkerResolved = true;
  shared = state;
}

/**
 * True when this module is the process entry point (run directly as a CLI, not
 * imported). Guards an undefined `process.argv[1]` (e.g. the REPL) before
 * resolving it: the bare `import.meta.url === pathToFileURL(process.argv[1])`
 * form throws there. Resolving argv[1] through pathToFileURL also normalizes a
 * relative invocation path to an absolute file URL before comparing.
 * @param {string} importMetaUrl  the caller's `import.meta.url`
 * @returns {boolean}
 */
export function isMain(importMetaUrl) {
  // Inside an esbuild bundle every inlined module shares the entry file's
  // import.meta.url, so a bundled hook's own isMain-guarded CLI would fire
  // alongside the real entry's and consume its stdin. An entry that claimed the
  // CLI slot (claimCliEntry) therefore makes every later isMain call answer
  // false — module bodies run in dependency order, so the claim lands first.
  if (shared.cliEntryClaimed) return false;
  return (
    Boolean(process.argv[1]) &&
    importMetaUrl === pathToFileURL(process.argv[1]).href
  );
}

/**
 * Claim the process's CLI-entry slot for the calling module: every subsequent
 * {@link isMain} call answers false. For bundle entry points that inline other
 * isMain-guarded hooks (see isMain's bundle note); a claim cannot be released.
 * @returns {void}
 */
export function claimCliEntry() {
  shared.cliEntryClaimed = true;
}

/**
 * Find a `--name=value` flag in argv (by prefix scan, not position) and return
 * its value, or undefined if absent. A named flag stays correct when unrelated
 * arguments are prepended or interspersed — a bare positional index (argv[2])
 * silently reads the wrong value the moment the command line grows.
 * @param {string[]} argv
 * @param {string} name flag name without the leading `--` or trailing `=`
 * @returns {string|undefined}
 */
export function readFlag(argv, name) {
  const prefix = `--${name}=`;
  const match = argv.find((arg) => arg.startsWith(prefix));
  return match === undefined ? undefined : match.slice(prefix.length);
}

/** Claude Code hook event names (the hookEventName field). */
export const HookEvent = Object.freeze({
  PRE_TOOL_USE: "PreToolUse",
  POST_TOOL_USE: "PostToolUse",
  USER_PROMPT_SUBMIT: "UserPromptSubmit",
  SESSION_START: "SessionStart",
});

/** Claude Code permissionDecision verdicts. */
export const PermissionDecision = Object.freeze({
  ALLOW: "allow",
  DENY: "deny",
  ASK: "ask",
});

// Unpaired UTF-16 surrogates: a high half with no low follower, or a low half
// with no high lead. Hook text spliced into the model's context must be
// well-formed UTF-16 there, so the sanitizers normalize these out before
// serializing.
const LONE_SURROGATE_RE =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/**
 * Hard cap on hook stdin. A well-formed Claude Code hook payload is at most a
 * few MB (tool input plus the harness-truncated tool output); 64 MiB leaves
 * generous headroom while refusing a runaway or malformed sender before its
 * bytes are buffered into memory — an unbounded read would OOM the hook process
 * and take its own fail-closed output down with it.
 */
export const MAX_STDIN_BYTES = 64 * 1024 * 1024;

/**
 * Read a stream to a single Buffer, refusing to buffer past `maxBytes` so a
 * runaway sender can't OOM the hook.
 * @param {AsyncIterable<Buffer>} stream
 * @param {number} [maxBytes] cap before aborting (overridable for tests)
 * @returns {Promise<Buffer>}
 */
async function readAllBounded(stream, maxBytes = MAX_STDIN_BYTES) {
  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    total += chunk.length;
    if (total > maxBytes)
      throw new Error(
        `hook stdin exceeds ${maxBytes} bytes; refusing to buffer`,
      );
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

/**
 * @param {number} [maxBytes] cap before aborting (overridable for tests)
 * @returns {Promise<any>}
 */
export async function readStdinJson(maxBytes = MAX_STDIN_BYTES) {
  return JSON.parse((await readAllBounded(process.stdin, maxBytes)).toString());
}

/**
 * Register already-loaded module namespaces for {@link lazyImport} to return in
 * place of a runtime dynamic import. Call before importing any module that
 * lazy-loads the given specifiers.
 * @param {Record<string, Record<string, any>>} modules  specifier → namespace
 * @returns {void}
 */
export function registerLazyModules(modules) {
  Object.assign(shared.lazyModules, modules);
}

/**
 * The pre-registered namespace for `specifier`, or undefined when none was
 * registered. The synchronous face of the registry, for call sites that cannot
 * await {@link lazyImport} (e.g. a sync callback binding a scanner package):
 * inside a bundle the registered namespace is the ONLY way to reach the
 * package, since a runtime require/import has no node_modules to resolve from.
 * @param {string} specifier
 * @returns {Record<string, any> | undefined}
 */
export function registeredLazyModule(specifier) {
  return shared.lazyModules[specifier];
}

/**
 * Last load error per specifier, recorded when {@link lazyImport} swallows a
 * failed import. Read by {@link lazyImportErrorFor} so a fail-closed hook can
 * say WHY its dependency is absent instead of a bare "unavailable".
 * @type {Map<string, unknown>}
 */
const lazyImportErrors = new Map();

/**
 * Dynamic-import `specifier`, yielding `{}` when the module cannot be loaded.
 * Hooks bind their npm packages through this instead of a bare static import: a
 * static npm import resolves before any try/catch, so a missing node_modules
 * would crash the hook at load — the harness treats that as a non-blocking
 * error and the tool call proceeds UNGUARDED (fail OPEN). Destructuring from
 * the `{}` failure value leaves each binding undefined, so the first use throws
 * into the hook's own catch and the hook takes its declared failure posture
 * instead. A specifier registered via {@link registerLazyModules} resolves from
 * the registry without touching the loader.
 * @param {string} specifier
 * @returns {Promise<Record<string, any>>}
 */
export async function lazyImport(specifier) {
  const registered = shared.lazyModules[specifier];
  if (registered) {
    lazyImportErrors.delete(specifier);
    return registered;
  }
  try {
    const loaded = await import(specifier);
    lazyImportErrors.delete(specifier);
    return loaded;
  } catch (err) {
    // Delete before set: a Map keeps a re-set key at its ORIGINAL insertion
    // position, and both readers below are recency-ordered — so re-recording in
    // place would let a stale first failure outrank the one that just happened.
    lazyImportErrors.delete(specifier);
    lazyImportErrors.set(specifier, err);
    return {};
  }
}

/**
 * The most recently recorded load error for `pkg` under any of its specifiers —
 * the bare package or a subpath export (`pkg/output`, `pkg/invisible`) — or
 * undefined when none is recorded. Hooks import a package through several
 * subpaths; any one of them names why the package is absent, and the newest
 * record reflects the current failure when they differ.
 * @param {string} pkg
 * @returns {unknown}
 */
export function lazyImportErrorFor(pkg) {
  for (const [specifier, err] of [...lazyImportErrors].reverse())
    if (specifier === pkg || specifier.startsWith(`${pkg}/`)) return err;
  return undefined;
}

/**
 * Package names (never relative-path specifiers) with a recorded load error,
 * newest first — so a fail-closed reason can name whichever dependency actually
 * failed instead of consulting a hardcoded package list.
 * @returns {string[]}
 */
export function failedLazyPackages() {
  const pkgs = new Set();
  for (const specifier of [...lazyImportErrors.keys()].reverse()) {
    // Only bare package names: relative/absolute paths and URL specifiers
    // (file:, node:) are not npm packages a reinstall could restore.
    if (!/^[\w@]/.test(specifier) || specifier.includes(":")) continue;
    const parts = specifier.split("/");
    pkgs.add(
      specifier.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0],
    );
  }
  return [...pkgs];
}

/**
 * The remedy {@link missingPackageMessage} states when the host does not supply
 * one of its own. A host whose install has a specific entry point (a setup
 * script, a devcontainer rebuild) passes that instead, so the reason names the
 * command the reader should actually run.
 */
export const DEFAULT_MISSING_PACKAGE_REMEDY =
  "reinstall the hook dependencies (pnpm install) and retry.";

/**
 * Adopt a host's own remedy as the default {@link missingPackageMessage} and
 * {@link missingPackageError} state when their caller passes none. This refusal
 * to hard-code the wording is what prevents a fail-closed reason whose remedy
 * names a command the host doesn't have: deep call sites (controlPlane's
 * missing-package throw) never take a remedy argument, so without this seam
 * they can only ever tell a reader to run `pnpm install` — wrong advice in a
 * host whose one install entry point is its own setup script. An explicit
 * per-call remedy still wins over the configured one. Unlike the hookgate
 * marker there is no too-late window: the remedy is consulted at each throw,
 * never resolved at module scope, so a later call steers every later message.
 * Keep it to a sentence — a remedy beyond ~260 characters overruns the 300-char
 * message budget (see missingPackageMessage).
 * @param {string | null} remedy  host remedy text, or null to restore the package default
 * @returns {void}
 */
export function configureMissingPackageRemedy(remedy) {
  shared.missingPackageRemedy = remedy;
}

/**
 * The fail-closed reason for a package a hook could not load: the recorded
 * loader error plus the remedy. The cause is scrubbed (it is spliced into
 * reasons shown to user and model) and its cap is COMPUTED so that
 * prefix + cause + remedy always fits the downstream 300-char safeErrMessage
 * re-scrub — the remedy can never be truncated off, whatever the package name.
 * A remedy that alone exceeds that budget (roughly 260 characters) leaves the
 * cause nothing to spend and still overruns; keep host remedies to a sentence.
 * @param {string} pkg
 * @param {unknown} [err]
 * @param {string} [remedy]
 * @returns {string}
 */
export function missingPackageMessage(
  pkg,
  err = lazyImportErrorFor(pkg),
  remedy = shared.missingPackageRemedy ?? DEFAULT_MISSING_PACKAGE_REMEDY,
) {
  const prefix = `${pkg} is unavailable: `;
  // 2 for the "; " joiner; 12 for safeErrMessage's own "…[truncated]" marker,
  // which lands past its cap when the cause is cut. Clamped at 0 because the
  // remedy is host text: a long one drives the budget negative, and
  // safeErrMessage does not clamp — `slice(0, -n)` trims from the END, returning
  // nearly the whole cause and pushing the joined message past 300, so the
  // downstream re-scrub cuts the remedy off. At 0 the cause degrades to the
  // truncation marker and the remedy always survives.
  const causeCap = Math.max(0, 300 - prefix.length - remedy.length - 2 - 12);
  const cause =
    err === undefined
      ? "no load error recorded — the package likely loaded but lacks an expected export (version skew)"
      : safeErrMessage(err, causeCap);
  return `${prefix}${cause}; ${remedy}`;
}

/**
 * {@link missingPackageMessage} as a throwable, tagged `code: "DEP_UNAVAILABLE"`
 * so downstream reason-builders can recognize it structurally and not append a
 * second copy of the same cause.
 * @param {string} pkg
 * @param {unknown} [err]
 * @param {string} [remedy]
 * @returns {Error}
 */
export function missingPackageError(
  pkg,
  err = lazyImportErrorFor(pkg),
  remedy = shared.missingPackageRemedy ?? DEFAULT_MISSING_PACKAGE_REMEDY,
) {
  return Object.assign(new Error(missingPackageMessage(pkg, err, remedy)), {
    code: "DEP_UNAVAILABLE",
  });
}

/**
 * A monotonic wall-clock budget shared across one hook run's downstream blocking
 * calls. `remainingMs()` returns the milliseconds left until the budget is spent
 * (clamped at 0), so an orchestrator hands each sub-call `min(its own timeout,
 * remaining)` and a SERIES of daemon calls can never sum past the budget. This is
 * the fail-open hazard a per-call-only deadline leaves open: when many output
 * leaves each pay the Layer-4 redactor, the calls' individual timeouts bound each
 * call but not their SUM — a pathological pile-up could exceed the PostToolUse
 * hook kill, and a killed hook is non-blocking, so the RAW output would be shown.
 * `now` is injectable so time-dependent logic is unit-testable with a fake clock.
 * @param {number} budgetMs total wall-clock budget from creation
 * @param {() => number} [now] clock source (defaults to Date.now)
 * @returns {{ remainingMs: () => number }}
 */
export function makeDeadline(budgetMs, now = Date.now) {
  const end = now() + budgetMs;
  return { remainingMs: () => Math.max(0, end - now()) };
}

// Cap (in whole code points) on untrusted text spliced into the model's context
// via a warning reason.
const UNTRUSTED_TEXT_CAP = 500;

/**
 * Scrub untrusted text before it is spliced into the model's context via a
 * warning/reason field: strip ANSI and payload-capable invisibles to a fixed
 * point (via the injected `layer1`, the package's composite Layer-1 view),
 * replace lone surrogates so the model's UTF-16 context stays well-formed, then
 * cap by whole code points (never mid-pair, which the surrogate pass above
 * already swept). `layer1` is injected rather than imported so this
 * dependency-light module never eagerly loads the sanitizer package — each
 * caller passes its own caught-import binding.
 * @param {unknown} raw
 * @param {(text: string) => { cleaned: string }} layer1
 * @param {number} [cap]
 * @returns {string}
 */
export function scrubUntrustedText(raw, layer1, cap = UNTRUSTED_TEXT_CAP) {
  if (typeof raw !== "string" || raw === "") return "";
  const cleaned = layer1(raw).cleaned.replace(LONE_SURROGATE_RE, "�");
  const points = [...cleaned];
  return points.length > cap
    ? points.slice(0, cap).join("") + "…[truncated]"
    : cleaned;
}

/**
 * Message from a caught value, which is `unknown` under strict mode. Appends
 * the cause chain (one level) when the cause is itself an Error so callers
 * get "outer: root" instead of just "outer" when an error wraps another.
 * @param {unknown} err
 * @returns {string}
 */
export function errMessage(err) {
  if (!(err instanceof Error)) return String(err);
  const cause = err.cause instanceof Error ? `: ${err.cause.message}` : "";
  return err.message + cause;
}

/**
 * errMessage() for an error whose message may embed attacker-chosen bytes: V8
 * quotes a snippet of the offending input in a JSON.parse SyntaxError, so a hook
 * that splices errMessage(err) into a user-/model-facing reason would relay raw
 * ANSI escapes and invisible/format characters lifted from that snippet. Keep only
 * printable ASCII (plus tab/newline) and drop every other code point — dropping the
 * ESC/CSI-introducer and zero-width bytes neutralizes the sequence while leaving the
 * residual literal text readable — then cap the length so a long snippet can't flood
 * the reason. Use this instead of errMessage at any callsite that splices the
 * message into a reason/warning shown to the user or model.
 * @param {unknown} err
 * @param {number} [cap]
 * @returns {string}
 */
export function safeErrMessage(err, cap = 300) {
  const cleaned = [...errMessage(err)]
    .filter((ch) => {
      const cp = /** @type {number} */ (ch.codePointAt(0));
      return cp === 0x09 || cp === 0x0a || (cp >= 0x20 && cp <= 0x7e);
    })
    .join("");
  return cleaned.length > cap
    ? cleaned.slice(0, cap) + "…[truncated]"
    : cleaned;
}

/**
 * Write the `hookSpecificOutput` envelope a hook returns to stdout.
 * @param {string} hookEventName
 * @param {Record<string, unknown>} fields
 * @returns {void}
 */
export function emitHookResponse(hookEventName, fields) {
  process.stdout.write(
    JSON.stringify({ hookSpecificOutput: { hookEventName, ...fields } }),
  );
}

/** The marker filename stem; the project directory is appended to it. */
const HOOKGATE_MARKER_STEM = "agent-sanitizer-hookgate-inflight-";

/**
 * Adopt a host's own cold-start marker path in place of the derived one, so a
 * host whose setup script already writes a marker under its own convention can
 * use these hooks without running a second, disagreeing wait loop against a path
 * nothing writes.
 *
 * ORDERING, same rule as {@link registerLazyModules}: call this before importing
 * any hook module. `lib/control-plane.mjs` resolves the marker at MODULE scope,
 * so a call that lands after that import cannot reach the wait it was meant to
 * steer. A late call is reported on stderr rather than thrown: a throw at a
 * bundle entry's top level kills the hook process before it writes a response,
 * and a hook that emits nothing is read as non-blocking — the fail-OPEN this
 * whole file is built to avoid. The late call still takes effect for every
 * later resolution.
 * @param {string | null} path  absolute marker path, or null to restore the derivation
 * @returns {void}
 */
export function configureHookgateMarker(path) {
  if (shared.hookgateMarkerResolved)
    process.stderr.write(
      "agent-sanitizer: configureHookgateMarker called after a marker path was " +
        "already resolved; whatever resolved it is using the previous path and " +
        "cannot be re-steered. Call it before importing any hook module.\n",
    );
  shared.hookgateMarker = path;
}

/**
 * Path of the cold-start in-flight marker a host's setup script writes
 * SYNCHRONOUSLY before it starts installing deps (its own PID as the contents)
 * and removes once the hook dependencies are provisioned. A hook that fires
 * before setup finishes finds the marker and WAITS for its dependency rather
 * than failing closed on it — so the first turn is merely delayed, never
 * blocked, for as long as setup is still alive (the PID lets the hook tell a
 * live install from a stale marker left by a killed setup). Derived purely from
 * the raw CLAUDE_PROJECT_DIR the harness sets for both processes (no
 * canonicalization — the two must produce byte-identical paths), so no env has
 * to propagate from setup to the hook. Null when CLAUDE_PROJECT_DIR is unset (no
 * setup ran → nothing to wait on), or whatever a host set via
 * {@link configureHookgateMarker}.
 * @param {string | undefined} [projectDir]
 * @param {string | undefined} [runtimeDir]
 * @returns {string | null}
 */
export function hookgateMarkerPath(
  projectDir = process.env.CLAUDE_PROJECT_DIR,
  runtimeDir = process.env.XDG_RUNTIME_DIR,
) {
  shared.hookgateMarkerResolved = true;
  if (shared.hookgateMarker !== null) return shared.hookgateMarker;
  if (!projectDir) return null;
  // Prefer the per-user, mode-0700 runtime dir when the harness gives an
  // absolute one; else the world-writable /tmp, where markerIsTrusted() — not
  // the path — defends against a squatted marker.
  const base = runtimeDir && runtimeDir.startsWith("/") ? runtimeDir : "/tmp";
  // The flattened dir is for a human reading `ls /tmp`; the digest of the RAW
  // dir is the identity. Flattening alone is lossy — /work/a-b, /work/a_b and
  // "/work/a b" all collapse to one name — and two such projects on one machine
  // would then share a marker: B's hook waits out A's install for a dependency A
  // is not installing, and A clearing the marker aborts B's legitimate wait. Both
  // directions are silent. A setup script reproduces the digest with sha256sum.
  const digest = createHash("sha256")
    .update(projectDir)
    .digest("hex")
    .slice(0, 8);
  const flattened = projectDir.replace(/[^A-Za-z0-9]/g, "_");
  return `${base}/${HOOKGATE_MARKER_STEM}${flattened}-${digest}`;
}

/**
 * Is the setup process that wrote `markerPath` still alive? `process.kill(pid, 0)`
 * probes liveness without signalling: it throws ESRCH once the process is gone (a
 * killed setup → stale marker, so stop waiting) and EPERM when it exists but isn't
 * ours (still alive). An unreadable / not-yet-written marker is treated as alive —
 * favouring a brief wait over a premature give-up during setup's write race. A null
 * markerPath (no project dir → no setup to wait on) reads as alive so the caller's
 * own grace/ceiling bound governs.
 * @param {string | null} markerPath
 * @returns {boolean}
 */
export function probeSetupAlive(markerPath) {
  if (markerPath === null) return true;
  let pid;
  try {
    pid = parseInt(readFileSync(markerPath, "utf8"), 10);
  } catch {
    return true;
  }
  if (!Number.isInteger(pid) || pid <= 0) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return /** @type {NodeJS.ErrnoException} */ (err).code === "EPERM";
  }
}

/**
 * Resolve a lazily-loaded dependency, blocking through the cold-start window while
 * setup is still installing it. Returns the loaded value, or null once it gives up
 * (the caller leaves its bindings undefined so the hook fails closed). It waits for
 * as long as setup is genuinely alive, so a slow install is never cut off; the only
 * bound on that wait is a backstop ceiling that stays under the hook's harness
 * timeout — a hook killed for running over is a fail-OPEN, the opposite of what a
 * gate wants. The give-up cases are the honest ones (setup finished/died without the
 * dep, or no setup at all), so a genuinely-absent dep fails closed fast, never after
 * a long block:
 *   - import succeeds                 → return immediately (warm session: no wait).
 *   - marker present AND setup alive  → setup is working; wait it out (ceilingMs is a
 *                                        backstop only, for a hung-but-alive setup).
 *   - was installing, now not (marker cleared, or a stale marker from a killed setup)
 *                                     → settleMs grace for a just-orphaned install to
 *                                        land, then give up: the dep is absent.
 *   - no live setup ever seen         → wait only graceMs (tolerating setup not having
 *                                        written the marker yet), then give up.
 * @param {{
 *   tryImport: () => Promise<object | null>,
 *   markerPresent: () => boolean,
 *   setupAlive: () => boolean,
 *   now?: () => number,
 *   sleep?: (ms: number) => Promise<void>,
 *   graceMs?: number,
 *   settleMs?: number,
 *   ceilingMs?: number,
 *   intervalMs?: number,
 * }} deps
 * @returns {Promise<object | null>}
 */
export async function awaitLazyDependency({
  tryImport,
  markerPresent,
  setupAlive,
  now = () => Date.now(),
  sleep = (ms) =>
    new Promise((resolve) => {
      setTimeout(resolve, ms);
    }),
  graceMs = 5000,
  settleMs = 1000,
  ceilingMs = 900000,
  intervalMs = 250,
}) {
  const start = now();
  let sawInstalling = false;
  let enteredDone = false;
  let doneAt = 0;
  for (;;) {
    const bindings = await tryImport();
    if (bindings) return bindings;
    const installing = markerPresent() && setupAlive();
    let giveUp;
    if (installing) {
      sawInstalling = true;
      enteredDone = false;
      giveUp = now() - start > ceilingMs;
    } else if (sawInstalling) {
      if (!enteredDone) {
        enteredDone = true;
        doneAt = now();
      }
      giveUp = now() - doneAt > settleMs;
    } else {
      giveUp = now() - start > graceMs;
    }
    if (giveUp) return null;
    await sleep(intervalMs);
  }
}

/**
 * Is the file at `path` one WE wrote — a regular file owned by this uid — rather
 * than a squat? These markers live at predictable, world-visible $TMPDIR paths, so
 * a co-tenant could pre-plant a file (or a symlink at the path) to steer a gate.
 * lstatSync does NOT traverse a final symlink, so a planted symlink reads as a
 * symlink (isFile() false) and a foreign file fails the uid check: either way the
 * marker is untrusted and the caller ignores it.
 * @param {string | null} path
 * @returns {boolean}
 */
export function markerIsTrusted(path) {
  if (path === null) return false;
  let st;
  try {
    st = lstatSync(path);
  } catch {
    return false;
  }
  return st.isFile() && st.uid === userInfo().uid;
}

/**
 * Create a presence sentinel at `path` without following a symlink a co-tenant
 * may have pre-planted there. These sentinels live at predictable, world-visible
 * paths under $TMPDIR (a project-hash or fixed name), so a plain writeFileSync —
 * which opens O_CREAT|O_TRUNC and follows a symlink at the path — would let
 * anyone able to plant that symlink redirect the write and truncate an arbitrary
 * file the hook's user owns. Unlink any existing entry first (removing a squatted
 * symlink), then create exclusively (O_EXCL) so a symlink re-planted in the race
 * window fails the open rather than being dereferenced. Content is irrelevant —
 * callers test only for existence — so the file is left empty. Best-effort: a
 * missing/read-only $TMPDIR or a lost race just leaves the sentinel absent, and
 * every caller treats "absent" as "not yet done" (a repeated ask, never a crash),
 * so all failures are swallowed.
 * @param {string} path
 * @returns {void}
 */
export function writeSentinelFile(path) {
  try {
    unlinkSync(path);
  } catch {
    // No existing entry (the common case), or an unremovable one — either way the
    // exclusive create below is the real guard, and its own failure is swallowed.
  }
  try {
    closeSync(openSync(path, "wx"));
  } catch {
    // A symlink re-planted in the unlink→open window, an unwritable dir, or a
    // leftover entry: skip silently — the caller simply re-asks next time.
  }
}

/**
 * Write `content` to `path` without following a symlink a co-tenant may have
 * pre-planted there — the content-bearing counterpart to writeSentinelFile. These
 * hooks write to predictable, world-visible $TMPDIR paths (a project-hash name, or
 * a content-addressed digest an attacker who chose the input bytes can precompute),
 * so a plain writeFileSync — which opens O_CREAT|O_TRUNC and follows a final
 * symlink — would let anyone able to plant that symlink redirect the write and
 * truncate/overwrite an arbitrary file the hook's user owns. Unlink any existing
 * entry first (removing a squatted symlink), then create exclusively (O_EXCL via
 * "wx") so a symlink re-planted in the unlink→open race window fails the open
 * rather than being dereferenced. Returns true on success, false when the write
 * could not be completed (unwritable dir, or a lost race) so the caller decides
 * whether a failed best-effort write is fatal.
 * @param {string} path
 * @param {string} content
 * @param {number} [mode]
 * @returns {boolean}
 */
export function writeFileNoFollow(path, content, mode = 0o600) {
  try {
    unlinkSync(path);
  } catch {
    // No existing entry (the common case), or an unremovable one — either way the
    // exclusive create below is the real guard, and its own failure is returned.
  }
  let fd;
  try {
    fd = openSync(path, "wx", mode);
  } catch {
    return false;
  }
  try {
    writeFileSync(fd, content);
    return true;
  } finally {
    closeSync(fd);
  }
}
