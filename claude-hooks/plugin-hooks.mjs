/**
 * Entry point: EVERY sanitization hook behind one dispatch flag. The hooks
 * share almost the entire package graph, so one bundle per hook would ship a
 * near-identical copy per hook; a single entry with a `--hook=<name>` flag
 * selecting the hook ships the graph once (hooks.json passes the flag).
 *
 * The plugin's shipped artifact is the esbuild BUNDLE with every package inlined
 * at build time — there is no node_modules for a runtime import to resolve — so
 * this binder statically imports the packages the hooks lazy-load and
 * pre-registers them BEFORE any hook module is imported. Each hook module is
 * loaded through a literal dynamic import so the registration (and the CLI-slot
 * claim) precede its top-level lazyImport calls, then its own exported CLI runs.
 *
 * Layer 2/3 (the remark/rehype HTML parser graph) is inlined and runs locally.
 */
import {
  claimCliEntry,
  disabledHooks,
  DISABLED_HOOKS_ENV,
  emitHookResponse,
  HookEvent,
  isMain,
  registerLazyModules,
  readFlag,
  readStdinJson,
} from "./lib/hook-io.mjs";
import {
  registerFaultPolicy,
  hookFaultOutcome,
  writeFaultOutcome,
} from "./lib/hook-fault.mjs";

const HOOK_NAME = "plugin-hooks";

// The dispatcher's entry in the one posture table (lib/hook-fault.mjs). It
// answers no single event — it is the binder in front of all of them — so it
// carries no stdout envelope and both arms are process-level. Its one fault is
// an unknown `--hook` mode: broken hooks.json wiring, so no hook runs for that
// event until the install is fixed.
//
// OPEN exits 1, which Claude Code treats as a non-blocking hook error; through
// plugin/scripts/safe-launch.sh it becomes that event's fail-open warning.
// CLOSED exits 2, the one non-zero code Claude Code treats as BLOCKING: it
// blocks PreToolUse and UserPromptSubmit, surfaces stderr for PostToolUse, and
// is harmless for SessionStart.
const unknownModeLine = (/** @type {{ message: string }} */ ctx) =>
  `${HOOK_NAME}: ${ctx.message} — hooks.json names a hook this bundle does ` +
  `not dispatch (known: ${HOOK_MODES.join(", ")}); reinstall or update the plugin.`;
registerFaultPolicy(HOOK_NAME, {
  event: null,
  guarded: "hook payload",
  open: (ctx) => ({
    stderr:
      `${unknownModeLine(ctx)} This event is UNGUARDED; set ` +
      "AGENT_SANITIZER_FAIL_OPEN=0 to block it instead.\n",
    exitCode: 1,
  }),
  closed: (ctx) => ({
    stderr: `${unknownModeLine(ctx)} Blocking (AGENT_SANITIZER_FAIL_OPEN=0).\n`,
    exitCode: 2,
  }),
});

// The packages the hooks lazy-load, each behind a thunk whose import specifier
// is a LITERAL — esbuild only inlines `import("…")` it can read statically, so
// an `import(variable)` here would survive into the bundle as a runtime dial
// against a node_modules the plugin does not ship, and every registration would
// fail at once.
const LAZY_LOADERS = {
  "agent-control-plane-core/claude": () =>
    import("agent-control-plane-core/claude"),
  "agent-control-plane-core/contract": () =>
    import("agent-control-plane-core/contract"),
  "agent-sanitizer": () => import("agent-sanitizer"),
  "agent-sanitizer/confusables": () => import("agent-sanitizer/confusables"),
  "agent-sanitizer/instructions": () => import("agent-sanitizer/instructions"),
  "agent-sanitizer/invisible": () => import("agent-sanitizer/invisible"),
  "agent-sanitizer/output": () => import("agent-sanitizer/output"),
  "agent-sanitizer/prompt": () => import("agent-sanitizer/prompt"),
  "agent-sanitizer/rehydrate": () => import("agent-sanitizer/rehydrate"),
  "agent-sanitizer/view-map": () => import("agent-sanitizer/view-map"),
  "namespace-guard": () => import("namespace-guard"),
};

/**
 * Pre-register every package the hooks lazy-load, skipping any that will not
 * load.
 *
 * A top-level static import of these would abort the process before `main`
 * runs, and an aborted hook writes NOTHING to stdout — which Claude Code reads
 * as a non-blocking hook error and shows the raw tool output. That is a
 * fail-OPEN on the very hook that withholds secrets. Registering what resolves
 * and leaving the rest absent hands the gap to each hook's own lazyImport
 * guard, which answers it loudly under the operator's fault posture.
 * @returns {Promise<void>}
 */
async function registerAvailableModules() {
  /** @type {Record<string, Record<string, any>>} */
  const loaded = {};
  await Promise.all(
    Object.entries(LAZY_LOADERS).map(async ([specifier, load]) => {
      try {
        loaded[specifier] = await load();
      } catch {
        // Left unregistered on purpose — see the fail-open note above.
      }
    }),
  );
  registerLazyModules(loaded);
}

/**
 * Every dispatchable hook: its Claude Code event, and the loader that runs it.
 *
 * A table rather than a switch because the mode NAMES are read three ways — the
 * dispatch, the {@link DISABLED_HOOKS_ENV} validation, and the tests that check
 * hooks.json wires exactly these — and each hand-written copy is one that can
 * drift into naming a hook nothing dispatches. The event is here because a
 * disabled hook still has to answer in its own event's envelope.
 *
 * Each module is loaded through a LITERAL dynamic import: esbuild inlines only
 * what it can read statically, so a computed specifier would survive into the
 * bundle as a runtime dial against a node_modules the plugin does not ship.
 * @type {Record<string, { event: string, run: () => Promise<void> }>}
 */
const HOOKS = {
  "pretooluse-sanitize": {
    event: HookEvent.PRE_TOOL_USE,
    run: async () => {
      const { cliMain } =
        /** @type {typeof import("./pretooluse-sanitize.mjs")} */ (
          await import("./pretooluse-sanitize.mjs")
        );
      await cliMain();
    },
  },
  "sanitize-output": {
    event: HookEvent.POST_TOOL_USE,
    run: async () => {
      const { cliMain } =
        /** @type {typeof import("./sanitize-output.mjs")} */ (
          await import("./sanitize-output.mjs")
        );
      await cliMain();
    },
  },
  "sanitize-user-prompt": {
    event: HookEvent.USER_PROMPT_SUBMIT,
    run: async () => {
      const { main: promptMain } =
        /** @type {typeof import("./sanitize-user-prompt.mjs")} */ (
          await import("./sanitize-user-prompt.mjs")
        );
      await promptMain(readStdinJson, (chunk) => process.stdout.write(chunk));
    },
  },
  "scan-invisible-chars": {
    event: HookEvent.SESSION_START,
    run: async () => {
      const { cliMain, sessionIdFromStdin } =
        /** @type {typeof import("./scan-invisible-chars.mjs")} */ (
          await import("./scan-invisible-chars.mjs")
        );
      // The SessionStart payload carries the session identity the alert store is
      // keyed by; without it every session shares one store and inherits the
      // previous one's gate acknowledgement.
      await cliMain({ sessionId: await sessionIdFromStdin() });
    },
  },
  "scan-loaded-instructions": {
    event: HookEvent.INSTRUCTIONS_LOADED,
    run: async () => {
      const { cliMain } =
        /** @type {typeof import("./scan-loaded-instructions.mjs")} */ (
          await import("./scan-loaded-instructions.mjs")
        );
      await cliMain();
    },
  },
};

/** The dispatchable hook names, in hooks.json's spelling. */
export const HOOK_MODES = Object.freeze(Object.keys(HOOKS));

/**
 * Dispatch to the hook named by `--hook=<name>` in argv. Exported and guarded by
 * isMain below so importing this module (the published entry point) is a no-op:
 * only a direct `node plugin-hooks.mjs --hook=…` run consumes stdin and exits.
 * @returns {Promise<void>}
 */
export async function main() {
  // This binder owns the process's CLI entry: inside the bundle every inlined
  // module shares this file's import.meta.url, so without the claim the inlined
  // hooks' own isMain-guarded CLIs would also fire and consume stdin.
  claimCliEntry();
  await registerAvailableModules();

  const mode = readFlag(process.argv, "hook");
  const hook = mode === undefined ? undefined : HOOKS[mode];
  if (mode === undefined || hook === undefined) {
    // An unknown mode means broken hooks.json wiring — never fall through to
    // some default hook and vet the wrong payload class. WHICH way it fails is
    // the operator's call, taken through the one posture table like every other
    // hook fault.
    process.exitCode = writeFaultOutcome(
      hookFaultOutcome(
        HOOK_NAME,
        new Error(`unknown hook mode ${JSON.stringify(mode)}`),
      ),
    );
    // Drained like the disabled arm below: under the open posture the event
    // proceeds, and a harness left writing into a closed pipe sees EPIPE.
    process.stdin.resume();
    return;
  }

  // An empty envelope is a verdict, not a crash: stdout stays non-empty, so the
  // launcher's post-condition sees an answer and Claude Code records a clean
  // run rather than a hook error. The operator asked for this hook not to
  // guard, so there is nothing to warn the MODEL about — the stderr line is
  // where an operator finds out which hooks are off.
  if (disabledHooks(HOOK_MODES).has(mode)) {
    process.stderr.write(
      `agent-sanitizer: ${mode} is off via ${DISABLED_HOOKS_ENV}; this ` +
        `${hook.event} event is UNGUARDED.\n`,
    );
    emitHookResponse(hook.event, {});
    // Every other hook reads the payload to EOF. Exiting without doing so
    // leaves Claude Code writing into a closed pipe — an EPIPE on the harness
    // side for any payload past the pipe buffer, which is most of them.
    // `resume()` with no data listener consumes and discards.
    process.stdin.resume();
    return;
  }

  await hook.run();
}

// isMain is read BEFORE main() claims the CLI slot (the claim makes every later
// isMain answer false, including this one).
if (isMain(import.meta.url)) {
  await main();
}
