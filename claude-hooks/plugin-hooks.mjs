/**
 * Entry point: ALL FOUR sanitization hooks behind one dispatch flag. The four
 * hooks share almost the entire package graph, so one bundle per hook would ship
 * four near-identical copies; a single entry with a `--hook=<name>` flag
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
  isMain,
  registerLazyModules,
  readFlag,
  readStdinJson,
} from "./lib/hook-io.mjs";

// The packages the hooks lazy-load, each behind a thunk whose import specifier
// is a LITERAL — esbuild only inlines `import("…")` it can read statically, so
// an `import(variable)` here would survive into the bundle as a runtime dial
// against a node_modules the plugin does not ship, and every registration would
// fail at once.
const LAZY_LOADERS = {
  "agent-control-plane-core": () => import("agent-control-plane-core"),
  "agent-control-plane-core/claude": () =>
    import("agent-control-plane-core/claude"),
  "agent-sanitizer": () => import("agent-sanitizer"),
  "agent-sanitizer/confusables": () => import("agent-sanitizer/confusables"),
  "agent-sanitizer/invisible": () => import("agent-sanitizer/invisible"),
  "agent-sanitizer/output": () => import("agent-sanitizer/output"),
  "agent-sanitizer/rehydrate": () => import("agent-sanitizer/rehydrate"),
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
 * guard, whose posture is to block.
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
  switch (mode) {
    case "pretooluse-sanitize": {
      const { cliMain } =
        /** @type {typeof import("./pretooluse-sanitize.mjs")} */ (
          await import("./pretooluse-sanitize.mjs")
        );
      await cliMain();
      break;
    }
    case "sanitize-output": {
      const { cliMain } =
        /** @type {typeof import("./sanitize-output.mjs")} */ (
          await import("./sanitize-output.mjs")
        );
      await cliMain();
      break;
    }
    case "sanitize-user-prompt": {
      const { main: promptMain } =
        /** @type {typeof import("./sanitize-user-prompt.mjs")} */ (
          await import("./sanitize-user-prompt.mjs")
        );
      await promptMain(readStdinJson, (chunk) => process.stdout.write(chunk));
      break;
    }
    case "scan-invisible-chars": {
      const { cliMain } =
        /** @type {typeof import("./scan-invisible-chars.mjs")} */ (
          await import("./scan-invisible-chars.mjs")
        );
      await cliMain();
      break;
    }
    default:
      // An unknown mode means broken hooks.json wiring — fail CLOSED, never fall
      // through to some default hook and vet the wrong payload class. Exit 2 is
      // the one non-zero code Claude Code treats as blocking (a plain exit 1 is
      // a non-blocking hook error that lets the guarded action through
      // unsanitized); it blocks PreToolUse and UserPromptSubmit, surfaces
      // stderr for PostToolUse, and is harmless for SessionStart.
      process.stderr.write(
        `plugin-hooks: unknown hook mode ${JSON.stringify(mode)}\n`,
      );
      process.exit(2);
  }
}

// isMain is read BEFORE main() claims the CLI slot (the claim makes every later
// isMain answer false, including this one).
if (isMain(import.meta.url)) {
  await main();
}
