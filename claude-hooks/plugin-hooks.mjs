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
import * as controlPlaneCore from "agent-control-plane-core";
import * as controlPlaneClaude from "agent-control-plane-core/claude";
import * as sanitizerRoot from "agent-sanitizer";
import * as sanitizerConfusables from "agent-sanitizer/confusables";
import * as sanitizerInvisible from "agent-sanitizer/invisible";
import * as sanitizerOutput from "agent-sanitizer/output";
import * as sanitizerRehydrate from "agent-sanitizer/rehydrate";
import * as namespaceGuard from "namespace-guard";
import {
  claimCliEntry,
  isMain,
  registerLazyModules,
  readFlag,
  readStdinJson,
} from "./lib/hook-io.mjs";

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
  registerLazyModules({
    "agent-control-plane-core": controlPlaneCore,
    "agent-control-plane-core/claude": controlPlaneClaude,
    "agent-sanitizer": sanitizerRoot,
    "agent-sanitizer/confusables": sanitizerConfusables,
    "agent-sanitizer/invisible": sanitizerInvisible,
    "agent-sanitizer/output": sanitizerOutput,
    "agent-sanitizer/rehydrate": sanitizerRehydrate,
    "namespace-guard": namespaceGuard,
  });

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
