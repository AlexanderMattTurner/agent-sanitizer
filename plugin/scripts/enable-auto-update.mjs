/**
 * Turn Claude Code's background auto-update on (or, with `--disable`, off) for
 * the marketplace this plugin ships from.
 *
 * Claude Code enables auto-update by default only for Anthropic's own
 * marketplaces, and exposes the toggle for everyone else's through the
 * interactive `/plugin` picker alone — there is no `/plugin marketplace
 * autoupdate <name>` command to call. Left off, an install pins the session to
 * the catalog snapshot taken when the marketplace was added, so a detector fix
 * released here never reaches it.
 *
 * The flag lives in Claude Code's own `known_marketplaces.json`, which is
 * internal state with no compatibility promise: this script therefore only ever
 * flips `autoUpdate` on an entry that is already there, and refuses loudly
 * rather than creating the file, inventing an entry, or writing through a shape
 * it does not recognize. A Claude Code release that moves or restructures the
 * file makes this exit non-zero with what it found — never silently no-op.
 */
import { readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

// Must equal `name` in .claude-plugin/marketplace.json — that is what Claude
// Code keys the entry by. plugin/test/enable-auto-update.test.mjs pins the pair;
// the manifest does not ship inside the plugin, so it cannot be read at runtime.
export const MARKETPLACE = "agent-sanitizer";

/** @param {string | undefined} value */
const isTruthy = (value) => value === "1" || value === "true";

/**
 * Where Claude Code keeps the marketplace registry, honouring its own overrides.
 *
 * @param {Record<string, string | undefined>} [env]
 */
export function knownMarketplacesPath(env = process.env) {
  const cache =
    env.CLAUDE_CODE_PLUGIN_CACHE_DIR ??
    join(
      env.CLAUDE_CONFIG_DIR ?? join(homedir(), ".claude"),
      // Cowork keeps a separate plugin root; writing the wrong one would leave
      // the toggle looking applied while changing nothing.
      isTruthy(env.CLAUDE_CODE_USE_COWORK_PLUGINS)
        ? "cowork_plugins"
        : "plugins",
    );
  return join(cache, "known_marketplaces.json");
}

/**
 * Exits with `message` on stderr — for a state the user is expected to fix.
 *
 * @param {string} message
 * @returns {never}
 */
function fail(message) {
  process.stderr.write(`agent-sanitizer: ${message}\n`);
  process.exit(1);
}

/** Errno codes that mean the OS refused the write, not that the write is wrong. */
const REFUSED = new Set(["EPERM", "EACCES", "EROFS"]);

/**
 * Wraps `word` so a POSIX shell sees it as one literal argument. Marketplace
 * installs sit under a versioned directory below the user's home, so the path
 * this quotes routinely contains a space and sometimes a quote.
 *
 * @param {string} word
 */
const shellQuote = (word) => `'${word.replaceAll("'", `'\\''`)}'`;

/**
 * The command line that reruns this invocation, for a human to paste into a
 * terminal. The refusal below is the one failure the agent running the skill
 * cannot act on itself — the sandbox denies it whatever it tries — so the
 * message has to hand the work back ready to run, not describe it.
 *
 * @param {boolean} disable
 */
const rerunCommand = (disable) =>
  `node ${shellQuote(process.argv[1])}${disable ? " --disable" : ""}`;

/**
 * Removes the temp file this run staged, reporting whether it is gone.
 *
 * Unlinking needs write permission on the directory, which is exactly what a
 * refused rename says we may not have — so a refusal here is reported in the
 * message below rather than crashing over it with the trace this path exists to
 * remove. Any other errno still propagates.
 *
 * @param {string} temp
 */
function removeStaged(temp) {
  try {
    rmSync(temp, { force: true });
    return true;
  } catch (error) {
    const code = /** @type {NodeJS.ErrnoException} */ (error).code;
    if (!REFUSED.has(code ?? "")) throw error;
    return false;
  }
}

/**
 * Replaces the registry, staged through a sibling temp file so an interrupted
 * write cannot leave the file Claude Code reads truncated.
 *
 * A refused write is a state the user can act on, so it exits with the two
 * routes that do work instead of a stack trace; every other errno propagates.
 *
 * @param {string} path
 * @param {string} contents
 * @param {boolean} disable  which invocation to hand back for a rerun
 */
function replaceRegistry(path, contents, disable) {
  const temp = `${path}.agent-sanitizer.tmp`;
  let staged = false;
  try {
    writeFileSync(temp, contents, "utf-8");
    staged = true;
    renameSync(temp, path);
  } catch (error) {
    const code = /** @type {NodeJS.ErrnoException} */ (error).code;
    if (!REFUSED.has(code ?? "")) throw error;
    // Only a temp file this run wrote is ours to remove; one an interrupted
    // earlier run left behind belongs to no one we can speak for.
    const litter = staged && !removeStaged(temp) ? temp : null;
    fail(
      `cannot write ${path} (${code}) — the OS refused it. Claude Code's Bash ` +
        `sandbox confines writes to the workspace, so no session that runs ` +
        `under it can reach the plugin cache; rerunning here cannot succeed.\n` +
        `Run this yourself, in a terminal outside Claude Code:\n` +
        `  ${rerunCommand(disable)}\n` +
        `Or toggle it without a terminal: /plugin -> Marketplaces -> ` +
        `${MARKETPLACE} -> Enable auto-update.\n` +
        `If the terminal refuses it too, the file's owner or permissions need ` +
        `fixing.` +
        (litter
          ? `\nThe staged copy at ${litter} could not be cleaned up either; ` +
            `delete it once the permissions are fixed.`
          : ""),
    );
  }
}

/**
 * @param {string[]} [argv]
 * @param {Record<string, string | undefined>} [env]
 */
export function main(argv = process.argv.slice(2), env = process.env) {
  const disable = argv.includes("--disable");
  const unknown = argv.filter((arg) => arg !== "--disable");
  if (unknown.length)
    fail(`unrecognized argument(s): ${unknown.join(" ")} (only --disable)`);
  const desired = !disable;

  const path = knownMarketplacesPath(env);
  let raw;
  try {
    raw = readFileSync(path, "utf-8");
  } catch (error) {
    if (/** @type {NodeJS.ErrnoException} */ (error).code !== "ENOENT")
      throw error;
    return fail(
      `no marketplace registry at ${path} — add the marketplace first:\n` +
        `  /plugin marketplace add AlexanderMattTurner/agent-sanitizer`,
    );
  }

  // A corrupt registry is Claude Code's to report, not ours to repair: parse
  // errors propagate rather than being rewritten over.
  const config = JSON.parse(raw);
  const entry = config[MARKETPLACE];
  if (!entry)
    return fail(
      `marketplace '${MARKETPLACE}' is not registered (found: ` +
        `${Object.keys(config).join(", ") || "none"}) — add it first:\n` +
        `  /plugin marketplace add AlexanderMattTurner/agent-sanitizer`,
    );
  if (typeof entry !== "object" || Array.isArray(entry) || !entry.source)
    return fail(
      `entry for '${MARKETPLACE}' in ${path} is not the shape this script ` +
        `knows how to edit — toggle auto-update from /plugin instead`,
    );
  if (entry.autoUpdate !== undefined && typeof entry.autoUpdate !== "boolean")
    return fail(
      `autoUpdate for '${MARKETPLACE}' in ${path} is ${JSON.stringify(entry.autoUpdate)}, ` +
        `not a boolean — toggle auto-update from /plugin instead`,
    );

  if ((entry.autoUpdate ?? false) === desired) {
    process.stdout.write(
      `agent-sanitizer: auto-update already ${desired ? "enabled" : "disabled"} for '${MARKETPLACE}'\n`,
    );
    return 0;
  }

  const updated = {
    ...config,
    [MARKETPLACE]: { ...entry, autoUpdate: desired },
  };
  // Same 2-space encoding Claude Code writes.
  replaceRegistry(path, JSON.stringify(updated, null, 2), disable);

  process.stdout.write(
    desired
      ? `agent-sanitizer: auto-update enabled for '${MARKETPLACE}' in ${path}.\n` +
          `Claude Code refreshes the catalog in the background shortly after a session starts; ` +
          `updates load on /reload-plugins or at the next launch.\n`
      : `agent-sanitizer: auto-update disabled for '${MARKETPLACE}' in ${path}.\n` +
          `Pull releases by hand with /plugin marketplace update ${MARKETPLACE} ` +
          `then /plugin update ${MARKETPLACE}@${MARKETPLACE}.\n`,
  );
  return 0;
}

// Compared as URLs, not as a `file://` string splice: a marketplace install path
// carries a version segment and may sit under a directory with a space in it,
// which the naive form mis-compares — and a mis-compare here is the one failure
// mode this script must not have, a silent no-op that reports nothing at all.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main();
