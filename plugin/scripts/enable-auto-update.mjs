#!/usr/bin/env node
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
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

// Must equal `name` in .claude-plugin/marketplace.json — that is what Claude
// Code keys the entry by. plugin/test/enable-auto-update.test.mjs pins the pair;
// the manifest does not ship inside the plugin, so it cannot be read at runtime.
export const MARKETPLACE = "agent-sanitizer";

const isTruthy = (value) => value === "1" || value === "true";

/** Where Claude Code keeps the marketplace registry, honouring its own overrides. */
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

/** Exits with `message` on stderr — for a state the user is expected to fix. */
function fail(message) {
  process.stderr.write(`agent-sanitizer: ${message}\n`);
  process.exit(1);
}

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
    if (error.code !== "ENOENT") throw error;
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
  // Same 2-space encoding Claude Code writes, staged through a sibling temp file
  // so an interrupted write cannot leave the registry truncated.
  const temp = `${path}.agent-sanitizer.tmp`;
  writeFileSync(temp, JSON.stringify(updated, null, 2), "utf-8");
  renameSync(temp, path);

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
