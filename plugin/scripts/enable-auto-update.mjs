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
import { randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  fchmodSync,
  fsyncSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
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
 * Replaces the registry with `contents`, atomically.
 *
 * The staging name is crypto-random and created with `O_EXCL`, because Claude
 * Code writes this same file and a second run of this script can be underway:
 * a fixed name is a path two writers meet on, where one truncates the other's
 * half-written copy and renames it over the registry. `O_EXCL` also refuses a
 * symlink planted at that name rather than writing through it. The bytes are
 * `fsync`ed before the rename and the directory after it, so a crash can leave
 * the registry only as it was or as it will be, never truncated. `fchmod`
 * restores the registry's exact mode, which `openSync`'s umask-masked create
 * mode would otherwise drop.
 *
 * A refused write is a state the user can act on, so it exits with the two
 * routes that do work instead of a stack trace; every other errno propagates.
 * Either way the staged copy is unlinked first, so no failure path leaves one
 * behind for the registry's owner to find.
 *
 * @param {string} path
 * @param {string} contents
 * @param {boolean} disable  which invocation to hand back for a rerun
 */
function replaceRegistry(path, contents, disable) {
  const dir = dirname(path);
  const temp = join(dir, `.${randomBytes(12).toString("hex")}.tmp`);
  const mode = statSync(path).mode & 0o7777;
  // Whether a temp of OURS is sitting at `temp` — the only file this run may
  // clean up, and the only one it can have created under a name it just drew.
  let staged = false;
  /** @type {number|null} */
  let fd = null;
  try {
    fd = openSync(
      temp,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
      mode,
    );
    staged = true;
    // writeFileSync(fd, …) loops until every byte lands; a bare writeSync can
    // short-write. It does not close the fd.
    writeFileSync(fd, contents, "utf-8");
    fchmodSync(fd, mode);
    fsyncSync(fd);
    closeSync(fd);
    fd = null;
    renameSync(temp, path);
    staged = false;
    fsyncDir(dir);
  } catch (error) {
    if (fd !== null) closeSync(fd);
    if (staged)
      try {
        unlinkSync(temp);
      } catch {
        // Best-effort cleanup only: the failure reported below is the ORIGINAL
        // one, not a secondary unlink error, so the real cause stays loud.
      }
    const code = /** @type {NodeJS.ErrnoException} */ (error).code;
    if (!REFUSED.has(code ?? "")) throw error;
    fail(
      `cannot write ${path} (${code}) — the OS refused it. Claude Code's Bash ` +
        `sandbox confines writes to the workspace, so no session that runs ` +
        `under it can reach the plugin cache; rerunning here cannot succeed.\n` +
        `Run this yourself, in a terminal outside Claude Code:\n` +
        `  ${rerunCommand(disable)}\n` +
        `Or toggle it without a terminal: /plugin -> Marketplaces -> ` +
        `${MARKETPLACE} -> Enable auto-update.\n` +
        `If the terminal refuses it too, the file's owner or permissions need ` +
        `fixing.`,
    );
  }
}

/**
 * The errnos that make a directory `fsync` unavailable rather than failed.
 * {@link REFUSED} is what the caller reads as "the write did not happen";
 * `EISDIR` is Windows' ordinary answer to a read-only open of a directory, and
 * `EINVAL` is what some filesystems answer to an `fsync` on a directory fd.
 */
const DIR_FSYNC_UNAVAILABLE = new Set([...REFUSED, "EISDIR", "EINVAL"]);

/**
 * Whether `error` says this host cannot fsync a directory at all.
 * @param {unknown} error
 */
const dirFsyncUnavailable = (error) =>
  DIR_FSYNC_UNAVAILABLE.has(
    /** @type {NodeJS.ErrnoException} */ (error).code ?? "",
  );

/**
 * `fsync`s a directory, so a rename into it survives a crash — a rename is a
 * directory metadata change, which flushing the file's own data blocks does not
 * make durable.
 *
 * Runs after the rename has landed, so a refused open or `fsync` costs
 * durability, not correctness — and the caller reads exactly {@link REFUSED} as
 * "the write did not happen", so letting one of those codes out of either call
 * would report a registry that was in fact updated as a refused write. Those it
 * swallows; every other errno (`EMFILE`, `ENFILE`, `EIO`) is a real fault the
 * caller propagates.
 *
 * @param {string} dir
 */
function fsyncDir(dir) {
  /** @type {number} */
  let fd;
  try {
    fd = openSync(dir, constants.O_RDONLY);
  } catch (error) {
    if (!dirFsyncUnavailable(error)) throw error;
    return;
  }
  try {
    fsyncSync(fd);
  } catch (error) {
    if (!dirFsyncUnavailable(error)) throw error;
  } finally {
    closeSync(fd);
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
