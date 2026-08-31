/**
 * WHICH files an agent loads as model context, as data: one table of context
 * KINDS, and the views of it each load moment needs — a launch-time glob set, a
 * whole-tree glob set, and the check that can tell the table it is wrong.
 *
 *   - {@link CLAUDE_LAUNCH_GLOBS} + {@link ancestorInstructionFiles} — what
 *     loads AT LAUNCH, costing a shallow glob and a walk up the parent chain
 *     whatever the tree below holds.
 *   - {@link CLAUDE_INSTRUCTION_GLOBS} — every instruction file ANYWHERE in a
 *     tree. A SessionStart hook must not walk this: a launch in `$HOME` charges
 *     the whole home tree — ~100 seconds of blocked startup — for files that
 *     mostly never load, and the InstructionsLoaded hook scans those as they do.
 *   - {@link contextScopeContradiction} — what a file the host just loaded says
 *     about this table, so a stale row surfaces as a notice, not as a hole.
 *
 * A standalone DATA module with no package dependency: `src/instructions.mjs`
 * re-exports it as the library's public door, and the hooks import it RELATIVELY
 * rather than through the `agent-sanitizer` specifier the plugin bundle pins to a
 * published engine. This scope is hook POLICY, not engine behavior — it must move
 * with the hook that walks it, or a plugin built against an older pin prunes the
 * wrong directories while believing it scanned everything.
 */
import { dirname, isAbsolute, join, relative, resolve } from "node:path";

// One row of the kind table. Both flags default to the conservative answer —
// this kind is not on the ancestor chain, and no event announces it — so a row
// added without them claims nothing the host has not been observed doing. Both
// describe how a kind LOADS, so neither means anything on a `claude-bulk` row:
// the readers below gate on shape before they read either flag.
/**
 * @param {"dir-file" | "claude-md" | "claude-subdir" | "claude-bulk"} shape
 * @param {string} name  how a reader spells this kind
 * @param {{ ancestorChain?: boolean, eventNamed?: boolean }} [flags]
 */
function kind(shape, name, { ancestorChain = false, eventNamed = false } = {}) {
  return Object.freeze({ shape, name, ancestorChain, eventNamed });
}

/**
 * Every kind of file an agent loads as model context — plus, as `claude-bulk`
 * rows, the `.claude/` directories that hold anything BUT context, so a consumer
 * filtering this table must filter on `shape` and never take it whole.
 *
 * Each row carries the two facts code branches on. `shape` says where the kind
 * lives; `ancestorChain` says whether Claude Code also loads it from the
 * directories ABOVE a scan root; `eventNamed` says whether `InstructionsLoaded`
 * names it as it loads, the claim {@link contextScopeContradiction} checks.
 *
 * Shapes:
 *   - `dir-file` — `name`, in any directory (`packages/foo/CLAUDE.md`).
 *   - `claude-md` — top-level markdown directly under a `.claude/` directory.
 *   - `claude-subdir` — `.claude/<name>/` and everything markdown below it.
 *   - `claude-bulk` — `.claude/<name>/`, holding data that is not context.
 *
 * The `claude-subdir` rows are a WHITELIST: an unlisted context directory costs
 * a scan nobody paid for anyway, while an unlisted BULK directory costs every
 * future session its startup. The `claude-bulk` rows name the bulk directories
 * this project has seen, so a load out of one asks for no whitelist entry.
 */
export const CLAUDE_CONTEXT_KINDS = Object.freeze([
  kind("dir-file", "CLAUDE.md", { ancestorChain: true, eventNamed: true }),
  kind("dir-file", "CLAUDE.local.md", {
    ancestorChain: true,
    eventNamed: true,
  }),
  // AGENTS.md is the cross-agent convention Claude Code does not read itself,
  // kept because this package guards agents generally. Off the ancestor chain
  // for the same reason: that load is Claude Code's rule.
  kind("dir-file", "AGENTS.md"),
  kind("claude-md", ".claude/*.md"),
  kind("claude-subdir", "agents"),
  kind("claude-subdir", "commands"),
  kind("claude-subdir", "output-styles"),
  kind("claude-subdir", "rules", { eventNamed: true }),
  kind("claude-subdir", "skills"),
  // Repo checkouts and session transcripts: storage the host writes and reads
  // back, so a load out of one is not evidence that the whitelist is short.
  kind("claude-bulk", "worktrees"),
  kind("claude-bulk", "projects"),
  kind("claude-bulk", "todos"),
]);

/** The rows of one shape, in table order. @param {string} shape */
function kindsOfShape(shape) {
  return CLAUDE_CONTEXT_KINDS.filter((row) => row.shape === shape);
}

// The names of `rows`, frozen: what a caller that wants one shape's spelling —
// a glob builder, the parent-chain walk — reads off the table.
/** @param {readonly {name: string}[]} rows @returns {readonly string[]} */
function namesOf(rows) {
  return Object.freeze(rows.map((row) => row.name));
}

/** The `.claude/` subdirectories whose markdown loads as model context. */
export const CLAUDE_CONTEXT_SUBDIRS = namesOf(kindsOfShape("claude-subdir"));

/** The `.claude/` subdirectories known to hold storage rather than context. */
const CLAUDE_BULK_SUBDIRS = namesOf(kindsOfShape("claude-bulk"));

/**
 * Claude Code's own per-directory memory files: the kinds it loads from every
 * directory above a scan root as well as from the root itself.
 */
export const CLAUDE_MEMORY_FILES = namesOf(
  // Shape first: only a per-directory file can be walked up a parent chain, so
  // no `.claude/` row can reach this list whatever its flags say.
  CLAUDE_CONTEXT_KINDS.filter(
    (row) => row.shape === "dir-file" && row.ancestorChain,
  ),
);

/** Every per-directory instruction file, memory files and `AGENTS.md` alike. */
export const CLAUDE_DIR_INSTRUCTION_FILES = namesOf(kindsOfShape("dir-file"));

// The glob patterns for one `.claude` tree at `prefix` (empty for the scan root,
// a doubled-star segment for nested ones), built from the table's rows.
/** @param {string} prefix @returns {string[]} */
function claudeDirPatterns(prefix) {
  return [
    `${prefix}.claude/*.md`,
    ...CLAUDE_CONTEXT_SUBDIRS.map((sub) => `${prefix}.claude/${sub}/**/*.md`),
  ];
}

/**
 * Every glob whose matches an agent loads as model context ANYWHERE in a tree.
 * Claude Code loads these on entry to their containing directory — a load path
 * that bypasses the PostToolUse sanitizer — so a payload planted in e.g.
 * `packages/foo/CLAUDE.md` reaches the model uncleaned unless something scans it.
 *
 * This is the WHOLE-TREE scope, for a caller scanning a project on demand (the
 * CLI, the Python port). It is not what a SessionStart hook walks — see
 * {@link CLAUDE_LAUNCH_GLOBS} for why, and for what does.
 *
 * `**` does not descend into dot directories, so NESTED `.claude/` trees need
 * their own doubled-star-prefixed patterns: without them a directory-scoped
 * skill at `packages/foo/.claude/skills/x/SKILL.md` — model context by the same
 * load path — is never matched. That same rule is why the root `.claude` needs
 * no separate entry: a leading doubled star matches zero segments, so the
 * nested patterns cover the root tree too.
 *
 * Pair with {@link excludeFromContextScan}: the patterns alone already refuse to
 * MATCH a bulk directory, but only pruning the WALK avoids paying to read it.
 */
export const CLAUDE_INSTRUCTION_GLOBS = Object.freeze([
  ...CLAUDE_DIR_INSTRUCTION_FILES.map((name) => `**/${name}`),
  ...claudeDirPatterns("**/"),
]);

/**
 * Every glob whose matches load AT LAUNCH from the scan root itself: the root's
 * own instruction files and its `.claude` context tree.
 *
 * Deliberately NOT recursive. A subdirectory's `CLAUDE.md` is loaded when Claude
 * Code reads a file in that subdirectory, not at launch, so globbing for it at
 * session start pays a whole-tree walk (the entire home directory, when the
 * session is launched there) to pre-scan files that mostly never load. The
 * InstructionsLoaded hook scans each of those at the moment it loads instead —
 * which is also the only moment that catches one created mid-session.
 *
 * Pair with {@link ancestorInstructionFiles} for the other half of the launch
 * set, and with {@link excludeFromContextScan} to prune the `.claude` walk.
 */
export const CLAUDE_LAUNCH_GLOBS = Object.freeze([
  ...CLAUDE_DIR_INSTRUCTION_FILES,
  ...claudeDirPatterns(""),
]);

/**
 * The instruction files Claude Code loads from the directories ABOVE `dir`:
 * walking up to the filesystem root, every `ancestorChain` kind in each parent
 * is loaded IN FULL at launch, so a payload planted in a parent directory
 * reaches the model exactly like one in the project's own file.
 *
 * Returns CANDIDATES — absolute paths, existing or not, because this module
 * touches no filesystem. Most parents of any directory hold neither file, so a
 * caller that buckets its misses as "absent" should filter first: ~10 phantom
 * entries per session would drown the one signal that bucket carries, a target
 * that existed when the scan listed it and vanished before the read.
 * @param {string} dir  the scan root; its own files are NOT included
 * @returns {string[]}
 */
export function ancestorInstructionFiles(dir) {
  /** @type {string[]} */
  const files = [];
  let current = resolve(dir);
  // `dirname` is its own fixed point at the filesystem root, which is what ends
  // the walk on every platform without spelling a root path here.
  for (
    let parent = dirname(current);
    parent !== current;
    parent = dirname(current)
  ) {
    current = parent;
    for (const name of CLAUDE_MEMORY_FILES) files.push(join(current, name));
  }
  return files;
}

/**
 * Whether `file` lives inside `dir`. Lexical, on already-absolute paths, and the
 * bound on where an instruction-file scanner may REWRITE: a file above the scan
 * root is shared with every other project beneath that root, so it is reported
 * rather than silently edited. Both scanners ask this — one for a target it
 * globbed, one for a path an event handed it — and a copy each is a copy that
 * can drift into rewriting a file the other would not.
 *
 * Symlinks are deliberately not resolved: the guard that stops a link from
 * redirecting the write has to live at the write itself (cleanFile opens
 * O_NOFOLLOW), and resolving here would only duplicate it a check too early.
 * @param {string} dir
 * @param {string} file
 * @returns {boolean}
 */
export function isInsideDir(dir, file) {
  const rel = relative(dir, file);
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
}

/**
 * The one directory no instruction-file walk ever descends into. Its own
 * function so the name is spelled once, and so the two predicates that need it
 * (a plain glob walk, and {@link excludeFromContextScan}) cannot disagree.
 * @param {string} entry  a bare entry name or a path relative to the scan root
 * @returns {boolean}
 */
export function excludeNodeModules(entry) {
  return entry === "node_modules";
}

// The path segments below one `.claude` directory in `path`, or null when it
// names none. Pruning asks whether the path is inside a bulk directory of the
// tree being walked, so it takes the OUTERMOST — a `worktrees/` checkout carries
// a whole `.claude` of its own, below which the prune must keep applying.
// Naming a kind asks what the file IS, so it takes the INNERMOST tree.
/** @param {string} path @param {"outermost" | "innermost"} which */
function claudeTail(path, which) {
  const parts = path.split(/[/\\]/);
  const claudeIndex =
    which === "outermost"
      ? parts.indexOf(".claude")
      : parts.lastIndexOf(".claude");
  return claudeIndex === -1 ? null : parts.slice(claudeIndex + 1);
}

/**
 * Entries a context scan must not descend into or return: `node_modules`, and
 * every child of a `.claude` directory that is not whitelisted context.
 *
 * The globs alone would already refuse to MATCH those files, but a glob walker
 * calls this on directories as it walks and prunes the ones it rejects — which
 * is where the cost actually is. Without the prune, a `.claude/worktrees/`
 * holding a few repo checkouts is walked in full on every session start, and a
 * `.claude` NESTED inside a worktree is scanned as if it were this session's
 * context: a doubled-star segment does cross into a dot directory when the
 * pattern names one.
 *
 * A walker calls this with both bare names and root-relative paths, so it must
 * answer for either; a bare name carries no `.claude` context and is judged only
 * against `node_modules`.
 * @param {string} entry  a bare entry name or a path relative to the scan root
 * @returns {boolean}
 */
export function excludeFromContextScan(entry) {
  if (excludeNodeModules(entry)) return true;
  const tail = claudeTail(entry, "outermost");
  if (tail === null || tail.length === 0) return false;
  // `.claude/<file>.md` is context (a top-level note); anything else directly
  // under `.claude` must be a whitelisted subdirectory to be walked at all.
  if (tail.length === 1 && tail[0].endsWith(".md")) return false;
  return !CLAUDE_CONTEXT_SUBDIRS.includes(tail[0]);
}

/**
 * The kind `path` is an instance of, or null when this table claims none — an
 * `@import` of an arbitrary markdown file, a source file, an unlisted `.claude`
 * directory. Null is the honest answer for anything the table does not name, and
 * callers must treat it as "no claim", never as "not context".
 * @param {string} path  absolute or relative; only its segments are read
 * @returns {(typeof CLAUDE_CONTEXT_KINDS)[number] | null}
 */
function classifyContextPath(path) {
  const segments = path.split(/[/\\]/);
  const name = segments[segments.length - 1];
  // A CLAUDE.md is that kind wherever it sits, `.claude` tree or not — which is
  // what keeps the ordinary nested-memory load from reading as evidence about
  // the directory it happens to sit under.
  const dirFile = kindsOfShape("dir-file").find((row) => row.name === name);
  const tail = claudeTail(path, "innermost");
  if (dirFile || tail === null) return dirFile ?? null;
  if (tail.length === 1 && name.endsWith(".md"))
    return kindsOfShape("claude-md")[0];
  // Both directory shapes, so a bulk directory classifies as itself rather than
  // falling through to the unlisted-directory report below.
  const dirShapes = ["claude-subdir", "claude-bulk"];
  return (
    CLAUDE_CONTEXT_KINDS.find(
      (row) => dirShapes.includes(row.shape) && row.name === tail[0],
    ) ?? null
  );
}

/**
 * The `eventNamed` kinds spelled relative to the USER-GLOBAL config root — the
 * `~/.claude` (or `CLAUDE_CONFIG_DIR`) directory Claude Code loads at launch
 * whatever the project is.
 *
 * A second spelling because that root is a `.claude` directory ITSELF: its files
 * are `CLAUDE.md` and `rules/x.md`, not `.claude/rules/x.md`, and under
 * `CLAUDE_CONFIG_DIR` the path may carry no `.claude` segment at all — so
 * {@link announcedByInstructionsLoaded}, which reads a path's own segments, has
 * nothing there to classify by. Every row's shape is asserted in
 * test/claude-context.test.mjs, since a shape with no spelling here would glob
 * to nothing and read as "no event is coming".
 */
export const USER_GLOBAL_EVENT_NAMED_GLOBS = Object.freeze(
  CLAUDE_CONTEXT_KINDS.filter((row) => row.eventNamed).map((row) =>
    row.shape === "dir-file" ? row.name : `${row.name}/**/*.md`,
  ),
);

/**
 * Whether Claude Code announces loading `path` with an `InstructionsLoaded`
 * event — the `eventNamed` column of {@link CLAUDE_CONTEXT_KINDS}, asked of one
 * path.
 *
 * The complement of {@link contextScopeContradiction}, which checks the same
 * column against an event that DID fire. This one answers before any fires, so a
 * consumer can tell "the event is not coming" from "the event never came": a
 * launch carrying only an `AGENTS.md` or a skill has nothing for the host to
 * announce, and its silence is evidence of nothing.
 *
 * A path the table does not name gets `false`, the same conservative answer a
 * row added without the flag gets: this says an event IS coming, never that a
 * file is uninteresting.
 * @param {string} path  absolute or relative; only its segments are read
 * @returns {boolean}
 */
export function announcedByInstructionsLoaded(path) {
  return classifyContextPath(path)?.eventNamed === true;
}

// The `load_reason` values that mean Claude Code reached the file on its own —
// its launch scan, and its walk into a directory. Every other reason names a
// file something else chose, which is not evidence about the scan's scope.
const HOST_CHOSEN_LOAD_REASONS = ["session_start", "nested_traversal"];

/**
 * What a file the host just loaded as model context says about this table, or
 * null when it says nothing new. The InstructionsLoaded event is the only
 * observation that can prove the table wrong, and this is what it proves:
 *
 *   - a `.claude/` subdirectory outside {@link CLAUDE_CONTEXT_SUBDIRS} loading
 *     as context means the launch scan skips that whole directory — the file
 *     here was scanned, every other file in it was not;
 *   - a kind the table marks `eventNamed: false` being named means the event's
 *     coverage is wider than the docs claim, and the lazy scan reaches files
 *     nothing was crediting it with.
 *
 * Both observations are about what the host reaches ON ITS OWN, so both require
 * a host-chosen `loadReason`: an `@import` names a file the user's own markdown
 * pointed at, and acting on it would either whitelist an import target or credit
 * the event with a kind it reaches only when imported. An unrecognized reason is
 * treated the same way, so this loses a notice rather than inventing one.
 *
 * A path the table does not name at all says nothing about the table either, so
 * it returns null rather than guessing. A `claude-bulk` row is silent for the
 * reason in reverse: the table already knows that directory is storage.
 * @param {string} path  the path the host loaded
 * @param {string} loadReason  the event's `load_reason`, or "unknown" when the
 *   host sent none; required rather than defaulted, since every observation here
 *   holds only for a load the host chose itself
 * @returns {string | null} what is stale, phrased for whoever fixes the table
 */
export function contextScopeContradiction(path, loadReason) {
  if (!HOST_CHOSEN_LOAD_REASONS.includes(loadReason)) return null;
  const row = classifyContextPath(path);
  if (row?.eventNamed || row?.shape === "claude-bulk") return null;
  if (row)
    return (
      `InstructionsLoaded named ${row.name}, which CLAUDE_CONTEXT_KINDS records as a kind the ` +
      "event never names: the lazy scan reaches further than this table, and the docs built " +
      "on it, claim"
    );
  const tail = claudeTail(path, "innermost");
  if (tail === null || tail.length < 2) return null;
  // A `.claude` tree nested inside storage describes that checkout's own layout,
  // not this project's: whitelisting a directory that exists only inside a
  // pruned worktree adds nothing the launch scan would ever walk.
  const outer = /** @type {string[]} */ (claudeTail(path, "outermost"));
  if (CLAUDE_BULK_SUBDIRS.includes(outer[0])) return null;
  return (
    `.claude/${tail[0]}/ loaded as model context, and CLAUDE_CONTEXT_SUBDIRS does not list it: ` +
    "the SessionStart scan prunes that directory, so every OTHER file in it goes unscanned. " +
    "Add it there if it is context, not bulk data"
  );
}
