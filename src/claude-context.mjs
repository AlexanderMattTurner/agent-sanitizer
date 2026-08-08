/**
 * WHICH files an agent loads as model context, as data: the glob set and the
 * walk-pruning predicate that together define "everything Claude Code reads as
 * instructions, and nothing else".
 *
 * This is the SINGLE SOURCE for that scope. It used to live inside
 * `claude-hooks/scan-invisible-chars.mjs`, which meant the SessionStart hook
 * knew the answer and nobody else did: `src/instructions.mjs` takes
 * caller-supplied globs by design (no agent's convention is baked into the
 * engine), so the CLI, the Python port and every downstream fork spelled their
 * own approximation of this list — and an approximation that drifts either
 * scans bulk data that can never reach the model (the 30-second session start
 * this whitelist exists to fix) or MISSES a context directory entirely, which
 * is a silent hole in the one scan standing between a poisoned instruction file
 * and a session that loads it.
 *
 * It is a standalone, dependency-free DATA module (like ./cf-charset.mjs) for
 * two reasons: `src/instructions.mjs` re-exports it as the library's public
 * door, and the hook imports it RELATIVELY — deliberately not through the
 * `agent-sanitizer` specifier the plugin bundle pins to a published engine.
 * This scope is hook POLICY, not engine behavior: it must ship and move with the
 * hook that walks it, or a plugin built against an older pin would prune the
 * wrong directories while believing it had scanned everything.
 */

/**
 * The `.claude/` subdirectories whose markdown Claude Code loads as model
 * context. This is a WHITELIST, and that is the point: `.claude/` is also where
 * tooling parks bulk data that is never loaded as context — `worktrees/`
 * (entire checked-out copies of the repo), plus caches, transcripts and
 * snapshots — and globbing `.claude/**` swept all of it in. On a repo with a few
 * populated worktrees that is thousands of files READ at every session start:
 * one report put it at 30 seconds of blocked startup, paid for scanning files
 * that cannot reach the model.
 *
 * A whitelist, not a `worktrees` denylist, because the failure modes are not
 * symmetric: an unlisted context directory costs a scan nobody asked for anyway
 * (the PostToolUse sanitizer still cleans those bytes when a tool reads them),
 * while an unlisted BULK directory silently costs every future session its
 * startup. Add an entry here when Claude Code starts loading a new `.claude/`
 * subdirectory as context.
 */
export const CLAUDE_CONTEXT_SUBDIRS = Object.freeze([
  "agents",
  "commands",
  "output-styles",
  "skills",
]);

// The glob patterns for one `.claude` tree at `prefix` (empty for the project
// root, a doubled-star segment for nested ones): its top-level markdown, plus the
// whitelisted context subdirectories. Built once, from the one list above.
/** @param {string} prefix @returns {string[]} */
function claudeDirPatterns(prefix) {
  return [
    `${prefix}.claude/*.md`,
    ...CLAUDE_CONTEXT_SUBDIRS.map((sub) => `${prefix}.claude/${sub}/**/*.md`),
  ];
}

/**
 * Every glob whose matches Claude Code loads as model context: the
 * per-directory instruction files (CLAUDE.md, CLAUDE.local.md, AGENTS.md) and
 * the whitelisted `.claude/` markdown. Claude Code loads these on entry to their
 * containing directory — a load path that bypasses the PostToolUse sanitizer —
 * so a payload planted in e.g. `packages/foo/CLAUDE.md` reaches the model
 * uncleaned unless something scans it here.
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
  "**/CLAUDE.md",
  "**/CLAUDE.local.md",
  "**/AGENTS.md",
  ...claudeDirPatterns("**/"),
]);

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

/**
 * Entries a context scan must not descend into or return: `node_modules`, and
 * every child of a `.claude` directory that is not whitelisted context.
 *
 * The globs alone would already refuse to MATCH those files, but a glob walker
 * calls this on directories as it walks and prunes the ones it rejects — which
 * is where the cost actually is. Without the prune, a `.claude/worktrees/`
 * holding a few repo checkouts is walked in full on every session start (and,
 * because a doubled-star segment does cross into a dot directory when the
 * pattern names one, a `.claude` NESTED inside a worktree was matched and
 * scanned as if it were this session's context).
 *
 * A walker calls this with both bare names and root-relative paths, so it must
 * answer for either; a bare name carries no `.claude` context and is judged only
 * against `node_modules`.
 * @param {string} entry  a bare entry name or a path relative to the scan root
 * @returns {boolean}
 */
export function excludeFromContextScan(entry) {
  if (excludeNodeModules(entry)) return true;
  const parts = entry.split(/[/\\]/);
  const claudeIndex = parts.indexOf(".claude");
  const tail = parts.slice(claudeIndex + 1);
  if (claudeIndex === -1 || tail.length === 0) return false;
  // `.claude/<file>.md` is context (a top-level note); anything else directly
  // under `.claude` must be a whitelisted subdirectory to be walked at all.
  if (tail.length === 1 && tail[0].endsWith(".md")) return false;
  return !CLAUDE_CONTEXT_SUBDIRS.includes(tail[0]);
}
