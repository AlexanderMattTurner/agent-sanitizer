/**
 * What git says is NOT this checkout's own source, as a prune set for an
 * instruction-file walk: the directories it ignores wholesale, and the linked
 * worktrees nested inside the scan root. A context scan that walks those pays
 * for a build tree it will never load from, and reports — and on the auto-clean
 * path REWRITES — another branch's copy of a file this checkout does not own.
 *
 * Git is asked rather than `.gitignore` parsed: it owns that grammar, nested
 * files, `info/exclude` and `core.excludesFile` included, and the answer is one
 * subprocess away.
 *
 * Every entry is a DIRECTORY. `git ls-files -o -i` also lists ignored FILES, and
 * discarding those is what keeps `CLAUDE.local.md` — gitignored by convention,
 * and loaded as model context at launch — inside every scan.
 *
 * Kept out of ./claude-context.mjs, which promises a dependency-free data module
 * with no filesystem of its own.
 */
import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { relative, resolve, sep } from "node:path";

import { excludeFromContextScan, isInsideDir } from "./claude-context.mjs";

/**
 * How git is asked. Injectable so a test can drive the failure paths, which no
 * filesystem state can force.
 * @typedef {(file: string, args: string[], cwd: string) => string} GitRun
 */

// Both bounds exist so a scan cannot hang or balloon on a pathological repo:
// past either one the query is abandoned and the walk keeps its wider,
// pre-prune scope (see askGit).
const GIT_TIMEOUT_MS = 10_000;
const GIT_MAX_BUFFER = 32 * 1024 * 1024;

/**
 * The default {@link GitRun}: git's stdout, with its stderr dropped so a
 * dubious-ownership complaint never lands in the operator's terminal from a
 * scan that recovers from it anyway.
 * @type {GitRun}
 */
const runGit = (file, args, cwd) =>
  execFileSync(file, args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
    timeout: GIT_TIMEOUT_MS,
    maxBuffer: GIT_MAX_BUFFER,
  });

/**
 * `git <args>` in `dir`, or null when git cannot answer — not a repo, git
 * absent, dubious ownership, a timeout, output past `maxBuffer`.
 *
 * The one recovery this module needs, and it is what keeps the prune from ever
 * being a new way for a session to fail: null degrades the caller to the WIDER
 * scope it walked before this prune existed. A throw with neither an errno nor
 * an exit status is not git refusing, it is a bug here, and it propagates.
 * @param {GitRun} run
 * @param {string[]} args
 * @param {string} dir
 * @returns {string | null}
 */
function askGit(run, args, dir) {
  try {
    return run("git", args, dir);
  } catch (err) {
    const spawned = /** @type {NodeJS.ErrnoException & {status?: number}} */ (
      err
    );
    if (spawned.code === undefined && spawned.status === undefined) throw err;
    return null;
  }
}

// `-z` because the newline-framed form cannot represent a worktree whose path
// contains a newline: the record truncates mid-path, and both readers below
// then name a directory that does not exist. It needs git >= 2.36, and an
// older git rejects the flag rather than mis-answering — the prune degrades
// through askGit to its wider pre-prune scope, and the teardown guard reaches
// its own entrypoint catch.
const WORKTREE_LIST_ARGS = Object.freeze([
  "worktree",
  "list",
  "--porcelain",
  "-z",
]);

/**
 * Whether `attrs` carries `name`, as a bare flag or with a value after it.
 * @param {string[]} attrs @param {string} name @returns {boolean}
 */
const hasAttribute = (attrs, name) =>
  attrs.some((attr) => attr === name || attr.startsWith(`${name} `));

/**
 * The linked worktrees in a `git worktree list --porcelain -z` dump, main and
 * bare ones excluded — those are not removable, so their state is never at risk
 * from a teardown command, and the main one is the scan root a prune must never
 * swallow.
 * @param {string} porcelain
 * @returns {string[]} absolute worktree paths
 */
export function parseWorktreeList(porcelain) {
  const paths = [];
  // Attributes are NUL-TERMINATED and a record ends with the resulting empty
  // attribute, so records split on a doubled NUL. The first is always the main
  // worktree; `bare` marks a bare repo's. `prunable` marks one whose directory
  // is already gone — it holds no work to lose, and asking git for its status
  // would only spawn into a missing cwd.
  for (const record of porcelain.split("\0\0").slice(1)) {
    const attrs = record.split("\0");
    if (hasAttribute(attrs, "bare") || hasAttribute(attrs, "prunable"))
      continue;
    const line = attrs.find((attr) => attr.startsWith("worktree "));
    if (line) paths.push(line.slice("worktree ".length));
  }
  return paths;
}

/**
 * The linked worktrees of the repo at `cwd`. The guard on `git worktree remove`
 * asks this the same way the prune below does, so one parser answers for both.
 * @param {string} cwd
 * @param {GitRun} run
 * @returns {string[]} absolute worktree paths
 */
export function linkedWorktrees(cwd, run) {
  return parseWorktreeList(run("git", [...WORKTREE_LIST_ARGS], cwd));
}

/**
 * The directories under `dir` that git ignores wholesale. `--directory`
 * collapses each to a single trailing-slash entry, and that slash is the only
 * thing separating an ignored directory from an ignored FILE in this output —
 * dropping the files is what keeps a gitignored instruction file scannable.
 *
 * `-z` because without it git C-quotes any path with a space, a quote or a
 * non-ASCII byte under `core.quotePath`, and the prune would silently miss
 * exactly those directories.
 * @param {string} dir
 * @param {GitRun} run
 * @returns {string[]}
 */
function ignoredDirectories(dir, run) {
  const out = askGit(
    run,
    ["ls-files", "-o", "-i", "--directory", "--exclude-standard", "-z"],
    dir,
  );
  if (out === null) return [];
  return out
    .split("\0")
    .filter((entry) => entry.endsWith("/"))
    .map((entry) => entry.slice(0, -1));
}

/**
 * The worktrees git has registered that live inside `dir`, as paths relative to
 * it. A nested checkout is not ignored by default, so nothing but git's own
 * registry can tell it apart from an ordinary subdirectory.
 * @param {string} dir
 * @param {GitRun} run
 * @returns {string[]}
 */
function nestedWorktrees(dir, run) {
  const out = askGit(run, [...WORKTREE_LIST_ARGS], dir);
  if (out === null) return [];
  // git reports PHYSICAL paths, so a scan root reached through a symlink only
  // ever matches once both sides are canonical. The relative tail it yields is
  // valid under the literal spelling too, which is what the walker's entries
  // are relative to. Asked after the git call so a missing `dir` still fails
  // open through the spawn's ENOENT rather than throwing here.
  const root = realpathSync(dir);
  return parseWorktreeList(out)
    .map((path) => resolve(path))
    .filter((path) => isInsideDir(root, path))
    .map((path) => relative(root, path).split(sep).join("/"));
}

// One prune set per scan root, because launchInstructionFiles runs on many tool
// calls and each would otherwise spawn git twice. Bypassed for an injected
// `run`, so a test never reads another test's answer. A worktree added
// mid-process is missed until the next process, which is the same staleness the
// walk's own glob already has.
/** @type {Map<string, Set<string>>} */
const pruneCache = new Map();

/**
 * Directory paths a context scan of `dir` must not walk, relative to it and
 * `/`-separated: every wholly-ignored directory (unless `ignoredDirs` is off)
 * and every linked worktree nested inside it.
 * @param {string} dir
 * @param {{ ignoredDirs?: boolean, run?: GitRun }} [options]
 * @returns {Set<string>}
 */
export function repoPrunedDirs(dir, { ignoredDirs = true, run } = {}) {
  const key = `${resolve(dir)}\0${ignoredDirs}`;
  const cached = run === undefined ? pruneCache.get(key) : undefined;
  if (cached !== undefined) return cached;
  const ask = run ?? runGit;
  const pruned = new Set([
    ...(ignoredDirs ? ignoredDirectories(dir, ask) : []),
    ...nestedWorktrees(dir, ask),
  ]);
  if (run === undefined) pruneCache.set(key, pruned);
  return pruned;
}

/**
 * The `exclude` predicate for an instruction-file walk of `dir`: the static
 * context-scope prune, plus {@link repoPrunedDirs}.
 *
 * `ignoredDirs: false` is the LAUNCH scan's posture, and it is a security
 * choice rather than a performance one: `.gitignore` is repo-controlled, so
 * honouring it in the one scan that covers launch-time ingress would let a
 * hostile repo hide a planted `.claude/skills/…/SKILL.md` from it by ignoring
 * that directory. The whole-tree scan can honour it because anything it prunes
 * is still scanned by scan-loaded-instructions at the moment the host loads it.
 *
 * The lookup is EXACT, so the walk must hand it the same spelling
 * {@link repoPrunedDirs} uses — one root-relative, `/`-separated path per entry,
 * which is what walkContextGlobs normalizes to. A predicate that accepted a bare
 * name as well would prune a tracked `src/build/` for a top-level ignored
 * `build/`, splicing real instruction files out of the scan.
 * @param {string} dir
 * @param {{ ignoredDirs?: boolean, run?: GitRun }} [options]
 * @returns {(entry: string) => boolean}
 */
export function contextScanExclude(dir, options = {}) {
  const pruned = repoPrunedDirs(dir, options);
  return (entry) => excludeFromContextScan(entry) || pruned.has(entry);
}
