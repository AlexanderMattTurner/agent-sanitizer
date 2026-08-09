#!/usr/bin/env node
/**
 * PreToolUse guard on `git worktree remove`: refuse to tear a worktree down
 * while it still holds uncommitted work.
 *
 * THE INCIDENT. An agent ran `git add -A`, then `git diff` — which reports
 * nothing once changes are STAGED — read that as "clean", and ran
 * `git worktree remove --force`. The edits went with the directory. Nothing in
 * the harness objected, because the one command that would have seen them,
 * `git status --porcelain`, was never the one being consulted.
 *
 * WHY --force IS THE WHOLE STORY. Plain `git worktree remove` already declines
 * on a worktree holding modified or untracked files; git guards that case
 * itself. `--force` exists precisely to switch the guard off, and an agent that
 * has just convinced itself the tree is clean reaches for it without friction.
 * So the eliminator cannot live in judgement — it has to be a second opinion
 * from the one command that sees the index.
 *
 * WHAT IT DOES, AND WHAT IT DELIBERATELY DOES NOT. It never parses the shell
 * command to work out which worktree is targeted: recovering an argument from a
 * command line means re-implementing quoting, and a guard that gets that subtly
 * wrong is worse than none. Instead it asks GIT for the linked worktrees and
 * reports any that are dirty. The verdict is `ask`, not `deny` — removing a
 * DIFFERENT, clean worktree while some other one is dirty is legitimate, so the
 * cost of the imprecision is one prompt naming exactly what is at stake, never a
 * block. Fails open on any fault: this guard must not be the reason a session
 * cannot clean up after itself.
 */
import { execFileSync } from "node:child_process";

import { errMessage, isMain, readStdinJson } from "./lib-hook-io.mjs";

/**
 * Coarse text test for whether the payload is worth asking git about. It only
 * decides whether to LOOK — every fact in the verdict below comes from git, so a
 * false positive here costs one `git worktree list` and produces no finding.
 */
const REMOVE_RE = /\bgit\b[^\n]*\bworktree\b[^\n]*\bremove\b/;

/**
 * Linked worktrees of the repo at `cwd`, main and bare ones excluded — those are
 * not removable, so their state is never at risk from this command.
 * @param {string} cwd
 * @param {(file: string, args: string[], cwd: string) => string} run
 * @returns {string[]} absolute worktree paths
 */
export function linkedWorktrees(cwd, run) {
  const records = run("git", ["worktree", "list", "--porcelain"], cwd).split(
    "\n\n",
  );
  const paths = [];
  // The first record is always the main worktree; `bare` marks a bare repo's.
  for (const record of records.slice(1)) {
    if (/^bare$/m.test(record)) continue;
    const line = record.split("\n").find((l) => l.startsWith("worktree "));
    if (line) paths.push(line.slice("worktree ".length));
  }
  return paths;
}

/**
 * The worktrees among `paths` that hold uncommitted work, with a count of the
 * entries at stake. `status --porcelain` is the point of the whole hook: it
 * reports staged changes, unstaged changes and untracked files alike, which is
 * the blind spot `git diff` left.
 * @param {string[]} paths
 * @param {(file: string, args: string[], cwd: string) => string} run
 * @returns {Array<{path: string, entries: number}>}
 */
export function dirtyWorktrees(paths, run) {
  const dirty = [];
  for (const path of paths) {
    const status = run("git", ["status", "--porcelain"], path).trim();
    if (status !== "") dirty.push({ path, entries: status.split("\n").length });
  }
  return dirty;
}

/**
 * The PreToolUse response for a payload, or null to stay silent.
 * @param {unknown} payload
 * @param {{cwd: string, run: (file: string, args: string[], cwd: string) => string}} io
 * @returns {object|null}
 */
export function judgeTeardown(payload, io) {
  const input = /** @type {any} */ (payload)?.tool_input ?? {};
  const command = typeof input.command === "string" ? input.command : "";
  if (!REMOVE_RE.test(command)) return null;

  const dirty = dirtyWorktrees(linkedWorktrees(io.cwd, io.run), io.run);
  if (dirty.length === 0) return null;

  const detail = dirty
    .map((w) => `${w.path} (${w.entries} uncommitted ${plural(w.entries)})`)
    .join(", ");
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "ask",
      permissionDecisionReason:
        `A linked worktree still holds uncommitted work: ${detail}. ` +
        "`git worktree remove --force` deletes it with the directory, and it is not in any commit " +
        "or on any branch, so nothing can bring it back. Note that `git diff` reports NOTHING once " +
        "changes are staged — run `git status --porcelain` in that worktree and commit or stash " +
        "what it lists before removing. Approve this call only if the loss is intended.",
    },
  };
}

const plural = (n) => (n === 1 ? "entry" : "entries");

/**
 * @param {string} file
 * @param {string[]} args
 * @param {string} cwd
 * @returns {string}
 */
const runGit = (file, args, cwd) =>
  execFileSync(file, args, { cwd, encoding: "utf8" });

if (isMain(import.meta.url)) {
  try {
    const response = judgeTeardown(await readStdinJson(), {
      cwd: process.env.CLAUDE_PROJECT_DIR || process.cwd(),
      run: runGit,
    });
    if (response !== null) process.stdout.write(JSON.stringify(response));
  } catch (err) {
    // Fails open: a broken guard must not strand a session that needs to clean
    // up. Loud on stderr, because a silent fault is how it stays broken.
    process.stderr.write(
      `worktree-teardown-check hook fault (failing open, tool call unaffected): ${errMessage(err)} — ` +
        "likely a bug; please file an issue: https://github.com/AlexanderMattTurner/agent-sanitizer/issues/new\n",
    );
    process.exit(0);
  }
}
