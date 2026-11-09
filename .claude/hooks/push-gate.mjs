#!/usr/bin/env node
/**
 * PreToolUse gate: before a push or a new pull request, run `pre-push-check.sh`
 * (the configured build, lint, typecheck, tests and ruff) and DENY the call when
 * a check fails. A push the checks let through is then recorded for
 * `completion-check.mjs`.
 *
 * The checks run on the PUSHED tree: each commit the push publishes, checked
 * out alone in a throwaway worktree of the repository the push runs in. The
 * session's own checkout is the wrong subject twice over — a push from another
 * worktree (`cd /tmp/wt && git push`, `git -C …`) never touches it, and its
 * uncommitted edits are not pushed — and concurrent runs in one checkout share
 * build and coverage output. A PR create checks `HEAD` of the call's cwd.
 *
 * The deny body is what blocks. Claude Code treats a hook's exit 1 as a
 * non-blocking error and runs the tool call anyway, so a check script that only
 * exits non-zero gates nothing.
 *
 * Posture: a GATE on the calls `lib-shell-intent.mjs` classifies as a push or a
 * PR create. A check that fails, or that cannot start, denies. A payload this
 * hook cannot read passes, because nothing then says it is a push. A speed bump,
 * not a boundary: the session can edit this file and the checks it runs.
 * Dependency-free on purpose: the template ships no node_modules.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { envWithoutGitLocation } from "../../.hooks/lib/git-location-env.mjs";
import { recordPush, statePath } from "./completion-check.mjs";
import { denyToolCall, isMain, readStdinJson } from "./lib-hook-io.mjs";
import {
  gitPushInvocations,
  opensPullRequest,
  pushesCommits,
} from "./lib-shell-intent.mjs";

const CHECK_SCRIPT = fileURLToPath(
  new URL("./pre-push-check.sh", import.meta.url),
);

/** Lines of check output the deny reason keeps: the tail, where a failure is named. */
export const REASON_TAIL_LINES = 200;

/** `git push` options that take the next word as their value. */
const PUSH_VALUE_OPTIONS = new Set([
  "--repo",
  "--receive-pack",
  "--exec",
  "-o",
  "--push-option",
]);

/** `git push` options that make every refspec a deletion. */
const PUSH_DELETE_OPTIONS = new Set(["-d", "--delete"]);

/** `git push` options that publish refs no argument names. */
const PUSH_MANY_REFS_OPTIONS = new Set(["--all", "--branches", "--mirror"]);

/** Refspecs that push every branch matching one on the remote. */
const MATCHING_REFSPECS = new Set([":", "+:"]);

/**
 * The local revisions `git push <args>` publishes: each refspec's source, or
 * `HEAD` when it names none. Empty for a deletion-only push; null when the
 * shell computes an argument or the push names no refs (`--all`, `--mirror`,
 * the matching refspec `:`).
 * @param {(string|null)[]} args @returns {string[]|null}
 */
export function pushedRevisions(args) {
  /** @type {(string|null)[]} */
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--") {
      positional.push(...args.slice(i + 1));
      break;
    }
    if (arg === null || !arg.startsWith("-")) positional.push(arg);
    else if (PUSH_MANY_REFS_OPTIONS.has(arg)) return null;
    else if (PUSH_DELETE_OPTIONS.has(arg)) return [];
    else if (PUSH_VALUE_OPTIONS.has(arg)) i++;
  }
  if (positional.includes(null)) return null;
  const refspecs = /** @type {string[]} */ (positional.slice(1));
  if (refspecs.length === 0) return ["HEAD"];
  if (refspecs.some((spec) => MATCHING_REFSPECS.has(spec))) return null;
  return refspecs
    .map((spec) => spec.replace(/^\+/, "").split(":")[0])
    .filter((source) => source !== "");
}

/**
 * Run git in `dir`. The location overrides are stripped: they beat `-C`, so an
 * inherited `GIT_DIR` would point every call at the session's repository.
 * @param {string} dir @param {string[]} args
 */
function git(dir, args) {
  return spawnSync("git", ["-C", dir, ...args], {
    encoding: "utf8",
    env: envWithoutGitLocation(process.env),
  });
}

/**
 * The repositories and commits this call publishes, or the reason they cannot
 * be named. A PR create, or a command the parser cannot read, checks `HEAD` of
 * the call's cwd.
 * @param {any} payload @param {boolean} pushes
 * @returns {Promise<{dir: string, commit: string}[]|string>}
 */
export async function pushTargets(payload, pushes) {
  const cwd = typeof payload?.cwd === "string" ? payload.cwd : process.cwd();
  const invocations = (pushes ? await gitPushInvocations(payload) : null) ?? [
    { chdirs: [], args: [] },
  ];
  /** @type {Map<string, {dir: string, commit: string}>} */
  const targets = new Map();
  for (const { chdirs, args } of invocations) {
    if (chdirs.includes(null))
      return "push-gate: cannot tell which repository this push runs in (a computed `cd`/`-C` target, `cd -`, a `cd` that may not run, or `--git-dir`/`--work-tree`); push with a literal `git -C <dir> push`.";
    const dir = resolve(
      cwd,
      ...chdirs.map((d) =>
        /** @type {string} */ (d).replace(/^~(?=\/|$)/, homedir()),
      ),
    );
    const revisions = pushedRevisions(args);
    if (revisions === null)
      return "push-gate: cannot tell which commits this push publishes (a computed refspec, `--all`/`--mirror`, or the matching refspec `:`); name each refspec literally.";
    for (const revision of revisions) {
      const parsed = git(dir, [
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        `${revision}^{commit}`,
      ]);
      if (parsed.status !== 0)
        return `push-gate: cannot resolve the pushed revision \`${revision}\` in ${dir}: ${parsed.stderr.trim() || "not a commit"}`;
      const commit = parsed.stdout.trim();
      targets.set(`${dir}\0${commit}`, { dir, commit });
    }
  }
  return [...targets.values()];
}

/**
 * Run the checks on `commit` of the repository at `repoDir`, alone in a
 * throwaway worktree. `null` when they pass, else the text that explains the
 * failure.
 * @param {string} repoDir @param {string} commit @param {string} [script]
 * @returns {string|null}
 */
export function failedChecks(repoDir, commit, script = CHECK_SCRIPT) {
  const tree = mkdtempSync(join(tmpdir(), "push-gate-"));
  const added = git(repoDir, [
    "worktree",
    "add",
    "--detach",
    "--quiet",
    tree,
    commit,
  ]);
  if (added.status !== 0) {
    rmSync(tree, { recursive: true, force: true });
    return `push-gate: could not check out ${commit} of ${repoDir}: ${added.stderr.trim()}`;
  }
  try {
    const env = {
      ...envWithoutGitLocation(process.env),
      CLAUDE_PROJECT_DIR: tree,
    };
    const install = existsSync(join(tree, "pnpm-lock.yaml"))
      ? ["install", "--frozen-lockfile", "--prefer-offline"]
      : ["install", "--prefer-offline"];
    const steps = existsSync(join(tree, "package.json"))
      ? [["pnpm", install]]
      : [];
    steps.push(["bash", [script]]);
    for (const [file, args] of steps) {
      const result = spawnSync(file, args, {
        cwd: tree,
        env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        maxBuffer: 64 * 1024 * 1024,
      });
      const step = `${file} ${args.join(" ")}`;
      if (result.error)
        return `push-gate: \`${step}\` could not run: ${result.error.message}`;
      if (result.status === 0) continue;
      const output = `${result.stdout}${result.stderr}`.trimEnd();
      const tail = output.split("\n").slice(-REASON_TAIL_LINES).join("\n");
      return `\`${step}\` exited ${result.status ?? result.signal} on ${commit.slice(0, 12)} of ${repoDir}:\n${tail}`;
    }
    return null;
  } finally {
    git(repoDir, ["worktree", "remove", "--force", tree]);
    rmSync(tree, { recursive: true, force: true });
  }
}

/**
 * The hook response for one payload: a deny body, or null to let the call run.
 * @param {any} payload
 * @param {{runChecks?: (dir: string, commit: string) => string|null, now?: () => number}} [deps] test seams
 * @returns {Promise<ReturnType<typeof denyToolCall>|null>}
 */
export async function judgePush(payload, deps = {}) {
  const pushes = await pushesCommits(payload);
  if (!pushes && !(await opensPullRequest(payload))) return null;
  const targets = await pushTargets(payload, pushes);
  if (typeof targets === "string") return denyToolCall(targets);
  const runChecks = deps.runChecks ?? failedChecks;
  for (const { dir, commit } of targets) {
    const failure = runChecks(dir, commit);
    if (failure !== null)
      return denyToolCall(
        `${failure}\n\nFix the failing check, commit, then retry this call.`,
      );
  }
  const path = pushes ? statePath(payload?.session_id) : null;
  if (path !== null) recordPush(path, (deps.now ?? Date.now)());
  return null;
}

if (isMain(import.meta.url)) {
  let payload;
  try {
    payload = await readStdinJson();
  } catch {
    // See the posture note in the header: an unreadable payload names no push.
  }
  const response = await judgePush(payload);
  if (response) process.stdout.write(JSON.stringify(response));
}
