// @ts-check
/**
 * Syscall-level fault matrix: every wired plugin hook runs through the real
 * launcher and bundle under `strace -e inject=<syscall>:error=<errno>:when=<N>`,
 * so its file and socket failure paths are driven by the kernel, not by stubs.
 * Under the DEFAULT posture a fault may warn, never stop the session; under
 * AGENT_SANITIZER_FAIL_OPEN=0 some run must close (non-vacuity).
 *
 * Scoping: every state root (TMPDIR, project, HOME, CLAUDE_PLUGIN_DATA,
 * XDG_RUNTIME_DIR) sits under one scratch root per scenario; node and the bundle
 * sit outside it. The paths under that root two un-injected discovery traces
 * BOTH touched become `-P` filters, and strace neither counts nor tampers a call
 * `-P` rejects — so `when=N` is the Nth state-file call of that syscall in one
 * process, never a module load. connect names no path and runs unfiltered (the
 * pipeline connects only to the redactor). Random-named files (the launcher's
 * mktemp capture) differ between the traces and are reported as unscoped.
 *
 * Usage: node .github/scripts/syscall-fault-matrix.mjs [--seed=N]
 *   [--budget=CELLS] [--jobs=N] [--only=<scenario or cell id>]
 * Needs strace (ptrace permitted), python3, `pnpm build:plugin`, `pnpm build:redactor`.
 */
import { spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const PLUGIN = join(ROOT, "plugin");
const LAUNCHER = join(PLUGIN, "scripts", "safe-launch.sh");

/** Logical syscall → the kernel syscalls node, bash and python actually issue. */
export const SYSCALLS = {
  openat: ["openat"],
  read: ["read"],
  write: ["write"],
  rename: ["rename", "renameat", "renameat2"],
  mkdir: ["mkdir", "mkdirat"],
  unlink: ["unlink", "unlinkat", "rmdir"],
  connect: ["connect"],
  stat: ["fstat", "newfstatat", "statx"],
};
/** Groups whose calls carry no path a `-P` filter can match. */
const UNFILTERED = new Set(["connect"]);
export const ERRNOS = ["EIO", "EACCES", "ENOSPC", "EMFILE"];
/** Syscalls whose only path is their first argument's fd (strace -y `<path>`). */
const FD_ONLY = new Set(["read", "write", "fstat"]);

/** The literal re-issue escape a releasable PreToolUse refusal carries. */
const REISSUE_MARK = "re-issue this exact call";
const RUN_TIMEOUT_MS = 60_000;
/** The project every scenario starts from. */
const PROJECT_FILES = {
  "CLAUDE.md": "# Project\n\nUse pnpm. Run the tests before pushing.\n",
  "README.md": "# Demo\n\nA small demo.\n",
};
/** Scratch-root subdirectories, all 0700 as a real per-user state dir is. */
const STATE_DIRS = ["tmp", "project", "home", "data", "run"];

/**
 * Seeded PRNG (mulberry32), so a sampled matrix replays from its printed seed.
 * @param {number} seed
 */
export function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * The run seed mixed with a scenario's id (FNV-1a), so scenarios with equally
 * many cells do not all sample the same positions.
 * @param {number} seed
 * @param {string} id
 */
export function scenarioSeed(seed, id) {
  let h = 0x811c9dc5 ^ seed;
  for (const ch of id) h = Math.imul(h ^ (ch.codePointAt(0) ?? 0), 0x01000193);
  return h >>> 0;
}

/**
 * `budget` items of `items` chosen by a seeded shuffle, in original order; all
 * of them when the budget covers the list.
 * @template T
 * @param {T[]} items
 * @param {number} budget
 * @param {number} seed
 * @returns {T[]}
 */
export function sampleCells(items, budget, seed) {
  if (budget >= items.length) return items;
  const rand = mulberry32(seed);
  const order = items.map((_, i) => i);
  for (let i = order.length - 1; i > 0; i -= 1) {
    const j = Math.floor(rand() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  const keep = new Set(order.slice(0, budget));
  return items.filter((_, i) => keep.has(i));
}

/**
 * @typedef {{ pid: string, name: string, paths: string[], injected: boolean }}
 *   TracedCall
 */

/**
 * The syscalls a `strace -f -y` trace shows, each with the paths under `root`
 * it names — the paths `-P` would match it on: the path arguments, and the fd
 * an fd-only call operates on. A read/write buffer is data, never a path, and
 * `AT_FDCWD<cwd>` is a decoration `-P` does not match. A call strace split
 * across `<unfinished ...>` / `resumed>` lines is one call, injected when its
 * resumed half says so.
 * @param {string} trace  strace -f -y -o output
 * @param {string} root  the scenario's scratch root
 * @returns {TracedCall[]}
 */
export function parseTrace(trace, root) {
  const inRoot = (/** @type {string} */ p) =>
    p === root || p.startsWith(`${root}/`);
  /** @type {TracedCall[]} */
  const calls = [];
  /** @type {Map<string, TracedCall>} */
  const unfinished = new Map();
  for (const raw of trace.split("\n")) {
    const injected = raw.endsWith("(INJECTED)");
    const resumed = /^(\d+)\s+<\.\.\. [a-z0-9_]+ resumed>/.exec(raw);
    if (resumed) {
      const call = unfinished.get(resumed[1]);
      if (call && injected) call.injected = true;
      unfinished.delete(resumed[1]);
      continue;
    }
    const m = /^(\d+)\s+([a-z0-9_]+)\((.*)$/.exec(raw);
    if (!m) continue;
    const [, pid, name] = m;
    // Arguments only: the return value's decoration repeats an argument's path.
    const end = m[3].search(/\) += |\s*<unfinished \.\.\.>$/);
    const args = (end === -1 ? m[3] : m[3].slice(0, end)).replace(
      /AT_FDCWD<[^<>]*>/g,
      "AT_FDCWD",
    );
    const named = FD_ONLY.has(name)
      ? [/^\d+<([^<>]*)>/.exec(args)?.[1] ?? ""]
      : [...args.matchAll(/"((?:[^"\\]|\\.)*)"|<([^<>]*)>/g)].map(
          (hit) => hit[1] ?? hit[2],
        );
    const call = { pid, name, paths: named.filter(inRoot), injected };
    calls.push(call);
    if (raw.endsWith("<unfinished ...>")) unfinished.set(pid, call);
  }
  return calls;
}

/**
 * The injection scope two discovery traces of the same run agree on: the paths
 * both touched (a random-named file differs between them, so no `-P` filter can
 * name it), minus `excluded` prefixes; and per syscall the most calls on those
 * paths any one process made — strace's `when=` counter is per process and per
 * syscall, so that is the last position an injection can reach. connect names
 * no path and is counted on every call.
 * @param {TracedCall[]} a
 * @param {TracedCall[]} b
 * @param {string[]} excluded  path prefixes never injected into
 * @returns {{ paths: string[], unscoped: number, counts: Map<string, number> }}
 */
export function scopeOf(a, b, excluded) {
  const seen = (/** @type {TracedCall[]} */ calls) =>
    new Set(calls.flatMap((c) => c.paths));
  const inB = seen(b);
  const kept = (/** @type {string} */ p) =>
    !excluded.some((x) => p === x || p.startsWith(`${x}/`));
  const all = [...seen(a)].filter(kept);
  const paths = all.filter((p) => inB.has(p)).sort();
  const scoped = new Set(paths);
  /** @type {Map<string, number>} */
  const perProcess = new Map();
  for (const call of a) {
    if (call.name !== "connect" && !call.paths.some((p) => scoped.has(p)))
      continue;
    const key = `${call.pid}\0${call.name}`;
    perProcess.set(key, (perProcess.get(key) ?? 0) + 1);
  }
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const [key, n] of perProcess) {
    const name = key.split("\0")[1];
    counts.set(name, Math.max(counts.get(name) ?? 0, n));
  }
  return { paths, unscoped: all.length - paths.length, counts };
}

/**
 * The narrowest injection that still hits what an injected run's trace says it
 * hit: `-P` on only the injected calls' paths, and — when exactly one call was
 * injected — `when=` re-counted against that narrower filter. Null when there
 * is nothing to narrow: an unfiltered group, or a trace naming no injected
 * call on a scoped path (an empty `-P` set would inject EVERYWHERE).
 * @param {TracedCall[]} calls  the injected run's trace (parseTrace)
 * @param {string} group
 * @param {string} when  the position the full-scope run used
 * @returns {{ paths: string[], when: string } | null}
 */
export function minimalInjection(calls, group, when) {
  const hit = calls.filter((c) => c.injected && c.paths.length > 0);
  if (UNFILTERED.has(group) || hit.length === 0) return null;
  const paths = [...new Set(hit.flatMap((c) => c.paths))].sort();
  if (hit.length > 1) return { paths, when };
  const [only] = hit;
  const narrowed = new Set(paths);
  const position = calls
    .slice(0, calls.indexOf(only) + 1)
    .filter(
      (c) =>
        c.pid === only.pid &&
        c.name === only.name &&
        c.paths.some((p) => narrowed.has(p)),
    ).length;
  return { paths, when: String(position) };
}

/**
 * The `when=` positions worth injecting at for a syscall a process makes `n`
 * in-scope calls of: the first, the last, and every one.
 * @param {number} n
 * @returns {string[]}
 */
export function injectionPoints(n) {
  if (n <= 0) return [];
  return [...new Set(["1", String(n)]), "1+"];
}

/**
 * The strace argv for one injected run (without the traced command). `-y` only
 * decorates the log, which the minimal reproducer is derived from.
 * @param {{ group: string, errno: string, when: string, paths: string[],
 *   log: string }} cell
 * @returns {string[]}
 */
export function straceArgv({ group, errno, when, paths, log }) {
  const set = SYSCALLS[/** @type {keyof typeof SYSCALLS} */ (group)].join(",");
  const filters = UNFILTERED.has(group) ? [] : paths.flatMap((p) => ["-P", p]);
  return [
    "-f",
    "-q",
    "-y",
    "--seccomp-bpf",
    // `-o FILE` defaults strace to -I3, which blocks SIGTERM, so the detach
    // that ends a run whose fault respawned the redactor never happened.
    "-I1",
    "-o",
    log,
    "-e",
    `trace=${set}`,
    ...filters,
    "-e",
    `inject=${set}:error=${errno}:when=${when}`,
  ];
}

/**
 * The enforcement channels one launch fired: how a hook stops, rewrites or
 * suppresses a session. Empty when it only warned or stayed silent.
 * @param {{ status: number | null, verdict: Record<string, any> | null }} run
 * @returns {string[]}
 */
export function enforcement({ status, verdict }) {
  const fired = [];
  if (status === 2) fired.push("exit 2");
  const specific = verdict?.hookSpecificOutput;
  const decision = specific?.permissionDecision;
  if (decision === "deny" || decision === "ask") fired.push(decision);
  if (verdict?.decision === "block") fired.push("decision: block");
  if (specific?.updatedToolOutput !== undefined)
    fired.push("updatedToolOutput");
  return fired;
}

/**
 * Parse a launch's stdout as the single verdict the harness reads: null when
 * empty, a plain object when well-formed, and an Error otherwise.
 * @param {string} stdout
 * @returns {Record<string, any> | null | Error}
 */
export function parseVerdict(stdout) {
  const text = stdout.trim();
  if (text === "") return null;
  let value;
  try {
    value = JSON.parse(text);
  } catch (err) {
    return new Error(`stdout is not one JSON verdict: ${String(err)}`);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return new Error("stdout is JSON but not a verdict object");
  return value;
}

/**
 * @typedef {{ status: number | null, stdout: string, stderr: string,
 *   injected: number, timedOut: boolean }} Launch
 * @typedef {{ launch: Launch, reissue?: Launch, probe?: Launch }} Observed
 */

/** @param {string} stdout */
function asVerdict(stdout) {
  const verdict = parseVerdict(stdout);
  return verdict instanceof Error ? null : verdict;
}

/** @param {Launch | undefined} run */
const firedBy = (run) =>
  run
    ? enforcement({ status: run.status, verdict: asVerdict(run.stdout) })
    : [];

/**
 * Is `run`'s verdict the scenario's ordinary decision — byte-identical to the
 * un-injected baseline's? Both ran from the same scratch root and session id,
 * so any difference is the fault's doing.
 * @param {Launch} run
 * @param {Launch} baseline
 */
const asBaseline = (run, baseline) =>
  run.stdout.trim() === baseline.stdout.trim();

/**
 * Judge one injected run under the DEFAULT posture. An enforcement channel is
 * the hook's own decision, not a fault response, only when the verdict equals
 * the un-injected baseline's (a redaction the fault did not touch). The one
 * sanctioned fault refusal is a placeholder write's deny carrying the re-issue
 * escape, and only if the exact re-issue — under the same fault — then
 * proceeds (or reaches the baseline's own decision).
 * @param {Observed} observed
 * @param {Launch} baseline
 * @param {{ placeholderWrite?: boolean }} scenario
 * @returns {{ outcome: string, problem?: string }}
 */
export function judgeOpen({ launch, reissue, probe }, baseline, scenario) {
  if (launch.injected === 0) return { outcome: "n/r" };
  if (launch.timedOut)
    return { outcome: "VIOL", problem: `no exit within ${RUN_TIMEOUT_MS} ms` };
  if (launch.status === 2) return { outcome: "VIOL", problem: "exit 2" };
  const verdict = parseVerdict(launch.stdout);
  if (verdict instanceof Error)
    return { outcome: "VIOL", problem: verdict.message };
  const probeFired = firedBy(probe);
  if (probeFired.length > 0)
    return {
      outcome: "VIOL",
      problem: `the next tool call was stopped: ${probeFired.join(", ")}`,
    };
  const fired = enforcement({ status: launch.status, verdict });
  const same = asBaseline(launch, baseline);
  if (same) return { outcome: "same" };
  if (fired.length === 0) return { outcome: "warn" };
  const releasable =
    scenario.placeholderWrite &&
    fired.join() === "deny" &&
    String(verdict?.hookSpecificOutput?.permissionDecisionReason).includes(
      REISSUE_MARK,
    );
  if (!releasable)
    return { outcome: "VIOL", problem: `blocked via ${fired.join(", ")}` };
  if (!reissue)
    return {
      outcome: "VIOL",
      problem: "releasable refusal was never re-issued",
    };
  const again = firedBy(reissue);
  if (again.length > 0 && !asBaseline(reissue, baseline))
    return {
      outcome: "VIOL",
      problem: `the exact re-issue was refused again: ${again.join(", ")}: ${reissue.stdout.slice(0, 300)}`,
    };
  return { outcome: "release" };
}

/**
 * Did one injected run under AGENT_SANITIZER_FAIL_OPEN=0 close something the
 * closed-posture baseline did not — in its own verdict, or through the gate
 * the next tool call reads?
 * @param {Observed} observed
 * @param {Launch} baseline
 * @returns {boolean}
 */
export function closedSomething({ launch, probe }, baseline) {
  if (launch.injected === 0) return false;
  const ownClose = firedBy(launch).length > 0 && !asBaseline(launch, baseline);
  return ownClose || firedBy(probe).length > 0;
}

/**
 * The compact outcome table: one row per (scenario, syscall, errno), one column
 * per `when=` position.
 * @param {Array<{ hook: string, group: string, errno: string, when: string,
 *   outcome: string }>} rows
 * @returns {string}
 */
export function formatTable(rows) {
  const whens = ["1", "N", "1+"];
  /** @type {Map<string, Record<string, string>>} */
  const lines = new Map();
  for (const row of rows) {
    const key = [row.hook, row.group, row.errno].join("\0");
    const cells = lines.get(key) ?? {};
    const slot = row.when === "1" || row.when === "1+" ? row.when : "N";
    cells[slot] = row.outcome;
    lines.set(key, cells);
  }
  const header = [
    "scenario",
    "syscall",
    "errno",
    ...whens.map((w) => `when=${w}`),
  ];
  const body = [...lines].map(([key, cells]) => [
    ...key.split("\0"),
    ...whens.map((w) => cells[w] ?? "-"),
  ]);
  const widths = header.map((h, i) =>
    Math.max(h.length, ...body.map((r) => r[i].length)),
  );
  return [header, ...body]
    .map((r) =>
      r
        .map((c, i) => c.padEnd(widths[i]))
        .join("  ")
        .trimEnd(),
    )
    .join("\n");
}

/**
 * Single-quote `s` for POSIX sh in one pass over its one metacharacter.
 * @param {string} s
 */
export function shQuote(s) {
  return `'${s.replaceAll("'", `'\\''`)}'`;
}

/**
 * The self-contained shell command that reproduces one injected run: recreate
 * the scenario's scratch root as `$R` at its original path (the stores' names
 * hash the project path, so `-P` filters only match there), seed the project,
 * start the redactor un-traced when Layer 4 is on, then run the launcher under
 * strace with the payload on stdin.
 * @param {{ root: string, env: Record<string, string>, strace: string[],
 *   event: string, mode: string, payload: string, warm: boolean }} run
 * @returns {string}
 */
export function reproducer({ root, env, strace, event, mode, payload, warm }) {
  const word = (/** @type {string} */ s) =>
    s.includes(root)
      ? s
          .split(root)
          .map((piece) => (piece === "" ? "" : shQuote(piece)))
          .join('"$R"')
      : shQuote(s);
  const assigns = Object.entries(env).map(([k, v]) => `${k}=${word(v)}`);
  const hook = [
    "env -u AGENT_SANITIZER_FAIL_OPEN -u NODE_OPTIONS",
    ...assigns,
  ].join(" ");
  const launcher = `bash ${shQuote(LAUNCHER)} ${event} --hook=${mode}`;
  return [
    `R=${shQuote(root)}`,
    `rm -rf "$R"`,
    `mkdir -p -m 700 ${STATE_DIRS.map((d) => `"$R"/${d}`).join(" ")}`,
    ...Object.entries(PROJECT_FILES).map(
      ([name, text]) => `printf %s ${shQuote(text)} >"$R"/project/${name}`,
    ),
    `cd "$R"/project`,
    ...(warm
      ? [`printf %s ${word(payload)} | ${hook} ${launcher} >/dev/null 2>&1`]
      : []),
    `printf %s ${word(payload)} | ${hook} strace ${strace.map(word).join(" ")} ${launcher}`,
  ].join(" && ");
}

// ── Scenarios ────────────────────────────────────────────────────────────────

/**
 * One ordinary payload per wired hook, plus the secret layer's own traffic.
 * `baseline` is the enforcement the un-injected run must show, so a scenario
 * that is not the ordinary traffic it claims fails loud instead of skewing the
 * matrix. `probe` marks hooks whose only enforcement is arming the gate the
 * next PreToolUse call reads; `daemon` marks traffic that reaches the
 * redactor, which must stay running between cells.
 * @typedef {{ id: string, event: string, mode: string, secrets: boolean,
 *   payload: (root: string) => Record<string, unknown>, baseline: string[],
 *   probe?: boolean, placeholderWrite?: boolean, daemon?: boolean }} Scenario
 */

/** @param {string} root */
const project = (root) => join(root, "project");

/** @type {Array<Omit<Scenario, "id" | "secrets">>} */
const ORDINARY = [
  {
    event: "SessionStart",
    mode: "scan-invisible-chars",
    payload: () => ({ hook_event_name: "SessionStart", source: "startup" }),
    baseline: [],
    probe: true,
  },
  {
    event: "UserPromptSubmit",
    mode: "sanitize-user-prompt",
    payload: () => ({
      hook_event_name: "UserPromptSubmit",
      prompt: "summarize README.md",
    }),
    baseline: [],
  },
  {
    event: "InstructionsLoaded",
    mode: "scan-loaded-instructions",
    payload: (root) => ({
      hook_event_name: "InstructionsLoaded",
      file_path: join(project(root), "CLAUDE.md"),
      load_reason: "session_start",
    }),
    baseline: [],
    probe: true,
  },
  {
    event: "PreToolUse",
    mode: "pretooluse-sanitize",
    payload: () => ({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: "ls -la" },
    }),
    baseline: [],
  },
  {
    event: "PreToolUse",
    mode: "pretooluse-sanitize",
    payload: (root) => ({
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: {
        file_path: join(project(root), "notes.md"),
        content: "# Notes\n\nRun the build before pushing.\n",
      },
    }),
    baseline: [],
  },
  {
    event: "PostToolUse",
    mode: "sanitize-output",
    payload: () => ({
      hook_event_name: "PostToolUse",
      tool_name: "Bash",
      tool_input: { command: "pnpm build" },
      tool_response: { stdout: "build finished in 3.2s", stderr: "" },
    }),
    baseline: [],
  },
];

/**
 * Traffic that reaches the redactor daemon, so only exists with Layer 4 on: a
 * secret the daemon redacts, and a write of the placeholder it leaves behind.
 * @type {Array<Omit<Scenario, "id" | "secrets">>}
 */
const SECRET_TRAFFIC = [
  {
    event: "PostToolUse",
    mode: "sanitize-output",
    payload: () => ({
      hook_event_name: "PostToolUse",
      tool_name: "Bash",
      tool_input: { command: "cat deploy.env" },
      tool_response: { stdout: "aws_key=AKIAIOSFODNN7EXAMPLE", stderr: "" },
    }),
    baseline: ["updatedToolOutput"],
    daemon: true,
  },
  {
    event: "PreToolUse",
    mode: "pretooluse-sanitize",
    payload: (root) => ({
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: {
        file_path: join(project(root), "deploy.env"),
        content: "aws_key=[REDACTED: AWS access key]\n",
      },
    }),
    baseline: ["deny"],
    placeholderWrite: true,
  },
];

/**
 * Every scenario: each ordinary payload with Layer 4 off and on, and the secret
 * traffic with it on. Ids are stable so `--only` can name one.
 * @returns {Scenario[]}
 */
export function scenarios() {
  /** @type {Scenario[]} */
  const all = [];
  for (const secrets of [false, true])
    for (const s of ORDINARY) all.push({ ...s, secrets, id: "" });
  for (const s of SECRET_TRAFFIC) all.push({ ...s, secrets: true, id: "" });
  return all.map((s, i) => ({
    ...s,
    id: `${s.mode}#${i}${s.secrets ? "+secrets" : ""}`,
  }));
}

/**
 * The wired (event, mode) pairs, from hooks.json, so a newly wired hook with no
 * scenario fails the run instead of going unmeasured.
 * @returns {Array<[string, string]>}
 */
function wiredHooks() {
  const manifest = JSON.parse(
    readFileSync(join(PLUGIN, "hooks", "hooks.json"), "utf8"),
  );
  /** @type {Array<[string, string]>} */
  const pairs = [];
  for (const [event, matchers] of Object.entries(manifest.hooks))
    for (const matcher of matchers)
      for (const entry of matcher.hooks ?? []) {
        const mode = /--hook=([\w-]+)/.exec(entry.command)?.[1];
        if (mode) pairs.push([event, mode]);
      }
  return pairs;
}

// ── Running ──────────────────────────────────────────────────────────────────

/**
 * Reset a scenario root to a just-started session: fresh stores, home and
 * project, while the running redactor (run/) and node's compile cache survive,
 * as they do across a real session's hook calls.
 * @param {string} root
 */
function resetRoot(root) {
  for (const dir of ["tmp", "project", "home"])
    rmSync(join(root, dir), { recursive: true, force: true });
  for (const dir of STATE_DIRS)
    mkdirSync(join(root, dir), { recursive: true, mode: 0o700 });
  const data = join(root, "data");
  for (const entry of readdirSync(data))
    if (entry !== "node-compile-cache")
      rmSync(join(data, entry), { recursive: true, force: true });
  for (const [name, text] of Object.entries(PROJECT_FILES))
    writeFileSync(join(project(root), name), text);
}

/**
 * The variables one launch sets on top of the inherited environment: the
 * scenario's roots, session and knobs.
 * @param {Scenario} scenario
 * @param {string} root
 * @param {boolean} closed
 * @returns {Record<string, string>}
 */
function scenarioEnv(scenario, root, closed) {
  /** @type {Record<string, string>} */
  const env = {
    TMPDIR: join(root, "tmp"),
    HOME: join(root, "home"),
    CLAUDE_PROJECT_DIR: project(root),
    CLAUDE_PLUGIN_ROOT: PLUGIN,
    CLAUDE_PLUGIN_DATA: join(root, "data"),
    XDG_RUNTIME_DIR: join(root, "run"),
    CLAUDE_SESSION_ID: `fault-matrix-${scenario.id}`,
    AGENT_SANITIZER_SECRETS_ENABLED: scenario.secrets ? "1" : "",
    // Bounds the spawn wait a refused connect falls into; the default is sized
    // for a cold detect-secrets import, which the warm-up has already paid.
    _AGENT_SANITIZER_REDACTOR_WAIT_MS: "1500",
  };
  if (closed) env.AGENT_SANITIZER_FAIL_OPEN = "0";
  return env;
}

/**
 * This process's environment with every sanitizer, Claude and XDG knob
 * stripped — a runner export must not pick the posture or roots under test —
 * then `env` on top.
 * @param {Record<string, string>} env
 */
function fullEnv(env) {
  const knob =
    /^_?AGENT_SANITIZER_|^CLAUDE_|^XDG_|^NODE_(?:COMPILE_CACHE|OPTIONS)$/;
  const inherited = Object.entries(process.env).filter(
    ([k, v]) => v !== undefined && !knob.test(k),
  );
  return { ...Object.fromEntries(inherited), ...env };
}

/** @param {Scenario} scenario @param {string} root */
const payloadOf = (scenario, root) =>
  JSON.stringify({
    session_id: `fault-matrix-${scenario.id}`,
    ...scenario.payload(root),
  });

/** How long strace may outlive the launcher before it is told to detach. */
const DETACH_GRACE_MS = 1000;

/**
 * The launcher's own exit status as strace logged it, or undefined while it
 * runs. strace prints `+++ exited` lines whatever `-P` filters.
 * @param {string} log
 * @param {string} pid
 * @returns {number | undefined}
 */
export function loggedExit(log, pid) {
  // strace pads the pid column, so `101 +++` and `101  +++` are both exits.
  const ending = log
    .split("\n")
    .map((l) => /^(\d+)\s+\+\+\+ (.*) \+\+\+$/.exec(l))
    .find((m) => m?.[1] === pid);
  if (ending === undefined) return undefined;
  const code = /^exited with (\d+)$/.exec(
    /** @type {string} */ (ending[2]),
  )?.[1];
  return code === undefined ? 128 : Number(code);
}

/**
 * Spawn one launch, optionally under strace, and collect what it did.
 *
 * Under strace the launcher writes its pid first, and its status is read from
 * the strace log. A redactor a fault made it respawn is a traced, detached,
 * long-lived child that `strace -f` would wait on forever; once the launcher
 * has exited, SIGTERM makes strace detach it and leave it running untraced, as
 * an un-traced session would.
 * @param {Scenario} scenario
 * @param {string} root
 * @param {{ closed: boolean, strace?: string[], log?: string }} opts
 * @returns {Promise<Launch>}
 */
function launch(scenario, root, { closed, strace, log }) {
  const hookArgv = [
    "bash",
    LAUNCHER,
    scenario.event,
    `--hook=${scenario.mode}`,
  ];
  if (strace && !log) throw new Error("a traced launch needs its log path");
  const pidFile = `${log}.pid`;
  const [cmd, ...args] = strace
    ? [
        "strace",
        ...strace,
        "bash",
        "-c",
        'printf %s "$$" >"$0" && exec "$@"',
        pidFile,
        ...hookArgv,
      ]
    : hookArgv;
  if (log) rmSync(log, { force: true });
  rmSync(pidFile, { force: true });
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd: project(root),
      env: fullEnv(scenarioEnv(scenario, root, closed)),
    });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    /** @type {number | undefined} */
    let exited;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, RUN_TIMEOUT_MS);
    const watch = strace
      ? setInterval(() => {
          if (exited !== undefined || !log || !existsSync(pidFile)) return;
          exited = loggedExit(
            readFileSync(log, "utf8"),
            readFileSync(pidFile, "utf8"),
          );
          if (exited !== undefined)
            setTimeout(() => child.kill("SIGTERM"), DETACH_GRACE_MS).unref();
        }, 50)
      : undefined;
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.on("error", reject);
    child.stdin.end(payloadOf(scenario, root));
    child.on("close", (code) => {
      clearTimeout(timer);
      clearInterval(watch);
      const trace = log && existsSync(log) ? readFileSync(log, "utf8") : "";
      // No pid file: strace never started the launcher, so there is no status.
      const status = !strace
        ? code
        : existsSync(pidFile)
          ? loggedExit(trace, readFileSync(pidFile, "utf8"))
          : undefined;
      resolve({
        status: status ?? null,
        stdout,
        stderr,
        injected: trace.split("(INJECTED)").length - 1,
        timedOut,
      });
    });
  });
}

/** The ordinary PreToolUse call that reads an alert an earlier hook armed. */
const PROBE = {
  event: "PreToolUse",
  mode: "pretooluse-sanitize",
  payload: () => ({
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "ls" },
  }),
};

/**
 * Restart the redactor un-traced if an earlier cell's fault took its socket
 * away. Otherwise the next traced run would spawn it under `strace -f`, which
 * then waits on a daemon that never exits, and the cell would read as a hang
 * the hook never caused.
 * @param {Scenario} scenario
 * @param {string} root
 */
async function ensureDaemon(scenario, root) {
  const socket = join(root, "run", "agent-sanitizer-redactor", "redactor.sock");
  if (existsSync(socket)) return;
  resetRoot(root);
  const warm = await launch(scenario, root, { closed: false });
  if (!existsSync(socket))
    throw new Error(
      `${scenario.id}: the redactor did not come back at ${socket}\n${warm.stderr}`,
    );
}

/**
 * One injected run from a fresh session, plus what its oracle needs: the gate
 * probe (un-injected — the next call), and the exact re-issue of a placeholder
 * write (under the same fault, which may still hold).
 * @param {Scenario} scenario
 * @param {string} root
 * @param {string[]} strace
 * @param {string} log
 * @param {boolean} closed
 * @returns {Promise<Observed & { trace: string }>}
 */
async function observe(scenario, root, strace, log, closed) {
  if (scenario.daemon) await ensureDaemon(scenario, root);
  resetRoot(root);
  const run = await launch(scenario, root, { closed, strace, log });
  const trace = existsSync(log) ? readFileSync(log, "utf8") : "";
  /** @type {Observed & { trace: string }} */
  const observed = { launch: run, trace };
  if (scenario.probe)
    observed.probe = await launch({ ...scenario, ...PROBE }, root, { closed });
  if (scenario.placeholderWrite)
    observed.reissue = await launch(scenario, root, { closed, strace, log });
  return observed;
}

/**
 * Discovery: trace one un-injected run twice from a fresh session and keep the
 * scope both agree on; the first run is the baseline every cell is judged by.
 * @param {Scenario} scenario
 * @param {string} root
 * @param {string} logBase
 */
async function discover(scenario, root, logBase) {
  const all = Object.values(SYSCALLS).flat().join(",");
  /** @type {TracedCall[][]} */
  const traces = [];
  /** @type {Launch[]} */
  const runs = [];
  for (const pass of [1, 2]) {
    resetRoot(root);
    const log = `${logBase}.discover${pass}`;
    runs.push(
      await launch(scenario, root, {
        closed: false,
        strace: [
          "-f",
          "-q",
          "-y",
          "--seccomp-bpf",
          "-o",
          log,
          "-e",
          `trace=${all}`,
        ],
        log,
      }),
    );
    traces.push(parseTrace(readFileSync(log, "utf8"), root));
  }
  return {
    // node's own V8 code cache: its loader shrugs off any I/O error, so an
    // injection there measures node, not the sanitizer.
    ...scopeOf(traces[0], traces[1], [
      join(root, "data", "node-compile-cache"),
    ]),
    baseline: runs[0],
  };
}

/**
 * Run `tasks` with at most `jobs` in flight.
 * @template T
 * @param {Array<() => Promise<T>>} tasks
 * @param {number} jobs
 * @returns {Promise<T[]>}
 */
async function pool(tasks, jobs) {
  /** @type {T[]} */
  const results = [];
  let next = 0;
  const worker = async () => {
    while (next < tasks.length) {
      const i = next;
      next += 1;
      results[i] = await tasks[i]();
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(jobs, tasks.length) }, worker),
  );
  return results;
}

/** @param {string[]} argv */
export function parseArgs(argv) {
  /** @type {Record<string, string>} */
  const opts = Object.create(null);
  for (const arg of argv) {
    const m = /^--(seed|budget|jobs|only)=(.+)$/.exec(arg);
    if (!m) throw new Error(`unknown argument ${JSON.stringify(arg)}`);
    opts[m[1]] = m[2];
  }
  const int = (/** @type {string} */ name, /** @type {number} */ fallback) => {
    const value = opts[name] === undefined ? fallback : Number(opts[name]);
    if (!Number.isInteger(value) || value < 0)
      throw new Error(`--${name} must be a non-negative integer`);
    return value;
  };
  return {
    seed: int("seed", Math.floor(Math.random() * 2 ** 31)),
    budget: opts.budget === undefined ? Infinity : int("budget", 0),
    jobs: Math.max(1, int("jobs", 4)),
    only: opts.only,
  };
}

/**
 * The reproducer for one violating cell: the minimal injection its trace
 * implies when re-running that alone still violates, else the full scope.
 * @param {Scenario} scenario
 * @param {string} root
 * @param {{ group: string, errno: string, when: string, paths: string[],
 *   log: string }} cell
 * @param {string} trace  the violating run's strace log
 * @param {Launch} baseline
 */
async function reproduce(scenario, root, cell, trace, baseline) {
  const narrowed = minimalInjection(
    parseTrace(trace, root),
    cell.group,
    cell.when,
  );
  const narrow = narrowed && { ...cell, ...narrowed };
  const again =
    narrow &&
    (await observe(scenario, root, straceArgv(narrow), cell.log, false));
  const minimal =
    again !== null &&
    judgeOpen(again, baseline, scenario).problem !== undefined;
  const chosen = minimal && narrow ? narrow : cell;
  const line = reproducer({
    root,
    env: scenarioEnv(scenario, root, false),
    strace: straceArgv({ ...chosen, log: "/dev/null" }),
    event: scenario.event,
    mode: scenario.mode,
    payload: payloadOf(scenario, root),
    warm: scenario.secrets,
  });
  const label = minimal
    ? "minimal"
    : `full-scope (${narrow ? "the narrowed injection did not reproduce" : "nothing to narrow"})`;
  return `${label}: ${line}`;
}

/**
 * One scenario end to end: warm-up, discovery and baselines, then every sampled
 * cell under both postures.
 * @param {Scenario} scenario
 * @param {string} base
 * @param {(cells: string[]) => string[]} pick
 */
async function runScenario(scenario, base, pick) {
  // Word characters only, so a scenario id cannot add a path separator.
  const name = scenario.id.replace(/\W/g, "_");
  const root = join(base, name);
  const logBase = join(base, name);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  resetRoot(root);
  // Warm-up: fills node's compile cache and, with Layer 4 on, starts the
  // redactor un-traced, so no traced run waits on a detached daemon.
  await launch(scenario, root, { closed: false });
  const found = await discover(scenario, root, logBase);
  const baselineFired = firedBy(found.baseline);
  if (baselineFired.join() !== scenario.baseline.join())
    throw new Error(
      `${scenario.id}: the un-injected run fired [${baselineFired}], expected ` +
        `[${scenario.baseline}] — not the ordinary traffic it claims to be\n` +
        found.baseline.stderr,
    );
  resetRoot(root);
  const closedBaseline = await launch(scenario, root, { closed: true });
  /** @type {string[]} */
  const cells = [];
  for (const [group, names] of Object.entries(SYSCALLS)) {
    const n = Math.max(0, ...names.map((s) => found.counts.get(s) ?? 0));
    for (const errno of ERRNOS)
      for (const when of injectionPoints(n))
        cells.push(`${scenario.id}:${group}:${errno}:${when}`);
  }
  const rows = [];
  const violations = [];
  let closes = 0;
  for (const id of pick(cells)) {
    const [, group, errno, when] = id.split(":");
    const cell = {
      group,
      errno,
      when,
      paths: found.paths,
      log: `${logBase}.inject`,
    };
    const strace = straceArgv(cell);
    const open = await observe(scenario, root, strace, cell.log, false);
    const verdict = judgeOpen(open, found.baseline, scenario);
    const closed = await observe(scenario, root, strace, cell.log, true);
    const didClose = closedSomething(closed, closedBaseline);
    if (didClose) closes += 1;
    rows.push({
      hook: scenario.id,
      group,
      errno,
      when,
      outcome: verdict.outcome + (didClose ? "/C" : ""),
    });
    if (verdict.problem)
      violations.push(
        [
          `${id}: ${verdict.problem}`,
          `  rerun: node .github/scripts/syscall-fault-matrix.mjs --only=${id}`,
          `  ${await reproduce(scenario, root, cell, open.trace, found.baseline)}`,
          `  stdout: ${open.launch.stdout.slice(0, 400)}`,
          `  stderr: ${open.launch.stderr.slice(0, 600)}`,
        ].join("\n"),
      );
  }
  return {
    rows,
    violations,
    closes,
    cells: cells.length,
    summary:
      `${scenario.id}: ${found.paths.length} scoped path(s), ` +
      `${found.unscoped} unscoped random-named, ` +
      `${found.counts.get("connect") ?? 0} connect call(s), ${cells.length} cell(s)`,
  };
}

/**
 * Stop every redactor the run started: each was spawned with a socket path
 * under `base`, which therefore appears in its argv.
 * @param {string} base
 */
function stopDaemons(base) {
  const res = spawnSync("pkill", ["-f", base]);
  // pkill: 0 = signalled something, 1 = nothing matched; anything else is real.
  if (res.status !== 0 && res.status !== 1)
    throw new Error(`pkill exited ${res.status}: ${res.stderr}`);
}

async function main() {
  const { seed, budget, jobs, only } = parseArgs(process.argv.slice(2));
  const all = scenarios();
  const covered = new Set(all.map((s) => `${s.event}:${s.mode}`));
  const missing = wiredHooks().filter(([e, m]) => !covered.has(`${e}:${m}`));
  if (missing.length > 0)
    throw new Error(`wired hook(s) with no scenario: ${missing.join(", ")}`);
  const chosen = only
    ? all.filter((s) => only === s.id || only.startsWith(`${s.id}:`))
    : all;
  if (chosen.length === 0) throw new Error(`--only=${only} names no scenario`);
  // Split evenly per scenario, so a small budget still samples every hook.
  const perScenario = Math.ceil(budget / chosen.length);
  const pick = (/** @type {string[]} */ cells) =>
    only
      ? cells.filter((c) => c === only || c.startsWith(`${only}:`))
      : sampleCells(cells, perScenario, scenarioSeed(seed, cells[0] ?? ""));
  console.log(
    `syscall fault matrix: seed=${seed} budget=${budget} jobs=${jobs} scenarios=${chosen.length}`,
  );
  // A space and a `+` in every state path, so each secrets-on baseline proves
  // the redactor starts from a path a URL would escape.
  const base = mkdtempSync(join(tmpdir(), "sfm +"));
  const cleanup = () => {
    stopDaemons(base);
    rmSync(base, { recursive: true, force: true });
  };
  // An interrupted run would otherwise leave its redactors running.
  for (const signal of /** @type {const} */ (["SIGINT", "SIGTERM"]))
    process.once(signal, () => {
      cleanup();
      process.exit(1);
    });
  const started = Date.now();
  let results;
  try {
    results = await pool(
      chosen.map((s) => () => runScenario(s, base, pick)),
      jobs,
    );
  } finally {
    cleanup();
  }
  for (const r of results) console.log(r.summary);
  console.log(`\n${formatTable(results.flatMap((r) => r.rows))}`);
  const ran = results.reduce((n, r) => n + r.rows.length, 0);
  const total = results.reduce((n, r) => n + r.cells, 0);
  const closes = results.reduce((n, r) => n + r.closes, 0);
  const violations = results.flatMap((r) => r.violations);
  console.log(
    `\n${ran}/${total} cell(s) in ${Math.round((Date.now() - started) / 1000)}s, seed=${seed}; ` +
      `${closes} closed under AGENT_SANITIZER_FAIL_OPEN=0; ${violations.length} violation(s).\n` +
      "same = verdict identical to the un-injected run; warn = changed, still open; " +
      "release = refused once, released on re-issue; n/r = injection never reached; " +
      "/C = the same cell closed under AGENT_SANITIZER_FAIL_OPEN=0.",
  );
  if (violations.length > 0) {
    console.error(`\nVIOLATIONS (seed=${seed}):\n${violations.join("\n\n")}`);
    process.exit(1);
  }
  if (!only && closes === 0) {
    console.error(
      "no injected fault closed anything under AGENT_SANITIZER_FAIL_OPEN=0: " +
        "the matrix never reached a posture decision, so its passes prove nothing",
    );
    process.exit(1);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  await main();
