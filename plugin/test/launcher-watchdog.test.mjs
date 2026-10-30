/**
 * The launcher's watchdog: a hook runtime that has not exited within its
 * per-event budget is killed — its whole process group, never the detached
 * redactor daemon — and answered with the same posture-governed degraded
 * verdict as any other no-verdict outcome. Without it a hung hook stalls the
 * session until hooks.json's harness timeout, whose kill Claude Code reads as
 * "no objection".
 *
 * Every hang here is driven through the real launcher against a staged plugin,
 * with `_AGENT_SANITIZER_HOOK_WATCHDOG_MS` shrinking the budget to
 * milliseconds. Each launch is bounded by LAUNCH_LIMIT_MS, so a launcher with
 * no watchdog fails these tests by timing out rather than wedging the suite —
 * and "the launcher with a large budget is still running" below proves the
 * fixtures genuinely hang, so a fast answer is the watchdog's doing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { connect } from "node:net";
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const PLUGIN_DIR = join(ROOT, "plugin");
const BUNDLE_REL = join("dist", "hooks", "plugin-hooks.bundle.mjs");
const MANIFEST_REL = join("dist", "hooks", "hook-binaries.sha256");
const STAGED_MANIFEST = "# staged hook-binary manifest\n";

if (!existsSync(join(PLUGIN_DIR, BUNDLE_REL)))
  throw new Error(
    `the plugin is not built (missing ${BUNDLE_REL}). Run \`pnpm build:plugin\` first.`,
  );

/** The watchdog budget the hang tests run under, in ms. */
const BUDGET_MS = 1500;
/** How far past the budget an answer may land: bash + node startup on a slow runner. */
const SLACK_MS = 4000;
/** A launch still running after this is killed and reported as hung. */
const LAUNCH_LIMIT_MS = 15000;
const FAIL_CLOSED = { AGENT_SANITIZER_FAIL_OPEN: "0" };

/** A scratch dir removed when the test finishes. */
function scratch(t) {
  const dir = mkdtempSync(join(tmpdir(), "agent-sanitizer-watchdog-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** Copy the built plugin tree into a scratch dir and return its root. */
function stagePlugin(t) {
  const dir = join(scratch(t), "plugin");
  cpSync(PLUGIN_DIR, dir, { recursive: true });
  writeFileSync(join(dir, MANIFEST_REL), STAGED_MANIFEST);
  return dir;
}

/** Overwrite the staged bundle with `body` (an ES module). */
function replaceBundle(plugin, body) {
  writeFileSync(join(plugin, BUNDLE_REL), body);
}

/**
 * This process's environment minus every knob that would pick the branch under
 * test from a host fact (a developer's posture, a provisioned binary, a cache
 * dir), with a fresh session id per launch so the once-per-session degraded
 * context is never deduplicated away between assertions.
 */
let launchSeq = 0;
function launchEnv(t, env) {
  const base = { ...process.env };
  for (const name of [
    "AGENT_SANITIZER_FAIL_OPEN",
    "AGENT_SANITIZER_NODE",
    "AGENT_SANITIZER_REPEAT_DEGRADED_CONTEXT",
    "AGENT_SANITIZER_HOOK_BINARY",
    "CLAUDE_PLUGIN_DATA",
    "NODE_COMPILE_CACHE",
    "_AGENT_SANITIZER_HOOK_WATCHDOG_MS",
  ])
    delete base[name];
  return {
    ...base,
    AGENT_SANITIZER_SECRETS_ENABLED: "1",
    CLAUDE_SESSION_ID: `watchdog-${process.pid}-${(launchSeq += 1)}`,
    CLAUDE_CODE_SESSION_ID: "",
    TMPDIR: scratch(t),
    ...env,
  };
}

/**
 * Run one hook through the staged launcher as hooks.json does, timing it. A
 * launcher still running at `limitMs` is TERMed (then its group KILLed) and
 * reported `{ hung: true }`, so a missing watchdog fails an assertion instead
 * of hanging the suite.
 */
function launch(
  t,
  plugin,
  event,
  hook,
  payload,
  { env = {}, limitMs = LAUNCH_LIMIT_MS, onSpawn } = {},
) {
  const started = Date.now();
  const child = spawn(
    "bash",
    [join(plugin, "scripts", "safe-launch.sh"), event, `--hook=${hook}`],
    { cwd: tmpdir(), env: launchEnv(t, env), detached: true },
  );
  onSpawn?.(child);
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (c) => (stdout += c));
  child.stderr.on("data", (c) => (stderr += c));
  child.stdin.on("error", () => {});
  child.stdin.end(
    typeof payload === "string" ? payload : JSON.stringify(payload),
  );
  return new Promise((resolve) => {
    let hung = false;
    const timer = setTimeout(() => {
      hung = true;
      child.kill("SIGTERM");
      setTimeout(() => signalGroup(child.pid, "SIGKILL"), 500).unref();
    }, limitMs);
    child.on("close", (status) => {
      clearTimeout(timer);
      resolve({ status, stdout, stderr, hung, ms: Date.now() - started });
    });
  });
}

/** Signal a process group, ignoring one that is already gone. */
function signalGroup(pgid, signal) {
  try {
    process.kill(-pgid, signal);
  } catch (err) {
    if (err.code !== "ESRCH") throw err;
  }
}

/**
 * Whether `pid` is a live process. A zombie counts as dead: a killed process
 * reparented to a PID 1 that never reaps (a container's) stays a zombie
 * forever, and it runs nothing.
 */
function alive(pid) {
  const res = spawnSync("ps", ["-o", "stat=", "-p", String(pid)], {
    encoding: "utf8",
  });
  const stat = res.stdout.trim();
  return stat !== "" && !stat.startsWith("Z");
}

/** Poll until `pid` is dead or `ms` passes; returns whether it died. */
async function diesWithin(pid, ms = 3000) {
  const deadline = Date.now() + ms;
  while (alive(pid)) {
    if (Date.now() > deadline) return false;
    await delay(50);
  }
  return true;
}

/** Kill `pid` when the test finishes, whatever the launcher did to it. */
function reapAfter(t, pid) {
  t.after(() => {
    try {
      process.kill(pid, "SIGKILL");
    } catch (err) {
      if (err.code !== "ESRCH") throw err;
    }
  });
}

/** Wait for `path` to hold a pid (or several, one per line) and return them. */
async function pidsFrom(path, ms = 5000) {
  const deadline = Date.now() + ms;
  while (!existsSync(path) || readFileSync(path, "utf8").trim() === "") {
    if (Date.now() > deadline) throw new Error(`no pid written to ${path}`);
    await delay(25);
  }
  return readFileSync(path, "utf8").trim().split("\n").map(Number);
}

/**
 * A bundle that writes `prefix` to stdout, records its pid (so a recorded pid
 * proves the prefix was written), and then spins forever on the main thread —
 * the sync-parse hang no node-side timer could interrupt.
 */
const hangingBundle = (prefix = "") => `
import { writeFileSync } from "node:fs";
process.stdout.write(${JSON.stringify(prefix)});
writeFileSync(process.env.HANG_PID_FILE, String(process.pid));
for (;;) {}
`;

/** Every (event, hook mode) pair hooks.json routes through the launcher. */
function wiredHooks() {
  const manifest = JSON.parse(
    readFileSync(join(PLUGIN_DIR, "hooks", "hooks.json"), "utf8"),
  );
  const pairs = [];
  for (const [event, matchers] of Object.entries(manifest.hooks))
    for (const matcher of matchers)
      for (const entry of matcher.hooks ?? []) {
        const mode = /--hook=([\w-]+)/u.exec(entry.command)?.[1];
        if (mode) pairs.push([event, mode]);
      }
  return pairs;
}

/** The single JSON verdict a launch printed, asserting there is exactly one. */
function soleVerdict(res) {
  const lines = res.stdout.trimEnd().split("\n");
  assert.equal(lines.length, 1, `expected one verdict line: ${res.stdout}`);
  return JSON.parse(lines[0]);
}

/** The reason text the watchdog's verdict carries for `hook`. */
const timeoutClause = (hook, budget = `${BUDGET_MS / 1000}s`) =>
  `the ${hook} hook did not answer within its ${budget} budget`;

/**
 * The closed-posture shape per event — the same table emit_degraded answers
 * every other no-verdict outcome with — returning the text carrying the reason.
 */
const CLOSED_REASON = {
  UserPromptSubmit: (v) => {
    assert.equal(v.decision, "block");
    return v.reason;
  },
  PostToolUse: (v) => {
    assert.equal(v.decision, "block");
    assert.equal(typeof v.hookSpecificOutput.updatedToolOutput, "string");
    return v.reason;
  },
  SessionStart: (v) => v.hookSpecificOutput.additionalContext,
  InstructionsLoaded: (v) => v.hookSpecificOutput.additionalContext,
  PreToolUse: (v) => {
    assert.equal(v.hookSpecificOutput.permissionDecision, "ask");
    return v.hookSpecificOutput.permissionDecisionReason;
  },
};

test("a hung hook is killed and answered within budget, open by default and closed under =0", async (t) => {
  const cases = wiredHooks().flatMap(([event, hook]) =>
    [{}, FAIL_CLOSED].map((posture) => ({ event, hook, posture })),
  );
  assert.ok(cases.length >= 10, "hooks.json lost its wired hooks");
  await Promise.all(
    cases.map(async ({ event, hook, posture }) => {
      const plugin = stagePlugin(t);
      replaceBundle(plugin, hangingBundle());
      const pidFile = join(plugin, "hang.pid");
      const res = await launch(t, plugin, event, hook, "{}", {
        env: {
          ...posture,
          HANG_PID_FILE: pidFile,
          _AGENT_SANITIZER_HOOK_WATCHDOG_MS: String(BUDGET_MS),
        },
      });
      const [pid] = await pidsFrom(pidFile);
      reapAfter(t, pid);
      const label = `${event}/${hook} ${posture === FAIL_CLOSED ? "closed" : "open"}`;
      assert.equal(res.hung, false, `${label}: never answered`);
      assert.equal(res.status, 0, `${label}: ${res.stderr}`);
      assert.ok(
        res.ms < BUDGET_MS + SLACK_MS,
        `${label}: answered after ${res.ms}ms`,
      );
      assert.ok(
        res.stderr.includes(`the ${hook} hook (`) &&
          res.stderr.includes(
            `did not answer within its ${BUDGET_MS / 1000}s watchdog budget`,
          ),
        `${label}: ${res.stderr}`,
      );
      assert.ok(
        await diesWithin(pid),
        `${label}: hung runtime outlived the watchdog`,
      );
      const verdict = soleVerdict(res);
      if (posture === FAIL_CLOSED) {
        const reason = CLOSED_REASON[event](verdict);
        assert.ok(reason.includes(timeoutClause(hook)), `${label}: ${reason}`);
        assert.ok(!reason.includes("failing open"), `${label}: ${reason}`);
        return;
      }
      // Open: nothing blocked, asked, or replaced — the warning is all there is.
      assert.deepEqual(Object.keys(verdict), ["hookSpecificOutput"], label);
      assert.deepEqual(
        Object.keys(verdict.hookSpecificOutput).sort(),
        ["additionalContext", "hookEventName"],
        label,
      );
      assert.equal(verdict.hookSpecificOutput.hookEventName, event, label);
      const context = verdict.hookSpecificOutput.additionalContext;
      assert.ok(context.includes(timeoutClause(hook)), `${label}: ${context}`);
      assert.ok(context.includes("failing open"), `${label}: ${context}`);
    }),
  );
});

test("the hang fixture really hangs: with a large budget the launcher is still running", async (t) => {
  // The positive marker every fast answer above rests on — and the harness's
  // cancel path: a TERM to the launcher takes the runtime's own group down.
  const plugin = stagePlugin(t);
  replaceBundle(plugin, hangingBundle());
  const pidFile = join(plugin, "hang.pid");
  let launcher;
  const pending = launch(t, plugin, "PreToolUse", "pretooluse-sanitize", "{}", {
    env: { HANG_PID_FILE: pidFile, _AGENT_SANITIZER_HOOK_WATCHDOG_MS: "60000" },
    onSpawn: (child) => (launcher = child),
  });
  const [pid] = await pidsFrom(pidFile);
  reapAfter(t, pid);
  await delay(BUDGET_MS + 1000);
  assert.equal(launcher.exitCode, null, "the launcher answered a hang early");
  assert.ok(alive(pid), "the hang fixture stopped on its own");
  launcher.kill("SIGTERM");
  const res = await pending;
  assert.equal(res.hung, false, "the launcher ignored the harness's TERM");
  assert.ok(
    await diesWithin(pid),
    "cancelling the launcher orphaned its hung runtime",
  );
});

test("a killed hook's partial stdout is discarded, never forwarded", async (t) => {
  for (const [name, prefix] of [
    [
      "a truncated verdict",
      '{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"PARTIAL',
    ],
    [
      "a whole verdict, then a hang",
      '{"decision":"block","reason":"PARTIAL"}\n',
    ],
  ]) {
    const plugin = stagePlugin(t);
    replaceBundle(plugin, hangingBundle(prefix));
    const pidFile = join(plugin, "hang.pid");
    const res = await launch(
      t,
      plugin,
      "PostToolUse",
      "sanitize-output",
      "{}",
      {
        env: {
          HANG_PID_FILE: pidFile,
          _AGENT_SANITIZER_HOOK_WATCHDOG_MS: String(BUDGET_MS),
        },
      },
    );
    reapAfter(t, (await pidsFrom(pidFile))[0]);
    assert.equal(res.status, 0, `${name}: ${res.stderr}`);
    assert.ok(!res.stdout.includes("PARTIAL"), `${name}: ${res.stdout}`);
    const context = soleVerdict(res).hookSpecificOutput.additionalContext;
    assert.ok(context.includes(timeoutClause("sanitize-output")), name);
  }
});

test("a fast hook is unaffected: bytes, exit code and stdin pass through, and nothing waits out the budget", async (t) => {
  const budget = 30000;
  const cases = [
    {
      name: "verdict echoing stdin, trailing newlines intact",
      body: `let d = ""; process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => (d += c)).on("end", () => process.stdout.write(JSON.stringify({ got: d }) + "\\n\\n"));`,
      status: 0,
      stdout: `${JSON.stringify({ got: '{"probe":1}' })}\n\n`,
    },
    {
      name: "exit 2 is a decision, forwarded as-is",
      body: `process.stdout.write('{"x":2}'); process.exitCode = 2;`,
      status: 2,
      stdout: '{"x":2}',
    },
  ];
  for (const { name, body, status, stdout } of cases) {
    const plugin = stagePlugin(t);
    replaceBundle(plugin, body);
    const res = await launch(
      t,
      plugin,
      "PreToolUse",
      "pretooluse-sanitize",
      { probe: 1 },
      {
        env: { _AGENT_SANITIZER_HOOK_WATCHDOG_MS: String(budget) },
      },
    );
    assert.equal(res.status, status, `${name}: ${res.stderr}`);
    assert.equal(res.stdout, stdout, name);
    assert.ok(!res.stderr.includes("watchdog"), `${name}: ${res.stderr}`);
    assert.ok(
      res.ms < budget / 3,
      `${name}: took ${res.ms}ms — waited on the watchdog`,
    );
  }

  // The real bundle on a clean call, at the shipped (unset) budget.
  const res = await launch(
    t,
    stagePlugin(t),
    "PreToolUse",
    "pretooluse-sanitize",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Read",
      tool_input: { file_path: "/tmp/x" },
    },
  );
  assert.equal(res.status, 0, res.stderr);
  assert.ok(!res.stderr.includes("watchdog"), res.stderr);
  assert.ok(res.ms < 20000, `the real bundle took ${res.ms}ms`);
});

test("the kill reaches the runtime's whole process group but not a detached descendant", async (t) => {
  const plugin = stagePlugin(t);
  const pidFile = join(plugin, "pids");
  replaceBundle(
    plugin,
    `import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
const attached = spawn("sleep", ["300"], { stdio: "ignore" });
const detached = spawn("sleep", ["300"], { stdio: "ignore", detached: true });
detached.unref();
writeFileSync(process.env.HANG_PID_FILE, attached.pid + "\\n" + detached.pid);
for (;;) {}`,
  );
  const res = await launch(
    t,
    plugin,
    "PreToolUse",
    "pretooluse-sanitize",
    "{}",
    {
      env: {
        HANG_PID_FILE: pidFile,
        _AGENT_SANITIZER_HOOK_WATCHDOG_MS: String(BUDGET_MS),
      },
    },
  );
  const [attached, detached] = await pidsFrom(pidFile);
  reapAfter(t, attached);
  reapAfter(t, detached);
  assert.equal(res.status, 0, res.stderr);
  assert.ok(res.ms < BUDGET_MS + SLACK_MS, `answered after ${res.ms}ms`);
  assert.ok(
    await diesWithin(attached),
    "a non-detached child survived the kill",
  );
  assert.ok(alive(detached), "the kill reached a detached (setsid) descendant");
});

test("a redactor that accepts and never answers: the hook is killed, the daemon it spawned survives", async (t) => {
  // The real bundle and the real client: the socket is absent, so the client
  // spawns the daemon (detached, as it does in production) and its request
  // then stalls for the 60 s request deadline — past the watchdog.
  const plugin = stagePlugin(t);
  const dir = scratch(t);
  const socketPath = join(dir, "redactor.sock");
  const daemonPidFile = join(dir, "daemon.pid");
  const daemon = join(dir, "silent-daemon");
  writeFileSync(
    daemon,
    `#!${process.execPath}
const { writeFileSync } = require("node:fs");
require("node:net")
  .createServer(() => {})
  .listen(process.argv[2], () =>
    writeFileSync(${JSON.stringify(daemonPidFile)}, String(process.pid)),
  );
`,
  );
  chmodSync(daemon, 0o755);
  const budget = 3000;
  const res = await launch(
    t,
    plugin,
    "PostToolUse",
    "sanitize-output",
    {
      hook_event_name: "PostToolUse",
      tool_name: "Bash",
      tool_input: {},
      tool_response: { stdout: "aws_key=AKIAIOSFODNN7EXAMPLE" },
    },
    {
      env: {
        _AGENT_SANITIZER_REDACTOR_SOCKET: socketPath,
        _AGENT_SANITIZER_REDACTOR_DAEMON: daemon,
        _AGENT_SANITIZER_REDACTOR_REQUEST_MS: "60000",
        _AGENT_SANITIZER_HOOK_WATCHDOG_MS: String(budget),
      },
    },
  );
  const [daemonPid] = await pidsFrom(daemonPidFile);
  reapAfter(t, daemonPid);
  assert.equal(res.hung, false, "never answered");
  assert.equal(res.status, 0, res.stderr);
  assert.ok(res.ms < budget + SLACK_MS, `answered after ${res.ms}ms`);
  const context = soleVerdict(res).hookSpecificOutput.additionalContext;
  assert.ok(context.includes(timeoutClause("sanitize-output", "3s")), context);
  assert.ok(!res.stdout.includes("AKIAIOSFODNN7EXAMPLE"), res.stdout);
  assert.ok(alive(daemonPid), "the watchdog killed the long-lived daemon");
  await new Promise((resolve, reject) => {
    const sock = connect(socketPath, () => {
      sock.destroy();
      resolve();
    });
    sock.on("error", reject);
  });
});

test("a hung hook binary is answered at once, not retried on node", async (t) => {
  const plugin = stagePlugin(t);
  replaceBundle(plugin, `process.stdout.write('{"from":"node"}');`);
  const data = scratch(t);
  const binDir = join(data, "hook-binary");
  mkdirSync(binDir);
  const bin = join(binDir, "agent-sanitizer-hooks");
  const pidFile = join(data, "bin.pid");
  writeFileSync(
    bin,
    `#!/bin/sh\ncat >/dev/null\necho $$ >"${pidFile}"\nexec sleep 300\n`,
  );
  chmodSync(bin, 0o755);
  writeFileSync(join(binDir, ".manifest-installed"), STAGED_MANIFEST);
  chmodSync(binDir, 0o700);
  const res = await launch(
    t,
    plugin,
    "PreToolUse",
    "pretooluse-sanitize",
    "{}",
    {
      env: {
        CLAUDE_PLUGIN_DATA: data,
        _AGENT_SANITIZER_HOOK_WATCHDOG_MS: String(BUDGET_MS),
      },
    },
  );
  const [pid] = await pidsFrom(pidFile);
  reapAfter(t, pid);
  assert.equal(res.status, 0, res.stderr);
  assert.ok(res.ms < BUDGET_MS + SLACK_MS, `answered after ${res.ms}ms`);
  assert.ok(res.stderr.includes(`(${bin})`), res.stderr);
  assert.ok(
    !res.stdout.includes("from"),
    `fell through to node: ${res.stdout}`,
  );
  const context = soleVerdict(res).hookSpecificOutput.additionalContext;
  assert.ok(context.includes(timeoutClause("pretooluse-sanitize")), context);
  assert.ok(await diesWithin(pid), "the hung binary outlived the watchdog");
});

test("a malformed watchdog override is reported and the event's default applies", async (t) => {
  const plugin = stagePlugin(t);
  replaceBundle(plugin, `process.stdout.write('{"ok":1}');`);
  for (const value of ["abc", "0", "-5", "1.5"]) {
    const res = await launch(
      t,
      plugin,
      "PostToolUse",
      "sanitize-output",
      "{}",
      {
        env: { _AGENT_SANITIZER_HOOK_WATCHDOG_MS: value },
      },
    );
    assert.equal(res.status, 0, `${value}: ${res.stderr}`);
    assert.equal(res.stdout, '{"ok":1}', value);
    assert.ok(
      res.stderr.includes(
        `_AGENT_SANITIZER_HOOK_WATCHDOG_MS=${value} is not a positive whole number of milliseconds — the 180000ms PostToolUse default applies`,
      ),
      `${value}: ${res.stderr}`,
    );
  }
});
