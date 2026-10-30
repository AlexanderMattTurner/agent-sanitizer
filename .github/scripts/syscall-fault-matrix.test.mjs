// The strace-driven half of syscall-fault-matrix.mjs runs only in the
// syscall-faults workflow (it needs strace and ptrace); this pins the logic that
// decides what an injection touched and whether a run broke the fail-open
// contract, so a wrong oracle cannot hide behind a green matrix.
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  closedSomething,
  enforcement,
  formatTable,
  injectionPoints,
  loggedExit,
  judgeOpen,
  minimalInjection,
  parseArgs,
  parseTrace,
  parseVerdict,
  reproducer,
  sampleCells,
  scenarioSeed,
  scenarios,
  scopeOf,
  shQuote,
  straceArgv,
} from "./syscall-fault-matrix.mjs";

const R = "/tmp/sfm-AbC123/pretooluse_sanitize_3";

// Lines in the exact shape `strace -f -q -y -o` writes them.
const TRACE = [
  `101 openat(AT_FDCWD<${R}/project>, "/usr/lib/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</usr/lib/libc.so.6>`,
  `101 openat(AT_FDCWD<${R}/project>, "${R}/tmp/store.json", O_RDONLY) = 4<${R}/tmp/store.json>`,
  `101 read(4<${R}/tmp/store.json>, "{\\"path\\":\\"${R}/data/x\\"}", 4096) = 22`,
  `101 write(1<pipe:[555]>, "${R}/tmp/store.json", 30) = 30`,
  `101 fstat(4<${R}/tmp/store.json>, {st_mode=S_IFREG|0600, st_size=22, ...}) = 0`,
  `101 rename("${R}/tmp/store.json.1a2b", "${R}/tmp/store.json" <unfinished ...>`,
  `102 openat(AT_FDCWD<${R}/project>, "${R}/tmp/store.json", O_RDONLY) = -1 EIO (Input/output error) (INJECTED)`,
  `101 <... rename resumed>) = -1 ENOSPC (No space left on device) (INJECTED)`,
  `101 connect(5<socket:[777]>, {sa_family=AF_UNIX, sun_path="${R}/run/redactor.sock"}, 110) = 0`,
  `102 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=103} ---`,
  `103 +++ killed by SIGKILL +++`,
  `101 +++ exited with 0 +++`,
].join("\n");

test("parseTrace keeps only the paths -P can match, and joins split calls", () => {
  assert.deepEqual(parseTrace(TRACE, R), [
    // AT_FDCWD's cwd decoration is not a path -P matches; libc is outside R.
    { pid: "101", name: "openat", paths: [], injected: false },
    {
      pid: "101",
      name: "openat",
      paths: [`${R}/tmp/store.json`],
      injected: false,
    },
    // A read buffer that happens to hold a path is data.
    {
      pid: "101",
      name: "read",
      paths: [`${R}/tmp/store.json`],
      injected: false,
    },
    { pid: "101", name: "write", paths: [], injected: false },
    {
      pid: "101",
      name: "fstat",
      paths: [`${R}/tmp/store.json`],
      injected: false,
    },
    {
      pid: "101",
      name: "rename",
      paths: [`${R}/tmp/store.json.1a2b`, `${R}/tmp/store.json`],
      injected: true,
    },
    {
      pid: "102",
      name: "openat",
      paths: [`${R}/tmp/store.json`],
      injected: true,
    },
    {
      pid: "101",
      name: "connect",
      paths: [`${R}/run/redactor.sock`],
      injected: false,
    },
  ]);
});

test("loggedExit reads one process's own exit line", () => {
  assert.equal(loggedExit(TRACE, "101"), 0);
  assert.equal(loggedExit(TRACE, "103"), 128);
  // 102 is still running; 10 is a prefix of 101, not 101.
  assert.equal(loggedExit(TRACE, "102"), undefined);
  assert.equal(loggedExit(TRACE, "10"), undefined);
});

test("a path that merely shares the root's prefix is out of scope", () => {
  const calls = parseTrace(`7 mkdir("${R}-other/x", 0700) = 0`, R);
  assert.deepEqual(calls, [
    { pid: "7", name: "mkdir", paths: [], injected: false },
  ]);
});

test("scopeOf keeps paths both traces saw and counts the busiest process", () => {
  const call = (pid, name, ...paths) => ({ pid, name, paths, injected: false });
  const a = [
    call("1", "openat", `${R}/tmp/a`),
    call("1", "openat", `${R}/tmp/a`),
    call("1", "openat", `${R}/tmp/random.X1`),
    call("2", "openat", `${R}/tmp/a`),
    call("1", "openat", `${R}/data/node-compile-cache/v22/blob`),
    call("1", "statx", `${R}/data/node-compile-cache`),
    call("3", "connect"),
    call("3", "connect"),
  ];
  const b = [
    call("9", "openat", `${R}/tmp/a`),
    call("9", "openat", `${R}/tmp/random.Y2`),
    call("9", "openat", `${R}/data/node-compile-cache/v22/blob`),
  ];
  const scope = scopeOf(a, b, [`${R}/data/node-compile-cache`]);
  assert.deepEqual(scope.paths, [`${R}/tmp/a`]);
  assert.equal(scope.unscoped, 1);
  // Process 1's openat count excludes its random-named and cache calls, and
  // statx on the excluded dir is not counted at all.
  assert.deepEqual(
    [...scope.counts],
    [
      ["openat", 2],
      ["connect", 2],
    ],
  );
});

test("minimalInjection narrows -P to what was hit and re-counts when=", () => {
  const call = (name, path, injected = false) => ({
    pid: "1",
    name,
    paths: [path],
    injected,
  });
  const calls = [
    call("openat", `${R}/tmp/a`),
    call("openat", `${R}/tmp/b`),
    call("openat", `${R}/tmp/b`, true),
  ];
  assert.deepEqual(minimalInjection(calls, "openat", "3"), {
    paths: [`${R}/tmp/b`],
    when: "2",
  });
  const twice = [
    call("openat", `${R}/tmp/a`, true),
    call("openat", `${R}/tmp/b`, true),
  ];
  assert.deepEqual(minimalInjection(twice, "openat", "1+"), {
    paths: [`${R}/tmp/a`, `${R}/tmp/b`],
    when: "1+",
  });
  // An empty -P set would inject everywhere, so "nothing to narrow" is null.
  assert.equal(
    minimalInjection([call("openat", `${R}/tmp/a`)], "openat", "1"),
    null,
  );
  assert.equal(minimalInjection(calls, "connect", "1"), null);
});

test("injectionPoints: first, last and every, deduplicated", () => {
  assert.deepEqual(injectionPoints(0), []);
  assert.deepEqual(injectionPoints(1), ["1", "1+"]);
  assert.deepEqual(injectionPoints(7), ["1", "7", "1+"]);
});

test("straceArgv filters every group by path except connect", () => {
  const cell = { errno: "EIO", when: "2", paths: ["/r/a", "/r/b"], log: "/l" };
  assert.deepEqual(straceArgv({ ...cell, group: "rename" }), [
    "-f",
    "-q",
    "-y",
    "--seccomp-bpf",
    "-o",
    "/l",
    "-e",
    "trace=rename,renameat,renameat2",
    "-P",
    "/r/a",
    "-P",
    "/r/b",
    "-e",
    "inject=rename,renameat,renameat2:error=EIO:when=2",
  ]);
  assert.ok(!straceArgv({ ...cell, group: "connect" }).includes("-P"));
});

test("enforcement names every channel that stops or rewrites a session", () => {
  assert.deepEqual(enforcement({ status: 0, verdict: null }), []);
  assert.deepEqual(
    enforcement({
      status: 0,
      verdict: { hookSpecificOutput: { additionalContext: "warning" } },
    }),
    [],
  );
  assert.deepEqual(
    enforcement({
      status: 2,
      verdict: {
        decision: "block",
        hookSpecificOutput: {
          permissionDecision: "ask",
          updatedToolOutput: "",
        },
      },
    }),
    ["exit 2", "ask", "decision: block", "updatedToolOutput"],
  );
  assert.deepEqual(
    enforcement({
      status: 0,
      verdict: { hookSpecificOutput: { permissionDecision: "allow" } },
    }),
    [],
  );
});

test("parseVerdict accepts empty or one object, and nothing else", () => {
  assert.equal(parseVerdict(" \n"), null);
  assert.deepEqual(parseVerdict('{"a":1}\n'), { a: 1 });
  for (const bad of ['{"a":1}{"b":2}', "[]", "null", "warning: x"])
    assert.ok(parseVerdict(bad) instanceof Error, bad);
});

const run = (stdout, extra = {}) => ({
  status: 0,
  stdout,
  stderr: "",
  injected: 1,
  timedOut: false,
  ...extra,
});
const DENY_RELEASABLE = JSON.stringify({
  hookSpecificOutput: {
    permissionDecision: "deny",
    permissionDecisionReason: `could not read ${R}/project/x. If writing this text as-is is intended, re-issue this exact call (same tool, same input) to confirm.`,
  },
});
const ORDINARY = { placeholderWrite: false };
const PLACEHOLDER = { placeholderWrite: true };

test("judgeOpen: the open posture's verdicts", async (t) => {
  const quiet = run("");
  const warned = run('{"hookSpecificOutput":{"additionalContext":"degraded"}}');
  const redacted = (root) =>
    run(`{"hookSpecificOutput":{"updatedToolOutput":{"stdout":"${root}"}}}`);
  const cases = [
    [
      "an injection that never landed",
      { launch: run("", { injected: 0, status: 2 }) },
      quiet,
      ORDINARY,
      { outcome: "n/r" },
    ],
    [
      "unchanged output",
      { launch: quiet },
      quiet,
      ORDINARY,
      { outcome: "same" },
    ],
    ["a warning", { launch: warned }, quiet, ORDINARY, { outcome: "warn" }],
    // The fault left the hook's own redaction intact: its decision, not a block.
    [
      "the baseline's own rewrite",
      { launch: redacted(R) },
      redacted(R),
      ORDINARY,
      { outcome: "same" },
    ],
    [
      "exit 2",
      { launch: run("", { status: 2 }) },
      quiet,
      ORDINARY,
      { outcome: "VIOL", problem: "exit 2" },
    ],
    [
      "a timeout",
      { launch: run("", { timedOut: true, status: null }) },
      quiet,
      ORDINARY,
      { outcome: "VIOL", problem: "no exit within 60000 ms" },
    ],
    [
      "a rewrite the baseline did not make",
      {
        launch: run(
          '{"hookSpecificOutput":{"updatedToolOutput":"[SANITIZATION FAILED]"}}',
        ),
      },
      quiet,
      ORDINARY,
      { outcome: "VIOL", problem: "blocked via updatedToolOutput" },
    ],
    [
      "a prompt block",
      { launch: run('{"decision":"block","reason":"x"}') },
      quiet,
      ORDINARY,
      { outcome: "VIOL", problem: "blocked via decision: block" },
    ],
    [
      "an armed gate",
      {
        launch: quiet,
        probe: run('{"hookSpecificOutput":{"permissionDecision":"ask"}}'),
      },
      quiet,
      ORDINARY,
      { outcome: "VIOL", problem: "the next tool call was stopped: ask" },
    ],
    // The re-issue escape licenses nothing outside a placeholder write.
    [
      "a releasable-looking deny on ordinary traffic",
      { launch: run(DENY_RELEASABLE), reissue: quiet },
      quiet,
      ORDINARY,
      { outcome: "VIOL", problem: "blocked via deny" },
    ],
    [
      "a placeholder refusal that releases",
      { launch: run(DENY_RELEASABLE), reissue: quiet },
      quiet,
      PLACEHOLDER,
      { outcome: "release" },
    ],
    [
      "a placeholder refusal never re-issued",
      { launch: run(DENY_RELEASABLE) },
      quiet,
      PLACEHOLDER,
      { outcome: "VIOL", problem: "releasable refusal was never re-issued" },
    ],
  ];
  for (const [name, observed, baseline, scenario, expected] of cases)
    await t.test(name, () =>
      assert.deepEqual(judgeOpen(observed, baseline, scenario), expected),
    );
  await t.test("a placeholder refusal refused again on re-issue", () => {
    const verdict = judgeOpen(
      { launch: run(DENY_RELEASABLE), reissue: run(DENY_RELEASABLE) },
      quiet,
      PLACEHOLDER,
    );
    assert.equal(verdict.outcome, "VIOL");
    assert.match(
      verdict.problem,
      /^the exact re-issue was refused again: deny: /,
    );
  });
  await t.test("unparseable stdout", () => {
    const verdict = judgeOpen({ launch: run("oops {") }, quiet, ORDINARY);
    assert.equal(verdict.outcome, "VIOL");
    assert.match(verdict.problem, /^stdout is not one JSON verdict/);
  });
});

test("closedSomething counts only new enforcement from a landed injection", () => {
  const quiet = run("");
  const denied = run('{"hookSpecificOutput":{"permissionDecision":"deny"}}');
  assert.equal(closedSomething({ launch: denied }, quiet), true);
  assert.equal(closedSomething({ launch: quiet, probe: denied }, quiet), true);
  assert.equal(closedSomething({ launch: denied }, denied), false);
  assert.equal(
    closedSomething({ launch: { ...denied, injected: 0 } }, quiet),
    false,
  );
  assert.equal(
    closedSomething({ launch: run('{"systemMessage":"x"}') }, quiet),
    false,
  );
});

test("formatTable puts each when= position in its own column", () => {
  const table = formatTable([
    { hook: "h", group: "openat", errno: "EIO", when: "1", outcome: "same" },
    { hook: "h", group: "openat", errno: "EIO", when: "4", outcome: "warn/C" },
    { hook: "h", group: "openat", errno: "EIO", when: "1+", outcome: "VIOL" },
    { hook: "h", group: "stat", errno: "EMFILE", when: "1", outcome: "n/r" },
  ]);
  assert.equal(
    table,
    [
      "scenario  syscall  errno   when=1  when=N  when=1+",
      "h         openat   EIO     same    warn/C  VIOL",
      "h         stat     EMFILE  n/r     -       -",
    ].join("\n"),
  );
});

test("sampleCells is seeded, keeps order, and keeps everything within budget", () => {
  const items = Array.from({ length: 50 }, (_, i) => i);
  const picked = sampleCells(items, 10, 42);
  assert.equal(picked.length, 10);
  assert.deepEqual(picked, sampleCells(items, 10, 42));
  assert.notDeepEqual(picked, sampleCells(items, 10, 43));
  assert.deepEqual(
    picked,
    [...picked].sort((a, b) => a - b),
  );
  assert.equal(sampleCells(items, 50, 1), items);
});

test("scenarioSeed separates scenarios and replays per seed", () => {
  assert.equal(scenarioSeed(7, "a:openat"), scenarioSeed(7, "a:openat"));
  assert.notEqual(scenarioSeed(7, "a:openat"), scenarioSeed(7, "b:openat"));
  assert.notEqual(scenarioSeed(7, "a:openat"), scenarioSeed(8, "a:openat"));
});

test("parseArgs rejects what it cannot use", () => {
  assert.deepEqual(parseArgs(["--seed=7", "--budget=20", "--jobs=2"]), {
    seed: 7,
    budget: 20,
    jobs: 2,
    only: undefined,
  });
  assert.equal(parseArgs([]).budget, Infinity);
  for (const bad of [
    ["--seed=x"],
    ["--budget=-1"],
    ["--frobnicate=1"],
    ["seed=1"],
  ])
    assert.throws(() => parseArgs(bad), bad.join());
});

test("every scenario id is unique and the secret traffic carries Layer 4", () => {
  const all = scenarios();
  assert.equal(new Set(all.map((s) => s.id)).size, all.length);
  for (const s of all.filter((s) => s.baseline.length > 0))
    assert.equal(s.secrets, true, s.id);
});

test("shQuote survives the real shell", () => {
  for (const s of ["plain", "it's", "a b", "$HOME `x` \\n", "'", ""]) {
    const out = spawnSync("sh", ["-c", `printf %s ${shQuote(s)}`], {
      encoding: "utf8",
    });
    assert.equal(out.stdout, s);
  }
});

test("the reproducer hands strace exactly the argv the harness used", (t) => {
  // strace stands in as a PATH stub because the test job has no strace (the
  // matrix job installs it); what is under test is the shell quoting between
  // this script and strace's argv, which the stub reports verbatim.
  const dir = mkdtempSync(join(tmpdir(), "sfm-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const bin = join(dir, "bin");
  spawnSync("mkdir", [bin]);
  writeFileSync(
    join(bin, "strace"),
    `#!/bin/sh\ncat >/dev/null\nnode -e 'console.log(JSON.stringify({argv: process.argv.slice(1), cwd: process.cwd(), env: process.env.CLAUDE_SESSION_ID}))' -- "$@"\n`,
  );
  chmodSync(join(bin, "strace"), 0o755);
  const root = join(dir, "it's root");
  const strace = straceArgv({
    group: "openat",
    errno: "EACCES",
    when: "1",
    paths: [join(root, "tmp", "a b"), join(root, "project")],
    log: "/dev/null",
  });
  const line = reproducer({
    root,
    env: { CLAUDE_SESSION_ID: `s'1 ${root}` },
    strace,
    event: "PreToolUse",
    mode: "pretooluse-sanitize",
    payload: JSON.stringify({ file_path: join(root, "project", "x") }),
    warm: false,
  });
  const res = spawnSync("bash", ["-c", line], {
    encoding: "utf8",
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
  });
  assert.equal(res.status, 0, res.stderr);
  const seen = JSON.parse(res.stdout);
  assert.deepEqual(seen.argv.slice(0, strace.length), strace);
  assert.equal(seen.cwd, join(root, "project"));
  assert.equal(seen.env, `s'1 ${root}`);
});
