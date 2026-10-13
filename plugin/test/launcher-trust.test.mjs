/**
 * What plugin/scripts/safe-launch.sh trusts from directories another uid may
 * be able to reach — CLAUDE_PLUGIN_DATA and TMPDIR — and what it hands the
 * runtimes it starts.
 *
 * The launcher reads four things from those trees: the hook binary it execs,
 * V8's compile cache, the redactor venv whose daemon it hands the client, and
 * the degraded-warning marker root. Each must pass `trusted_dir`. The partition
 * test derives the set of paths the launcher touches from bash's own execution
 * trace, so a fifth path added later without a gate fails here.
 *
 * Every case uses a stand-in node (a shell script reporting what it was
 * handed), so nothing here depends on the bundle or on a real node.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  chownSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { PYZ_PATH } from "../scripts/build-redactor-pyz.mjs";

const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const PLUGIN_DIR = join(ROOT, "plugin");
const MANIFEST_REL = join("dist", "hooks", "hook-binaries.sha256");
const IS_ROOT = process.getuid?.() === 0;
const NO_BINARY = { AGENT_SANITIZER_HOOK_BINARY: "0" };
const PYZ_REL = join("dist", "redactor", "daemon.pyz");

/** A scratch dir (mode 0700, from mkdtemp) removed when the test finishes. */
function scratch(t) {
  const dir = mkdtempSync(join(tmpdir(), "agent-sanitizer-trust-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/**
 * The launcher and its libs, plus a manifest for its stale-binary check. The
 * launcher only compares the manifest byte-for-byte with the install stamp, so
 * fixed text stands in for the one only the release bake writes.
 */
function stagePlugin(t) {
  const plugin = join(scratch(t), "plugin");
  cpSync(join(PLUGIN_DIR, "scripts"), join(plugin, "scripts"), {
    recursive: true,
  });
  mkdirSync(join(plugin, "dist", "hooks"), { recursive: true });
  writeFileSync(join(plugin, MANIFEST_REL), "# staged hook-binary manifest\n");
  return plugin;
}

/** A PATH holding the shell utilities the launcher uses, and no node. */
let sharedBin;
function stubBin() {
  if (sharedBin) return sharedBin;
  sharedBin = mkdtempSync(join(tmpdir(), "agent-sanitizer-trust-bin-"));
  process.on("exit", () => rmSync(sharedBin, { recursive: true, force: true }));
  for (const cmd of [
    "bash",
    "sh",
    "cat",
    "dirname",
    "find",
    "mkdir",
    "mktemp",
    "rm",
    "rmdir",
  ]) {
    const found = spawnSync("command", ["-v", cmd], {
      shell: true,
      encoding: "utf8",
    }).stdout.trim();
    assert.ok(found, `${cmd} is not on this host`);
    symlinkSync(found, join(sharedBin, cmd));
  }
  return sharedBin;
}

/** A stand-in node that reports what the launcher exported to it. */
const REPORTING_NODE =
  "cat >/dev/null\n" +
  `printf '{"fromNode":true,"daemon":"%s","cache":"%s","pyz":"%s"}' ` +
  '"${_AGENT_SANITIZER_REDACTOR_DAEMON:-}" "${NODE_COMPILE_CACHE:-}" "${_AGENT_SANITIZER_REDACTOR_PYZ:-}"';

function writeExecutable(path, body) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `#!/bin/sh\n${body}\n`);
  chmodSync(path, 0o755);
}

/**
 * A data dir holding every artifact the launcher may read: a hook binary with
 * its install stamp (unless `stamp` is false), and a provisioned venv daemon.
 * Modes are stated, not left to the runner's umask.
 */
function stageData(t, plugin, { stamp = true } = {}) {
  const data = join(scratch(t), "data");
  const binDir = join(data, "hook-binary");
  writeExecutable(
    join(binDir, "agent-sanitizer-hooks"),
    `cat >/dev/null; printf '{"fromBinary":true}'`,
  );
  if (stamp)
    cpSync(join(plugin, MANIFEST_REL), join(binDir, ".manifest-installed"));
  chmodSync(binDir, 0o700);
  writeExecutable(
    join(data, "venv", "bin", "agent-secret-redactor-daemon"),
    "",
  );
  chmodSync(join(data, "venv"), 0o755);
  chmodSync(join(data, "venv", "bin"), 0o755);
  return data;
}

/** A fresh, owner-only TMPDIR. */
function tmpDir(t) {
  const dir = join(scratch(t), "tmp");
  mkdirSync(dir, { mode: 0o700 });
  return dir;
}

/**
 * A staged launcher: plugin, data dir, owner-only TMPDIR and a stand-in node.
 * `node` is a script body (default: REPORTING_NODE) or null for a host with none.
 */
function setup(t, { stamp = true, node } = {}) {
  const plugin = stagePlugin(t);
  let nodeBin = null;
  if (node !== null) {
    nodeBin = join(scratch(t), "node-bin");
    writeExecutable(join(nodeBin, "node"), node ?? REPORTING_NODE);
  }
  return {
    plugin,
    data: stageData(t, plugin, { stamp }),
    tmp: tmpDir(t),
    node: nodeBin,
  };
}

/** Run the staged launcher once; `over` replaces fields of `s`. */
function launch(s, { env = {}, trace = false, ...over } = {}) {
  const { plugin, data, tmp, node } = { ...s, ...over };
  return spawnSync(
    "bash",
    [
      ...(trace ? ["-x"] : []),
      join(plugin, "scripts", "safe-launch.sh"),
      "PreToolUse",
      "--hook=pretooluse-sanitize",
    ],
    {
      input: "{}",
      encoding: "utf8",
      cwd: tmpdir(),
      env: {
        PATH: node ? `${node}:${stubBin()}` : stubBin(),
        HOME: tmp,
        TMPDIR: tmp,
        CLAUDE_PLUGIN_DATA: data,
        CLAUDE_SESSION_ID: "trust-test-session",
        _AGENT_SANITIZER_NODE_SEARCH: "0",
        ...env,
      },
    },
  );
}

// ─── The partition: every path the launcher touches is gated or exempt ───────

/** Directories the launcher must pass through trusted_dir, relative to a root. */
const GATED = Object.freeze({
  data: ["hook-binary", "venv", "venv/bin", "node-compile-cache"],
  tmp: [`agent-sanitizer-degraded-${process.getuid?.() ?? 0}`],
});

/** Paths the launcher may touch WITHOUT a gate, each with its reason. */
const EXEMPT = Object.freeze([
  // The data root itself: tested for emptiness and used as a prefix, never
  // read or executed.
  { root: "data", pattern: /^$/ },
  // mktemp's own files: created 0600 under an unpredictable name, so no other
  // uid can pre-place or swap them.
  { root: "tmp", pattern: /^tmp\.[A-Za-z0-9]{10}$/ },
]);

/** Every path under `roots` that the traced lines mention, relative to its root. */
function mentionedPaths(traceLines, roots) {
  const found = [];
  for (const line of traceLines)
    for (const [name, root] of Object.entries(roots))
      for (const m of line.matchAll(
        new RegExp(
          `${root.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&")}(/[^\\s'"]*)?`,
          "g",
        ),
      ))
        found.push({ root: name, rel: (m[1] ?? "").replace(/^\//, "") });
  return found;
}

test("every CLAUDE_PLUGIN_DATA / TMPDIR path the launcher touches is gated or exempt", (t) => {
  const s = setup(t);
  const stale = { ...s, data: stageData(t, s.plugin, { stamp: false }) };
  // One run per launcher branch that reads a different path: the binary
  // answering, a stale binary passed over for node (the stamp read and the
  // compile cache), and the degraded verdict (the marker root).
  const runs = [
    launch(s, { trace: true }),
    launch(stale, { trace: true }),
    launch(s, { node: null, env: NO_BINARY, trace: true }),
  ];
  const answeredBy = (res) => {
    const out = JSON.parse(res.stdout);
    if (out.fromBinary) return "binary";
    return out.fromNode ? "node" : "degraded";
  };
  assert.deepEqual(
    runs.map(answeredBy),
    ["binary", "node", "degraded"],
    "a run did not take the branch it exists to trace",
  );
  const trace = runs
    .flatMap((r) => r.stderr.split("\n"))
    .filter((l) => /^\++ /.test(l));

  const rootPaths = { data: s.data, staleData: stale.data, tmp: s.tmp };
  const gated = new Set();
  for (const line of trace) {
    const m = /^\++ trusted_dir (.+)$/.exec(line);
    if (!m) continue;
    for (const p of mentionedPaths([m[1]], rootPaths))
      gated.add(`${p.root === "tmp" ? "tmp" : "data"}:${p.rel}`);
  }
  const declared = [
    ...GATED.data.map((d) => `data:${d}`),
    ...GATED.tmp.map((d) => `tmp:${d}`),
  ];
  // Exact: a gate that stops running fails here, and so does an undeclared one.
  assert.deepEqual([...gated].sort(), declared.sort());

  const exemptHits = new Set();
  const unclassified = [];
  const live = mentionedPaths(trace, rootPaths);
  assert.ok(
    live.length > 0,
    "the trace mentioned no path — the parse is wrong",
  );
  for (const { root, rel } of live) {
    const kind = root === "tmp" ? "tmp" : "data";
    const underGate = GATED[kind].some(
      (g) => rel === g || rel.startsWith(`${g}/`),
    );
    const exempt = EXEMPT.findIndex(
      (e) => e.root === kind && e.pattern.test(rel),
    );
    if (exempt >= 0) exemptHits.add(exempt);
    if (!underGate && exempt < 0) unclassified.push(`${kind}:${rel}`);
  }
  assert.deepEqual(
    [...new Set(unclassified)],
    [],
    "the launcher touches these paths without a trusted_dir gate or a stated exemption",
  );
  // Every exemption is live: one that matches nothing is a hole waiting for a
  // path to fall into it.
  assert.deepEqual(
    [...exemptHits].sort(),
    EXEMPT.map((_, i) => i),
  );
});

// ─── Each gated directory refuses a mode or owner it cannot trust ────────────

/** How to make a gated directory untrustworthy. */
const UNTRUSTED = Object.freeze({
  "mode 0777": (dir) => chmodSync(dir, 0o777),
  "owned by another uid": (dir) => chownSync(dir, 65534, 65534),
});
/** A node:test `skip` for the cases only root can set up. */
const skipUnlessRoot = (how) =>
  how.startsWith("owned") &&
  !IS_ROOT &&
  "only root can hand a directory to another uid";

const daemonUsed = (res) =>
  JSON.parse(res.stdout).daemon.endsWith(
    "/venv/bin/agent-secret-redactor-daemon",
  );
const viaNode = (s) => launch(s, { env: NO_BINARY });

/** Per gated directory: how to exercise it, and whether the launcher used it. */
const GATE_CASES = Object.freeze({
  "hook-binary": {
    run: (s) => launch(s),
    used: (res) => JSON.parse(res.stdout).fromBinary === true,
  },
  venv: { run: viaNode, used: daemonUsed },
  "venv/bin": { run: viaNode, used: daemonUsed },
  "node-compile-cache": {
    run: viaNode,
    used: (res) => JSON.parse(res.stdout).cache.endsWith("/node-compile-cache"),
  },
});

for (const [gate, { run, used }] of Object.entries(GATE_CASES)) {
  test(`${gate}: used when owner-only (positive control)`, (t) => {
    const res = run(setup(t));
    assert.equal(res.status, 0, res.stderr);
    assert.ok(used(res), res.stdout);
  });
  for (const [how, spoil] of Object.entries(UNTRUSTED))
    test(`${gate}: refused when ${how}`, { skip: skipUnlessRoot(how) }, (t) => {
      const s = setup(t);
      if (gate === "node-compile-cache")
        mkdirSync(join(s.data, gate), { mode: 0o700 });
      spoil(join(s.data, gate));
      const res = run(s);
      assert.equal(res.status, 0, res.stderr);
      assert.ok(!used(res), `the untrusted ${gate} was used: ${res.stdout}`);
      // Refused out loud, never in silence.
      assert.match(res.stderr, /owner-only write/);
    });
}

/** Two degraded calls in one session; returns whether each carried context. */
function degradedContexts(s) {
  return [1, 2].map(() => {
    const res = launch(s, { node: null, env: NO_BINARY });
    assert.equal(res.status, 0, res.stderr);
    return "additionalContext" in JSON.parse(res.stdout).hookSpecificOutput;
  });
}

test("marker root: an owner-only root dedupes the warning (positive control)", (t) => {
  assert.deepEqual(degradedContexts(setup(t)), [true, false]);
});

for (const [how, spoil] of Object.entries(UNTRUSTED))
  test(
    `marker root: a pre-existing marker is ignored when the root is ${how}`,
    { skip: skipUnlessRoot(how) },
    (t) => {
      // The squat: the root, and this session's marker for this very fault,
      // are already there. A launcher that trusted them would drop the warning
      // from the FIRST degraded call — the one the model must see.
      const s = setup(t);
      assert.deepEqual(degradedContexts(s), [true, false]);
      const markerRoot = join(s.tmp, GATED.tmp[0]);
      assert.ok(existsSync(markerRoot));
      spoil(markerRoot);
      assert.deepEqual(degradedContexts(s), [true, true]);
    },
  );

// ─── Stale binary: node runs the bundle this install ships ───────────────────

/** A stand-in node answering `--version` with `v`, else REPORTING_NODE. */
const nodeVersion = (v) =>
  `[ "$1" = --version ] && { echo ${v}; exit 0; }\n${REPORTING_NODE}`;

// A stale binary still beats an unsanitized call, so it answers (saying why on
// stderr) only where node cannot run the bundle: none found, or one below the
// floor, which would die after stdin is spent.
const STALE_CASES = [
  ["no install stamp", { stamp: false }, "node"],
  [
    "a stamp naming a different manifest",
    {},
    "node",
    (s) =>
      writeFileSync(
        join(s.data, "hook-binary", ".manifest-installed"),
        "# older\n",
      ),
  ],
  ["no node on the host", { stamp: false, node: null }, "binary"],
  [
    "a node below the floor",
    { stamp: false, node: nodeVersion("v20.1.0") },
    "binary",
  ],
  [
    "a node at the floor",
    { stamp: false, node: nodeVersion("v22.14.0") },
    "node",
  ],
];

for (const [name, opts, runtime, mutate] of STALE_CASES)
  test(`a stale binary with ${name} is answered by ${runtime}`, (t) => {
    const s = setup(t, opts);
    mutate?.(s);
    const res = launch(s);
    assert.equal(res.status, 0, res.stderr);
    if (runtime === "node") {
      assert.equal(JSON.parse(res.stdout).fromNode, true);
      return;
    }
    assert.deepEqual(JSON.parse(res.stdout), { fromBinary: true });
    assert.match(res.stderr, /running it anyway/);
  });

// ─── What the runtimes are handed ────────────────────────────────────────────

test("both runtimes are told where the shipped zipapp is", (t) => {
  // The compiled binary resolves its modules inside bun's virtual filesystem,
  // where a module-relative zipapp path names nothing on disk.
  const s = setup(t);
  assert.equal(
    JSON.parse(launch(s, { env: NO_BINARY }).stdout).pyz,
    join(s.plugin, PYZ_REL),
  );
  // The path names the artifact the build really writes there.
  assert.equal(join(PLUGIN_DIR, PYZ_REL), PYZ_PATH);
});

test("an explicit zipapp path is honored, not overwritten", (t) => {
  const res = launch(setup(t), {
    env: { ...NO_BINARY, _AGENT_SANITIZER_REDACTOR_PYZ: "/chosen/daemon.pyz" },
  });
  assert.equal(JSON.parse(res.stdout).pyz, "/chosen/daemon.pyz");
});

// ─── The degraded envelope is JSON whatever the operator typed ───────────────

/** Every C0 control character JSON forbids raw, built in-language. */
const CONTROL_CHARS = Array.from({ length: 0x1f }, (_, i) =>
  String.fromCharCode(i + 1),
);

for (const posture of ["open", "closed"])
  test(`a control character in AGENT_SANITIZER_NODE still yields parseable JSON (fail ${posture})`, (t) => {
    assert.equal(CONTROL_CHARS.length, 31);
    const s = setup(t, { node: null });
    for (const ch of CONTROL_CHARS) {
      const res = launch(s, {
        tmp: tmpDir(t),
        env: {
          ...NO_BINARY,
          AGENT_SANITIZER_NODE: `/opt/no${ch}de/bin/node`,
          AGENT_SANITIZER_FAIL_OPEN: posture === "open" ? "1" : "0",
        },
      });
      const label = `byte 0x${ch.charCodeAt(0).toString(16)}`;
      assert.equal(res.status, 0, `${label}: ${res.stderr}`);
      const out = JSON.parse(res.stdout).hookSpecificOutput;
      // The verdict the posture asks for, with the typo still named in it.
      const reason =
        posture === "open"
          ? out.additionalContext
          : (assert.equal(out.permissionDecision, "ask", label),
            out.permissionDecisionReason);
      assert.match(
        reason,
        /AGENT_SANITIZER_NODE points at \/opt\/no de\/bin\/node/,
        label,
      );
    }
  });
