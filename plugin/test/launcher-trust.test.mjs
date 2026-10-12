/**
 * What plugin/scripts/safe-launch.sh trusts from directories another uid may
 * be able to reach — CLAUDE_PLUGIN_DATA and TMPDIR — and what it hands the
 * runtimes it starts.
 *
 * The launcher reads four things from those trees: the hook binary it execs,
 * V8's compile cache, the redactor venv whose daemon it hands the client, and
 * the degraded-warning marker root. Each is code in the session (or, for the
 * marker, the one model-visible signal that a call ran unguarded), so each must
 * pass `trusted_dir`. The partition test below derives the set of paths the
 * launcher actually touches from bash's own execution trace, so a fifth path
 * added later without a gate fails here rather than shipping unguarded.
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

const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const PLUGIN_DIR = join(ROOT, "plugin");
const MANIFEST_REL = join("dist", "hooks", "hook-binaries.sha256");
const IS_ROOT = process.getuid?.() === 0;

/** A scratch dir (mode 0700, from mkdtemp) removed when the test finishes. */
function scratch(t) {
  const dir = mkdtempSync(join(tmpdir(), "agent-sanitizer-trust-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/**
 * The launcher and its libs, plus the manifest its stale-binary check reads.
 * The stand-in node never opens the bundle, so the rest of dist/ is not staged.
 */
function stagePlugin(t) {
  const plugin = join(scratch(t), "plugin");
  cpSync(join(PLUGIN_DIR, "scripts"), join(plugin, "scripts"), {
    recursive: true,
  });
  mkdirSync(join(plugin, "dist", "hooks"), { recursive: true });
  cpSync(join(PLUGIN_DIR, MANIFEST_REL), join(plugin, MANIFEST_REL));
  return plugin;
}

/**
 * A PATH holding the shell utilities the launcher uses, and no node. Built once
 * per file: it is read-only to every case, and resolving it costs a shell per
 * utility.
 */
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

/**
 * Run the staged launcher once. `node` is a stand-in node dir to put on PATH,
 * or null for a host with none. Returns spawnSync's result.
 */
function launch(t, plugin, { data, tmp, node, env = {}, trace = false }) {
  const path = node ? `${node}:${stubBin()}` : stubBin();
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
        PATH: path,
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

/** A stand-in node dir running `body`. */
function nodeDir(t, body = REPORTING_NODE) {
  const dir = join(scratch(t), "node-bin");
  writeExecutable(join(dir, "node"), body);
  return dir;
}

/** A fresh, owner-only TMPDIR. */
function tmpDir(t) {
  const dir = join(scratch(t), "tmp");
  mkdirSync(dir, { mode: 0o700 });
  return dir;
}

// ─── The partition: every path the launcher touches is gated or exempt ───────

/** Directories the launcher must pass through trusted_dir, relative to a root. */
const GATED = Object.freeze({
  data: ["hook-binary", "venv", "venv/bin", "node-compile-cache"],
  tmp: [`agent-sanitizer-degraded-${process.getuid?.() ?? 0}`],
});

/**
 * Paths the launcher may touch WITHOUT a gate, each with the reason it needs
 * none. Matched against the path relative to its root.
 */
const EXEMPT = Object.freeze([
  // The data root itself: tested for emptiness and used as a prefix, never
  // read or executed.
  { root: "data", pattern: /^$/ },
  // mktemp's own files: created 0600 under a name nobody can predict, so no
  // other uid can pre-place or swap them.
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
  const plugin = stagePlugin(t);
  const roots = {
    data: stageData(t, plugin),
    staleData: stageData(t, plugin, { stamp: false }),
  };
  const tmp = tmpDir(t);
  const node = nodeDir(t);
  // One run per launcher branch that reads a different path: the binary
  // answering, a stale binary passed over for node (the stamp read and the
  // compile cache), and the degraded verdict (the marker root).
  const runs = [
    launch(t, plugin, { data: roots.data, tmp, node, trace: true }),
    launch(t, plugin, { data: roots.staleData, tmp, node, trace: true }),
    launch(t, plugin, {
      data: roots.data,
      tmp,
      node: null,
      env: { AGENT_SANITIZER_HOOK_BINARY: "0" },
      trace: true,
    }),
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

  // Gated: every directory handed to trusted_dir, relative to its root.
  const rootPaths = { data: roots.data, staleData: roots.staleData, tmp };
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
  // Exact: a gate that stops running fails here, and so does a new one that
  // nobody declared.
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

/**
 * Per gated directory: what the launcher does when it is trustworthy, and the
 * assertion that it did NOT use it once it is not.
 */
const GATE_CASES = Object.freeze({
  "hook-binary": {
    run: (t, plugin, data, tmp) =>
      launch(t, plugin, { data, tmp, node: nodeDir(t) }),
    used: (res) => JSON.parse(res.stdout).fromBinary === true,
  },
  venv: {
    run: (t, plugin, data, tmp) =>
      launch(t, plugin, {
        data,
        tmp,
        node: nodeDir(t),
        env: { AGENT_SANITIZER_HOOK_BINARY: "0" },
      }),
    used: (res) =>
      JSON.parse(res.stdout).daemon.endsWith(
        "/venv/bin/agent-secret-redactor-daemon",
      ),
  },
  "venv/bin": {
    run: (t, plugin, data, tmp) =>
      launch(t, plugin, {
        data,
        tmp,
        node: nodeDir(t),
        env: { AGENT_SANITIZER_HOOK_BINARY: "0" },
      }),
    used: (res) =>
      JSON.parse(res.stdout).daemon.endsWith(
        "/venv/bin/agent-secret-redactor-daemon",
      ),
  },
  "node-compile-cache": {
    run: (t, plugin, data, tmp) => {
      mkdirSync(join(data, "node-compile-cache"), {
        mode: 0o700,
        recursive: true,
      });
      return launch(t, plugin, {
        data,
        tmp,
        node: nodeDir(t),
        env: { AGENT_SANITIZER_HOOK_BINARY: "0" },
      });
    },
    used: (res) => JSON.parse(res.stdout).cache.endsWith("/node-compile-cache"),
  },
});

for (const [gate, { run, used }] of Object.entries(GATE_CASES)) {
  test(`${gate}: used when owner-only (positive control)`, (t) => {
    const plugin = stagePlugin(t);
    const res = run(t, plugin, stageData(t, plugin), tmpDir(t));
    assert.equal(res.status, 0, res.stderr);
    assert.ok(used(res), res.stdout);
  });
  for (const [how, spoil] of Object.entries(UNTRUSTED))
    test(`${gate}: refused when ${how}`, (t) => {
      if (how.startsWith("owned") && !IS_ROOT) {
        t.skip("only root can hand a directory to another uid");
        return;
      }
      const plugin = stagePlugin(t);
      const data = stageData(t, plugin);
      if (gate === "node-compile-cache")
        mkdirSync(join(data, gate), { mode: 0o700 });
      spoil(join(data, gate));
      const res = run(t, plugin, data, tmpDir(t));
      assert.equal(res.status, 0, res.stderr);
      assert.ok(!used(res), `the untrusted ${gate} was used: ${res.stdout}`);
      // Refused out loud, never in silence.
      assert.match(res.stderr, /owner-only write/);
    });
}

/** Two degraded calls in one session; returns whether each carried context. */
function degradedContexts(t, plugin, data, tmp) {
  return [1, 2].map(() => {
    const res = launch(t, plugin, {
      data,
      tmp,
      node: null,
      env: { AGENT_SANITIZER_HOOK_BINARY: "0" },
    });
    assert.equal(res.status, 0, res.stderr);
    return "additionalContext" in JSON.parse(res.stdout).hookSpecificOutput;
  });
}

test("marker root: an owner-only root dedupes the warning (positive control)", (t) => {
  const plugin = stagePlugin(t);
  assert.deepEqual(
    degradedContexts(t, plugin, stageData(t, plugin), tmpDir(t)),
    [true, false],
  );
});

for (const [how, spoil] of Object.entries(UNTRUSTED))
  test(`marker root: a pre-existing marker is ignored when the root is ${how}`, (t) => {
    if (how.startsWith("owned") && !IS_ROOT) {
      t.skip("only root can hand a directory to another uid");
      return;
    }
    // The squat: the root, and this session's marker for this very fault, are
    // already there. A launcher that trusted them would drop the warning from
    // the FIRST degraded call — the one the model must see.
    const plugin = stagePlugin(t);
    const data = stageData(t, plugin);
    const tmp = tmpDir(t);
    assert.deepEqual(degradedContexts(t, plugin, data, tmp), [true, false]);
    const markerRoot = join(tmp, GATED.tmp[0]);
    assert.ok(existsSync(markerRoot));
    spoil(markerRoot);
    assert.deepEqual(degradedContexts(t, plugin, data, tmp), [true, true]);
  });

// ─── Stale binary: node runs the bundle this install ships ───────────────────

test("a binary installed from another manifest is passed over for node", (t) => {
  const plugin = stagePlugin(t);
  const res = launch(t, plugin, {
    data: stageData(t, plugin, { stamp: false }),
    tmp: tmpDir(t),
    node: nodeDir(t),
  });
  assert.equal(res.status, 0, res.stderr);
  assert.equal(JSON.parse(res.stdout).fromNode, true);
});

test("a stamp naming a different manifest is stale too", (t) => {
  const plugin = stagePlugin(t);
  const data = stageData(t, plugin);
  writeFileSync(join(data, "hook-binary", ".manifest-installed"), "# older\n");
  const res = launch(t, plugin, { data, tmp: tmpDir(t), node: nodeDir(t) });
  assert.equal(JSON.parse(res.stdout).fromNode, true);
});

test("a stale binary still answers on a host with no node", (t) => {
  // An older sanitizer beats an unsanitized call, so the binary runs — and
  // says why on stderr.
  const plugin = stagePlugin(t);
  const res = launch(t, plugin, {
    data: stageData(t, plugin, { stamp: false }),
    tmp: tmpDir(t),
    node: null,
  });
  assert.equal(res.status, 0, res.stderr);
  assert.deepEqual(JSON.parse(res.stdout), { fromBinary: true });
  assert.match(res.stderr, /running it anyway/);
});

test("a stale binary still answers when the only node is below the floor", (t) => {
  // That node would die on the bundle after stdin is spent, leaving the call
  // unsanitized; the older binary can still guard it.
  const plugin = stagePlugin(t);
  const res = launch(t, plugin, {
    data: stageData(t, plugin, { stamp: false }),
    tmp: tmpDir(t),
    node: nodeDir(
      t,
      `[ "$1" = --version ] && { echo v20.1.0; exit 0; }\n${REPORTING_NODE}`,
    ),
  });
  assert.equal(res.status, 0, res.stderr);
  assert.deepEqual(JSON.parse(res.stdout), { fromBinary: true });
  assert.match(res.stderr, /running it anyway/);
});

test("a stale binary is still passed over for a node at the floor", (t) => {
  const plugin = stagePlugin(t);
  const res = launch(t, plugin, {
    data: stageData(t, plugin, { stamp: false }),
    tmp: tmpDir(t),
    node: nodeDir(
      t,
      `[ "$1" = --version ] && { echo v22.14.0; exit 0; }\n${REPORTING_NODE}`,
    ),
  });
  assert.equal(JSON.parse(res.stdout).fromNode, true);
});

// ─── What the runtimes are handed ────────────────────────────────────────────

test("both runtimes are told where the committed zipapp is", (t) => {
  // The compiled binary resolves its modules inside bun's virtual filesystem,
  // where a module-relative zipapp path names nothing on disk.
  const plugin = stagePlugin(t);
  const res = launch(t, plugin, {
    data: stageData(t, plugin),
    tmp: tmpDir(t),
    node: nodeDir(t),
    env: { AGENT_SANITIZER_HOOK_BINARY: "0" },
  });
  assert.equal(
    JSON.parse(res.stdout).pyz,
    join(plugin, "dist", "redactor", "daemon.pyz"),
  );
  // The path names the artifact the plugin really ships there.
  assert.ok(existsSync(join(PLUGIN_DIR, "dist", "redactor", "daemon.pyz")));
});

test("an explicit zipapp path is honored, not overwritten", (t) => {
  const plugin = stagePlugin(t);
  const res = launch(t, plugin, {
    data: stageData(t, plugin),
    tmp: tmpDir(t),
    node: nodeDir(t),
    env: {
      AGENT_SANITIZER_HOOK_BINARY: "0",
      _AGENT_SANITIZER_REDACTOR_PYZ: "/chosen/daemon.pyz",
    },
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
    const plugin = stagePlugin(t);
    const data = stageData(t, plugin);
    for (const ch of CONTROL_CHARS) {
      const res = launch(t, plugin, {
        data,
        tmp: tmpDir(t),
        node: null,
        env: {
          AGENT_SANITIZER_HOOK_BINARY: "0",
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
