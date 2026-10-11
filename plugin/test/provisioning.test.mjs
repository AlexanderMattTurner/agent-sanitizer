/**
 * The SessionStart provisioners' shared machinery, driven with stubbed
 * toolchains so nothing here touches the network:
 *
 *   - provision-redactor.sh re-provisions an EXISTING venv (the plugin-update
 *     path) by building beside it and swapping the result in, because real uv
 *     refuses to create a venv over one that already exists;
 *   - the lock-directory fallback in lib/provision-common.sh (the macOS path,
 *     where flock(1) is absent) never breaks a live holder and never releases
 *     a lock that is no longer its own.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const PLUGIN_DIR = join(ROOT, "plugin");
const WHEEL = "agent_sanitizer-0.0.0-py3-none-any.whl";
const COMMON_LIB = join(PLUGIN_DIR, "scripts", "lib", "provision-common.sh");

/** A scratch dir removed when the test finishes. */
function scratch(t) {
  const dir = mkdtempSync(join(tmpdir(), "agent-sanitizer-provisioning-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** A PATH dir linking `cmds` from this host, so a test controls what is absent. */
function binWith(t, cmds) {
  const dir = join(scratch(t), "bin");
  mkdirSync(dir);
  for (const cmd of cmds) {
    const found = spawnSync("command", ["-v", cmd], {
      shell: true,
      encoding: "utf8",
    }).stdout.trim();
    assert.ok(found, `${cmd} is not on this host`);
    symlinkSync(found, join(dir, cmd));
  }
  return dir;
}

// ─── provision-redactor.sh: re-provisioning an existing venv ─────────────────

/**
 * A `uv` that behaves like the real one where it matters: `uv venv` REFUSES a
 * path that already exists, and the engine wheel's console script is written
 * with the absolute interpreter path of the venv it was installed into. Every
 * `uv pip install` argv is appended to `log`. `failLock` makes the hashed-lock
 * install fail, as a network or hash error would.
 */
function fakeUv(t, log, { failLock = false } = {}) {
  const dir = join(scratch(t), "uv-bin");
  mkdirSync(dir);
  writeFileSync(
    join(dir, "uv"),
    "#!/bin/sh\n" +
      'if [ "$1" = venv ]; then\n' +
      '  for d in "$@"; do :; done\n' +
      '  if [ -e "$d" ]; then echo "error: A virtual environment already exists at: $d" >&2; exit 2; fi\n' +
      '  mkdir -p "$d/bin" && printf "#!/bin/sh\\n" > "$d/bin/python" && chmod 755 "$d/bin/python"\n' +
      "  exit 0\n" +
      "fi\n" +
      `echo "$*" >> "${log}"\n` +
      'py=""; prev=""; for a in "$@"; do [ "$prev" = --python ] && py="$a"; prev="$a"; done\n' +
      'case " $* " in\n' +
      `  *" -r "*) ${failLock ? "exit 1" : "exit 0"} ;;\n` +
      "esac\n" +
      'venv="$(dirname "$(dirname "$py")")"\n' +
      'printf "#!%s/bin/python\\nimport sys\\n" "$venv" > "$venv/bin/agent-secret-redactor-daemon"\n' +
      'chmod 755 "$venv/bin/agent-secret-redactor-daemon"\n',
  );
  chmodSync(join(dir, "uv"), 0o755);
  return dir;
}

/** The provisioner and its inputs, with a wheel the fake uv never opens. */
function stageRedactor(t) {
  const plugin = join(scratch(t), "plugin");
  cpSync(join(PLUGIN_DIR, "scripts"), join(plugin, "scripts"), {
    recursive: true,
  });
  cpSync(
    join(PLUGIN_DIR, "requirements.txt"),
    join(plugin, "requirements.txt"),
  );
  mkdirSync(join(plugin, "dist", "redactor"), { recursive: true });
  writeFileSync(join(plugin, "dist", "redactor", WHEEL), "wheel v1\n");
  return { plugin, data: join(scratch(t), "data") };
}

function provisionRedactor({ plugin, data }, uvDir) {
  return spawnSync("bash", [join(plugin, "scripts", "provision-redactor.sh")], {
    encoding: "utf8",
    env: {
      PATH: `${uvDir}:/usr/bin:/bin`,
      AGENT_SANITIZER_SECRETS_ENABLED: "1",
      CLAUDE_PLUGIN_DATA: data,
    },
  });
}

/** What a provisioned venv records about itself. */
function venvState(data) {
  const venv = join(data, "venv");
  return {
    lock: readFileSync(join(venv, ".requirements-installed"), "utf8"),
    wheel: readFileSync(join(venv, ".engine-wheel-installed"), "utf8"),
    daemon: readFileSync(
      join(venv, "bin", "agent-secret-redactor-daemon"),
      "utf8",
    ),
    siblings: readdirSync(data)
      .filter((name) => name.startsWith("venv"))
      .sort(),
  };
}

test("a plugin update re-provisions an existing venv instead of failing on it", (t) => {
  const staged = stageRedactor(t);
  const log = join(scratch(t), "uv-log");
  const uv = fakeUv(t, log);
  const first = provisionRedactor(staged, uv);
  assert.equal(first.status, 0, first.stderr);

  // A re-lock and a new engine build land with the next plugin update.
  const req = join(staged.plugin, "requirements.txt");
  writeFileSync(req, `${readFileSync(req, "utf8")}# a later re-lock\n`);
  writeFileSync(join(staged.plugin, "dist", "redactor", WHEEL), "wheel v2\n");
  const second = provisionRedactor(staged, uv);
  assert.equal(second.status, 0, second.stderr);

  const state = venvState(staged.data);
  assert.equal(state.lock, readFileSync(req, "utf8"));
  assert.equal(state.wheel, "wheel v2\n");
  // Built at a temporary path and swapped in: the daemon's interpreter must
  // name the venv's FINAL path, which is the only one that exists afterwards.
  assert.equal(
    state.daemon,
    `#!${join(staged.data, "venv")}/bin/python\nimport sys\n`,
  );
  // Neither the build dir nor the retired venv is left behind.
  assert.deepEqual(state.siblings, ["venv"]);
  // Two installs, each with an explicit --require-hashes on the lock.
  const lockInstalls = readFileSync(log, "utf8")
    .trim()
    .split("\n")
    .filter((argv) => / -r /.test(argv));
  assert.equal(lockInstalls.length, 2);
  for (const argv of lockInstalls) assert.match(argv, /--require-hashes/);
});

test("a re-provision that fails leaves the previous venv serving", (t) => {
  const staged = stageRedactor(t);
  const log = join(scratch(t), "uv-log");
  assert.equal(provisionRedactor(staged, fakeUv(t, log)).status, 0);
  const before = venvState(staged.data);

  const req = join(staged.plugin, "requirements.txt");
  writeFileSync(req, `${readFileSync(req, "utf8")}# a later re-lock\n`);
  const res = provisionRedactor(staged, fakeUv(t, log, { failLock: true }));
  assert.notEqual(res.status, 0);
  // Untouched, stamps and all, and the half-built venv is gone: the next
  // session sees the stamp mismatch and tries again.
  assert.deepEqual(venvState(staged.data), before);
});

// ─── The lock-directory fallback ─────────────────────────────────────────────

/** Utilities the lock needs, and no flock — the stock-macOS shape. */
const LOCK_PATH_CMDS = ["bash", "cat", "dirname", "mkdir", "rm", "sleep"];

/** bash argv and env running `body` with provision-common.sh sourced. */
function withLib(bin, body) {
  return {
    args: ["-c", `. "$1"\n${body}`, "lock-test", COMMON_LIB],
    env: { PATH: bin },
  };
}

function runLib(bin, body) {
  const { args, env } = withLib(bin, body);
  return spawnSync("bash", args, { encoding: "utf8", env });
}

/** A pid that has exited, so `kill -0` on it fails. */
function deadPid() {
  const { pid } = spawnSync("true");
  assert.ok(pid > 0);
  return pid;
}

test("the lock fallback never breaks a LIVE holder, however long it holds", async (t) => {
  const bin = binWith(t, LOCK_PATH_CMDS);
  const lock = join(scratch(t), ".x.lock");
  const ready = `${lock}.d/owner`;
  const { args, env } = withLib(
    bin,
    `provision_hold_lock "${lock}"; sleep 3; provision_release_lock; echo released`,
  );
  const holder = spawn("bash", args, { env });
  let holderOut = "";
  holder.stdout.on("data", (chunk) => (holderOut += chunk));
  const holderDone = new Promise((resolve) => holder.on("close", resolve));
  // allow-wall-clock: polling for the holder's record, not timing anything.
  while (!existsSync(ready)) await new Promise((r) => setTimeout(r, 20));

  // A waiter whose patience is far shorter than the hold.
  const waiter = runLib(
    bin,
    `_provision_lock_timeout_s=1\nprovision_hold_lock "${lock}" && echo acquired`,
  );
  assert.notEqual(waiter.status, 0);
  assert.doesNotMatch(waiter.stdout, /acquired/);
  assert.match(waiter.stderr, /still held by live pid \d+/);
  // The holder's lock survived the waiter, and its own release still works.
  assert.ok(existsSync(ready), "the waiter broke a live holder's lock");
  assert.equal(await holderDone, 0);
  assert.match(holderOut, /released/);
  assert.equal(existsSync(`${lock}.d`), false);
});

test("the lock fallback breaks a lock whose holder is gone", (t) => {
  const bin = binWith(t, LOCK_PATH_CMDS);
  const lock = join(scratch(t), ".x.lock");
  mkdirSync(`${lock}.d`);
  const pid = deadPid();
  writeFileSync(`${lock}.d/owner`, `${pid} 12345\n`);
  // A waiter that would give up at once on a live holder: acquiring proves
  // it judged this one dead, not that it outwaited it.
  const res = runLib(
    bin,
    `_provision_lock_timeout_s=0\nprovision_hold_lock "${lock}" && echo acquired && cat "${lock}.d/owner"`,
  );
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stderr, new RegExp(`its holder, pid ${pid}, is gone`));
  assert.match(res.stdout, /^acquired\n\d+ \d+\n$/);
  assert.doesNotMatch(res.stdout, new RegExp(`^${pid} 12345$`, "m"));
});

test("the lock fallback breaks a lock no holder ever recorded itself in", (t) => {
  const bin = binWith(t, LOCK_PATH_CMDS);
  const lock = join(scratch(t), ".x.lock");
  mkdirSync(`${lock}.d`);
  const res = runLib(
    bin,
    `_provision_lock_ownerless_s=1\nprovision_hold_lock "${lock}" && echo acquired`,
  );
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stderr, /no holder recorded itself in it/);
  assert.match(res.stdout, /acquired/);
});

test("a holder never releases a lock that has been taken over", (t) => {
  const bin = binWith(t, LOCK_PATH_CMDS);
  const lock = join(scratch(t), ".x.lock");
  // The takeover a broken lock leads to: another provisioner's record is in
  // the directory by the time this holder's EXIT trap releases.
  const res = runLib(
    bin,
    `provision_hold_lock "${lock}"\nprintf '1 other-token\\n' > "${lock}.d/owner"\nprovision_release_lock`,
  );
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stderr, /no longer names this provisioner/);
  assert.equal(readFileSync(`${lock}.d/owner`, "utf8"), "1 other-token\n");

  // Non-vacuity: with its own record still in place, the release removes it.
  const own = runLib(
    bin,
    `provision_hold_lock "${lock}.own"\nprovision_release_lock`,
  );
  assert.equal(own.status, 0, own.stderr);
  assert.equal(existsSync(`${lock}.own.d`), false);
});
