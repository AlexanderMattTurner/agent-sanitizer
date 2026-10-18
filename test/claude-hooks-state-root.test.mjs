/**
 * Where the session-lifetime hook state lives, and that an OS temp cleaner
 * cannot take it from a live session.
 *
 * macOS's dirhelper deletes anything in the per-user $TMPDIR not accessed for 3
 * days. A launch-time InstructionsLoaded marker is written once and only ever
 * `lstat`ed, so a session open past that window lost it and the PreToolUse hook
 * reported that no InstructionsLoaded scan had run — naming three causes, none
 * of them true. The same purge lifts the invisible-char gate by deleting its
 * findings. STATE_ROOT is fixed at module load, so the purge cases run a fresh
 * process; the root-trust cases call resolveStateRoot directly.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import { resolveStateRoot } from "../claude-hooks/lib/hook-io.mjs";

const dir = mkdtempSync(join(tmpdir(), "state-root-"));
after(() => rmSync(dir, { recursive: true, force: true }));
let seq = 0;
/** A fresh directory with exactly `mode`, bypassing the umask. */
const fresh = (/** @type {number} */ mode = 0o700) => {
  const path = join(dir, `d${seq++}`);
  mkdirSync(path);
  chmodSync(path, mode);
  return path;
};

describe("resolveStateRoot", () => {
  it("is $TMPDIR when the host provides no plugin data dir", () => {
    assert.equal(resolveStateRoot({}), tmpdir());
    assert.equal(resolveStateRoot({ CLAUDE_PLUGIN_DATA: "" }), tmpdir());
  });

  it("creates an owner-only session-state dir under a private plugin data dir", () => {
    const data = fresh(0o755);
    const root = resolveStateRoot({ CLAUDE_PLUGIN_DATA: data });
    assert.equal(root, join(data, "session-state"));
    const st = lstatSync(root);
    assert.ok(st.isDirectory());
    assert.equal(st.mode & 0o777, 0o700);
  });

  it("creates the plugin data dir itself when the host has not yet", () => {
    const data = join(fresh(), "not-yet");
    assert.equal(
      resolveStateRoot({ CLAUDE_PLUGIN_DATA: data }),
      join(data, "session-state"),
    );
  });

  // Write on either level lets another uid swap or empty the store — the
  // deletion this root exists to prevent, done on purpose.
  const groupWritableLeaf = () => {
    const data = fresh();
    const leaf = join(data, "session-state");
    mkdirSync(leaf);
    chmodSync(leaf, 0o770);
    return data;
  };
  const symlinked = () => {
    const link = join(dir, `link${seq++}`);
    symlinkSync(fresh(), link);
    return link;
  };
  // mkdir reports EEXIST through a symlink to a directory, so only the lstat
  // check stands between this leaf and a store in a directory someone chose.
  const symlinkedLeaf = () => {
    const data = fresh();
    symlinkSync(fresh(), join(data, "session-state"));
    return data;
  };
  const aFile = () => {
    const file = join(dir, `file${seq++}`);
    writeFileSync(file, "");
    return file;
  };
  for (const [name, make] of /** @type {[string, () => string][]} */ ([
    ["a world-writable plugin data dir", () => fresh(0o777)],
    ["a group-writable session-state dir", groupWritableLeaf],
    ["a symlinked plugin data dir", symlinked],
    ["a symlinked session-state dir", symlinkedLeaf],
    ["a plugin data path that is a file", aFile],
  ]))
    it(`falls back to $TMPDIR for ${name}`, () => {
      assert.equal(resolveStateRoot({ CLAUDE_PLUGIN_DATA: make() }), tmpdir());
    });

  it("plants nothing in the target of a refused plugin data dir", () => {
    const target = fresh(0o777);
    const link = join(dir, `link${seq++}`);
    symlinkSync(target, link);
    resolveStateRoot({ CLAUDE_PLUGIN_DATA: link });
    resolveStateRoot({ CLAUDE_PLUGIN_DATA: target });
    assert.deepEqual(readdirSync(target), []);
  });
});

const ALERT = new URL(
  "../claude-hooks/lib/invisible-alert.mjs",
  import.meta.url,
).href;
const REVEAL = new URL("../claude-hooks/lib/reveal.mjs", import.meta.url).href;

/**
 * Record a launch InstructionsLoaded scan, a gate finding and a Layer-2 span in a
 * fresh process, empty its whole $TMPDIR the way dirhelper does, then ask each
 * reader again.
 * @param {{ pluginData: boolean }} opts
 */
function afterTmpPurge({ pluginData }) {
  const project = fresh();
  writeFileSync(join(project, "CLAUDE.md"), "project rules\n");
  const fakeTmp = fresh();
  const env = {
    ...process.env,
    TMPDIR: fakeTmp,
    CLAUDE_PROJECT_DIR: project,
    CLAUDE_CONFIG_DIR: fresh(),
  };
  delete env.CLAUDE_PLUGIN_DATA;
  delete env._AGENT_SANITIZER_REVEAL_DIR;
  if (pluginData) env.CLAUDE_PLUGIN_DATA = fresh();
  const script = `
    import { readdirSync, rmSync } from "node:fs";
    import { join } from "node:path";
    const a = await import(${JSON.stringify(ALERT)});
    const r = await import(${JSON.stringify(REVEAL)});
    const sid = "long-lived-session";
    const key = "0123456789ab";
    a.recordInstructionsLoaded(sid);
    a.appendAlert("uncleanable CLAUDE.md", sid);
    r.persistSpan(key, "hidden original");
    const before = {
      notice: a.instructionsLoadedGapNotice(sid),
      alert: a.invisibleCharAlert(sid),
      span: r.readSpan(key),
    };
    for (const name of readdirSync(process.env.TMPDIR))
      rmSync(join(process.env.TMPDIR, name), { recursive: true, force: true });
    console.log(JSON.stringify({
      before,
      notice: a.instructionsLoadedGapNotice(sid),
      alert: a.invisibleCharAlert(sid),
      span: r.readSpan(key),
      alertBase: a.ALERT_BASE,
    }));
  `;
  const res = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { env, encoding: "utf8" },
  );
  assert.equal(res.status, 0, res.stderr);
  return {
    ...JSON.parse(res.stdout),
    fakeTmp,
    pluginData: env.CLAUDE_PLUGIN_DATA,
  };
}

describe("a $TMPDIR purge under a live session", () => {
  it("keeps the marker, the gate's findings and the spans under a plugin data dir", () => {
    const r = afterTmpPurge({ pluginData: true });
    assert.equal(r.before.notice, null);
    assert.match(r.before.alert, /uncleanable CLAUDE\.md/u);
    assert.equal(r.before.span, "hidden original");
    assert.ok(r.alertBase.startsWith(join(r.pluginData, "session-state")));
    assert.equal(r.notice, null, "the purge produced a false gap notice");
    assert.equal(r.span, "hidden original", "the purge failed a rehydration");
    assert.match(
      r.alert,
      /uncleanable CLAUDE\.md/u,
      "the purge lifted the gate",
    );
  });

  // Non-vacuity for the case above: the purge reaches the store wherever the
  // store is in $TMPDIR. Pins the remaining exposure of hosts with no plugin
  // data dir — this goes red, deliberately, the day that gap is closed.
  it("still loses all three without one", () => {
    const r = afterTmpPurge({ pluginData: false });
    assert.equal(r.before.notice, null);
    assert.match(r.before.alert, /uncleanable CLAUDE\.md/u);
    assert.equal(r.before.span, "hidden original");
    assert.ok(r.alertBase.startsWith(r.fakeTmp));
    assert.match(r.notice, /no InstructionsLoaded scan has run/u);
    assert.equal(r.alert, null);
    assert.equal(r.span, null);
  });
});
