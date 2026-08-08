/**
 * The invariant every shipped esbuild artifact must hold: it runs where no
 * `node_modules` and no sibling data file exists.
 *
 * Both bundles have shipped broken in exactly the same way — css-tree reaches
 * for its CSS syntax tables through `createRequire(import.meta.url)(…json)`,
 * esbuild leaves that require intact, and the artifact then throws the first
 * time HTML is sanitized. The plugin caught it once; the wheel's CLI shipped it
 * again because its build script had its own bare esbuild call. So this file
 * enumerates the entries from `BUNDLE_TARGETS` — the one list both build scripts
 * read — rather than restating them, and covers each one two ways: the surviving
 * runtime-require set must be within the entry's declared allowlist, and the
 * artifact must actually splice hidden HTML when asked to.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { isBuiltin } from "node:module";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import {
  BUNDLE_TARGETS,
  assertNoRuntimeRequires,
  bundleHardened,
  bundleTarget,
  runtimeRequires,
} from "../scripts/lib/bundle-esbuild.mjs";

/** Hidden-HTML input and the Layer-2 splice it must produce. */
const HIDDEN_HTML = '<p style="display:none">hi</p>ok';
const SPLICED = "[hidden HTML removed]ok";

/** A scratch dir removed when the test finishes. */
function scratch(t) {
  const dir = mkdtempSync(join(tmpdir(), "agent-sanitizer-bundle-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/**
 * Build `target` fresh and write it to a scratch dir — NOT beside the repo's
 * node_modules and NOT beside the data files a dependency might reach for, which
 * is the deployment the artifacts actually ship into.
 * @returns {Promise<{artifact: string, text: string}>}
 */
async function stageArtifact(t, target) {
  const text = await bundleHardened(target);
  const artifact = join(scratch(t), basename(target.outfile));
  writeFileSync(artifact, text);
  return { artifact, text };
}

/** Run `artifact` with `args`, feeding `input` on stdin. */
function run(t, artifact, args, input) {
  return spawnSync(process.execPath, [artifact, ...args], {
    input,
    encoding: "utf8",
    cwd: tmpdir(),
    env: {
      ...env(),
      // Layer 2 writes the pre-splice original here; keep it out of the shared
      // /tmp default so the run leaves nothing behind.
      _AGENT_SANITIZER_REVEAL_DIR: scratch(t),
    },
  });
}

/**
 * This process's environment with the plugin's posture knob stripped, so a
 * developer who exported AGENT_SANITIZER_FAIL_OPEN in their own shell cannot
 * turn the splice assertion into a spurious red (or a different verdict shape).
 */
function env() {
  const copy = { ...process.env };
  delete copy.AGENT_SANITIZER_FAIL_OPEN;
  return copy;
}

/**
 * One driver per shipped artifact: feed it hidden HTML the way its own consumer
 * does, and return the sanitized text. Keyed by target name, and the coverage
 * assertion below fails if a target has no entry — a new artifact cannot be
 * added without a behavioural case.
 * @type {Record<string, (t: import("node:test").TestContext, artifact: string) => string>}
 */
const SMOKE_DRIVERS = {
  // The wheel's CLI, driven exactly as `python/agent_sanitizer` drives it: one
  // JSON request on stdin, one response line out.
  "python-cli": (t, artifact) => {
    const res = run(
      t,
      artifact,
      [],
      JSON.stringify({ text: HIDDEN_HTML, html: true }),
    );
    assert.equal(res.status, 0, `${res.stdout}${res.stderr}`);
    return JSON.parse(res.stdout).cleaned;
  },
  // The plugin's PostToolUse hook, driven as Claude Code drives it: the whole
  // hook payload on stdin, the verdict object out. HTML sanitization is on by
  // default for tool output, so no flag is passed — this is the WebFetch path
  // that broke.
  "plugin-hooks": (t, artifact) => {
    const res = run(
      t,
      artifact,
      ["--hook=sanitize-output"],
      JSON.stringify({
        hook_event_name: "PostToolUse",
        tool_name: "WebFetch",
        tool_input: {},
        tool_response: { stdout: HIDDEN_HTML },
      }),
    );
    assert.equal(res.status, 0, `${res.stdout}${res.stderr}`);
    // The hook fails OPEN by default, so a thrown layer yields a verdict with no
    // updatedToolOutput at all rather than a non-zero exit — reading the field
    // directly is what turns that silent pass-through into a failure here.
    return JSON.parse(res.stdout).hookSpecificOutput.updatedToolOutput.stdout;
  },
};

test("every shipped bundle target is non-empty and covered", () => {
  // Every assertion below iterates BUNDLE_TARGETS; an empty list would pass them
  // all while proving nothing.
  assert.ok(
    BUNDLE_TARGETS.length > 0,
    "BUNDLE_TARGETS is empty — nothing is being checked",
  );
  for (const target of BUNDLE_TARGETS)
    assert.ok(
      SMOKE_DRIVERS[target.name],
      `bundle target ${target.name} has no behavioural smoke driver`,
    );
});

for (const target of BUNDLE_TARGETS) {
  test(`${target.name}: no runtime require() outside its allowlist`, async (t) => {
    const { text } = await stageArtifact(t, target);
    const survivors = runtimeRequires(text).filter(
      (spec) => !target.allowedRuntimeRequires.includes(spec),
    );
    assert.deepEqual(
      survivors,
      [],
      `${target.name} keeps unresolvable runtime require(): ${survivors.join(", ")}`,
    );
  });

  test(`${target.name}: imports nothing but Node builtins`, async (t) => {
    // The static half of the same invariant: a surviving bare import means the
    // artifact needs a node_modules, which neither deployment has.
    const { text } = await stageArtifact(t, target);
    const specifiers = [
      ...new Set(
        [...text.matchAll(/^\s*(?:import|export)[^;]*?from\s+"([^"]+)"/gm)].map(
          (m) => m[1],
        ),
      ),
    ];
    // Non-vacuity: an artifact that imported nothing would pass the filter below
    // without proving the parse found anything.
    assert.ok(specifiers.length > 0, `${target.name} has no import specifiers`);
    const nonBuiltin = specifiers.filter(
      (s) => !isBuiltin(s.replace(/^node:/, "")),
    );
    assert.deepEqual(
      nonBuiltin,
      [],
      `${target.name} needs a node_modules for: ${nonBuiltin.join(", ")}`,
    );
  });

  test(`${target.name}: splices hidden HTML when run standalone`, async (t) => {
    const { artifact } = await stageArtifact(t, target);
    assert.equal(SMOKE_DRIVERS[target.name](t, artifact), SPLICED);
  });
}

test("the require guard rejects a survivor and accepts the allowlist", () => {
  // The guard is what makes a would-be-broken bundle unwritable, so prove it
  // fires rather than trusting that the builds above passed it.
  assert.throws(
    () =>
      assertNoRuntimeRequires(
        'var patch = require2("../data/patch.json");',
        [],
      ),
    /runtime require\(\) of: \.\.\/data\/patch\.json/,
  );
  assert.doesNotThrow(() =>
    assertNoRuntimeRequires('require("namespace-guard");', ["namespace-guard"]),
  );
});

test("an unknown bundle target fails loud", () => {
  assert.throws(() => bundleTarget("no-such-bundle"), /unknown bundle target/);
  assert.equal(bundleTarget(BUNDLE_TARGETS[0].name), BUNDLE_TARGETS[0]);
});
