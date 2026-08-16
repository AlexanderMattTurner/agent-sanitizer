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
 * runtime-require set must equal the entry's declared allowlist, and the
 * artifact must actually splice hidden HTML when asked to.
 *
 * Colocated with the module it tests rather than living in `test/`, because
 * `stryker.conf.json` runs `test/**\/*.test.mjs` on every mutation dry run.
 * These cases build real bundles and execute them in a spawned child, which
 * reports no coverage back and so can never kill a `src/` mutant — in `test/`
 * they would be pure cost. `node --test` discovers this path either way.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { isBuiltin } from "node:module";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import { layer2Placeholder } from "../../src/html.mjs";

import {
  BUNDLE_TARGETS,
  COMPUTED_SPECIFIER,
  assertNoRuntimeRequires,
  bundleHardened,
  bundleTarget,
  runtimeRequires,
} from "./bundle-esbuild.mjs";

/** Hidden-HTML input and the Layer-2 splice it must produce. */
const HIDDEN_HTML = '<p style="display:none">hi</p>ok';
// Derived from the engine's own producer rather than written out: the
// placeholder is a content-addressed grammar, so a literal here would be a
// second definition of it. Both artifacts bundle that same in-tree engine, so
// both splice identically; the map is per target so a new target must declare
// its expectation rather than inherit one silently.
const SPLICED_HTML =
  layer2Placeholder("hidden", '<p style="display:none">hi</p>') + "ok";
const SPLICED = {
  "python-cli": SPLICED_HTML,
  "plugin-hooks": SPLICED_HTML,
};

/** A scratch dir removed when the test finishes. */
function scratch(t) {
  const dir = mkdtempSync(join(tmpdir(), "agent-sanitizer-bundle-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/**
 * One build per target for the whole file. `bundleHardened` is deterministic
 * for a given target, and a full esbuild run costs seconds; each test still
 * stages its own scratch copy below, so sharing the bytes costs no isolation.
 * @type {Map<string, Promise<string>>}
 */
const builds = new Map();

/**
 * Build `target` and write it to a scratch dir — NOT beside the repo's
 * node_modules and NOT beside the data files a dependency might reach for, which
 * is the deployment the artifacts actually ship into.
 * @returns {Promise<{artifact: string, text: string}>}
 */
async function stageArtifact(t, target) {
  if (!builds.has(target.name)) builds.set(target.name, bundleHardened(target));
  const text = await builds.get(target.name);
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
  test(`${target.name}: runtime require() set equals its allowlist`, async (t) => {
    const { text } = await stageArtifact(t, target);
    // Exact equality, not a subset check. `bundleHardened` has already thrown on
    // anything outside the allowlist, so a subset check is empty by construction
    // and passes even when the allowlist was WIDENED to silence a real survivor
    // — which would reship the css-tree defect with a green build. Requiring the
    // sets to match means an unused allowlist entry is itself a failure, so
    // nobody can quiet the guard without deleting a line this test reads.
    const survivors = runtimeRequires(text);
    assert.deepEqual(
      survivors.sort(),
      [...target.allowedRuntimeRequires].sort(),
      `${target.name} runtime require() set must equal its declared allowlist; got: ${survivors.join(", ")}`,
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
    const expected = SPLICED[target.name];
    assert.ok(
      expected,
      `bundle target ${target.name} has no splice expectation`,
    );
    assert.equal(SMOKE_DRIVERS[target.name](t, artifact), expected);
  });
}

/**
 * What `runtimeRequires` must answer on the shapes this build actually emits.
 * Each case is a source form a text scan gets wrong in one direction or the
 * other; naming which one it is here is what keeps the case from being
 * redundant with its neighbours.
 * @type {readonly [string, string, readonly string[]][]}
 */
const REQUIRE_SHAPES = [
  // esbuild pretty-prints (`minify: false`), so it wraps a long argument list
  // onto its own line. This is the reachable false negative: a wrapped require
  // in a future dependency would pass the guard and ship.
  [
    "wrapped across lines",
    'require2(\n  "./data/patch.json"\n)',
    ["./data/patch.json"],
  ],
  // The positive control: the one shape a text scan already got right, so a
  // table that failed on every row would be visible as a bug in the table.
  [
    "single line",
    'var patch = require2("./data/patch.json");',
    ["./data/patch.json"],
  ],
  // The four computed shapes. None can be allowlisted, so each fails the build.
  [
    "variable specifier",
    'const p = "./data/patch.json"; require2(p);',
    [COMPUTED_SPECIFIER],
  ],
  [
    "template literal",
    "require2(`./data/${name}.json`);",
    [COMPUTED_SPECIFIER],
  ],
  [
    "concatenation",
    'require2("./data/" + name + ".json");',
    [COMPUTED_SPECIFIER],
  ],
  ["no argument", "require2();", [COMPUTED_SPECIFIER]],
  // The two probes every text scanner must survive. `inlineRuntimeJsonRequires`
  // splices dependency JSON into the bundle and `legalComments: "eof"` appends
  // third-party comments to it, so both shapes are present in shipped bytes.
  [
    "inside a string literal",
    'var json = {"note": "require(\'left-pad\')"};',
    [],
  ],
  ["inside a comment", '// TODO: require("left-pad") here\n', []],
];

for (const [shape, source, expected] of REQUIRE_SHAPES)
  test(`runtimeRequires reads a require ${shape}`, () => {
    assert.deepEqual(runtimeRequires(source), [...expected]);
  });

test("a computed specifier fails the build", () => {
  // The whole point of reporting `<computed>`: an allowlist cannot contain it,
  // so a require whose target the build cannot read is refused rather than
  // passed. The wide allowlist proves the refusal is not an allowlist miss.
  assert.throws(
    () =>
      assertNoRuntimeRequires('const p = "./data/patch.json"; require2(p);', [
        "./data/patch.json",
        "namespace-guard",
      ]),
    /runtime require\(\) of: <computed>.*not a string literal/s,
  );
  // The explanation of `<computed>` stays out of a message that has no computed
  // survivor to explain.
  assert.throws(
    () => assertNoRuntimeRequires('require2("../data/patch.json");', []),
    (err) => !/not a string literal/.test(err.message),
  );
});

test("a bundle that is not valid ESM fails loud", () => {
  // A parse error must not read as "this bundle has no runtime requires".
  assert.throws(() => runtimeRequires("const = ;"), SyntaxError);
});

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
