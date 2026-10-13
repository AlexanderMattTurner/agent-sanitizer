/**
 * Contract test for the guard-pair derivation.
 *
 * `.hooks/lib/guarded-data-scan.mjs` computes which suite guards which repo
 * file; `.hooks/run-guard-pairs.mjs` runs that scan at commit time and executes
 * the suites covering the staged files. Nothing between them is hand-written —
 * a hand-written list is what goes stale: two branches each green on their own
 * base can go red together on main because a new file's pair could not exist
 * until both had landed.
 *
 * What is left to check is therefore NOT "is the list complete" (it is derived,
 * so it is complete by construction) but "does the derivation still resolve
 * what it was written to resolve". A resolver that silently stops finding a
 * read makes the hook run nothing for exactly the file it was added to protect,
 * and nothing else in the repo would notice. So every mechanism below is
 * anchored by name, and every hand-written residue entry in
 * `.hooks/guard-pairs.json` must justify itself against the scan.
 *
 * The resolution runs on acorn's AST, Node's own module resolver and Python's
 * `ast` — not on regexes over source text: "validate against the actual
 * tokenizer/parser, not a hand-rolled approximation" (CLAUDE.md, Code Style).
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { extname, join } from "node:path";
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  MODULE_EXTENSIONS,
  expandPathspec,
  scanGuardedData,
  scanJsGuards,
  scanPythonGuards,
  tracked,
} from "../.hooks/lib/guarded-data-scan.mjs";

/**
 * The repo root, resolved HERE rather than imported from the module under test.
 *
 * Two reasons, and the second is why it is not the scanner's `repoRoot` export.
 * A test should not take its ground truth from the thing it is testing. And the
 * self-read pin below asserts that the scan resolves THIS file's
 * `join(repoRoot, ".hooks", "guard-pairs.json")` — with `repoRoot` imported,
 * that resolution runs through the scanner's own source, so Stryker's
 * instrumentation of the scanner (which turns its `".."` literals into
 * conditional expressions the resolver correctly declines) broke the pin and
 * failed the mutation run's dry run before a single mutant was applied.
 */
const repoRoot = join(import.meta.dirname, "..");

const { pairs, tooSlowForCommit } = JSON.parse(
  readFileSync(join(repoRoot, ".hooks", "guard-pairs.json"), "utf8"),
);

const derived = scanGuardedData();

/** Assert `path` is guarded by `reader`, naming the mechanism that finds it. */
function assertGuardedBy(map, path, reader, mechanism) {
  assert.ok(map.has(path), `${mechanism}: scan no longer finds ${path}`);
  assert.ok(
    map.get(path).has(reader),
    `${mechanism}: scan no longer attributes ${path} to ${reader} (found: ${[
      ...map.get(path),
    ].join(", ")})`,
  );
}

describe("guard-pair residue (.hooks/guard-pairs.json)", () => {
  it("names only files the scan cannot reach, mapped to tests that exist", () => {
    const entries = Object.entries(pairs);
    assert.ok(entries.length > 0, "residue must not be empty");
    for (const [source, tests] of entries) {
      assert.ok(
        existsSync(join(repoRoot, source)),
        `residue source does not exist: ${source}`,
      );
      assert.ok(
        !derived.has(source),
        `${source} is derived now — delete its hand-written entry rather than ` +
          `keeping a second copy that can disagree with the scan`,
      );
      assert.ok(
        Array.isArray(tests) && tests.length > 0,
        `${source} must map to at least one guard test`,
      );
      for (const test of tests) {
        assert.ok(
          existsSync(join(repoRoot, test)),
          `guard test for ${source} does not exist: ${test}`,
        );
        assert.match(
          test,
          /(?:\.test\.mjs|\/test_[^/]+\.py)$/,
          `guard test for ${source} must be a node --test file (*.test.mjs) or a ` +
            `pytest module (test_*.py) — .hooks/run-guard-pairs.mjs dispatches on ` +
            `the extension and would silently run neither: ${test}`,
        );
      }
    }
  });

  it("keeps the generator inputs the scan genuinely cannot chain to a test", () => {
    // Non-vacuity for the residue: an emptied guard-pairs.json cannot pass.
    // The UCD tables live in the pinned `@unicode/unicode-*` package under
    // node_modules, which the scan never walks; what a bump of it changes in
    // the tree is the lockfile. Pinned by name because it is the whole reason
    // the residue still exists: a Unicode bump must run every suite that
    // regenerates a table from the package and compares.
    assert.deepEqual(pairs["pnpm-lock.yaml"], [
      "test/invisible-charset.test.mjs",
      "test/joining-type.test.mjs",
      "test/unicode-properties.test.mjs",
    ]);
  });

  it("excludes only real, reached, expensive suites from commit time", () => {
    const reached = new Set(
      [...derived.values()].flatMap((tests) => [...tests]),
    );
    for (const [test, reason] of Object.entries(tooSlowForCommit)) {
      assert.ok(
        existsSync(join(repoRoot, test)),
        `tooSlowForCommit names a test that does not exist: ${test}`,
      );
      assert.ok(
        reached.has(test),
        `tooSlowForCommit[${test}] excuses a suite nothing schedules any more — delete it`,
      );
      assert.ok(
        reason.length > 10,
        `tooSlowForCommit[${test}] needs a real reason`,
      );
    }
  });

  it("classifies every tracked shipped/tooling input: derived, residue, pending or CI-only", () => {
    const population = execFileSync(
      "git",
      ["ls-files", "--", ...GUARDED_ROOTS],
      { cwd: repoRoot, encoding: "utf8" },
    )
      .split("\n")
      .filter((path) => path !== "" && !NOT_AN_INPUT.test(path));
    assert.ok(population.length > 50, `only ${population.length} inputs`);
    const parts = [
      population.filter((path) => derived.has(path)),
      Object.keys(pairs),
      Object.keys(RESIDUE_PENDING),
      Object.keys(CI_ONLY),
    ];
    assert.deepEqual(
      [...population].sort(),
      parts.flat().sort(),
      "each tracked input must be derived by the scan, listed in the " +
        ".hooks/guard-pairs.json residue, or named in RESIDUE_PENDING / CI_ONLY " +
        "here with its reason — exactly once",
    );
    for (const [source, tests] of Object.entries(RESIDUE_PENDING))
      for (const test of tests)
        assert.ok(existsSync(join(repoRoot, test)), `${source}: ${test}`);
    for (const [source, reason] of Object.entries(CI_ONLY))
      assert.ok(reason.length > 10, `CI_ONLY[${source}] needs a real reason`);
  });
});

/*
 * Declared BELOW the `describe` that reads them, on purpose. The scan walks this
 * file in source order and only resolves a `git ls-files -- ...GUARDED_ROOTS`
 * once the constant is bound, so hoisting these above the `describe` makes the
 * partition's own enumeration count as a read of every guarded file: all of
 * them derive to this suite and the partition passes on nothing. (`node:test`
 * defers the `it` bodies, so the later declaration is initialised before use.)
 */

/** The tracked trees whose files a commit should never change unguarded. */
const GUARDED_ROOTS = [
  "bin",
  "claude-hooks",
  "plugin/scripts",
  "python/agent_sanitizer",
  "scripts",
  "src",
  // Pins the @unicode/unicode-* package the Unicode generators read.
  "pnpm-lock.yaml",
];

/** Suites and prose: not inputs a guard test reads. */
const NOT_AN_INPUT = /(?:\.test\.mjs|\.md)$/;

/**
 * Inputs the scan cannot chain to their suite and the `.hooks/guard-pairs.json`
 * residue does not yet name. That file is synced from the template, so the
 * entry is listed here, with the suite it should map to, until it lands there;
 * the partition above fails once it does, which is the cue to delete it here.
 */
const RESIDUE_PENDING = {
  // Run as a `["node", "scripts/extract-js-regexes.mjs", …]` subprocess, an
  // argv the scan does not resolve.
  "scripts/extract-js-regexes.mjs": ["tests/test_redos_js_static_guard.py"],
};

/** Inputs with no commit-time suite by design, each with the gate it has. */
const CI_ONLY = {
  "plugin/scripts/build-redactor-pyz.mjs":
    "installs from PyPI, so no offline commit-time suite can run it; node-tests and plugin-dist-autofix rebuild the zipapp in CI",
  "scripts/bundle-python-cli.mjs":
    "a release-time build run by auto-version and publish-python; its output is git-ignored",
  "src/vendor/gfm-autolink-literal.d.ts":
    "a type declaration whose only gate is `pnpm check` (tsc)",
};

describe("guarded-data scan (the map is derived from the tests)", () => {
  it("guards a source module with the suites that import it", () => {
    // The scan used to drop modules with "a moved .mjs already fails loudly at
    // import resolution". That is true of an imported module and beside the
    // point: the map's job is to run the cheap check covering the file, and for
    // a source module that check is the suite exercising it. It was also false
    // of a module a test SPAWNS by name — `.github/scripts/npm-max-stable.mjs`
    // is imported by nothing and was guarded only by a hand-typed line.
    for (const [path, reader, mechanism] of [
      ["src/ansi.mjs", "test/invisible-charset.test.mjs", "import graph"],
      ["src/invisible.mjs", "test/instructions.test.mjs", "import graph"],
      ["src/instructions.mjs", "test/instructions.test.mjs", "import graph"],
      [
        ".github/scripts/npm-max-stable.mjs",
        ".github/scripts/npm-max-stable.test.mjs",
        "spawned by path",
      ],
      [
        "claude-hooks/scan-invisible-chars.mjs",
        "test/claude-hooks-scan-coverage.test.mjs",
        "spawned by path",
      ],
    ])
      assertGuardedBy(derived, path, reader, mechanism);

    // The three modules above are the ones whose fan-out was the argument for
    // NOT deriving them. Deriving them is the point: an edit to the invisible
    // layer must run the suites that exercise it, not one hand-picked suite.
    assert.ok(
      derived.get("src/invisible.mjs").size > 20,
      `src/invisible.mjs is guarded by only ${derived.get("src/invisible.mjs").size} suites`,
    );
    // Every module extension the repo actually has must contribute: `.js` is a
    // separate arm in practice (the `.github` scripts are plain `.js`), and it
    // going quiet would leave the `.mjs` anchors above passing alone. `.cjs` is
    // in MODULE_EXTENSIONS but not in this repo, so it is not asserted — an
    // assertion over an empty set is exactly the vacuity this test exists to
    // prevent.
    const present = [...MODULE_EXTENSIONS].filter((extension) =>
      [...tracked].some((path) => extname(path) === extension),
    );
    assert.ok(present.length > 1, "MODULE_EXTENSIONS matches nothing tracked");
    for (const extension of present)
      assert.ok(
        [...derived.keys()].some((path) => extname(path) === extension),
        `no ${extension} module is guarded — that arm of the scan is dead`,
      );
  });

  it("still resolves every path-resolver idiom it was written for", () => {
    // Non-vacuity: nothing else notices if an arm of `resolvePath` stops
    // resolving. Each of these covers one — `join(gitRoot, …)`, a
    // module-relative `join(dirname(fileURLToPath(…)), …)`, a path exported by
    // an imported generator, a subpath resolved through the package's `exports`
    // map, a bare string handed to a one-argument repo-root read helper, a
    // `.sh` driven through execFileSync, and this test's own read.
    for (const [path, reader, mechanism] of [
      [
        "python/agent_sanitizer/secrets/data/secret-detectors.json",
        "test/secret-detectors-portability.test.mjs",
        "join(gitRoot, …)",
      ],
      [
        "tests/golden-corpus.json",
        "test/golden-corpus.test.mjs",
        "module-relative join",
      ],
      [
        "plugin/dist/hooks/hook-binaries.sha256",
        "plugin/test/plugin-bundle.test.mjs",
        "generator-exported path",
      ],
      [
        "python/agent_sanitizer/secrets/data/credential-names.json",
        "test/credential-names-export.test.mjs",
        "exports-map subpath",
      ],
      [
        "THREAT-MODEL.md",
        "test/threat-model-layers.test.mjs",
        "root read helper",
      ],
      [
        "plugin/scripts/lib/hook-timing.sh",
        "test/hook-timing-shell-parity.test.mjs",
        "shell source driven by path",
      ],
      [
        "python/agent_sanitizer/secrets/placeholders.py",
        "test/placeholder-guards.test.mjs",
        "python source driven by path",
      ],
      [".hooks/guard-pairs.json", "test/guard-pairs.test.mjs", "self-read"],
      // Reached ONLY through a dynamic `await import("./…")` chain: the hook
      // suites load their subjects that way, so this anchors the
      // ImportExpression arm of the walk.
      [
        "python/agent_sanitizer/secrets/data/redaction-floor.json",
        "test/claude-hooks-host-seams.test.mjs",
        "dynamic import chain",
      ],
      // A repo-relative fragment built by `join("plugin", …)` and only later
      // joined onto the root. The constant is what made the file invisible.
      [
        "plugin/.claude-plugin/plugin.json",
        "scripts/set-plugin-version.test.mjs",
        "relative fragment constant",
      ],
      // The scan's own subject: the hook must be guarded by the suite that
      // proves it fails closed, or a hook edit runs nothing.
      [
        ".hooks/run-guard-pairs.mjs",
        "tests/test_hook_fail_closed.py",
        "python REPO_ROOT join",
      ],
      // The one cross-module Python case: the test binds `D.DETECTORS_FILE`
      // from a package that re-exports it from a submodule two levels down.
      [
        "python/agent_sanitizer/secrets/data/secret-detectors.json",
        "tests/secrets/test_secrets_detectors.py",
        "python cross-module constant",
      ],
      // Named by no test at all: `test_secrets_config.py` imports the package
      // and the package reads the floor at import time.
      [
        "python/agent_sanitizer/secrets/data/redaction-floor.json",
        "tests/secrets/test_secrets_config.py",
        "python transitive import read",
      ],
    ])
      assertGuardedBy(derived, path, reader, mechanism);
  });

  it("expands the enumerations a suite uses instead of naming its subjects", () => {
    // Five suites enumerate their subjects rather than listing them, so before
    // this arm existed the cheapest guard in the repo — "does this new workflow
    // have a notifier?" — could not be scheduled at commit time at all.
    for (const [path, reader, mechanism] of [
      [
        ".github/workflows/fuzz-nightly.yaml",
        "test/failure-notify-roster.test.mjs",
        "git ls-files literal array",
      ],
      [
        "src/html.mjs",
        "test/threat-model-layers.test.mjs",
        "git ls-files spread constant",
      ],
      [
        "test/golden-corpus.test.mjs",
        "test/test-runner-partition.test.mjs",
        "git ls-files through a rest-param helper",
      ],
      [
        ".github/workflows/auto-version.yaml",
        ".github/scripts/workflow-step-refs.test.mjs",
        "readdirSync directory enumeration",
      ],
    ])
      assertGuardedBy(derived, path, reader, mechanism);

    // Non-vacuity for the pathspec matcher itself: git matches with fnmatch and
    // no FNM_PATHNAME, so `*` crosses `/`. An expander that lost that would
    // still find `.github/workflows/*.yaml` and silently drop every nested hit.
    assert.ok(
      expandPathspec("*.test.mjs").includes(
        "plugin/test/plugin-manifest.test.mjs",
      ),
      "pathspec `*` no longer crosses a directory separator",
    );
    assert.deepEqual(expandPathspec("scripts/lib/ucd.mjs"), [
      "scripts/lib/ucd.mjs",
    ]);
    assert.throws(
      () => expandPathspec("src/[ai]*.mjs"),
      /character classes are not supported/u,
      "an unsupported pathspec must fail loud, not silently match nothing",
    );
  });

  it("keeps both language halves live", () => {
    // Non-vacuity for the two runners the hook dispatches on: either half going
    // dead would leave its arm of run-guard-pairs.mjs unreachable while every
    // assertion above still passed on the other half's findings.
    const js = scanJsGuards();
    const python = scanPythonGuards();
    assert.ok(js.size > 100, `JS scan resolved only ${js.size} paths`);
    assert.ok(
      python.size > 20,
      `Python scan resolved only ${python.size} paths — is python3 on PATH?`,
    );
    const pytestGuards = new Set(
      [...python.values()].flatMap((tests) => [...tests]),
    );
    assert.ok(
      pytestGuards.size > 5,
      "no pytest module guards anything — the hook's pytest runner is dead code",
    );
  });

  it("attributes every derived pair to a suite that exists and can run", () => {
    const bad = [];
    for (const [path, tests] of derived) {
      if (!tracked.has(path)) bad.push(`${path} is not a tracked file`);
      for (const test of tests)
        if (!/(?:\.test\.mjs|\/test_[^/]+\.py)$/.test(test))
          bad.push(`${path} -> ${test} matches no runner`);
    }
    assert.deepEqual(bad, []);
  });

  it("pins the reads that actually broke main", () => {
    // Both incidents this mechanism exists for, re-pointed at the derived map.
    // auto-version.yaml's six PyPI-publish steps gate on `steps.release.outputs`
    // and a sync once dropped the `id: release` that defines it — an unknown
    // step id renders empty rather than erroring, so the whole coupled half
    // no-opped silently. And the generated fail-open shell lib landed on main
    // with no pair at all, because the branch that taught the scan to see .sh
    // sources never saw the file.
    assertGuardedBy(
      derived,
      ".github/workflows/auto-version.yaml",
      "scripts/version-bump.test.mjs",
      "release-token guard",
    );
    assertGuardedBy(
      derived,
      ".github/workflows/auto-version.yaml",
      ".github/scripts/workflow-step-refs.test.mjs",
      "step-ref guard",
    );
    assertGuardedBy(
      derived,
      "plugin/scripts/lib/fail-open.sh",
      "plugin/test/fail-open-parity.test.mjs",
      "fail-open parity guard",
    );
    assertGuardedBy(
      derived,
      "src/instructions.mjs",
      "test/instructions.test.mjs",
      "instructions guard",
    );
  });

  it("declines to guess: a path built from a temp dir yields no pair", () => {
    // Precision over recall is the doctrine the whole resolver is built on, and
    // every assertion above checks only what IS found. `plugin-bundle.test.mjs`
    // copies the plugin into a temp tree and drives `safe-launch.sh` from
    // THERE, through a `pluginRoot` parameter — a resolver that guessed the
    // repo path from that call would pair a 35s suite with a file it never
    // reads in place, which is worse than the pair being absent.
    assert.ok(
      derived.has("plugin/scripts/safe-launch.sh"),
      "safe-launch.sh lost every guard — this assertion no longer proves anything",
    );
    assert.ok(
      !derived
        .get("plugin/scripts/safe-launch.sh")
        .has("plugin/test/plugin-bundle.test.mjs"),
      "resolver claimed a repo path from a staged temp-directory binding",
    );
    // The same suite's REAL, in-place reads must still be found, or the check
    // above would pass by the whole module going unanalysed.
    assertGuardedBy(
      derived,
      "plugin/hooks/hooks.json",
      "plugin/test/plugin-bundle.test.mjs",
      "in-place read by the same suite",
    );
  });
});
