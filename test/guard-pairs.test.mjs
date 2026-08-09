/**
 * Contract test for the guard-pair derivation.
 *
 * `.hooks/lib/guarded-data-scan.mjs` computes which suite guards which repo
 * file; `.hooks/run-guard-pairs.mjs` runs that scan at commit time and executes
 * the suites covering the staged files. Nothing between them is hand-written
 * any more — the map used to be a 69-entry list, and the list is what went
 * stale: two branches each green on their own base went red together on main
 * because a new file's pair could not exist until both had landed.
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
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, extname, join, sep } from "node:path";
import { pathToFileURL } from "node:url";
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

/** True when this suite is itself running from a Stryker sandbox copy. */
const IN_SANDBOX = repoRoot.includes(`${sep}.stryker-tmp${sep}sandbox-`);

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
    // These two UCD tables reach a test only as data → generator → GENERATED
    // module → the suites that import it, and the generated module is what the
    // scan sees. Pinned by name because they are the whole reason the residue
    // still exists; if the generator ever became a test dependency they would
    // derive, and the assertion above would then tell you to delete them.
    for (const source of [
      "scripts/data/DerivedJoiningType.json",
      "scripts/data/IndicSyllabicCategory.Virama.json",
    ])
      assert.deepEqual(pairs[source], ["test/joining-type.test.mjs"]);
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
});

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
        "python/agent_sanitizer/data/invisible-charset.json",
        "test/invisible-charset.test.mjs",
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
        ".github/scripts/auto-resolve/discover.py",
        ".github/scripts/auto-resolve/discover.test.mjs",
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
    assert.deepEqual(expandPathspec("scripts/data/README.md"), [
      "scripts/data/README.md",
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

  it(
    "answers about the real checkout when loaded from a mutation sandbox",
    {
      skip:
        IN_SANDBOX &&
        "nesting a sandbox inside a sandbox strips to a path that never existed; the shard itself is the live case",
    },
    async () => {
      // Every answer this scan gives is derived from source TEXT, so the copy it
      // reads decides what resolves. Stryker rewrites the files in its --mutate
      // set inside the sandbox, and `new URL("../..", import.meta.url)` arrives
      // as a guarded conditional the resolver declines — which drops
      // THREAT-MODEL.md and the other helper-rooted guards out of the map and
      // fails the shard's dry run before a mutant is applied.
      //
      // Simulated rather than observed: the sandbox holds only `.hooks/lib`, with
      // repo-root.mjs in the shape Stryker emits (its guard returns false, so the
      // runtime value is unchanged and only the SOURCE differs).
      mkdirSync(join(repoRoot, ".stryker-tmp"), { recursive: true });
      const sandbox = mkdtempSync(join(repoRoot, ".stryker-tmp", "sandbox-"));
      try {
        const lib = join(sandbox, ".hooks", "lib");
        mkdirSync(dirname(lib), { recursive: true });
        cpSync(join(repoRoot, ".hooks", "lib"), lib, { recursive: true });
        const rootModule = join(lib, "repo-root.mjs");
        const original = readFileSync(rootModule, "utf8");
        // Run FROM a shard and the copy is already instrumented, by Stryker
        // itself; run from a healthy tree and the fixture supplies the shape.
        // Keyed on the emitted GUARD FUNCTION, not on the name: repo-root.mjs's
        // own header quotes an instrumented line, and a mention would read as the
        // real thing and skip the rewrite.
        if (!/^function stryMutAct_/mu.test(original))
          writeFileSync(
            rootModule,
            `function stryMutAct_9fa48() {\n  return false;\n}\n${original.replace(
              'new URL("../..", import.meta.url)',
              'new URL(stryMutAct_9fa48("0") ? "" : "../..", import.meta.url)',
            )}`,
          );
        const rewritten = readFileSync(rootModule, "utf8");
        assert.ok(
          rewritten
            .slice(rewritten.indexOf("export const repoRoot ="))
            .includes("stryMutAct_"),
          "repo-root.mjs no longer spells the initializer this fixture instruments — " +
            "re-derive the fixture, it proves nothing as written",
        );

        const sandboxed = await import(
          pathToFileURL(join(lib, "guarded-data-scan.mjs")).href
        );
        assert.equal(sandboxed.repoRoot, repoRoot);
        assertGuardedBy(
          sandboxed.scanJsGuards(),
          "THREAT-MODEL.md",
          "test/threat-model-layers.test.mjs",
          "root read helper, scanned from a sandbox",
        );
      } finally {
        rmSync(sandbox, { recursive: true, force: true });
      }
    },
  );

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
