/**
 * Contract test for the SSOT guard-pair map (.hooks/guard-pairs.json)
 * that the pre-commit hook uses to run a source's paired contract test in the
 * same commit as the source. A pair pointing at a moved/renamed file would
 * make the hook a silent no-op for exactly the SSOT it was added to protect,
 * so every path is asserted to exist, and the two pairings that actually broke
 * main are pinned by name (non-vacuity: an emptied map cannot pass).
 *
 * The map is also checked in the OTHER direction, which is what keeps it from
 * rotting: `scanGuardedData()` below reads every `node --test` file (and the
 * repo modules those tests import) and resolves the repo data files they open.
 * Every data file so found must be either registered in `pairs` or listed in
 * NOT_GUARDED with a reason — a partition. Without that the map is a
 * hand-maintained list one new contract test away from its next gap, and a data
 * file whose guard test exists but is unpaired breaks only in full CI, after
 * the commit the hook was supposed to block.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, extname, join, normalize } from "node:path";
import assert from "node:assert/strict";
import { describe, it } from "node:test";

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();

const { pairs } = JSON.parse(
  readFileSync(join(repoRoot, ".hooks", "guard-pairs.json"), "utf8"),
);

const tracked = new Set(
  execFileSync("git", ["ls-files"], {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  })
    .split("\n")
    .filter(Boolean),
);

/**
 * Scanned data paths deliberately kept OUT of the pair map, with the reason.
 * Every key must still be found by the scan (a stale entry fails below), so an
 * excuse cannot outlive the read it excuses.
 */
const NOT_GUARDED = {
  // plugin/test/plugin-bundle.test.mjs is the only test that reads these three,
  // and it stages the whole plugin and provisions a Python venv — ~55s on a warm
  // checkout, against the hook's ~1s-per-touched-SSOT budget. Pairing it would
  // make every plugin edit unbearable at commit time; CI runs it instead.
  "plugin/hooks/hooks.json": "only reader is the ~55s plugin-bundle test",
  "plugin/requirements.in": "only reader is the ~55s plugin-bundle test",
  "plugin/requirements.txt": "only reader is the ~55s plugin-bundle test",
};

// Extensions of the files the map is FOR: data a test mirrors or validates.
// Source modules are excluded on purpose — every test imports the module it
// exercises, so pairing those would run most of the suite on every commit, and
// a module that moves already fails loudly at import resolution.
const DATA_EXTENSIONS = new Set([
  ".csv",
  ".in",
  ".json",
  ".json5",
  ".jsonc",
  ".jsonl",
  ".md",
  ".toml",
  ".txt",
  ".yaml",
  ".yml",
]);
const MODULE_EXTENSIONS = new Set([".cjs", ".js", ".mjs"]);

/** Slice from the bracket at `start` to its match, skipping string literals. */
function balanced(text, start) {
  const open = text[start];
  const close = { "(": ")", "[": "]", "{": "}" }[open];
  let depth = 0;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (c === '"' || c === "'" || c === "`") {
      i++;
      while (i < text.length && text[i] !== c) i += text[i] === "\\" ? 2 : 1;
      continue;
    }
    if (c === open) depth++;
    else if (c === close && --depth === 0)
      return { inner: text.slice(start + 1, i), end: i };
  }
  return null;
}

/** Split a call's argument list on top-level commas. */
function splitArgs(inner) {
  const args = [];
  let depth = 0;
  let cur = "";
  for (let i = 0; i < inner.length; i++) {
    const c = inner[i];
    if (c === '"' || c === "'" || c === "`") {
      let j = i + 1;
      while (j < inner.length && inner[j] !== c) j += inner[j] === "\\" ? 2 : 1;
      cur += inner.slice(i, j + 1);
      i = j;
      continue;
    }
    if ("([{".includes(c)) depth++;
    if (")]}".includes(c)) depth--;
    if (c === "," && depth === 0) {
      args.push(cur.trim());
      cur = "";
      continue;
    }
    cur += c;
  }
  if (cur.trim()) args.push(cur.trim());
  return args;
}

const STRING_LITERAL = /^(?:"([^"\\]*)"|'([^'\\]*)')$/;
const IDENTIFIER = /^[A-Za-z_$][\w$]*$/;
const GIT_ROOT_CALL =
  /^execFileSync\(\s*"git"\s*,\s*\[\s*"rev-parse"\s*,\s*"--show-toplevel"\s*,?\s*\][\s\S]*\)(?:\.trim\(\))?$/;
const IMPORT_META_URL =
  /^(?:fileURLToPath\(\s*)?new URL\(\s*(?:"([^"\\]*)"|'([^'\\]*)')\s*,\s*import\.meta\.url\s*\)\s*\)?$/;

/**
 * Resolve a path expression to a repo-relative path, or null when it cannot be
 * resolved statically. Null is the safe answer and the common one: a template
 * literal, a computed segment or an unknown base yields no registry entry
 * rather than a guessed one (precision over recall — a wrong entry pairs a data
 * file with a test that never reads it, which is worse than no entry at all).
 *
 * @param {string} expr source text of the expression
 * @param {string} file repo-relative path of the module it appears in
 * @param {Map<string, string>} scope identifiers already resolved to paths
 * @returns {string|null} repo-relative path ("" is the repo root)
 */
function resolvePathExpression(expr, file, scope) {
  const e = expr.trim().replace(/\s+/g, " ");
  if (IDENTIFIER.test(e)) return scope.get(e) ?? null;
  if (e === "fileURLToPath(import.meta.url)") return file;
  if (GIT_ROOT_CALL.test(e)) return "";
  const url = e.match(IMPORT_META_URL);
  if (url) return normalize(join(dirname(file), url[1] ?? url[2]));
  if (!/^(?:path\.)?(?:dirname|join|resolve)\(/.test(e)) return null;
  const bracket = balanced(e, e.indexOf("("));
  // A trailing `.slice(…)`, `+ suffix`, … means the value is more than this call.
  if (!bracket || bracket.end !== e.length - 1) return null;
  const args = splitArgs(bracket.inner);
  if (args.length === 0) return null;
  const base = resolvePathExpression(args[0], file, scope);
  if (base === null) return null;
  if (/^(?:path\.)?dirname\(/.test(e))
    return args.length === 1 ? dirname(base) : null;
  const segments = [];
  for (const arg of args.slice(1)) {
    const literal = arg.match(STRING_LITERAL);
    if (!literal) return null;
    segments.push(literal[1] ?? literal[2]);
  }
  return normalize(join(base, ...segments));
}

/**
 * Map every `const` in `file` that names a path to that path.
 *
 * Bindings are collected flat, so a name declared twice — the classic case is a
 * module-level `const plugin = join(ROOT, "plugin")` beside a per-test
 * `const plugin = stagePlugin(t)` pointing at a temp dir — is AMBIGUOUS. Those
 * names are banned and the pass repeats, because anything derived from a banned
 * name is unsound too. Banning rather than guessing is what stops a temp-dir
 * path from being registered as though it were repo data.
 */
function collectPathBindings(file, text, imported) {
  // Terminates: every repeat adds at least one name to `banned`, which is
  // bounded by the file's distinct `const` names.
  const banned = new Set();
  for (;;) {
    const scope = new Map(imported);
    const resolutions = new Map();
    for (const m of text.matchAll(/\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*/g)) {
      const rest = text.slice(m.index + m[0].length);
      const end = rest.indexOf(";");
      const resolved =
        banned.has(m[1]) || end === -1
          ? null
          : resolvePathExpression(rest.slice(0, end), file, scope);
      if (!resolutions.has(m[1])) resolutions.set(m[1], new Set());
      resolutions.get(m[1]).add(resolved);
      if (resolved !== null) scope.set(m[1], resolved);
    }
    const ambiguous = [...resolutions]
      .filter(
        ([name, values]) =>
          !banned.has(name) && (values.size > 1 || values.has(null)),
      )
      .map(([name]) => name);
    for (const name of ambiguous) {
      banned.add(name);
      scope.delete(name);
    }
    // A name derived from one banned this round still holds its stale value,
    // so re-resolve until a whole pass finds nothing new to ban.
    if (ambiguous.length === 0) return scope;
  }
}

/** Repo-relative paths this module names: path bindings plus call arguments. */
function collectPathReferences(file, text, scope) {
  const found = new Set(scope.values());
  for (const m of text.matchAll(/\b[A-Za-z_$][\w$.]*\s*\(/g)) {
    const bracket = balanced(text, m.index + m[0].length - 1);
    if (!bracket) continue;
    for (const arg of splitArgs(bracket.inner)) {
      const resolved = resolvePathExpression(arg, file, scope);
      if (resolved !== null) found.add(resolved);
    }
  }
  for (const m of text.matchAll(/from\s*"(\.[^"]+\.json)"/g))
    found.add(normalize(join(dirname(file), m[1])));
  return found;
}

/** Repo-local module imports of `file`, with the binding names they pull in. */
function collectImports(file, text) {
  const imports = [];
  for (const m of text.matchAll(
    /import\s+([\s\S]*?)\s+from\s*"(\.[^"]+)"|import\s*"(\.[^"]+)"/g,
  )) {
    const target = normalize(join(dirname(file), m[2] ?? m[3]));
    if (!MODULE_EXTENSIONS.has(extname(target)) || !tracked.has(target))
      continue;
    const names = [];
    const braces = (m[1] ?? "").match(/\{([\s\S]*)\}/);
    if (braces)
      for (const part of braces[1].split(","))
        if (part.trim())
          names.push(
            part
              .trim()
              .split(/\s+as\s+/)
              .map((s) => s.trim()),
          );
    imports.push({ target, names });
  }
  return imports;
}

const analyzed = new Map();
/** Resolve a module's path bindings, path references and repo-local imports. */
function analyzeModule(file, stack = new Set()) {
  const cached = analyzed.get(file);
  if (cached) return cached;
  // Seeded before recursion so an import cycle terminates with an empty scope
  // (a false negative) instead of recursing forever.
  const result = { scope: new Map(), references: new Set(), deps: [] };
  analyzed.set(file, result);
  if (stack.has(file)) return result;
  stack.add(file);
  const text = readFileSync(join(repoRoot, file), "utf8");
  const imported = new Map();
  for (const { target, names } of collectImports(file, text)) {
    const dep = analyzeModule(target, stack);
    result.deps.push(target);
    for (const [name, alias] of names) {
      const value = dep.scope.get(name);
      if (value !== undefined) imported.set(alias ?? name, value);
    }
  }
  result.scope = collectPathBindings(file, text, imported);
  result.references = collectPathReferences(file, text, result.scope);
  stack.delete(file);
  return result;
}

/** @returns {Map<string, Set<string>>} data path → the test files reaching it */
function scanGuardedData() {
  const readers = new Map();
  for (const test of [...tracked].filter((p) => p.endsWith(".test.mjs"))) {
    const seen = new Set();
    const walk = (file) => {
      if (seen.has(file)) return;
      seen.add(file);
      const { references, deps } = analyzeModule(file);
      for (const path of references) {
        if (!DATA_EXTENSIONS.has(extname(path)) || !tracked.has(path)) continue;
        if (!readers.has(path)) readers.set(path, new Set());
        readers.get(path).add(test);
      }
      for (const dep of deps) walk(dep);
    };
    walk(test);
  }
  return readers;
}

const scanned = scanGuardedData();

describe("SSOT guard-pair map", () => {
  it("is non-empty and every mapped path exists in the repo", () => {
    const entries = Object.entries(pairs);
    assert.ok(entries.length > 0, "pair map must not be empty");
    for (const [source, tests] of entries) {
      assert.ok(
        existsSync(join(repoRoot, source)),
        `mapped SSOT source does not exist: ${source}`,
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
          /\.test\.mjs$/,
          `guard test for ${source} must be a node --test file: ${test}`,
        );
      }
    }
  });

  it("pins the pairings that actually broke main (release-token + instructions guards)", () => {
    assert.deepEqual(pairs[".github/workflows/auto-version.yaml"], [
      "scripts/version-bump.test.mjs",
      // The workflow's six PyPI-publish steps gate on `steps.release.outputs`,
      // and a sync once dropped the `id: release` that defines it — an unknown
      // step id renders empty rather than erroring, so the whole coupled half
      // no-opped silently. The step-ref guard is what catches that.
      ".github/scripts/workflow-step-refs.test.mjs",
    ]);
    assert.deepEqual(pairs["src/instructions.mjs"], [
      "test/instructions.test.mjs",
    ]);
    assert.ok(
      pairs["src/invisible.mjs"].includes("test/invisible-charset.test.mjs"),
      "invisible.mjs must pair with its charset drift guard",
    );
  });
});

describe("guarded-data scan (the map is a checked projection of the tests)", () => {
  it("still resolves the reads it was written for", () => {
    // Non-vacuity: the resolver is regex-driven, so a repo-wide switch to some
    // other path idiom would silently empty the scan and let every assertion
    // below pass over nothing. These four cover the idioms that matter — a
    // `join(gitRoot, …)`, a module-relative `join(dirname(fileURLToPath(…)), …)`,
    // a path exported by an imported generator, and this test's own read.
    assert.ok(
      scanned.size >= 15,
      `scan found only ${scanned.size} guarded data files — the resolver stopped matching`,
    );
    for (const [path, reader] of [
      [
        "python/agent_sanitizer/secrets/data/secret-detectors.json",
        "test/secret-detectors-portability.test.mjs",
      ],
      ["tests/golden-corpus.json", "test/golden-corpus.test.mjs"],
      [
        "python/agent_sanitizer/data/invisible-charset.json",
        "test/invisible-charset.test.mjs",
      ],
      [".hooks/guard-pairs.json", "test/guard-pairs.test.mjs"],
    ]) {
      assert.ok(scanned.has(path), `scan no longer finds ${path}`);
      assert.ok(
        scanned.get(path).has(reader),
        `scan no longer attributes ${path} to ${reader}`,
      );
    }
  });

  it("accounts for every scanned data file: pairs and NOT_GUARDED partition it", () => {
    const unaccounted = [...scanned.keys()]
      .filter((path) => !(path in pairs) && !(path in NOT_GUARDED))
      .map((path) => `${path} (read by ${[...scanned.get(path)].join(", ")})`);
    assert.deepEqual(
      unaccounted,
      [],
      "a test reads these data files but nothing pairs them: add each to .hooks/guard-pairs.json (mapped to the test that reads it) or to NOT_GUARDED with a reason",
    );
    assert.deepEqual(
      Object.keys(NOT_GUARDED).filter((path) => path in pairs),
      [],
      "paths are both paired and NOT_GUARDED",
    );
  });

  it("pairs each scanned data file with a test that actually reads it", () => {
    const misdirected = [...scanned.entries()]
      .filter(([path]) => path in pairs)
      .filter(([path, readers]) => !pairs[path].some((t) => readers.has(t)))
      .map(
        ([path, readers]) =>
          `${path}: paired to ${pairs[path].join(", ")} but read by ${[...readers].join(", ")}`,
      );
    assert.deepEqual(
      misdirected,
      [],
      "a pair naming a test that never reads the data cannot guard it",
    );
  });

  it("has no stale NOT_GUARDED entries", () => {
    assert.deepEqual(
      Object.keys(NOT_GUARDED).filter((path) => !scanned.has(path)),
      [],
      "NOT_GUARDED lists paths no test reads any more — delete them",
    );
    for (const [path, reason] of Object.entries(NOT_GUARDED))
      assert.ok(reason.length > 10, `NOT_GUARDED[${path}] needs a real reason`);
  });
});
