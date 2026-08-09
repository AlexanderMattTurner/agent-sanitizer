/**
 * Contract test for the SSOT guard-pair map (.hooks/guard-pairs.json)
 * that the pre-commit hook uses to run a source's paired contract test in the
 * same commit as the source. A pair pointing at a moved/renamed file would
 * make the hook a silent no-op for exactly the SSOT it was added to protect,
 * so every path is asserted to exist, and the two pairings that actually broke
 * main are pinned by name (non-vacuity: an emptied map cannot pass).
 *
 * The map is also checked in the OTHER direction, which is what keeps it from
 * rotting: `scanGuardedData()` below parses every `node --test` file (and the
 * repo modules those tests import) and resolves the repo files they open by
 * path — data files (DATA_EXTENSIONS) and the `.sh`/`.py` sources a suite
 * DRIVES (MIRROR_EXTENSIONS). Every one so found must be either registered in
 * `pairs` or listed in NOT_GUARDED / NOT_MIRRORED with a reason — a partition.
 * Without that the map is a hand-maintained list one new contract test away
 * from its next gap, and a file whose guard test exists but is unpaired breaks
 * only in full CI, after the commit the hook was supposed to block.
 *
 * The resolution below runs on acorn's AST and Node's own module resolver, not
 * on regexes over source text: "validate against the actual tokenizer/parser,
 * not a hand-rolled approximation" (CLAUDE.md, Code Style). A bracket-matching
 * approximation has to keep tracking the language — regex literals holding
 * unbalanced quotes, template segments, shadowed bindings — and each gap it
 * develops silently narrows the partition assertions that depend on it.
 */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, extname, join, normalize, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parse } from "acorn";

// The SHIPPED tree, climbed out of Stryker's sandbox. What this suite resolves
// is which repo files each test opens, and a path constant it reads out of a
// module — `export const OUTPUT_PATH = join("plugin", …)` — is not readable in
// an instrumented copy, where the literal has become
// `stryMutAct_9fa48("7") ? "" : "plugin"`. Analysed against the sandbox the scan
// therefore resolves FEWER paths than the count pinned below and fails, taking
// every mutation shard with it. Analysed against the shipped sources it answers
// the question it is actually asking. Outside a sandbox the two are identical.
import { repoRoot, unsandbox } from "./helpers/repo-root.mjs";

const { pairs } = JSON.parse(
  readFileSync(join(repoRoot, ".hooks", "guard-pairs.json"), "utf8"),
);

/**
 * Directories the file walk below never descends into: dependency trees, build
 * output, and the sandbox/worktree copies of the repo that would otherwise be
 * enumerated a second time. Every entry is `.gitignore`d, so the walk lists the
 * same files `git ls-files` does for the extensions this scan cares about.
 */
const SKIP_DIRS = new Set([
  ".git",
  ".idea",
  ".local",
  ".pnpm-store",
  ".stryker-tmp",
  ".uv",
  ".venv",
  ".vscode",
  ".worktrees",
  "__pycache__",
  "_bundled",
  "coverage",
  "node_modules",
  "reports",
  "types",
  "worktrees",
]);

/**
 * Every file in the checkout, repo-relative.
 *
 * Deliberately NOT `git ls-files`, but not for the reason first written here.
 * Git does not FAIL in Stryker's sandbox: the sandbox is a plain directory copy
 * at `<repoRoot>/.stryker-tmp/sandbox-XXXXXX/`, so git walks up out of it and
 * answers about the real checkout — which, now that `repoRoot` is unsandboxed,
 * is the same tree this scan wants. So git is not WRONG here, merely an
 * unnecessary dependency: enumerating from this file's own location keeps the
 * suite runnable in any copy of the repo, including one with no `.git` at all.
 */
function listFiles(dir = "", out = []) {
  const entries = readdirSync(join(repoRoot, dir), { withFileTypes: true });
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const path = dir ? `${dir}/${entry.name}` : entry.name;
    // Checked before the type test: in a linked worktree `.git` is a FILE.
    if (SKIP_DIRS.has(entry.name)) continue;
    if (entry.isDirectory()) listFiles(path, out);
    // Symlinks are neither followed nor listed: nothing this scan resolves is
    // one, and following them risks walking back into a skipped tree.
    else if (entry.isFile()) out.push(path);
  }
  return out;
}

const tracked = new Set(listFiles());

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

/**
 * Scanned SOURCE mirrors (`.sh`/`.py` opened by path) deliberately kept out of
 * the pair map, with the reason — the MIRROR_EXTENSIONS counterpart of
 * NOT_GUARDED, held separate so the two kinds of excuse cannot be confused.
 *
 * Empty today: every script a suite drives by path is cheap enough to run at
 * commit time (the slowest, `.github/scripts/auto-resolve/prepare.test.mjs`, is
 * ~8s — well inside the tolerance the already-paired ~13s
 * `scripts/version-bump.test.mjs` sets). It exists so the partition assertion
 * below has something to tell a contributor to do when one is not.
 *
 * @type {Record<string, string>}
 */
const NOT_MIRRORED = {};

// Extensions of the files the map is FOR: data a test mirrors or validates.
// JS modules are excluded on purpose — every test imports the module it
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

/**
 * Extensions of SOURCE files a test reaches BY PATH rather than by import.
 *
 * The "source modules need no pair" rationale above is about import resolution:
 * a `.mjs` that moves or is renamed takes its own suite down at load time, so
 * the pair would be redundant. A `.sh` or `.py` driven through `execFileSync`
 * gets none of that. It is read as a string path, and a test that mirrors its
 * behaviour (`test/hook-timing-shell-parity.test.mjs` runs the shell port of the
 * hook timer and byte-compares it against the node one) is exactly the cheap
 * guard the map exists to schedule — but while the scan was keyed on
 * DATA_EXTENSIONS alone the pair could not even be proposed, and editing
 * `plugin/scripts/lib/hook-timing.sh` left the hook exiting 0 having run
 * nothing while full CI went 25 tests red.
 *
 * So these join the partition. They keep a SEPARATE exemption map (NOT_MIRRORED)
 * from the data one: "no test mirrors this script" and "no test validates this
 * data file" are different excuses and should not share a list.
 */
const MIRROR_EXTENSIONS = new Set([".py", ".sh"]);

/**
 * True for a tracked file that is a script with no extension to key on.
 *
 * Keying the scan on `extname` alone made MIRROR_EXTENSIONS an allowlist, and
 * the repo's shell scripts with the strongest claim to it — `.hooks/commit-msg`,
 * `.hooks/pre-commit`, `.hooks/pre-push` — have no extension at all. One of them
 * is already mirrored by path (`.github/scripts/synced-deps.test.mjs` parses
 * `commit-msg`'s `config="…"` line), so the same gap the hook-timing.sh case
 * motivated survived one filename convention over. The shebang is what makes it
 * a script, so that is what the scan asks.
 * @param {string} path
 * @returns {boolean}
 */
function isExtensionlessScript(path) {
  return (
    extname(path) === "" &&
    readFileSync(join(repoRoot, path), "utf8").startsWith("#!")
  );
}

/** Everything the scan is responsible for accounting for. */
const SCANNED_EXTENSIONS = new Set([...DATA_EXTENSIONS, ...MIRROR_EXTENSIONS]);
const MODULE_EXTENSIONS = new Set([".cjs", ".js", ".mjs"]);

// Node types that open a lexical scope. Shadowing has to be honoured or a
// per-test `const plugin = stagePlugin(t)` temp dir reads as the repo's
// `plugin/` directory — the false positive that would register a temp path as
// though it were committed data.
const SCOPE_NODES = new Set([
  "ArrowFunctionExpression",
  "BlockStatement",
  "CatchClause",
  "ForInStatement",
  "ForOfStatement",
  "ForStatement",
  "FunctionDeclaration",
  "FunctionExpression",
]);

/**
 * Nearest binding for `name` in `kind` ("vars" for paths, "strings" for string
 * constants); null both when unresolvable and when unbound, since a shadowing
 * binding whose value is unknown must not fall through to an outer one.
 */
function lookup(scope, kind, name) {
  for (let s = scope; s; s = s.parent)
    if (s[kind].has(name)) return s[kind].get(name);
  return null;
}

/** The string a node denotes, or null if it is not a static string. */
function staticString(node, scope) {
  if (node.type === "Identifier") return lookup(scope, "strings", node.name);
  if (node.type === "Literal")
    return typeof node.value === "string" ? node.value : null;
  if (node.type !== "TemplateLiteral" || node.expressions.length > 0)
    return null;
  return node.quasis[0].value.cooked;
}

/** `import.meta` itself. */
const isImportMeta = (node) =>
  node.type === "MetaProperty" &&
  node.meta.name === "import" &&
  node.property.name === "meta";

/** Dotted name of a callee (`join`, `path.join`, `import.meta.resolve`). */
function calleeName(node) {
  if (node.type === "Identifier") return node.name;
  if (node.type !== "MemberExpression" || node.computed) return null;
  if (isImportMeta(node.object)) return `import.meta.${node.property.name}`;
  if (node.object.type !== "Identifier") return null;
  return `${node.object.name}.${node.property.name}`;
}

/** `execFileSync("git", ["rev-parse", "--show-toplevel"], …)`. */
function isGitRootCall(node, scope) {
  const [command, args] = node.arguments;
  return (
    calleeName(node.callee) === "execFileSync" &&
    command !== undefined &&
    staticString(command, scope) === "git" &&
    args?.type === "ArrayExpression" &&
    staticString(args.elements[0] ?? {}, scope) === "rev-parse" &&
    staticString(args.elements[1] ?? {}, scope) === "--show-toplevel"
  );
}

/**
 * Resolve a bare specifier through Node's REAL resolver — the package's own
 * `exports` map, which is what a consumer's import performs — and return it
 * repo-relative, or null when it lands outside the repo.
 */
function resolveBareSpecifier(specifier) {
  let url;
  try {
    url = import.meta.resolve(specifier);
  } catch {
    // A specifier that does not resolve (tests assert on those too) is exactly
    // the "no path" case every other unresolvable form returns null for.
    return null;
  }
  if (!url.startsWith("file:")) return null;
  // Node resolves relative to THIS module, which under Stryker lives in the
  // sandbox — so the answer comes back as `.stryker-tmp/sandbox-XXXXXX/src/x.mjs`,
  // a path the tracked-file set below has never heard of, and every bare
  // specifier silently stops resolving. Map it back onto the real checkout.
  const absolute = unsandbox(fileURLToPath(url));
  return absolute.startsWith(repoRoot + sep)
    ? relative(repoRoot, absolute)
    : null;
}

/**
 * Resolve an expression to a repo-relative path, or null when it is not a
 * statically-known repo path.
 *
 * Null is the safe answer and the common one: a computed segment, an unknown
 * base or a shadowed binding yields no registry entry rather than a guessed one
 * (precision over recall — a wrong entry pairs a data file with a test that
 * never reads it, which is worse than no entry at all).
 *
 * @param {object} node acorn AST node
 * @param {string} file repo-relative path of the module it appears in
 * @param {object} scope lexical scope chain of resolved bindings
 * @returns {string|null} repo-relative path ("" is the repo root)
 */
function resolvePath(node, file, scope) {
  if (node.type === "Identifier") return lookup(scope, "vars", node.name);
  if (node.type === "MemberExpression" && isImportMeta(node.object)) {
    if (node.property.name === "url" || node.property.name === "filename")
      return file;
    return node.property.name === "dirname" ? dirname(file) : null;
  }
  if (node.type === "NewExpression") {
    const [specifier, base] = node.arguments;
    const literal =
      specifier === undefined ? null : staticString(specifier, scope);
    const relativeToThisFile =
      base?.type === "MemberExpression" &&
      isImportMeta(base.object) &&
      base.property.name === "url";
    if (calleeName(node.callee) !== "URL" || literal === null) return null;
    return relativeToThisFile ? normalize(join(dirname(file), literal)) : null;
  }
  if (node.type !== "CallExpression") return null;
  if (isGitRootCall(node, scope)) return "";
  // `unsandbox(p)` from test/helpers/repo-root.mjs is the identity on a
  // repo-RELATIVE path: outside a sandbox it returns its argument, and inside one
  // it strips the `.stryker-tmp/sandbox-XXXXXX` segment, which repo-relative is
  // the same place. Named rather than inferred, exactly like the git arm above —
  // a resolver that guessed at unknown calls would resolve paths that are not
  // paths. The helper is the blessed replacement for that git call, so without
  // this arm every suite that adopts it drops out of the scan silently.
  if (calleeName(node.callee) === "unsandbox")
    return node.arguments.length === 1
      ? resolvePath(node.arguments[0], file, scope)
      : null;
  // `execFileSync(…).trim()`: the trimmed value is the same path. Checked
  // before calleeName(), which only names simple `a.b()` callees.
  if (
    node.callee.type === "MemberExpression" &&
    !node.callee.computed &&
    node.callee.property.name === "trim" &&
    node.arguments.length === 0
  )
    return resolvePath(node.callee.object, file, scope);
  const name = calleeName(node.callee);
  if (name === "import.meta.resolve") {
    const specifier =
      node.arguments[0] && staticString(node.arguments[0], scope);
    // A relative specifier would resolve against THIS file, not the module the
    // AST came from, so only bare specifiers are answered.
    return specifier === null ||
      specifier === undefined ||
      /^[./]/.test(specifier)
      ? null
      : resolveBareSpecifier(specifier);
  }
  if (name === "fileURLToPath")
    return node.arguments.length === 1
      ? resolvePath(node.arguments[0], file, scope)
      : null;
  const bare = name?.replace(/^path\./, "");
  if (bare === "dirname")
    return node.arguments.length === 1
      ? mapPath(resolvePath(node.arguments[0], file, scope), dirname)
      : null;
  if (bare !== "join" && bare !== "resolve") return null;
  const base = resolvePath(node.arguments[0] ?? {}, file, scope);
  if (base === null) return null;
  const segments = [];
  for (const argument of node.arguments.slice(1)) {
    const literal = staticString(argument, scope);
    if (literal === null) return null;
    segments.push(literal);
  }
  return normalize(join(base, ...segments));
}

const mapPath = (path, fn) => (path === null ? null : fn(path));

/**
 * The repo-root read helper: `const read = (p) => readFileSync(join(root, p))`.
 *
 * A test that defines one names its data as a BARE relative string at every call
 * site (`read("THREAT-MODEL.md")`), which every other arm of `resolvePath`
 * correctly declines — a literal is not a path expression. So the file dropped
 * out of the scan and out of the partition with it, and
 * `test/threat-model-layers.test.mjs` guarded a doc the hook would never
 * schedule it for.
 *
 * Returns the base the single parameter is joined onto, or null. Deliberately
 * narrow: exactly one parameter, and somewhere in the body a two-argument
 * `join`/`resolve` whose SECOND argument is that parameter and whose first
 * resolves to a repo path. A helper that decorates its argument, or joins more
 * than the one segment, is not recognised and its reads stay unresolved —
 * precision over recall, as everywhere else in this resolver.
 *
 * @param {object} fn arrow/function node
 * @param {string} file repo-relative path of the module it appears in
 * @param {object} scope scope the helper is DEFINED in (its parameter is not in it)
 * @returns {string|null}
 */
function rootHelperBase(fn, file, scope) {
  if (fn.params?.length !== 1 || fn.params[0].type !== "Identifier")
    return null;
  const parameter = fn.params[0].name;
  const search = (node) => {
    if (node.type === "CallExpression") {
      const bare = calleeName(node.callee)?.replace(/^path\./, "");
      const [first, second] = node.arguments;
      if (
        (bare === "join" || bare === "resolve") &&
        node.arguments.length === 2 &&
        second.type === "Identifier" &&
        second.name === parameter
      ) {
        const base = resolvePath(first, file, scope);
        if (base !== null) return base;
      }
    }
    for (const value of Object.values(node)) {
      for (const child of Array.isArray(value) ? value : [value]) {
        if (!child || typeof child.type !== "string") continue;
        const found = search(child);
        if (found !== null) return found;
      }
    }
    return null;
  };
  return search(fn.body);
}

/** Every identifier a binding pattern introduces. */
function patternNames(node, out = []) {
  if (node.type === "Identifier") out.push(node.name);
  if (node.type === "ObjectPattern")
    for (const p of node.properties)
      patternNames(p.type === "RestElement" ? p.argument : p.value, out);
  if (node.type === "ArrayPattern")
    for (const e of node.elements) if (e) patternNames(e, out);
  if (node.type === "AssignmentPattern") patternNames(node.left, out);
  if (node.type === "RestElement") patternNames(node.argument, out);
  return out;
}

/**
 * Walk `node`, recording every repo path it names and binding the `const`s that
 * hold one. Paths are collected from variable initialisers and call arguments:
 * that is where a test names the data it opens, whether it opens it directly or
 * hands the path to a helper.
 */
function visit(node, scope, ctx) {
  // A DYNAMIC `await import("./x.mjs")` with a literal specifier reaches the
  // module exactly as a static import does. Following only the static form made
  // the scan under-attribute: the hook suites load their subjects dynamically
  // (so a module-load failure lands inside the test rather than at parse time),
  // so a test that genuinely guards a data file read through one of those
  // modules looked like a non-reader, and "pairs each scanned data file with a
  // test that actually reads it" rejected the correct pair.
  if (node.type === "ImportExpression" && node.source.type === "Literal") {
    const specifier = node.source.value;
    if (typeof specifier === "string" && specifier.startsWith(".")) {
      const target = normalize(join(dirname(ctx.file), specifier));
      if (tracked.has(target)) {
        if (DATA_EXTENSIONS.has(extname(target))) ctx.refs.add(target);
        if (MODULE_EXTENSIONS.has(extname(target))) ctx.deps.push(target);
      }
    }
  }
  if (node.type === "VariableDeclarator") {
    const names = patternNames(node.id);
    // A destructuring pattern binds names whose values this resolver does not
    // track, so they bind to null and shadow anything of the same name outside.
    const single = names.length === 1 && node.init;
    const path = single ? resolvePath(node.init, ctx.file, scope) : null;
    if (node.init) {
      if (path !== null) ctx.refs.add(path);
      visit(node.init, scope, ctx);
    }
    // A rebinding always writes all three maps, null included: a name that used
    // to hold a helper and now holds something else must stop resolving, not
    // fall through to the stale outer entry.
    const helper =
      single &&
      (node.init.type === "ArrowFunctionExpression" ||
        node.init.type === "FunctionExpression")
        ? rootHelperBase(node.init, ctx.file, scope)
        : null;
    for (const name of names) {
      scope.vars.set(name, path);
      scope.strings.set(name, single ? staticString(node.init, scope) : null);
      scope.helpers.set(name, helper);
    }
    return;
  }
  if (node.type === "CallExpression" || node.type === "NewExpression")
    for (const argument of node.arguments) {
      const path = resolvePath(argument, ctx.file, scope);
      if (path !== null) ctx.refs.add(path);
    }
  if (node.type === "CallExpression" && node.arguments.length === 1) {
    const base = lookup(scope, "helpers", calleeName(node.callee) ?? "");
    const literal = staticString(node.arguments[0], scope);
    if (base !== null && literal !== null)
      ctx.refs.add(normalize(join(base, literal)));
  }
  if (node.type === "FunctionDeclaration" && node.id) {
    scope.vars.set(node.id.name, null);
    scope.helpers.set(node.id.name, rootHelperBase(node, ctx.file, scope));
  }

  const inner = SCOPE_NODES.has(node.type)
    ? {
        vars: new Map(),
        strings: new Map(),
        helpers: new Map(),
        parent: scope,
      }
    : scope;
  if (node.params)
    for (const param of node.params)
      for (const name of patternNames(param)) {
        inner.vars.set(name, null);
        inner.strings.set(name, null);
        inner.helpers.set(name, null);
      }

  for (const value of Object.values(node)) {
    const children = Array.isArray(value) ? value : [value];
    for (const child of children)
      if (child && typeof child.type === "string") visit(child, inner, ctx);
  }
}

const analyzed = new Map();
/** Resolve a module's path bindings, the repo paths it names, and its imports. */
function analyzeModule(file) {
  const cached = analyzed.get(file);
  if (cached) return cached;
  // Seeded before recursion so an import cycle terminates with an empty scope
  // (a false negative) instead of recursing forever.
  const result = {
    vars: new Map(),
    strings: new Map(),
    helpers: new Map(),
    refs: new Set(),
    deps: [],
  };
  analyzed.set(file, result);

  const ast = parse(readFileSync(join(repoRoot, file), "utf8"), {
    ecmaVersion: "latest",
    sourceType: "module",
    allowHashBang: true,
    allowReturnOutsideFunction: true,
  });
  const scope = {
    vars: result.vars,
    strings: result.strings,
    helpers: result.helpers,
    parent: null,
  };

  // Imports first, so a binding is resolved wherever the body uses it.
  for (const node of ast.body) {
    if (node.type !== "ImportDeclaration") continue;
    const specifier = node.source.value;
    if (!specifier.startsWith(".")) continue;
    const target = normalize(join(dirname(file), specifier));
    if (!tracked.has(target)) continue;
    if (DATA_EXTENSIONS.has(extname(target))) result.refs.add(target);
    if (!MODULE_EXTENSIONS.has(extname(target))) continue;
    const dep = analyzeModule(target);
    result.deps.push(target);
    for (const imported of node.specifiers) {
      if (imported.type !== "ImportSpecifier") continue;
      // A generator exports the path it writes (`OUTPUT_PATH`) and a config
      // module exports the directory names its readers join — both are how a
      // contract test names data it never spells out itself.
      const path = dep.vars.get(imported.imported.name);
      const text = dep.strings.get(imported.imported.name);
      if (path) scope.vars.set(imported.local.name, path);
      if (text) scope.strings.set(imported.local.name, text);
    }
  }
  visit(ast, scope, { file, refs: result.refs, deps: result.deps });
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
      const { refs, deps } = analyzeModule(file);
      for (const path of refs) {
        if (!tracked.has(path)) continue;
        if (
          !SCANNED_EXTENSIONS.has(extname(path)) &&
          !isExtensionlessScript(path)
        )
          continue;
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

// Every path the AST walk resolves today. Pinned exactly rather than as a loose
// floor: a path that drops out of the scan drops out of the partition and
// direction assertions with it, so a resolver regression would quietly narrow
// all of them at once while staying green.
const RESOLVED_PATH_COUNT = 55;

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
          /(?:\.test\.mjs|\/test_[^/]+\.py)$/,
          `guard test for ${source} must be a node --test file (*.test.mjs) or a ` +
            `pytest module (test_*.py) — .hooks/run-guard-pairs.mjs dispatches on ` +
            `the extension and would silently run neither: ${test}`,
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

  it("covers data whose only guard is a pytest module", () => {
    // secret-format-samples.json is mirrored by test_secrets_detectors.py and by
    // nothing on the JS side, so while the map's value domain was `.test.mjs` it
    // could not be paired at all: its guard ran in full CI and never at commit
    // time — the gap the map exists to close. Pinned by name so a revert to a
    // JS-only value domain fails here rather than silently dropping the pair.
    assert.deepEqual(pairs["tests/secrets/secret-format-samples.json"], [
      "tests/secrets/test_secrets_detectors.py",
    ]);
  });

  it("uses BOTH runners the hook dispatches on, so neither arm goes dead", () => {
    // Non-vacuity for the value-domain assertion above: it accepts two idioms,
    // and would keep passing if the map drifted back to only ever using one
    // while run-guard-pairs.mjs still carried the other runner.
    const values = Object.values(pairs).flat();
    assert.ok(
      values.some((test) => test.endsWith(".test.mjs")),
      "no node --test guard is paired",
    );
    assert.ok(
      values.some((test) => test.endsWith(".py")),
      "no pytest guard is paired — the hook's pytest runner is dead code",
    );
  });
});

describe("guarded-data scan (the map is a checked projection of the tests)", () => {
  it("still resolves the reads it was written for", () => {
    // Non-vacuity: nothing else notices if the walk stops resolving. These five
    // cover the idioms that matter — `join(gitRoot, …)`, a module-relative
    // `join(dirname(fileURLToPath(…)), …)`, a path exported by an imported
    // generator, a subpath resolved through the package's `exports` map, and
    // this test's own read.
    assert.equal(
      scanned.size,
      RESOLVED_PATH_COUNT,
      `scan resolved ${scanned.size} data files, expected ${RESOLVED_PATH_COUNT} — a resolver regression narrows every assertion below, and a genuinely new read means bumping this count in the same commit`,
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
      [
        "python/agent_sanitizer/secrets/data/credential-names.json",
        "test/credential-names-export.test.mjs",
      ],
      [".hooks/guard-pairs.json", "test/guard-pairs.test.mjs"],
      // Reached ONLY through a dynamic `await import("./…")` chain: the hook
      // suites load their subjects that way, so this anchors the
      // ImportExpression arm of the walk. Without it that arm could regress to a
      // no-op with only the count above noticing.
      [
        "python/agent_sanitizer/secrets/data/redaction-floor.json",
        "test/claude-hooks-host-seams.test.mjs",
      ],
    ]) {
      assert.ok(scanned.has(path), `scan no longer finds ${path}`);
      assert.ok(
        scanned.get(path).has(reader),
        `scan no longer attributes ${path} to ${reader}`,
      );
    }
  });

  it("reaches the sources a test drives BY PATH, not only the data it parses", () => {
    // Non-vacuity for MIRROR_EXTENSIONS and for the repo-root-helper arm of
    // `resolvePath`. Both were added because a real edit slipped the hook:
    // touching hook-timing.sh ran no guard while full CI went 25 tests red, and
    // THREAT-MODEL.md is named only as a bare string handed to a one-argument
    // `read()` helper, which every other arm correctly declines to resolve.
    for (const [path, reader] of [
      [
        "plugin/scripts/lib/hook-timing.sh",
        "test/hook-timing-shell-parity.test.mjs",
      ],
      [
        ".github/scripts/auto-resolve/discover.py",
        ".github/scripts/auto-resolve/discover.test.mjs",
      ],
      ["THREAT-MODEL.md", "test/threat-model-layers.test.mjs"],
    ]) {
      assert.ok(scanned.has(path), `scan no longer finds ${path}`);
      assert.ok(
        scanned.get(path).has(reader),
        `scan no longer attributes ${path} to ${reader}`,
      );
    }
    // Every mirror extension must still contribute something: a set that
    // silently stopped matching one of them would narrow the partition below
    // without changing which named anchors above pass.
    for (const extension of MIRROR_EXTENSIONS)
      assert.ok(
        [...scanned.keys()].some((path) => path.endsWith(extension)),
        `no ${extension} source is reached any more — MIRROR_EXTENSIONS is decorative`,
      );
  });

  it("accounts for every scanned file: pairs, NOT_GUARDED and NOT_MIRRORED partition it", () => {
    const excused = (path) =>
      path in pairs || path in NOT_GUARDED || path in NOT_MIRRORED;
    const unaccounted = [...scanned.keys()]
      .filter((path) => !excused(path))
      .map((path) => `${path} (read by ${[...scanned.get(path)].join(", ")})`);
    assert.deepEqual(
      unaccounted,
      [],
      "a test reads these files but nothing pairs them: add each to .hooks/guard-pairs.json (mapped to the test that reads it), or to NOT_GUARDED (data) / NOT_MIRRORED (a .sh/.py source) with a reason",
    );
    for (const [name, excuses] of [
      ["NOT_GUARDED", NOT_GUARDED],
      ["NOT_MIRRORED", NOT_MIRRORED],
    ])
      assert.deepEqual(
        Object.keys(excuses).filter((path) => path in pairs),
        [],
        `paths are both paired and ${name}`,
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

  it("has no stale NOT_GUARDED / NOT_MIRRORED entries", () => {
    for (const [name, excuses] of [
      ["NOT_GUARDED", NOT_GUARDED],
      ["NOT_MIRRORED", NOT_MIRRORED],
    ]) {
      assert.deepEqual(
        Object.keys(excuses).filter((path) => !scanned.has(path)),
        [],
        `${name} lists paths no test reads any more — delete them`,
      );
      for (const [path, reason] of Object.entries(excuses))
        assert.ok(reason.length > 10, `${name}[${path}] needs a real reason`);
    }
  });
});
