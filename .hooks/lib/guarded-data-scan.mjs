/**
 * The guarded-data scan: which test file guards which repo file.
 *
 * This is the DERIVATION behind the guard-pair map. `.hooks/run-guard-pairs.mjs`
 * runs it at commit time to decide what to schedule, and
 * `test/guard-pairs.test.mjs` runs it to assert the derivation still resolves
 * what it was written to resolve. One implementation, two callers — the hook
 * used to trust a hand-written cache of this scan, and the cache is exactly
 * what went stale (a hand-pinned count is what caught the last red main).
 *
 * A pair is a GUARD, not an SSOT: it says "run this check when that file
 * changes". It derives no content, so calling it otherwise would launder the
 * very smell a drift guard exists to expose.
 *
 * Three mechanisms find a test's inputs, and every one of them is the real
 * parser rather than a regex over source text (CLAUDE.md, Code Style):
 *
 *   1. the IMPORT GRAPH — `import "./x.mjs"` (static and dynamic), transitively;
 *   2. the PATH RESOLVER — `join(repoRoot, "…")`, `new URL("…", import.meta.url)`,
 *      `import.meta.resolve("pkg/sub")`, a one-argument repo-root read helper,
 *      and paths a generator module exports;
 *   3. GLOB EXPANSION — `execFileSync("git", ["ls-files", "--", …])`, expanded
 *      against the file walk below rather than against git.
 *
 * Precision over recall throughout: an expression this resolver cannot pin down
 * yields NO entry rather than a guessed one. A wrong pair schedules a test that
 * never reads the file, which is worse than scheduling nothing.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, extname, join, normalize, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "acorn";

export const repoRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
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
 * Deliberately NOT `git ls-files`: Stryker's sandbox is a copy of the repo with
 * no `.git`, so a scan that shells out to git there fails during the dry run and
 * takes every mutation shard down with it. Enumerating the tree keeps this scan
 * runnable wherever its own files are — which now includes the pre-commit hook,
 * whose whole job is to run before git has a commit to look at.
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

export const tracked = new Set(listFiles());

/**
 * Add paths the walk cannot see, so the scan still attributes them.
 *
 * The one caller is the pre-commit hook, and the one case is a staged DELETION:
 * `git rm python/…/redaction-floor.json` is gone from the working tree, so the
 * walk misses it, `derived.get(path)` is undefined and the commit passes having
 * run nothing — the silent no-op this whole mechanism exists to close, and a
 * regression against the hand-written map, which keyed on the path alone. The
 * suites still NAME the deleted path; only the `tracked` filter drops it.
 *
 * Must be called BEFORE the first scan: `analyzeModule` memoizes.
 * @param {Iterable<string>} paths
 */
export function includePaths(paths) {
  for (const path of paths) tracked.add(path);
}

/** True when a tracked path is a file this scan can actually parse. */
const readable = (file) => existsSync(join(repoRoot, file));

export const MODULE_EXTENSIONS = new Set([".cjs", ".js", ".mjs"]);

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

/** The binding kinds `visit` tracks; every rebinding writes all of them. */
const BINDING_KINDS = ["vars", "strings", "arrays", "helpers", "globHelpers"];

const newScope = (parent = null) => {
  const scope = { parent };
  for (const kind of BINDING_KINDS) scope[kind] = new Map();
  return scope;
};

/**
 * Nearest binding for `name` in `kind`; null both when unresolvable and when
 * unbound, since a shadowing binding whose value is unknown must not fall
 * through to an outer one.
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
  // `join("plugin", ".claude-plugin", "plugin.json")` is a repo-RELATIVE
  // fragment, not a path: `resolvePath` correctly declines it (a bare literal
  // base could be any cwd). But the same fragment handed to `join(REPO_ROOT, …)`
  // one line later IS the data the test reads, and without this arm the file
  // dropped out of the scan — the constant is what made it invisible.
  if (node.type === "CallExpression") {
    const bare = calleeName(node.callee)?.replace(/^path\./, "");
    if (bare !== "join" && bare !== "resolve") return null;
    const segments = node.arguments.map((a) => staticString(a, scope));
    return segments.length > 0 && segments.every((s) => s !== null)
      ? normalize(join(...segments))
      : null;
  }
  if (node.type !== "TemplateLiteral" || node.expressions.length > 0)
    return null;
  return node.quasis[0].value.cooked;
}

/**
 * The array of strings a node denotes, or null if any element is not statically
 * known. Spreads of other static string arrays are followed, which is how
 * `["ls-files", "-z", "--", ...SOURCE_GLOBS]` reads as one pathspec list.
 */
function staticStringArray(node, scope) {
  if (node.type === "Identifier") return lookup(scope, "arrays", node.name);
  if (node.type !== "ArrayExpression") return null;
  const out = [];
  for (const element of node.elements) {
    if (element === null) return null;
    if (element.type === "SpreadElement") {
      const nested = staticStringArray(element.argument, scope);
      if (nested === null) return null;
      out.push(...nested);
      continue;
    }
    const literal = staticString(element, scope);
    if (literal === null) return null;
    out.push(literal);
  }
  return out;
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

/** `execFileSync("git", [<subcommand>, …], …)` — the args node, or null. */
function gitArgs(node, scope, subcommand) {
  const [command, args] = node.arguments;
  if (calleeName(node.callee) !== "execFileSync") return null;
  if (command === undefined || staticString(command, scope) !== "git")
    return null;
  if (args?.type !== "ArrayExpression") return null;
  const first = args.elements[0];
  if (!first || first.type === "SpreadElement") return null;
  return staticString(first, scope) === subcommand ? args : null;
}

/** `execFileSync("git", ["rev-parse", "--show-toplevel"], …)`. */
function isGitRootCall(node, scope) {
  const args = gitArgs(node, scope, "rev-parse");
  return (
    args !== null &&
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
  const absolute = fileURLToPath(url);
  return absolute.startsWith(repoRoot + sep)
    ? relative(repoRoot, absolute)
    : null;
}

const mapPath = (path, fn) => (path === null ? null : fn(path));

/**
 * Resolve an expression to a repo-relative path, or null when it is not a
 * statically-known repo path.
 *
 * Null is the safe answer and the common one: a computed segment, an unknown
 * base or a shadowed binding yields no entry rather than a guessed one.
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

/**
 * The repo-root read helper: `const read = (p) => readFileSync(join(root, p))`.
 *
 * A test that defines one names its data as a BARE relative string at every call
 * site (`read("THREAT-MODEL.md")`), which every other arm of `resolvePath`
 * correctly declines — a literal is not a path expression. So the file dropped
 * out of the scan, and `test/threat-model-layers.test.mjs` guarded a doc the
 * hook would never schedule it for.
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

/**
 * The tracked-files helper: `const tracked = (...specs) =>
 * execFileSync("git", ["ls-files", "--", ...specs])`.
 *
 * Five suites in this repo enumerate their subjects through one of these
 * instead of naming them: every workflow, every shipped source, every
 * `*.test.mjs`, every `.github` script. Without this arm each of those files is
 * read by a test that the scan cannot attribute it to, so the cheapest guard in
 * the repo — "does this new workflow have a notifier?" — never runs at commit
 * time. Recognised by shape: a rest parameter spread into the pathspec position
 * of a `git ls-files` call.
 *
 * @param {object} fn arrow/function node
 * @param {object} scope scope the helper is DEFINED in
 * @returns {boolean}
 */
function isGlobHelper(fn, scope) {
  const rest = fn.params?.find((p) => p.type === "RestElement");
  if (!rest || rest.argument.type !== "Identifier") return false;
  const name = rest.argument.name;
  const search = (node) => {
    const args =
      node.type === "CallExpression" && gitArgs(node, scope, "ls-files");
    if (
      args &&
      args.elements.some(
        (element) =>
          element?.type === "SpreadElement" &&
          element.argument.type === "Identifier" &&
          element.argument.name === name,
      )
    )
      return true;
    for (const value of Object.values(node)) {
      for (const child of Array.isArray(value) ? value : [value]) {
        if (child && typeof child.type === "string" && search(child))
          return true;
      }
    }
    return false;
  };
  return search(fn.body);
}

/**
 * Tracked files matching a git pathspec.
 *
 * git matches a pathspec with fnmatch and NO `FNM_PATHNAME`, so `*` crosses `/`
 * — `*.test.mjs` finds `plugin/test/x.test.mjs`, and `.github/**.mjs` is just
 * `.github/` followed by anything ending `.mjs`. A pathspec with no wildcard is
 * a literal path or a directory prefix.
 *
 * Character classes are refused rather than approximated: none exist in this
 * repo today, and silently mis-expanding one would attribute files to a test
 * that never reads them.
 */
export function expandPathspec(pathspec) {
  if (/[[\]]/.test(pathspec))
    throw new Error(
      `guarded-data-scan: git pathspec character classes are not supported: ${pathspec}`,
    );
  if (!/[*?]/.test(pathspec)) {
    const prefix = `${pathspec.replace(/\/$/, "")}/`;
    return [...tracked].filter(
      (path) => path === pathspec || path.startsWith(prefix),
    );
  }
  const pattern = new RegExp(
    `^${pathspec
      .replace(/[.+^${}()|\\]/g, "\\$&")
      .replace(/\*/g, "[^\\0]*")
      .replace(/\?/g, "[^\\0]")}$`,
    "u",
  );
  return [...tracked].filter((path) => pattern.test(path));
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
 * The git pathspecs a call enumerates: the arguments after `--` of a direct
 * `execFileSync("git", ["ls-files", …])`, or the arguments of a call to a
 * helper that spreads them into one.
 *
 * The `--` separator is required rather than inferred: without it the
 * subcommand and its flags would read as pathspecs, and `-z` expands to nothing
 * while quietly making the call look understood.
 *
 * @returns {string[]} empty when this is not an enumeration, or not a static one
 */
function pathspecsOf(node, scope, callee) {
  const direct = gitArgs(node, scope, "ls-files");
  if (direct) {
    const args = staticStringArray(direct, scope);
    const separator = args?.indexOf("--") ?? -1;
    return separator === -1 ? [] : args.slice(separator + 1);
  }
  if (!lookup(scope, "globHelpers", callee)) return [];
  return node.arguments
    .map((argument) => staticString(argument, scope))
    .filter((spec) => spec !== null);
}

/** Record a tracked repo path this module names. */
function addRef(ctx, path) {
  if (path !== null && tracked.has(path)) ctx.refs.add(path);
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
  // so a test that genuinely guards a file read through one of those modules
  // looked like a non-reader.
  if (node.type === "ImportExpression" && node.source.type === "Literal") {
    const specifier = node.source.value;
    if (typeof specifier === "string" && specifier.startsWith(".")) {
      const target = normalize(join(dirname(ctx.file), specifier));
      if (tracked.has(target)) {
        ctx.refs.add(target);
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
      addRef(ctx, path);
      visit(node.init, scope, ctx);
    }
    const isFunction =
      single &&
      (node.init.type === "ArrowFunctionExpression" ||
        node.init.type === "FunctionExpression");
    // A rebinding always writes every map, null included: a name that used to
    // hold a helper and now holds something else must stop resolving, not fall
    // through to the stale outer entry.
    const bindings = {
      vars: path,
      strings: single ? staticString(node.init, scope) : null,
      arrays: single ? staticStringArray(node.init, scope) : null,
      helpers: isFunction ? rootHelperBase(node.init, ctx.file, scope) : null,
      globHelpers: isFunction ? isGlobHelper(node.init, scope) : null,
    };
    for (const name of names)
      for (const kind of BINDING_KINDS) scope[kind].set(name, bindings[kind]);
    return;
  }
  if (node.type === "CallExpression" || node.type === "NewExpression")
    for (const argument of node.arguments)
      addRef(ctx, resolvePath(argument, ctx.file, scope));
  if (node.type === "CallExpression") {
    const callee = calleeName(node.callee) ?? "";
    if (node.arguments.length === 1) {
      const base = lookup(scope, "helpers", callee);
      const literal = staticString(node.arguments[0], scope);
      if (base !== null && literal !== null)
        addRef(ctx, normalize(join(base, literal)));
    }
    // A directory enumeration. `readdirSync(join(REPO_ROOT, ".github/workflows"))`
    // is how the step-ref guard finds every workflow, and it names none of them
    // — the same blind spot as a `git ls-files` glob, one API over. Recursive
    // reads take the whole subtree.
    if (callee.replace(/^fs\./, "") === "readdirSync") {
      const dir = resolvePath(node.arguments[0] ?? {}, ctx.file, scope);
      const recursive = node.arguments[1]?.properties?.some(
        (p) => p.key?.name === "recursive" && p.value?.value === true,
      );
      if (dir !== null) {
        // The repo root is "" here and "." from `dirname`; a recursive read of
        // it has no prefix to test.
        const prefix = dir === "" ? "" : `${dir}/`;
        for (const path of tracked)
          if (
            recursive ? path.startsWith(prefix) : dirname(path) === (dir || ".")
          )
            addRef(ctx, path);
      }
    }
    // A `git ls-files` enumeration, called directly or through a helper: every
    // tracked file the pathspecs match is an input of this module.
    for (const spec of pathspecsOf(node, scope, callee))
      for (const path of expandPathspec(spec)) addRef(ctx, path);
  }
  if (node.type === "FunctionDeclaration" && node.id) {
    scope.vars.set(node.id.name, null);
    scope.helpers.set(node.id.name, rootHelperBase(node, ctx.file, scope));
    scope.globHelpers.set(node.id.name, isGlobHelper(node, scope));
  }

  const inner = SCOPE_NODES.has(node.type) ? newScope(scope) : scope;
  if (node.params)
    for (const param of node.params)
      for (const name of patternNames(param))
        for (const kind of BINDING_KINDS) inner[kind].set(name, null);

  for (const value of Object.values(node)) {
    const children = Array.isArray(value) ? value : [value];
    for (const child of children)
      if (child && typeof child.type === "string") visit(child, inner, ctx);
  }
}

const analyzed = new Map();
/** Resolve a module's path bindings, the repo paths it names, and its imports. */
export function analyzeModule(file) {
  const cached = analyzed.get(file);
  if (cached) return cached;
  // Seeded before recursion so an import cycle terminates with an empty scope
  // (a false negative) instead of recursing forever.
  // The module's own top-level scope IS its result: `analyzeModule` hands its
  // bindings to importers, which is how a generator's exported path constant
  // reaches the suite that never spells the path out.
  const result = { ...newScope(), refs: new Set(), deps: [] };
  analyzed.set(file, result);
  // A path seeded by `includePaths` may be a staged DELETION, with nothing left
  // on disk to parse. It still belongs in `tracked` — the suites that name it
  // must still be scheduled — but it contributes no reads of its own.
  if (!readable(file)) return result;

  const ast = parse(readFileSync(join(repoRoot, file), "utf8"), {
    ecmaVersion: "latest",
    sourceType: "module",
    allowHashBang: true,
    allowReturnOutsideFunction: true,
  });
  const scope = result;

  // Imports first, so a binding is resolved wherever the body uses it.
  for (const node of ast.body) {
    if (node.type !== "ImportDeclaration") continue;
    const specifier = node.source.value;
    if (!specifier.startsWith(".")) continue;
    const target = normalize(join(dirname(file), specifier));
    if (!tracked.has(target)) continue;
    result.refs.add(target);
    if (!MODULE_EXTENSIONS.has(extname(target))) continue;
    const dep = analyzeModule(target);
    result.deps.push(target);
    for (const imported of node.specifiers) {
      if (imported.type !== "ImportSpecifier") continue;
      // A generator exports the path it writes (`OUTPUT_PATH`) and a config
      // module exports the directory names its readers join — both are how a
      // contract test names data it never spells out itself.
      for (const kind of ["vars", "strings", "arrays"]) {
        const value = dep[kind].get(imported.imported.name);
        if (value) scope[kind].set(imported.local.name, value);
      }
    }
  }
  visit(ast, scope, { file, refs: result.refs, deps: result.deps });
  return result;
}

/**
 * Every repo file each `node --test` suite reaches, by import or by path.
 *
 * MODULES ARE INCLUDED. The scan used to drop them with "a moved .mjs already
 * fails loudly at import resolution" — true of an imported module, false of one
 * a test SPAWNS by name (`.github/scripts/npm-max-stable.mjs` is reached by
 * zero imports and was guarded only by a hand-typed line), and in either case
 * beside the point: the map's job is to run the cheap check that covers the
 * file, and for a source module that check is the suite that exercises it.
 * Editing `src/invisible.mjs` should run the 42 suites that import it.
 *
 * @returns {Map<string, Set<string>>} repo path → the test files reaching it
 */
export function scanJsGuards() {
  const readers = new Map();
  const record = (path, test) => {
    if (!readers.has(path)) readers.set(path, new Set());
    readers.get(path).add(test);
  };
  const suites = [...tracked].filter(
    (path) => path.endsWith(".test.mjs") && readable(path),
  );
  for (const test of suites) {
    const seen = new Set();
    const walk = (file) => {
      if (seen.has(file)) return;
      seen.add(file);
      // `refs` already holds every import target, so recording them here and
      // recursing covers the module itself and everything it pulls in.
      const { refs, deps } = analyzeModule(file);
      for (const path of refs) record(path, test);
      for (const dep of deps) walk(dep);
    };
    walk(test);
  }
  return readers;
}

/**
 * Error code for "the scan needs a tool this machine does not have", carried so
 * a caller can print an operator message instead of a spawn stack. The hook is
 * a gate: it must refuse the commit either way, but the two failures it can
 * actually hit — no acorn, no python3 — are both one install away, and telling
 * an operator which one is the difference between a fixable commit and a wedge.
 */
export const MISSING_TOOL = "GUARD_SCAN_TOOL_MISSING";

/** Run the Python half, translating an absent interpreter into a fixable error. */
function runPythonScan(input) {
  try {
    return execFileSync(
      "python3",
      [join(repoRoot, ".hooks", "lib", "guarded-python-scan.py"), repoRoot],
      { input, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
    );
  } catch (error) {
    // ONLY the missing interpreter is translated. A scan that ran and failed is
    // a bug in this code, and its stack is what a maintainer needs to see.
    if (error?.code !== "ENOENT") throw error;
    const wrapped = new Error(
      "`python3` is not on PATH, so the pytest half of the guard-pair map " +
        "cannot be derived. Install Python 3.10+ (or activate .venv), then " +
        "retry the commit.",
    );
    wrapped.code = MISSING_TOOL;
    throw wrapped;
  }
}

/**
 * Every repo file each pytest module names through `REPO_ROOT / "…" / "…"`.
 *
 * Delegated to `guarded-python-scan.py` because the rule everywhere else in
 * this file applies here too: parse with the language's own parser, not with a
 * regex that has to keep tracking the language. It runs under bare `python3`
 * with nothing but the standard library, so the hook does not need this repo's
 * virtualenv provisioned to derive its own map.
 *
 * @returns {Map<string, Set<string>>} repo path → the pytest modules reaching it
 */
export function scanPythonGuards() {
  const tests = [...tracked].filter(
    (path) => /(?:^|\/)test_[^/]+\.py$/.test(path) && readable(path),
  );
  const readers = new Map();
  // A repo with no pytest module needs no interpreter: `python3` is a hard
  // commit-path dependency only where there is Python to parse.
  if (tests.length === 0) return readers;
  // The scan dying must take the caller down loudly — an empty map would drop
  // every pytest guard from the derivation, which is the silent no-op this
  // mechanism exists to prevent. The one thing translated is a missing
  // interpreter, so it reads like the sibling acorn failure instead of a raw
  // spawn stack.
  const raw = runPythonScan(JSON.stringify({ tests, tracked: [...tracked] }));
  for (const [test, paths] of Object.entries(JSON.parse(raw)))
    for (const path of paths) {
      if (!tracked.has(path)) continue;
      if (!readers.has(path)) readers.set(path, new Set());
      readers.get(path).add(test);
    }
  return readers;
}

/**
 * The derived guard-pair map: repo path → the guard tests that read it.
 *
 * @returns {Map<string, Set<string>>}
 */
export function scanGuardedData() {
  const readers = scanJsGuards();
  for (const [path, tests] of scanPythonGuards()) {
    if (!readers.has(path)) readers.set(path, new Set());
    for (const test of tests) readers.get(path).add(test);
  }
  return readers;
}
