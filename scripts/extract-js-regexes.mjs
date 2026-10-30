/**
 * Static inventory of every regex in the JS that runs over untrusted input, for
 * the ReDoS guard (tests/test_redos_js_static_guard.py). Parses each source with
 * the TypeScript compiler (a dev dependency — a real JS parser, not a
 * hand-rolled regex-over-regex approximation) and emits, as JSON on stdout:
 *
 *   { "patterns": [{ "file": "src/html.mjs", "line": 12, "pattern": "...",
 *                    "flags": "..." }],
 *     "constructionSites": [{ "file": "...", "line": 1, "expr": "new RegExp(…)",
 *                             "resolved": true, "callTimeInputs": [] }],
 *     "coercionSites": [{ "file": "...", "line": 1, "expr": "s.match(RE)",
 *                         "argType": "RegExp", "isRegExp": true }] }
 *
 * `patterns` carries every regex literal plus every `RegExp(…)` construction
 * whose pattern and flags this file resolves to static text.
 * `constructionSites` carries EVERY `RegExp(…)` / `new RegExp(…)` site, resolved
 * or not, so the guard can assert the partition: a site is either analyzed or
 * named in the guard's exemption list with a reason. That is what makes a new
 * dynamic construction site a red build rather than a silent hole. An inventory
 * COUNT cannot do it: an unresolved site contributes no inventory entry, so the
 * count does not move when one appears.
 *
 * `callTimeInputs` lists every binding through which a site's pattern can read
 * run-time data ({@link callTimeInputs}); the guard requires none, because such
 * a pattern is as long as that data. `coercionSites` is every string
 * `.match`/`.matchAll`/`.search`, which compiles a non-RegExp argument.
 *
 * Resolution handles the shapes these sources actually use, and nothing more:
 * string/number/regex literals, template literals, `+` and `<<`, a same-module
 * `const`, a named import followed to its relative module, and `X.source`. When
 * static composition runs out — a `const` built by calling a function — the
 * binding's own module is imported and the live value read, if the module
 * exports it. The engine is the authority on what a JS expression evaluates to;
 * re-deriving that from source text is the partial evaluator this file
 * deliberately does not contain. A name that some inner scope also binds is
 * refused outright — this walk cannot tell the two bindings apart, and a
 * confidently wrong pattern is worse than a reported gap. A name a module-scope
 * `let`/`var` binds is refused for the same reason. Everything still unresolved
 * is reported as such, never dropped.
 *
 * Usage:
 *   node scripts/extract-js-regexes.mjs           → every shipped `.mjs`
 *   node scripts/extract-js-regexes.mjs FILE...   → just those files
 *
 * The file arguments exist for the guard's own fixtures, which prove the
 * resolved/unresolved split is real rather than vacuous.
 */
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import ts from "typescript";

import { shippedSources } from "./shipped-sources.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

/** @param {string} abs @returns {string} repo-relative POSIX path */
const relPath = (abs) => relative(repoRoot, abs).split(sep).join("/");

/**
 * @typedef {object} ModuleInfo
 * @property {string} abs absolute path
 * @property {string} rel repo-relative POSIX path
 * @property {import("typescript").SourceFile} sf
 * @property {Map<string, import("typescript").Expression>} consts module-scope `const` initializers
 * @property {Set<string>} exported names this module exports
 * @property {Map<string, {spec: string, imported: string}>} imports local name -> origin
 * @property {Set<string>} shadowed names also bound in some inner scope
 * @property {Map<import("typescript").Node, string>} owner initializer -> the name it binds
 */

/** @type {Map<string, ModuleInfo>} */
const moduleCache = new Map();

/**
 * Every name bound anywhere BELOW module scope — a parameter, a local, a
 * nested function.
 *
 * This walk knows the syntax but not the scopes, so it cannot tell which
 * binding an identifier inside a function refers to. Refusing to resolve a name
 * that some inner scope also binds is what keeps that ignorance from producing a
 * confidently WRONG pattern: a local `const STRIP = <runtime value>` beside a
 * `new RegExp(STRIP)` would otherwise be analyzed as the module-level one. The
 * site is reported unresolved instead, which the guard's exemption list makes
 * visible.
 *
 * @param {import("typescript").SourceFile} sf @returns {Set<string>}
 */
function innerScopeNames(sf) {
  /** @type {Set<string>} */
  const names = new Set();
  /** @param {import("typescript").Node} node @param {boolean} inner */
  const walk = (node, inner) => {
    if (
      inner &&
      (ts.isVariableDeclaration(node) ||
        ts.isParameter(node) ||
        ts.isBindingElement(node) ||
        ts.isFunctionDeclaration(node) ||
        ts.isClassDeclaration(node)) &&
      node.name &&
      ts.isIdentifier(node.name)
    )
      names.add(node.name.text);
    const opensScope =
      inner ||
      ts.isFunctionLike(node) ||
      ts.isBlock(node) ||
      ts.isCatchClause(node) ||
      ts.isForStatement(node) ||
      ts.isForOfStatement(node) ||
      ts.isForInStatement(node);
    ts.forEachChild(node, (child) => walk(child, opensScope));
  };
  walk(sf, false);
  return names;
}

/** Parse a module once and index the module-scope bindings resolution needs.
 * @param {string} abs @returns {ModuleInfo} */
function loadModule(abs) {
  const cached = moduleCache.get(abs);
  if (cached) return cached;

  const sf = program.getSourceFile(abs);
  if (!sf) throw new Error(`${abs} is not in the TypeScript program`);
  /** @type {ModuleInfo} */
  const mod = {
    abs,
    rel: relPath(abs),
    sf,
    consts: new Map(),
    exported: new Set(),
    imports: new Map(),
    shadowed: innerScopeNames(sf),
    owner: new Map(),
  };

  for (const st of sf.statements) {
    if (ts.isVariableStatement(st)) {
      // Only a `const` binding has a single value. A module-scope `let`/`var`
      // can be reassigned after its initializer, so neither the initializer nor
      // the live value an import reads is reliably the one a site compiles.
      // Leaving it out of both `consts` and `owner` is what makes a site built
      // from such a name report as unresolved instead of as a guess.
      if (!(st.declarationList.flags & ts.NodeFlags.Const)) continue;
      const isExported = st.modifiers?.some(
        (m) => m.kind === ts.SyntaxKind.ExportKeyword,
      );
      for (const decl of st.declarationList.declarations) {
        if (!ts.isIdentifier(decl.name) || !decl.initializer) continue;
        mod.consts.set(decl.name.text, decl.initializer);
        mod.owner.set(decl.initializer, decl.name.text);
        if (isExported) mod.exported.add(decl.name.text);
      }
      continue;
    }
    if (!ts.isImportDeclaration(st)) continue;
    const bindings = st.importClause?.namedBindings;
    if (!bindings || !ts.isNamedImports(bindings)) continue;
    const spec = /** @type {import("typescript").StringLiteral} */ (
      st.moduleSpecifier
    ).text;
    for (const el of bindings.elements)
      mod.imports.set(el.name.text, {
        spec,
        imported: (el.propertyName ?? el.name).text,
      });
  }

  moduleCache.set(abs, mod);
  return mod;
}

/**
 * A resolved value. `number` stays distinct from `string` so `1 << 20` folds
 * arithmetically while `"a" + b` concatenates, which is what JS does.
 * @typedef {{kind: "string", value: string}
 *   | {kind: "number", value: number}
 *   | {kind: "regex", source: string, flags: string}} Value
 */

/** @param {Value | null} v @returns {string | null} */
const asText = (v) =>
  v === null || v.kind === "regex" ? null : String(v.value);

/** @param {import("typescript").Node} node */
const isRegExpConstruction = (node) =>
  (ts.isNewExpression(node) || ts.isCallExpression(node)) &&
  ts.isIdentifier(node.expression) &&
  node.expression.text === "RegExp";

/** Split a `/pattern/flags` literal's raw text.
 * @param {string} text @returns {{source: string, flags: string}} */
function splitRegexLiteral(text) {
  const lastSlash = text.lastIndexOf("/");
  return { source: text.slice(1, lastSlash), flags: text.slice(lastSlash + 1) };
}

/** @type {Map<string, Record<string, unknown>>} */
const namespaceCache = new Map();

/**
 * The live value of `name` as `mod` exports it.
 *
 * Reached only when static composition cannot answer — a `const` whose
 * initializer calls a function (`charClass([...])`, `cfClassSource(...)`). These
 * modules are pure libraries, so importing one has no side effect, and the value
 * read is by construction the exact one the shipped regex compiles from.
 *
 * @param {ModuleInfo} mod @param {string} name @returns {Promise<Value | null>}
 */
async function runtimeValue(mod, name) {
  if (!mod.exported.has(name)) return null;
  const cached = namespaceCache.get(mod.abs);
  const ns =
    cached ??
    /** @type {Record<string, unknown>} */ (
      await import(pathToFileURL(mod.abs).href)
    );
  namespaceCache.set(mod.abs, ns);
  const value = ns[name];
  if (typeof value === "string") return { kind: "string", value };
  if (typeof value === "number") return { kind: "number", value };
  if (value instanceof RegExp)
    return { kind: "regex", source: value.source, flags: value.flags };
  return null;
}

/** Guards against a binding cycle sending resolution into infinite recursion.
 * @type {Set<string>} */
const resolving = new Set();

/**
 * Resolve the binding `name` as seen from `mod`.
 * @param {string} name @param {ModuleInfo} mod @returns {Promise<Value | null>}
 */
async function evaluateBinding(name, mod) {
  if (mod.shadowed.has(name)) return null;
  const key = `${mod.abs}#${name}`;
  if (resolving.has(key)) return null;
  resolving.add(key);
  try {
    const init = mod.consts.get(name);
    if (init) {
      const value = await evaluate(init, mod);
      return value ?? (await runtimeValue(mod, name));
    }
    const imported = mod.imports.get(name);
    if (!imported?.spec.startsWith(".")) return null;
    return await evaluateBinding(
      imported.imported,
      loadModule(resolve(dirname(mod.abs), imported.spec)),
    );
  } finally {
    resolving.delete(key);
  }
}

/**
 * Resolve an expression to its static value, or null when no supported shape
 * applies. Null is a reported outcome, never a silent drop.
 *
 * @param {import("typescript").Node} node @param {ModuleInfo} mod
 * @returns {Promise<Value | null>}
 */
async function evaluate(node, mod) {
  if (ts.isStringLiteralLike(node)) return { kind: "string", value: node.text };
  if (ts.isNumericLiteral(node))
    return { kind: "number", value: Number(node.text) };
  if (ts.isRegularExpressionLiteral(node))
    return { kind: "regex", ...splitRegexLiteral(node.text) };
  if (ts.isParenthesizedExpression(node))
    return await evaluate(node.expression, mod);
  if (ts.isIdentifier(node)) return await evaluateBinding(node.text, mod);

  if (ts.isTemplateExpression(node)) {
    let out = node.head.text;
    for (const span of node.templateSpans) {
      const hole = asText(await evaluate(span.expression, mod));
      if (hole === null) return null;
      out += hole + span.literal.text;
    }
    return { kind: "string", value: out };
  }

  if (ts.isBinaryExpression(node)) return await evaluateBinary(node, mod);

  if (ts.isPropertyAccessExpression(node) && node.name.text === "source") {
    const target = await evaluate(node.expression, mod);
    return target?.kind === "regex"
      ? { kind: "string", value: target.source }
      : null;
  }

  if (isRegExpConstruction(node))
    return await evaluateConstruction(
      /** @type {import("typescript").NewExpression} */ (node),
      mod,
    );
  return null;
}

/**
 * Fold `+` (concatenation or addition) and `<<` (the chunk-size shift).
 * @param {import("typescript").BinaryExpression} node @param {ModuleInfo} mod
 * @returns {Promise<Value | null>}
 */
async function evaluateBinary(node, mod) {
  const op = node.operatorToken.kind;
  const isShift = op === ts.SyntaxKind.LessThanLessThanToken;
  if (op !== ts.SyntaxKind.PlusToken && !isShift) return null;

  const left = await evaluate(node.left, mod);
  const right = await evaluate(node.right, mod);
  if (!left || !right || left.kind === "regex" || right.kind === "regex")
    return null;

  if (left.kind === "number" && right.kind === "number")
    return {
      kind: "number",
      value: isShift ? left.value << right.value : left.value + right.value,
    };
  // A shift over anything but two numbers is not a shape these sources use, so
  // it stays unresolved rather than being guessed at.
  if (isShift) return null;
  return { kind: "string", value: String(left.value) + String(right.value) };
}

/**
 * Resolve a `RegExp(…)` site to the regex it builds.
 *
 * @param {import("typescript").NewExpression | import("typescript").CallExpression} node
 * @param {ModuleInfo} mod @returns {Promise<Value | null>}
 */
async function evaluateConstruction(node, mod) {
  const [patternArg, flagsArg] = node.arguments ?? [];
  const source = patternArg ? asText(await evaluate(patternArg, mod)) : "";
  const flags = flagsArg ? asText(await evaluate(flagsArg, mod)) : "";
  if (source !== null && flags !== null)
    return { kind: "regex", source, flags };

  // The pattern is composed from something no supported shape reaches. When the
  // site IS an exported binding's initializer, the module still holds the
  // answer — read the compiled regex rather than reporting a hole that is not
  // one.
  const name = mod.owner.get(node);
  return name ? await runtimeValue(mod, name) : null;
}

/**
 * Globals a pattern may read: constructors and pure functions whose result
 * depends only on their arguments. Every other ambient binding — `process`,
 * `globalThis`, `Date`, `Intl`, a package import — can carry state from the
 * running host, so it counts as a call-time input.
 */
const PURE_GLOBALS = new Set([
  "Array",
  "Boolean",
  "Error",
  "JSON",
  "Map",
  "Math",
  "Number",
  "Object",
  "RangeError",
  "RegExp",
  "Set",
  "String",
  "TypeError",
  "undefined",
]);

/** @param {import("typescript").Node} outer @param {import("typescript").Node} inner */
const contains = (outer, inner) =>
  outer.getSourceFile() === inner.getSourceFile() &&
  outer.pos <= inner.pos &&
  inner.end <= outer.end;

/** @param {import("typescript").Node} node @returns {number} 1-based */
const lineOf = (node) => {
  const sf = node.getSourceFile();
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
};

/** @param {import("typescript").Node} node @returns {string} */
const where = (node) =>
  `${relPath(node.getSourceFile().fileName)}:${lineOf(node)}`;

/** @param {import("typescript").Node} decl */
const isModuleScope = (decl) =>
  ts.isVariableDeclaration(decl) &&
  ts.isVariableDeclarationList(decl.parent) &&
  ts.isVariableStatement(decl.parent.parent) &&
  ts.isSourceFile(decl.parent.parent.parent);

/** A module-scope variable, function or class in a source (not .d.ts) file.
 * @param {import("typescript").Declaration} decl */
const isModuleBinding = (decl) =>
  !decl.getSourceFile().isDeclarationFile &&
  (isModuleScope(decl) ||
    ((ts.isFunctionDeclaration(decl) || ts.isClassDeclaration(decl)) &&
      ts.isSourceFile(decl.parent)));

/** A declaration the walk reaches through its owner instead: an object
 * literal's property, a class member, a JSDoc type.
 * @param {import("typescript").Declaration} decl */
const isMemberDeclaration = (decl) =>
  ts.isPropertyAssignment(decl) ||
  ts.isShorthandPropertyAssignment(decl) ||
  ts.isPropertySignature(decl) ||
  ts.isPropertyDeclaration(decl) ||
  ts.isMethodDeclaration(decl) ||
  ts.isGetAccessorDeclaration(decl) ||
  ts.isSetAccessorDeclaration(decl) ||
  ts.isJSDocPropertyLikeTag(decl) ||
  ts.isTypeAliasDeclaration(decl) ||
  ts.isJSDocTypedefTag(decl);

/**
 * Every binding through which `site`'s pattern can read data that exists only
 * while the code runs, as `"<kind> <name> at <file>:<line>"`.
 *
 * The walk starts at the construction's arguments and follows each binding
 * they read to the code that produces its value: a module-scope `const`'s
 * initializer, a function's whole body, and a module-scope `let`/`var`'s
 * initializer plus every assignment to it. Resolution is TypeScript's own
 * checker, so scopes, shadowing and imports are the language's, not a guess.
 * A binding counts as a call-time input when it is:
 *
 * - a parameter or local of a function enclosing the code being walked — the
 *   caller's argument, the tool output being scanned, a prompt;
 * - an ambient global outside {@link PURE_GLOBALS} or a package import —
 *   `process.env`, host state, code this walk cannot see into;
 * - `this`, `arguments`, a dynamic `import()`, or any declaration shape the
 *   walk has no rule for, so an unknown fails closed.
 *
 * Mutation through a property (`CONFIG.x = v`) is not traced: the walk follows
 * bindings, not object contents.
 *
 * @param {import("typescript").NewExpression | import("typescript").CallExpression} site
 * @returns {string[]}
 */
function callTimeInputs(site) {
  /** @type {Set<string>} */
  const inputs = new Set();
  /** @type {Set<import("typescript").Node>} */
  const walked = new Set();

  /** @param {import("typescript").Node} root */
  const walk = (root) => {
    if (walked.has(root)) return;
    walked.add(root);
    /** @param {import("typescript").Node} node */
    const visit = (node) => {
      if (node.kind === ts.SyntaxKind.ThisKeyword)
        inputs.add(`this at ${where(node)}`);
      else if (
        ts.isCallExpression(node) &&
        node.expression.kind === ts.SyntaxKind.ImportKeyword
      )
        inputs.add(`dynamic-import at ${where(node)}`);
      else if (ts.isIdentifier(node)) reference(node, root);
      ts.forEachChild(node, visit);
    };
    visit(root);
  };

  /** @param {import("typescript").Identifier} id @param {import("typescript").Node} root */
  const reference = (id, root) => {
    const parent = id.parent;
    // `import.meta` / `new.target`, and a statement label: not bindings.
    if (
      ts.isMetaProperty(parent) ||
      ts.isLabeledStatement(parent) ||
      ts.isBreakOrContinueStatement(parent)
    )
      return;
    const isPropertyName =
      (ts.isPropertyAccessExpression(parent) && parent.name === id) ||
      (ts.isPropertyAssignment(parent) && parent.name === id) ||
      (ts.isBindingElement(parent) && parent.propertyName === id) ||
      ((ts.isMethodDeclaration(parent) || ts.isPropertyDeclaration(parent)) &&
        parent.name === id);
    const symbol = ts.isShorthandPropertyAssignment(parent)
      ? checker.getShorthandAssignmentValueSymbol(parent)
      : checker.getSymbolAtLocation(id);
    const decl = symbol?.valueDeclaration ?? symbol?.declarations?.[0];
    // A property name is read through its object, which the walk already
    // follows — except a namespace import's member, which is a binding.
    if (isPropertyName && !(decl && isModuleBinding(decl))) return;
    if (!symbol) {
      inputs.add(`unbound ${id.text} at ${where(id)}`);
      return;
    }
    if (decl && /** @type {any} */ (decl).name === id) return;
    binding(symbol, id, root);
  };

  /**
   * @param {import("typescript").Symbol} symbol
   * @param {import("typescript").Identifier} id
   * @param {import("typescript").Node} root
   */
  const binding = (symbol, id, root) => {
    const name = symbol.name;
    if (symbol.flags & ts.SymbolFlags.Alias) {
      const target = checker.getAliasedSymbol(symbol);
      const targetDecl = target.valueDeclaration ?? target.declarations?.[0];
      if (targetDecl && !targetDecl.getSourceFile().isDeclarationFile)
        binding(target, id, root);
      else inputs.add(`import ${name} at ${where(id)}`);
      return;
    }
    const decl = symbol.valueDeclaration ?? symbol.declarations?.[0];
    if (!decl) {
      inputs.add(`undeclared ${name} at ${where(id)}`);
      return;
    }
    if (decl.getSourceFile().isDeclarationFile) {
      if (!PURE_GLOBALS.has(name)) inputs.add(`global ${name} at ${where(id)}`);
      return;
    }
    // A JSON module or a namespace import (each member is followed as it is
    // read), or an object member (reached through the object that owns it).
    if (ts.isSourceFile(decl) || isMemberDeclaration(decl)) return;
    if (contains(root, decl)) return;
    if (ts.isFunctionLike(decl) || ts.isClassLike(decl)) {
      walk(decl);
      return;
    }
    const variable = ts.isBindingElement(decl)
      ? ts.walkUpBindingElementsAndPatterns(decl)
      : decl;
    if (ts.isParameter(variable)) {
      inputs.add(`parameter ${name} at ${where(id)}`);
      return;
    }
    if (!ts.isVariableDeclaration(variable)) {
      inputs.add(
        `${ts.SyntaxKind[decl.kind]} ${name} at ${where(id)} (no rule)`,
      );
      return;
    }
    if (!isModuleScope(variable)) {
      inputs.add(`local ${name} at ${where(id)}`);
      return;
    }
    walk(variable);
    if (variable.parent.flags & ts.NodeFlags.Const) return;
    for (const assignment of assignmentsTo(symbol, variable.getSourceFile()))
      walk(assignment.right);
  };

  for (const arg of site.arguments ?? []) walk(arg);
  return [...inputs].sort();
}

/**
 * Every `x = …` / `x ??= …` (any assignment operator) whose target is `symbol`.
 * @param {import("typescript").Symbol} symbol
 * @param {import("typescript").SourceFile} sf
 * @returns {import("typescript").BinaryExpression[]}
 */
function assignmentsTo(symbol, sf) {
  /** @type {import("typescript").BinaryExpression[]} */
  const found = [];
  /** @param {import("typescript").Node} node */
  const visit = (node) => {
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
      node.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
      ts.isIdentifier(node.left) &&
      checker.getSymbolAtLocation(node.left) === symbol
    )
      found.push(node);
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

/** The string methods that compile a non-RegExp argument with `new RegExp`. */
const COERCING_METHODS = new Set(["match", "matchAll", "search"]);

/**
 * A `.match`/`.matchAll`/`.search` call on a string (or an untyped receiver),
 * with whether its argument is typed as a RegExp; null for any other node.
 * @param {import("typescript").Node} node
 */
function coercionSite(node) {
  if (
    !ts.isCallExpression(node) ||
    !ts.isPropertyAccessExpression(node.expression) ||
    !COERCING_METHODS.has(node.expression.name.text) ||
    node.arguments.length === 0
  )
    return null;
  const receiver = checker.getNonNullableType(
    checker.getTypeAtLocation(node.expression.expression),
  );
  const stringy = (/** @type {import("typescript").Type} */ t) =>
    Boolean(t.flags & (ts.TypeFlags.StringLike | ts.TypeFlags.Any));
  if (!(receiver.isUnion() ? receiver.types.every(stringy) : stringy(receiver)))
    return null;
  const argType = checker.getTypeAtLocation(node.arguments[0]);
  return {
    file: relPath(node.getSourceFile().fileName),
    line: lineOf(node),
    expr: node.getText().replace(/\s+/g, " "),
    argType: checker.typeToString(argType),
    isRegExp: argType.getSymbol()?.getName() === "RegExp",
  };
}

// Every .mjs this package SHIPS, from the one place that answers that question
// (scripts/shipped-sources.mjs, which resolves package.json's `files`). Shipped
// is exactly the scope that matters here: those modules are inlined into the
// plugin bundle and run inside a host's hook over tool output and prompts, so a
// super-linear pattern there can push the hook past the kill a host reads as a
// non-blocking error. Build and CI tooling is not shipped and so is not walked;
// it reads what this repo produces under a job timeout, not what a remote sent.
//
// Reading the manifest rather than a hardcoded root list is what keeps this
// honest: a newly shipped module, or a whole new shipped directory, joins the
// inventory with no edit here. An explicit file list overrides the scope only
// for the guard's own fixtures.
const args = process.argv.slice(2);
const analyzed = args.length
  ? args.map((arg) => (isAbsolute(arg) ? arg : resolve(arg)))
  : shippedSources(repoRoot).map((rel) => join(repoRoot, rel));

// One program over the analyzed files and everything they import, under the
// repo's own tsconfig.json, so the checker resolves a binding across modules
// exactly as `pnpm check` does. JSON resolution is added because a JSON import
// is shipped data the call-time walk must see as such.
const tsconfig = ts.readConfigFile(
  join(repoRoot, "tsconfig.json"),
  ts.sys.readFile,
);
if (tsconfig.error)
  throw new Error(
    ts.flattenDiagnosticMessageText(tsconfig.error.messageText, "\n"),
  );
const { options, errors } = ts.convertCompilerOptionsFromJson(
  tsconfig.config.compilerOptions,
  repoRoot,
);
if (errors.length)
  throw new Error(ts.flattenDiagnosticMessageText(errors[0].messageText, "\n"));
const program = ts.createProgram(analyzed, {
  ...options,
  resolveJsonModule: true,
});
const checker = program.getTypeChecker();

/** @type {{file: string, line: number, pattern: string, flags: string}[]} */
const found = [];
/** @type {{file: string, line: number, expr: string, resolved: boolean, callTimeInputs: string[]}[]} */
const constructionSites = [];
/** @type {NonNullable<ReturnType<typeof coercionSite>>[]} */
const coercionSites = [];
/** @type {{node: import("typescript").NewExpression, mod: ModuleInfo}[]} */
const pending = [];

for (const abs of analyzed) {
  const mod = loadModule(abs);

  /** @param {import("typescript").Node} node */
  const visit = (node) => {
    const coercion = coercionSite(node);
    if (coercion) coercionSites.push(coercion);
    if (ts.isRegularExpressionLiteral(node)) {
      const { source, flags } = splitRegexLiteral(node.text);
      found.push({ file: mod.rel, line: lineOf(node), pattern: source, flags });
    } else if (isRegExpConstruction(node)) {
      pending.push({
        node: /** @type {import("typescript").NewExpression} */ (node),
        mod,
      });
    }
    ts.forEachChild(node, visit);
  };
  visit(mod.sf);
}

for (const { node, mod } of pending) {
  const value = await evaluateConstruction(node, mod);
  const line = lineOf(node);
  constructionSites.push({
    file: mod.rel,
    line,
    expr: node.getText(mod.sf).replace(/\s+/g, " "),
    resolved: value !== null,
    callTimeInputs: callTimeInputs(node),
  });
  if (value?.kind === "regex")
    found.push({
      file: mod.rel,
      line,
      pattern: value.source,
      flags: value.flags,
    });
}

process.stdout.write(
  JSON.stringify(
    { patterns: found, constructionSites, coercionSites },
    null,
    2,
  ) + "\n",
);
