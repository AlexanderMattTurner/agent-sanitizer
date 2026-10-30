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
 * or not — recognised by the callee's type, plus any call handed the
 * constructor (`Reflect.construct(RegExp, …)`) — so the guard can assert the
 * partition: a site is either analyzed or named in the guard's exemption list
 * with a reason. That is what makes a new dynamic construction site a red
 * build rather than a silent hole. An inventory
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

/** @param {import("typescript").Type} type */
const isRegExpConstructorType = (type) =>
  (type.isUnion() ? type.types : [type]).some((member) => {
    const decl = member.getSymbol()?.declarations?.[0];
    return (
      member.getSymbol()?.getName() === "RegExpConstructor" &&
      decl !== undefined &&
      program.isSourceFileDefaultLibrary(decl.getSourceFile())
    );
  });

/**
 * A `RegExp(…)` / `new RegExp(…)` site, recognised by the callee's TYPE rather
 * than its spelling: `const R = RegExp; new R(x)`, `new (RegExp)(x)` and
 * `globalThis.RegExp(x)` all construct a regex, and a local binding that
 * shadows the name `RegExp` does not. A union callee that may be the global
 * constructor counts as a site.
 * @param {import("typescript").Node} node
 */
const isRegExpConstruction = (node) =>
  (ts.isNewExpression(node) || ts.isCallExpression(node)) &&
  isRegExpConstructorType(checker.getTypeAtLocation(node.expression));

/**
 * A call that constructs a regex without calling the constructor directly:
 * `RegExp.call(…)` / `.apply` / `.bind`, or the constructor handed to another
 * call (`Reflect.construct(RegExp, args)`, `[RegExp].map(…)`). Its pattern is
 * out of reach, so it is reported as a site that never resolves.
 * @param {import("typescript").Node} node
 */
const isIndirectRegExpConstruction = (node) => {
  if (!ts.isCallExpression(node) && !ts.isNewExpression(node)) return false;
  const callee = node.expression;
  const isConstructor = (/** @type {import("typescript").Node} */ n) =>
    isRegExpConstructorType(checker.getTypeAtLocation(n));
  return (
    (ts.isPropertyAccessExpression(callee) &&
      ["apply", "bind", "call"].includes(callee.name.text) &&
      isConstructor(callee.expression)) ||
    (node.arguments ?? []).some(isConstructor)
  );
};

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
  "Number",
  "Object",
  "RangeError",
  "Set",
  "String",
  "TypeError",
]);

/**
 * `RegExp` carries run-time state too — `RegExp.$1` / `RegExp.input` hold the
 * last match — so it is pure only as the constructor being called. `Math` is
 * impure through `Math.random`, so any read of it is an input.
 * @param {string} name @param {import("typescript").Identifier} id
 */
const isPureGlobalRead = (name, id) =>
  PURE_GLOBALS.has(name) ||
  (name === "RegExp" &&
    (ts.isNewExpression(id.parent) || ts.isCallExpression(id.parent)) &&
    id.parent.expression === id);

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
 * they read to the code that produces its value: a variable's initializer plus
 * every write into it (`writesInto`), and a function's whole body. Resolution
 * is TypeScript's own checker, so scopes, shadowing and imports are the
 * language's, not a guess. A binding counts as a call-time input when it is:
 *
 * - a parameter of a function enclosing the code being walked — the caller's
 *   argument, the tool output being scanned, a prompt — or a loop or catch
 *   variable there;
 * - an ambient global outside {@link PURE_GLOBALS} or a package import —
 *   `process.env`, host state, code this walk cannot see into;
 * - written once per call, or aliased somewhere its writes cannot be followed;
 * - `this`, `arguments`, a dynamic `import()`, or any declaration shape the
 *   walk has no rule for, so an unknown fails closed.
 *
 * Not traced: a write into a JSON module's object, and data that steers a
 * write only through control flow (`for (…) parts.push("a")`, where the loop
 * count is the input).
 *
 * @param {import("typescript").NewExpression | import("typescript").CallExpression} site
 * @returns {string[]}
 */
function callTimeInputs(site) {
  /** @type {Set<string>} */
  const inputs = new Set();
  /** @type {Set<import("typescript").Node>} */
  const walked = new Set();
  /** @type {Set<import("typescript").Symbol>} */
  const followedWrites = new Set();

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
    // The checker's own `undefined`, which has no declaration to judge.
    if (!decl && name === "undefined") return;
    if (!decl) {
      inputs.add(`undeclared ${name} at ${where(id)}`);
      return;
    }
    if (decl.getSourceFile().isDeclarationFile) {
      if (!isPureGlobalRead(name, id))
        inputs.add(`global ${name} at ${where(id)}`);
      return;
    }
    // A JSON module or a namespace import (each member is followed as it is
    // read), or an object member (reached through the object that owns it).
    // Writes into a JSON module's object are not traced: its validators read
    // it through `unknown`, where no type separates a read from a write.
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
    // A local is followed like a module binding when a plain declaration
    // statement gives it its value; a loop variable or catch binding takes its
    // value from code with no initializer to walk.
    const followable =
      isModuleScope(variable) ||
      (ts.isVariableStatement(variable.parent.parent) &&
        variable.initializer !== undefined);
    if (!followable) {
      inputs.add(`local ${name} at ${where(id)}`);
      return;
    }
    walk(variable);
    writesInto(
      symbol,
      name,
      ts.findAncestor(variable, ts.isFunctionLike),
      false,
    );
  };

  /**
   * Follow every write into the value `symbol` holds, anywhere in the program:
   * a reassignment of the binding itself (plain, compound or destructuring, a
   * `for…of` target, `++`/`--`), and — unless the value is immutable — a write
   * into its contents (`X.k = v`, `delete X.k`, a mutating method such as
   * `X.push(v)` or `X.get(k).add(v)`, `Object.assign(X, v)`). Each write's
   * data is walked like the value's own initializer. A binding the value flows
   * into — `const a = X`, a loop variable, a parameter of a function X is
   * handed to, a callback's parameter — is followed the same way. A write that
   * runs inside a function the original binding's scope does not run — once per
   * call rather than once per load — makes the value depend on the call
   * history, so it is an input itself; a logical assignment (`??=`, `||=`,
   * `&&=`) is exempt, since it lands at most once. A flow the walk cannot
   * follow (the value stored in an object, returned, passed to code it cannot
   * see) is an input, since writes through it are invisible.
   *
   * @param {import("typescript").Symbol} symbol @param {string} name
   * @param {import("typescript").Node | undefined} home the function the
   *   original binding is declared in; undefined at module scope
   * @param {boolean} isAlias rebinding an alias leaves the value untouched
   * @param {import("typescript").Type} type what flows in: an alias's declared
   *   type can be wider (`any`, `unknown`) than the value handed to it
   */
  const writesInto = (
    symbol,
    name,
    home,
    isAlias,
    type = checker.getTypeOfSymbol(symbol),
  ) => {
    const mutableContents = !(
      isImmutableValue(type) || isFrozenConstant(symbol)
    );
    if ((isAlias && !mutableContents) || followedWrites.has(symbol)) return;
    followedWrites.add(symbol);
    /** @param {import("typescript").Node} at */
    const escape = (at) => inputs.add(`alias ${name} at ${where(at)}`);
    /** @param {import("typescript").Node} writer */
    const write = (writer) => {
      const isLogical =
        ts.isBinaryExpression(writer) &&
        LOGICAL_ASSIGNMENTS.has(writer.operatorToken.kind);
      if (!isLogical && ts.findAncestor(writer, ts.isFunctionLike) !== home)
        inputs.add(`write ${name} at ${where(writer)}`);
      walk(
        ts.isForInStatement(writer) || ts.isForOfStatement(writer)
          ? writer.expression
          : writer,
      );
    };
    /** A binding that receives the value or part of it, typed as `type`
     * when the flow says more than the binding's declaration.
     * @param {import("typescript").BindingName} target
     * @param {import("typescript").Type} [type] */
    const flowsInto = (target, type) => {
      if (!ts.isIdentifier(target)) {
        for (const element of target.elements)
          if (!ts.isOmittedExpression(element)) flowsInto(element.name);
        return;
      }
      const aliased = checker.getSymbolAtLocation(target);
      if (!aliased) throw new Error(`no symbol for ${where(target)}`);
      writesInto(aliased, name, home, true, type);
    };
    /** The function `callee` resolves to, when the walk can read its body.
     * @param {import("typescript").Signature | undefined} signature */
    const bodyOf = (signature) => {
      const decl = signature?.declaration;
      return decl &&
        ts.isFunctionLike(decl) &&
        "body" in decl &&
        decl.body !== undefined
        ? decl
        : null;
    };
    /** A callback handed to a read-only library call on the value receives
     * its elements (and, for `forEach` and kin, the value itself).
     * @param {import("typescript").CallLikeExpression} call */
    const callbacksReceive = (call) => {
      for (const arg of callableArguments(call)) {
        const signature = checker.getTypeAtLocation(arg).getCallSignatures()[0];
        if (signature.declaration?.getSourceFile().isDeclarationFile) continue;
        const callback = bodyOf(signature);
        if (!callback) {
          escape(arg);
          continue;
        }
        // What the library passes each parameter (`(value: string, index:
        // number, array: string[])`), which a separately declared callback's
        // own untyped parameters do not say.
        const expected = checker
          .getContextualType(
            /** @type {import("typescript").Expression} */ (arg),
          )
          ?.getCallSignatures()[0]?.parameters;
        callback.parameters.forEach((param, index) => {
          const passed = expected?.[index];
          flowsInto(
            param.name,
            passed ? checker.getTypeOfSymbol(passed) : undefined,
          );
        });
      }
    };
    /** The value handed to a call outside the default library flows into the
     * matching parameter. @param {import("typescript").CallExpression} call
     * @param {import("typescript").Expression} arg */
    const passedTo = (call, arg) => {
      const callee = bodyOf(checker.getResolvedSignature(call));
      const index = call.arguments.indexOf(arg);
      const param = callee?.parameters[index];
      if (!param || param.dotDotDotToken || readsArguments(callee)) write(call);
      else flowsInto(param.name, checker.getTypeAtLocation(arg));
    };
    /** @param {import("typescript").Expression} held an expression whose
     * value may be the binding's value or part of it */
    const flow = (held) => {
      const { top, calls } = accessChain(held);
      const writer = writerOf(top);
      if (writer) {
        const rebinds = top === skipPassThrough(held);
        const writesValue = rebinds
          ? !isAlias
          : mutableContents && !isRegExpStateWrite(top);
        if (writesValue) write(writer);
        return;
      }
      if (!mutableContents) {
        // `RE.compile(p)` rewrites a RegExp's source in place.
        for (const call of calls) if (isRegExpRecompile(call)) write(call);
        return;
      }
      for (const call of calls) {
        if (mutatesReceiver(call)) {
          write(call);
          continue;
        }
        callbacksReceive(call);
        // `X.map(f)`, `X.filter(f).sort()`: the rest of the chain works on a
        // new value, which holds nothing of X when its elements are immutable.
        const fresh = checker.getTypeAtLocation(call);
        if (isFreshResult(call) && elementsAreImmutable(fresh)) return;
      }
      const type = checker.getTypeAtLocation(top);
      if (isImmutableValue(type)) return;
      const parent = top.parent;
      if (ts.isDeleteExpression(parent)) write(parent);
      else if (ts.isSpreadElement(parent) && isCallArgument(parent))
        escape(top);
      else if (isCallArgument(top)) {
        const call = /** @type {import("typescript").CallExpression} */ (
          parent
        );
        if (!isDefaultLibraryCall(call)) passedTo(call, top);
        else if (!mutatesReceiver(call)) {
          callbacksReceive(call);
          // `new Set(X)`, `Array.from(X)`: the result holds X's elements.
          flow(call);
        } else if (call.arguments[0] === top && isStaticMutator(call))
          write(call);
        else escape(top);
      } else if (ts.isVariableDeclaration(parent) && parent.initializer === top)
        flowsInto(parent.name, type);
      else if (ts.isForOfStatement(parent) && parent.expression === top) {
        if (elementsAreImmutable(type)) return;
        const loop = parent.initializer;
        if (!ts.isVariableDeclarationList(loop)) escape(top);
        else flowsInto(loop.declarations[0].name);
      } else if (!isConsumedInPlace(top, parent)) escape(top);
    };
    for (const ref of referencesTo(symbol))
      if (!isDeclarationName(ref)) flow(ref);
  };

  for (const arg of site.arguments ?? []) walk(arg);
  return [...inputs].sort();
}

/** @type {Map<import("typescript").Symbol, import("typescript").Identifier[]> | null} */
let referenceIndex = null;

/**
 * Every identifier in the program's own sources that names `symbol`, through
 * import aliases — so a write in an importing module is found too.
 * @param {import("typescript").Symbol} symbol
 */
function referencesTo(symbol) {
  if (!referenceIndex) {
    const index = new Map();
    /** @param {import("typescript").Node} node */
    const visit = (node) => {
      if (ts.isIdentifier(node)) {
        const parent = node.parent;
        let named =
          ts.isShorthandPropertyAssignment(parent) && parent.name === node
            ? checker.getShorthandAssignmentValueSymbol(parent)
            : checker.getSymbolAtLocation(node);
        if (named && named.flags & ts.SymbolFlags.Alias)
          named = checker.getAliasedSymbol(named);
        if (named) index.set(named, [...(index.get(named) ?? []), node]);
      }
      ts.forEachChild(node, visit);
    };
    for (const sf of program.getSourceFiles())
      if (!sf.isDeclarationFile) visit(sf);
    referenceIndex = index;
  }
  return referenceIndex.get(symbol) ?? [];
}

/** Whether `fn` reads `arguments`, which reaches every argument by position
 * rather than through the parameter a flow follows.
 * @param {import("typescript").Node} fn */
const readsArguments = (fn) => {
  /** @param {import("typescript").Node} node @returns {boolean} */
  const visit = (node) =>
    (ts.isIdentifier(node) && node.text === "arguments") ||
    Boolean(ts.forEachChild(node, visit));
  return visit(fn);
};

/** @param {import("typescript").Identifier} id */
const isDeclarationName = (id) =>
  /** @type {any} */ (id.parent).name === id &&
  (ts.isVariableDeclaration(id.parent) ||
    ts.isBindingElement(id.parent) ||
    ts.isParameter(id.parent) ||
    ts.isFunctionDeclaration(id.parent) ||
    ts.isClassDeclaration(id.parent) ||
    ts.isImportSpecifier(id.parent) ||
    ts.isExportSpecifier(id.parent) ||
    ts.isImportClause(id.parent) ||
    ts.isNamespaceImport(id.parent));

/** The outermost of the parentheses and type assertions wrapping `node`,
 * which hand on its value unchanged.
 * @param {import("typescript").Expression} node
 * @returns {import("typescript").Expression} */
const skipPassThrough = (node) => {
  let out = node;
  while (
    ts.isParenthesizedExpression(out.parent) ||
    ts.isNonNullExpression(out.parent) ||
    ts.isAsExpression(out.parent) ||
    ts.isSatisfiesExpression(out.parent)
  )
    out = out.parent;
  return out;
};

/**
 * The longest member/call chain rooted at `held` (for `X` in
 * `X.a.get(k).push(v)`, that whole expression), with every call made along it.
 * @param {import("typescript").Expression} held
 */
function accessChain(held) {
  /** @type {import("typescript").Expression} */
  let top = held;
  /** @type {import("typescript").CallExpression[]} */
  const calls = [];
  for (;;) {
    const outer = skipPassThrough(top);
    const parent = outer.parent;
    if (
      (ts.isPropertyAccessExpression(parent) ||
        ts.isElementAccessExpression(parent)) &&
      parent.expression === outer
    )
      top = parent;
    else if (ts.isCallExpression(parent) && parent.expression === outer) {
      calls.push(parent);
      top = parent;
    } else return { top: outer, calls };
  }
}

/** @param {import("typescript").SyntaxKind} kind */
const isAssignmentOperator = (kind) =>
  kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;

const LOGICAL_ASSIGNMENTS = new Set([
  ts.SyntaxKind.QuestionQuestionEqualsToken,
  ts.SyntaxKind.BarBarEqualsToken,
  ts.SyntaxKind.AmpersandAmpersandEqualsToken,
]);

/**
 * The assignment, `++`/`--` or `for…in`/`of` whose target `node` is, through
 * any destructuring pattern around it; undefined when `node` is read. The
 * climb is TypeScript's own `getAssignmentTarget`, which its public API does
 * not export.
 * @param {import("typescript").Node} node
 * @returns {import("typescript").Node | undefined}
 */
function assignmentTarget(node) {
  let target = node;
  for (;;) {
    const parent = target.parent;
    if (ts.isBinaryExpression(parent))
      return isAssignmentOperator(parent.operatorToken.kind) &&
        parent.left === target
        ? parent
        : undefined;
    if (
      ts.isPrefixUnaryExpression(parent) ||
      ts.isPostfixUnaryExpression(parent)
    )
      return parent.operator === ts.SyntaxKind.PlusPlusToken ||
        parent.operator === ts.SyntaxKind.MinusMinusToken
        ? parent
        : undefined;
    if (ts.isForInStatement(parent) || ts.isForOfStatement(parent))
      return parent.initializer === target ? parent : undefined;
    if (
      ts.isParenthesizedExpression(parent) ||
      ts.isArrayLiteralExpression(parent) ||
      ts.isSpreadElement(parent) ||
      ts.isNonNullExpression(parent)
    )
      target = parent;
    else if (ts.isSpreadAssignment(parent)) target = parent.parent;
    else if (ts.isShorthandPropertyAssignment(parent)) {
      if (parent.name !== target) return undefined;
      target = parent.parent;
    } else if (ts.isPropertyAssignment(parent)) {
      if (parent.name === target) return undefined;
      target = parent.parent;
    } else return undefined;
  }
}

/**
 * The write `target` takes part in, or null when `target` is read. A target
 * nested in a destructuring pattern — including one with a default,
 * `[X.a = d] = e` — resolves to the outermost assignment, whose right side is
 * the data written.
 * @param {import("typescript").Node} target
 */
function writerOf(target) {
  let writer = assignmentTarget(target);
  if (!writer) return null;
  for (
    let outer = assignmentTarget(writer);
    outer;
    outer = assignmentTarget(writer)
  )
    writer = outer;
  return writer;
}

/** Default-library methods and statics that write into their receiver or first
 * argument. Every other default-library call only reads them. */
const MUTATING_LIB_CALLS = new Set([
  "add",
  "assign",
  "clear",
  "compile",
  "copyWithin",
  "defineProperties",
  "defineProperty",
  "delete",
  "deleteProperty",
  "fill",
  "pop",
  "push",
  "reverse",
  "set",
  "setPrototypeOf",
  "shift",
  "sort",
  "splice",
  "unshift",
]);

/** @param {import("typescript").CallLikeExpression} call */
const isDefaultLibraryCall = (call) => {
  const decl = checker.getResolvedSignature(call)?.declaration;
  return (
    decl !== undefined &&
    program.isSourceFileDefaultLibrary(decl.getSourceFile())
  );
};

/** A call that may write into what it is handed: anything outside the default
 * library (whose body this walk does not judge), or a mutating library call.
 * @param {import("typescript").CallLikeExpression} call */
const mutatesReceiver = (call) => {
  if (!isDefaultLibraryCall(call)) return true;
  const callee =
    ts.isCallExpression(call) || ts.isNewExpression(call)
      ? call.expression
      : null;
  const calleeName =
    callee && ts.isPropertyAccessExpression(callee)
      ? callee.name.text
      : callee && ts.isIdentifier(callee)
        ? callee.text
        : null;
  return calleeName === null || MUTATING_LIB_CALLS.has(calleeName);
};

/** The arguments of a read-only library call that are code it runs — a
 * `map`/`forEach` callback can still write into what it is handed.
 * @param {import("typescript").CallLikeExpression} call */
const callableArguments = (call) =>
  (ts.isCallExpression(call) || ts.isNewExpression(call)
    ? (call.arguments ?? [])
    : []
  ).filter(
    (arg) => checker.getTypeAtLocation(arg).getCallSignatures().length > 0,
  );

/** @param {import("typescript").Node} node */
const isCallArgument = (node) =>
  (ts.isCallExpression(node.parent) || ts.isNewExpression(node.parent)) &&
  /** @type {readonly import("typescript").Node[]} */ (
    node.parent.arguments ?? []
  ).includes(node);

/** `Object.assign(X, …)`, `Reflect.set(X, …)`: a library static that writes
 * into its first argument. @param {import("typescript").CallExpression} call */
const isStaticMutator = (call) =>
  ts.isPropertyAccessExpression(call.expression) &&
  ts.isIdentifier(call.expression.expression) &&
  ["Object", "Reflect"].includes(call.expression.expression.text);

/** Library calls whose result may be one of the receiver's own elements
 * rather than a fresh value. */
const ELEMENT_RETURNING_LIB_CALLS = new Set([
  "at",
  "find",
  "findLast",
  "get",
  "pop",
  "reduce",
  "reduceRight",
  "shift",
]);

/** A read-only library call whose result is a new value (`X.map(f)`,
 * `X.join(s)`), so an immutable element type means it holds nothing of X.
 * @param {import("typescript").CallExpression} call */
const isFreshResult = (call) =>
  isDefaultLibraryCall(call) &&
  ts.isPropertyAccessExpression(call.expression) &&
  !ELEMENT_RETURNING_LIB_CALLS.has(call.expression.name.text);

/**
 * `re.lastIndex = 0`: a RegExp's only writable slot, which no pattern reads —
 * `source` and `flags` are fixed at construction (`compile` is a mutating call).
 * @param {import("typescript").Node} target
 */
const isRegExpStateWrite = (target) =>
  ts.isPropertyAccessExpression(target) &&
  isRegExpType(checker.getTypeAtLocation(target.expression));

/** @param {import("typescript").CallExpression} call */
const isRegExpRecompile = (call) =>
  ts.isPropertyAccessExpression(call.expression) &&
  call.expression.name.text === "compile" &&
  isRegExpType(checker.getTypeAtLocation(call.expression.expression));

/** @param {import("typescript").Type} type */
const isRegExpType = (type) => {
  const decl = type.getSymbol()?.declarations?.[0];
  return (
    type.getSymbol()?.getName() === "RegExp" &&
    decl !== undefined &&
    program.isSourceFileDefaultLibrary(decl.getSourceFile())
  );
};

/**
 * A value no reference can write into: a primitive, a RegExp (whose pattern
 * is fixed at construction), or a function (its behaviour is its body, which
 * the walk follows when the function is read). `any` is not immutable.
 * @param {import("typescript").Type} type
 */
const isImmutableValue = (type) =>
  (type.isUnion() ? type.types : [type]).every(
    (member) =>
      member.flags &
        (ts.TypeFlags.StringLike |
          ts.TypeFlags.NumberLike |
          ts.TypeFlags.BigIntLike |
          ts.TypeFlags.BooleanLike |
          ts.TypeFlags.ESSymbolLike |
          ts.TypeFlags.Undefined |
          ts.TypeFlags.Null |
          ts.TypeFlags.Void) ||
      isRegExpType(member) ||
      (member.getCallSignatures().length > 0 &&
        member.getProperties().length === 0),
  );

/**
 * `const X = Object.freeze([…])` over immutable elements: a value no write can
 * reach, so how it is read does not matter.
 * @param {import("typescript").Symbol} symbol
 */
const isFrozenConstant = (symbol) => {
  const decl = symbol.valueDeclaration;
  const init =
    decl &&
    ts.isVariableDeclaration(decl) &&
    decl.parent.flags & ts.NodeFlags.Const
      ? decl.initializer
      : undefined;
  return (
    init !== undefined &&
    ts.isCallExpression(init) &&
    ts.isPropertyAccessExpression(init.expression) &&
    init.expression.name.text === "freeze" &&
    isDefaultLibraryCall(init) &&
    elementsAreImmutable(checker.getTypeOfSymbol(symbol))
  );
};

/**
 * A read of a mutable value that holds no reference to it afterwards — a
 * comparison, a coercion to text, a condition, a discarded expression, an
 * export (whose importers' references are followed directly), a `for…in`
 * (its keys are strings), or a spread into an array whose elements are
 * immutable.
 * @param {import("typescript").Node} node @param {import("typescript").Node} parent
 */
function isConsumedInPlace(node, parent) {
  if (
    ts.isExpressionStatement(parent) ||
    ts.isTypeOfExpression(parent) ||
    ts.isVoidExpression(parent) ||
    ts.isPrefixUnaryExpression(parent) ||
    ts.isImportSpecifier(parent) ||
    ts.isExportSpecifier(parent) ||
    ts.isExportAssignment(parent)
  )
    return true;
  // A tagged template hands its holes to the tag uncoerced.
  if (ts.isTemplateSpan(parent))
    return !ts.isTaggedTemplateExpression(parent.parent.parent);
  if (ts.isBinaryExpression(parent)) {
    const op = parent.operatorToken.kind;
    return !(
      isAssignmentOperator(op) ||
      [
        ts.SyntaxKind.QuestionQuestionToken,
        ts.SyntaxKind.BarBarToken,
        ts.SyntaxKind.AmpersandAmpersandToken,
        ts.SyntaxKind.CommaToken,
      ].includes(op)
    );
  }
  if (
    (ts.isIfStatement(parent) ||
      ts.isWhileStatement(parent) ||
      ts.isDoStatement(parent)) &&
    parent.expression === node
  )
    return true;
  if (ts.isConditionalExpression(parent) && parent.condition === node)
    return true;
  if (ts.isForInStatement(parent)) return parent.expression === node;
  return (
    ts.isSpreadElement(parent) &&
    ts.isArrayLiteralExpression(parent.parent) &&
    elementsAreImmutable(checker.getTypeAtLocation(node))
  );
}

/** @param {import("typescript").Type} type */
const elementsAreImmutable = (type) => {
  const args =
    type.flags & ts.TypeFlags.Object &&
    /** @type {import("typescript").ObjectType} */ (type).objectFlags &
      ts.ObjectFlags.Reference
      ? checker.getTypeArguments(
          /** @type {import("typescript").TypeReference} */ (type),
        )
      : null;
  return args !== null && args.length > 0 && args.every(isImmutableValue);
};

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
/** @type {{node: import("typescript").NewExpression, mod: ModuleInfo, direct: boolean}[]} */
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
    } else if (
      isRegExpConstruction(node) ||
      isIndirectRegExpConstruction(node)
    ) {
      pending.push({
        node: /** @type {import("typescript").NewExpression} */ (node),
        mod,
        direct: isRegExpConstruction(node),
      });
    }
    ts.forEachChild(node, visit);
  };
  visit(mod.sf);
}

for (const { node, mod, direct } of pending) {
  // An indirect site's arguments are not (pattern, flags), so it never resolves.
  const value = direct ? await evaluateConstruction(node, mod) : null;
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
