/**
 * Every BLOCKING outcome the shipped hook code can produce, read off acorn's
 * AST and partitioned into a named allowlist, so a new blocking outcome on a
 * fault path is a red build. The plugin is fail-OPEN: no sanitizer FAULT may
 * block, deny, ask, suppress or exit 2 unless AGENT_SANITIZER_FAIL_OPEN=0.
 * Each allowlist entry names exactly one of three legitimate reasons:
 *
 *   - CONTENT: a working sanitizer found something in the content. A relay
 *     that only forwards a verdict upward is CONTENT; its origin is classified.
 *   - CLOSED: reachable only through hookFaultOutcome's closed branch — a
 *     policy's `closed:` arm, a knob-blind failClosed* helper, or a rendering
 *     of a hookFaultOutcome result whose open arm never blocks.
 *   - RELEASABLE: the refuse-once-then-reissue path; RELEASABLE_PROOFS names
 *     the tests proving it cannot loop.
 *
 * Helpers are followed: a function whose return carries a blocking value is a
 * blocking helper, and each call to it is a site. A FaultOutcome slot's relay
 * (`process.exitCode = writeFaultOutcome(o)`) is not a site; its origin in the
 * policy arm is. `ruleViolations` binds each category to lexical position.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, posix } from "node:path";
import { parse } from "acorn";
import { fullAncestor } from "acorn-walk";
import { repoRoot } from "./helpers/repo-root.mjs";
import {
  shippedSources,
  SRC_SCOPE,
  VENDOR_SCOPE,
} from "../scripts/shipped-sources.mjs";

/** The three reasons a blocking site may exist. */
const Category = Object.freeze({
  CONTENT: "content verdict",
  CLOSED: "closed arm",
  RELEASABLE: "releasable refusal",
});
const { CONTENT, CLOSED, RELEASABLE } = Category;

/**
 * The shipped hook code: every published `claude-hooks/` module plus the
 * library under `src/` the hooks call into. Vendored third-party code is
 * excluded — it produces no hook outcome and is not this repo's to classify.
 */
const SCANNED = shippedSources(repoRoot).filter(
  (file) =>
    file.startsWith("claude-hooks/") ||
    (file.startsWith(SRC_SCOPE) && !file.startsWith(VENDOR_SCOPE)),
);

const PACKAGE = JSON.parse(
  readFileSync(join(repoRoot, "package.json"), "utf8"),
);

/**
 * The two primitives the scan keys on by identity rather than by shape: the
 * output withholder (a call to it IS a suppression) and the posture resolver
 * (a value derived from its result renders a registered policy's verdict).
 */
const SUPPRESSOR = { file: "src/output.mjs", name: "suppressToolOutput" };
const POSTURE = {
  file: "claude-hooks/lib/hook-fault.mjs",
  name: "hookFaultOutcome",
};

/** Members of a decision table that block: `PermissionDecision.DENY` etc. */
const BLOCKING_MEMBERS = new Set(["DENY", "ASK", "BLOCK"]);
/** The decision-table objects those members are read off. */
const DECISION_TABLES = new Set(["PermissionDecision", "Decision"]);
/** Literal spellings of a blocking decision. */
const BLOCKING_LITERALS = new Set(["deny", "ask", "block"]);
/** Keys whose value IS a verdict, judged by `blockingDecisionValue`. */
const DECISION_KEYS = new Set(["permissionDecision", "decision"]);
/** The sibling key that carries a decision's reason. */
const REASON_KEYS = new Set(["permissionDecisionReason", "reason"]);
/**
 * Keys of the internal stage-verdict shapes (`{ deny }`, `{ ask }`) the
 * PreToolUse hook renders as a permissionDecision; any value blocks.
 */
const VERDICT_KEYS = new Set(["deny", "ask"]);
/** A withheld value's placeholder text opens like this. */
const WITHHELD_TEXT = /^\[[^\]]*withheld/iu;
/** A knob-blind fail-closed helper's name. */
const FAIL_CLOSED_HELPER = /^(?:emit)?failClosed/iu;
/** The two arms of a registered fault policy, as `functionPath` names them. */
const OPEN_ARM = "registerFaultPolicy:open";
const CLOSED_ARM = "registerFaultPolicy:closed";

// ── AST helpers ─────────────────────────────────────────────────────────────

/** @param {any} node @returns {boolean} */
const isFunction = (node) =>
  node.type === "FunctionDeclaration" ||
  node.type === "FunctionExpression" ||
  node.type === "ArrowFunctionExpression";

/** @param {any} key @returns {string | undefined} */
const keyName = (key) =>
  key.type === "Identifier"
    ? key.name
    : typeof key.value === "string"
      ? key.value
      : undefined;

/** The callee's own name: `f` for `f()`, `g` for `a.b.g()`. */
const calleeName = (/** @type {any} */ callee) =>
  callee.type === "Identifier"
    ? callee.name
    : callee.type === "MemberExpression" && !callee.computed
      ? callee.property.name
      : "<computed>";

/**
 * The cooked text of a string or template literal, or undefined.
 * @param {any} node
 * @returns {string | undefined}
 */
const literalText = (node) =>
  node?.type === "Literal" && typeof node.value === "string"
    ? node.value
    : node?.type === "TemplateLiteral"
      ? node.quasis.map((/** @type {any} */ q) => q.value.cooked).join("…")
      : undefined;

/**
 * Whether `node` evaluates to a blocking decision on some branch.
 * @param {any} node
 * @returns {boolean}
 */
function blockingDecisionValue(node) {
  if (node.type === "Literal") return BLOCKING_LITERALS.has(node.value);
  if (node.type === "ConditionalExpression")
    return (
      blockingDecisionValue(node.consequent) ||
      blockingDecisionValue(node.alternate)
    );
  if (node.type === "LogicalExpression")
    return (
      blockingDecisionValue(node.left) || blockingDecisionValue(node.right)
    );
  if (node.type !== "MemberExpression" || node.computed) return false;
  if (!BLOCKING_MEMBERS.has(node.property.name)) return false;
  const table = node.object;
  return (
    (table.type === "Identifier" && DECISION_TABLES.has(table.name)) ||
    (table.type === "MemberExpression" &&
      !table.computed &&
      DECISION_TABLES.has(table.property.name))
  );
}

/** Whether `node` evaluates to the literal `value` on some branch. */
const literalOn = (/** @type {any} */ node, /** @type {unknown} */ value) =>
  node.type === "Literal"
    ? node.value === value
    : node.type === "ConditionalExpression" &&
      (literalOn(node.consequent, value) || literalOn(node.alternate, value));

/**
 * The blocking kind a `key: value` pair (an object property or a member
 * assignment) produces, or null.
 * @param {string | undefined} key
 * @param {any} value
 * @param {(node: any) => string} text
 * @returns {string | null}
 */
function pairKind(key, value, text) {
  if (key === undefined) return null;
  if (DECISION_KEYS.has(key) && blockingDecisionValue(value))
    return `${key}=${text(value)}`;
  if (key === "updatedToolOutput") return "updatedToolOutput";
  if (key === "exitCode" && literalOn(value, 2)) return "exitCode=2";
  if (key === "armAlert" && literalOn(value, true)) return "armAlert=true";
  return null;
}

/** The immediate child nodes of `node`. @param {any} node @returns {any[]} */
function children(node) {
  const out = [];
  for (const [field, value] of Object.entries(node)) {
    if (field === "type") continue;
    for (const child of Array.isArray(value) ? value : [value])
      if (child !== null && typeof child?.type === "string") out.push(child);
  }
  return out;
}

/**
 * Whether an Identifier under `parent` reads a binding, as opposed to naming a
 * property or declaring one.
 * @param {any} parent
 * @param {any} node
 * @returns {boolean}
 */
function isRead(parent, node) {
  if (parent === undefined) return true;
  if (parent.type === "MemberExpression")
    return parent.object === node || parent.computed;
  if (parent.type === "Property") return parent.value === node;
  return ![
    "ImportSpecifier",
    "ImportDefaultSpecifier",
    "ExportSpecifier",
    "VariableDeclarator",
    "FunctionDeclaration",
    "LabeledStatement",
  ].includes(parent.type);
}

/** The names a binding pattern introduces. @param {any} pattern @returns {string[]} */
function patternNames(pattern) {
  if (pattern.type === "Identifier") return [pattern.name];
  if (pattern.type === "ObjectPattern")
    return pattern.properties.flatMap((/** @type {any} */ prop) =>
      patternNames(prop.type === "RestElement" ? prop.argument : prop.value),
    );
  if (pattern.type === "ArrayPattern")
    return pattern.elements.filter(Boolean).flatMap(patternNames);
  if (pattern.type === "AssignmentPattern") return patternNames(pattern.left);
  if (pattern.type === "RestElement") return patternNames(pattern.argument);
  if (pattern.type !== "MemberExpression") return [];
  let root = pattern;
  while (root.type === "MemberExpression") root = root.object;
  return root.type === "Identifier" ? [root.name] : [];
}

/**
 * The name a function node is known by, from where it sits: its own id, the
 * binding or default it initializes, `callee:key` for a property of an object
 * passed straight to a call (`registerFaultPolicy:closed`), `key[name]` for a
 * property of an object carrying a `name: "…"` tag (a stage table entry), and
 * `callee(arg N)` for a bare callback.
 * @param {any[]} ancestors
 * @param {number} i  the function's index in `ancestors`
 * @param {(node: any) => string} text
 * @returns {string}
 */
function ownName(ancestors, i, text) {
  const fn = ancestors[i];
  const parent = ancestors[i - 1];
  if (fn.id) return fn.id.name;
  if (parent?.type === "VariableDeclarator") return text(parent.id);
  if (parent?.type === "AssignmentPattern") return text(parent.left);
  if (parent?.type === "AssignmentExpression") return text(parent.left);
  if (parent?.type === "Property" || parent?.type === "MethodDefinition") {
    const key = keyName(parent.key) ?? "<computed>";
    const object = ancestors[i - 2];
    const holder = ancestors[i - 3];
    if (holder?.type === "CallExpression" && holder.arguments.includes(object))
      return `${calleeName(holder.callee)}:${key}`;
    const tag = object?.properties?.find(
      (/** @type {any} */ p) =>
        p.type === "Property" &&
        keyName(p.key) === "name" &&
        typeof p.value.value === "string",
    );
    return tag === undefined ? key : `${key}[${tag.value.value}]`;
  }
  if (parent?.type === "CallExpression")
    return `${calleeName(parent.callee)}(arg ${parent.arguments.indexOf(fn)})`;
  return "<anonymous>";
}

/** Outer-to-inner names of the functions in `ancestors`, `>`-joined. */
function functionPath(/** @type {any[]} */ ancestors, text) {
  const names = [];
  for (let i = 0; i < ancestors.length; i++)
    if (isFunction(ancestors[i])) names.push(ownName(ancestors, i, text));
  return names.length === 0 ? "<module>" : names.join(">");
}

/**
 * A short, AST-derived label for a value: the opening words of a string or
 * template literal (or of a `+` chain that starts with one), else its source
 * text, whitespace-collapsed and cut to five words. Used only to tell apart
 * two sites that would otherwise share a key.
 * @param {any} node
 * @param {(node: any) => string} text
 * @returns {string}
 */
function summary(node, text) {
  if (node.type === "BinaryExpression" && node.operator === "+")
    return summary(node.left, text);
  const literal = literalText(node);
  const words = (literal ?? text(node)).split(/\s+/u).filter(Boolean);
  const head = `${words.slice(0, 5).join(" ")}${words.length > 5 ? "…" : ""}`;
  return literal === undefined ? head : `"${head}"`;
}

/**
 * Resolve a module specifier to a repo path, or null for a module outside the
 * tree (node builtins, third-party packages). The package's own subpaths
 * resolve through its `exports` map, which is how the hooks reach `src/`.
 * @param {string} from
 * @param {string} spec
 * @returns {string | null}
 */
function resolveSpecifier(from, spec) {
  if (spec.startsWith("."))
    return posix.normalize(posix.join(posix.dirname(from), spec));
  if (spec !== PACKAGE.name && !spec.startsWith(`${PACKAGE.name}/`))
    return null;
  const subpath =
    spec === PACKAGE.name ? "." : `.${spec.slice(PACKAGE.name.length)}`;
  const target = PACKAGE.exports[subpath];
  const file = typeof target === "string" ? target : target?.default;
  return typeof file === "string" ? posix.normalize(file) : null;
}

/** The specifier of the `await lazyImport("spec")` an `init` reads, or null. */
function lazyImportSpec(/** @type {any} */ init) {
  const call = init?.type === "AwaitExpression" ? init.argument : init;
  return call?.type === "CallExpression" &&
    call.callee.type === "Identifier" &&
    call.callee.name === "lazyImport" &&
    call.arguments[0]?.type === "Literal"
    ? String(call.arguments[0].value)
    : null;
}

// ── Module index ────────────────────────────────────────────────────────────

/**
 * @typedef {{ node: any, returns: any[], bindings: any[] }} FunctionInfo
 * @typedef {{
 *   file: string,
 *   ast: any,
 *   text: (node: any) => string,
 *   scopes: Map<any, Map<string, any>>,
 *   imports: Map<string, { file: string, name: string }>,
 *   exports: Map<string, { local: string } | { file: string, name: string }>,
 *   stars: string[],
 *   markers: Set<string>,
 *   functions: Map<any, FunctionInfo>,
 *   labels: Map<any, string>,
 * }} ModuleInfo
 */

/**
 * Parse one module and index what the scan needs: the function bindings of
 * each scope (declarations, function-valued initializers, and injectable
 * parameter defaults), imports (static and lazyImport-destructured), exports,
 * the module-level withheld-placeholder constants, and each function's
 * returns and local bindings.
 * @param {string} root
 * @param {string} file
 * @returns {ModuleInfo}
 */
function indexModule(root, file) {
  const source = readFileSync(join(root, file), "utf8");
  const ast = parse(source, { ecmaVersion: "latest", sourceType: "module" });
  /** @type {ModuleInfo} */
  const mod = {
    file,
    ast,
    text: (node) => source.slice(node.start, node.end),
    scopes: new Map(),
    imports: new Map(),
    exports: new Map(),
    stars: [],
    markers: new Set(),
    functions: new Map(),
    labels: new Map(),
  };
  // acorn-walk calls back in POST-order, so a function's returns are seen
  // before the function itself: its record is created on first touch.
  const infoOf = (/** @type {any} */ fn) => {
    let info = mod.functions.get(fn);
    if (info === undefined) {
      info = { node: fn, returns: [], bindings: [] };
      mod.functions.set(fn, info);
    }
    return info;
  };
  const declare = (/** @type {any} */ scope, name, binding) => {
    if (!mod.scopes.has(scope)) mod.scopes.set(scope, new Map());
    mod.scopes.get(scope)?.set(name, binding);
  };
  // `const ns = await lazyImport("spec")`, destructured later from `ns`.
  /** @type {Map<string, string>} */
  const lazyNamespaces = new Map();
  const bindLazy = (/** @type {any} */ pattern, /** @type {any} */ init) => {
    const spec = lazyImportSpec(init);
    const target =
      spec !== null
        ? resolveSpecifier(file, spec)
        : init?.type === "Identifier"
          ? lazyNamespaces.get(init.name)
          : undefined;
    if (target === undefined || target === null) return;
    if (pattern.type === "Identifier") lazyNamespaces.set(pattern.name, target);
    if (pattern.type !== "ObjectPattern") return;
    for (const prop of pattern.properties)
      if (prop.type === "Property" && prop.value.type === "Identifier")
        mod.imports.set(prop.value.name, {
          file: target,
          name: keyName(prop.key) ?? "",
        });
  };

  fullAncestor(ast, (node, _state, ancestors) => {
    // acorn-walk hands the visited node over as the last ancestor.
    const enclosing = ancestors
      .slice(0, -1)
      .findLast((a) => isFunction(a) || a === ast);
    const fn = enclosing === ast ? undefined : enclosing;
    if (isFunction(node)) {
      mod.labels.set(node, functionPath(ancestors, mod.text));
      const info = infoOf(node);
      if (node.type === "ArrowFunctionExpression" && node.expression)
        info.returns.push(node.body);
      if (node.type === "FunctionDeclaration")
        declare(enclosing, node.id.name, node);
    }
    if (node.type === "ReturnStatement" && node.argument && fn)
      infoOf(fn).returns.push(node.argument);
    if (node.type === "VariableDeclarator") {
      if (fn) infoOf(fn).bindings.push(node);
      bindLazy(node.id, node.init);
      if (node.id.type === "Identifier" && node.init && isFunction(node.init))
        declare(enclosing, node.id.name, node.init);
      if (
        fn === undefined &&
        node.id.type === "Identifier" &&
        WITHHELD_TEXT.test(literalText(node.init) ?? "")
      )
        mod.markers.add(node.id.name);
    }
    if (node.type === "AssignmentExpression") {
      if (fn) infoOf(fn).bindings.push(node);
      bindLazy(node.left, node.right);
    }
    // An injectable default (`guard = secretDropGuard`, `emit = (f) => …`)
    // names the helper the parameter calls when no test overrides it.
    if (node.type === "AssignmentPattern" && node.left.type === "Identifier") {
      if (isFunction(node.right))
        declare(enclosing, node.left.name, node.right);
      if (node.right.type === "Identifier")
        declare(enclosing, node.left.name, {
          alias: node.right.name,
          ancestors: ancestors.slice(0, -1),
        });
    }
  });

  for (const stmt of ast.body) indexModuleStatement(mod, stmt);
  return mod;
}

/**
 * Record one top-level import/export statement in `mod`'s binding tables.
 * @param {ModuleInfo} mod
 * @param {any} stmt
 */
function indexModuleStatement(mod, stmt) {
  const from =
    stmt.source?.type === "Literal"
      ? resolveSpecifier(mod.file, String(stmt.source.value))
      : null;
  if (stmt.type === "ImportDeclaration" && from !== null)
    for (const spec of stmt.specifiers)
      if (spec.type !== "ImportNamespaceSpecifier")
        mod.imports.set(spec.local.name, {
          file: from,
          name:
            spec.type === "ImportDefaultSpecifier"
              ? "default"
              : (keyName(spec.imported) ?? ""),
        });
  if (stmt.type === "ExportAllDeclaration" && !stmt.exported && from !== null)
    mod.stars.push(from);
  if (stmt.type !== "ExportNamedDeclaration") return;
  const decl = stmt.declaration;
  if (decl?.type === "FunctionDeclaration")
    mod.exports.set(decl.id.name, { local: decl.id.name });
  if (decl?.type === "VariableDeclaration")
    for (const name of decl.declarations.flatMap((/** @type {any} */ d) =>
      patternNames(d.id),
    ))
      mod.exports.set(name, { local: name });
  for (const spec of stmt.specifiers) {
    const exported = keyName(spec.exported) ?? "";
    const local = keyName(spec.local) ?? "";
    if (stmt.source === null) mod.exports.set(exported, { local });
    else if (from !== null)
      mod.exports.set(exported, { file: from, name: local });
  }
}

/**
 * Follow `file`'s export `name` — through re-exports, and through a local
 * that is itself an import (`export const { x } = ns`) — to the module and
 * local name that define it, or undefined when it leaves the scanned tree.
 * @param {Map<string, ModuleInfo>} modules
 * @param {string} file
 * @param {string} name
 * @param {Set<string>} [seen]
 * @returns {{ mod: ModuleInfo, local: string } | undefined}
 */
function resolveExport(modules, file, name, seen = new Set()) {
  const mod = modules.get(file);
  if (mod === undefined || seen.has(`${file}#${name}`)) return undefined;
  seen.add(`${file}#${name}`);
  const entry = mod.exports.get(name);
  if (entry === undefined) {
    for (const star of mod.stars) {
      const found = resolveExport(modules, star, name, seen);
      if (found !== undefined) return found;
    }
    return undefined;
  }
  if (!("local" in entry))
    return resolveExport(modules, entry.file, entry.name, seen);
  const imported = mod.imports.get(entry.local);
  return imported === undefined
    ? { mod, local: entry.local }
    : resolveExport(modules, imported.file, imported.name, seen);
}

/**
 * Where an Identifier read at `ancestors` is bound: a function declared in an
 * enclosing scope (following parameter-default aliases), else the module and
 * local name that define it — this module's own, or an import's origin.
 * @param {Map<string, ModuleInfo>} modules
 * @param {ModuleInfo} mod
 * @param {string} name
 * @param {any[]} ancestors
 * @returns {{ fn?: any, mod?: ModuleInfo, local?: string }}
 */
function resolveName(modules, mod, name, ancestors) {
  for (let i = ancestors.length - 2; i >= 0; i--) {
    const bound = mod.scopes.get(ancestors[i])?.get(name);
    if (bound === undefined) continue;
    if (bound.alias === undefined) return { fn: bound };
    if (bound.alias !== name)
      return resolveName(modules, mod, bound.alias, bound.ancestors);
  }
  const imported = mod.imports.get(name);
  if (imported === undefined) return { mod, local: name };
  const origin = resolveExport(modules, imported.file, imported.name);
  if (origin === undefined) return {};
  return {
    fn: origin.mod.scopes.get(origin.mod.ast)?.get(origin.local),
    ...origin,
  };
}

// ── The scan ────────────────────────────────────────────────────────────────

/**
 * @typedef {{
 *   key: string,
 *   file: string,
 *   line: number,
 *   kind: string,
 *   path: string,
 *   node: any,
 *   ancestors: any[],
 *   inCatch: boolean,
 *   inOpenArm: boolean,
 *   inClosedArm: boolean,
 *   rendersPosture: boolean,
 *   detail: string,
 * }} Site
 */

/**
 * Whether `expr` — not descending into nested functions — contains a node
 * `seeded` accepts or reads one of `tainted`.
 * @param {any} expr
 * @param {(node: any) => boolean} seeded
 * @param {Set<string>} tainted
 * @returns {boolean}
 */
function reaches(expr, seeded, tainted) {
  const stack = [{ node: expr, parent: undefined }];
  while (stack.length > 0) {
    const { node, parent } = /** @type {{ node: any, parent: any }} */ (
      stack.pop()
    );
    if (seeded(node)) return true;
    if (
      node.type === "Identifier" &&
      tainted.has(node.name) &&
      isRead(parent, node)
    )
      return true;
    if (isFunction(node)) continue;
    for (const child of children(node))
      stack.push({ node: child, parent: node });
  }
  return false;
}

/**
 * Locals of `fn` bound, to a fixed point, from an expression `seeded`
 * accepts — directly, or through another such local.
 * @param {FunctionInfo} fn
 * @param {(node: any) => boolean} seeded
 * @returns {Set<string>}
 */
function taintedLocals(fn, seeded) {
  /** @type {Set<string>} */
  const tainted = new Set();
  for (let grew = true; grew;) {
    grew = false;
    for (const binding of fn.bindings) {
      const declarator = binding.type === "VariableDeclarator";
      const from = declarator ? binding.init : binding.right;
      const into = declarator ? binding.id : binding.left;
      if (from === null) continue;
      if (!seeded(binding) && !reaches(from, seeded, tainted)) continue;
      for (const name of patternNames(into))
        if (!tainted.has(name)) {
          tainted.add(name);
          grew = true;
        }
    }
  }
  return tainted;
}

/**
 * Scan `files` under `root` and return every blocking site, keyed and sorted.
 * @param {string} root
 * @param {string[]} files  repo-relative POSIX paths
 * @returns {Site[]}
 */
function scanBlockingSites(root, files) {
  /** @type {Map<string, ModuleInfo>} */
  const modules = new Map(files.map((file) => [file, indexModule(root, file)]));
  const primitive = (/** @type {{ file: string, name: string }} */ ref) => {
    const origin = resolveExport(modules, ref.file, ref.name);
    return origin?.mod.scopes.get(origin.mod.ast)?.get(origin.local);
  };
  const suppressor = primitive(SUPPRESSOR);
  const posture = primitive(POSTURE);

  /** @typedef {{ mod: ModuleInfo, node: any, ancestors: any[] }} Hit */
  /** @type {Array<Hit & { kind: string }>} */
  const direct = [];
  /** @type {Array<Hit & { target: any }>} */
  const calls = [];
  for (const mod of modules.values())
    fullAncestor(mod.ast, (node, _state, ancestors) => {
      const at = { mod, node, ancestors: [...ancestors] };
      if (node.type === "CallExpression" && node.callee.type === "Identifier") {
        const { fn } = resolveName(modules, mod, node.callee.name, ancestors);
        if (fn !== undefined) calls.push({ ...at, target: fn });
        if (fn !== undefined && fn === suppressor)
          direct.push({ ...at, kind: `${node.callee.name}()` });
      }
      const kind = directKind(modules, mod, node, ancestors);
      if (kind !== null) direct.push({ ...at, kind });
    });

  const directNodes = new Set(direct.map((hit) => hit.node));
  const targets = new Map(calls.map((call) => [call.node, call.target]));
  const infos = [...modules.values()].flatMap((mod) => [
    ...mod.functions.values(),
  ]);
  /** @type {Set<any>} */
  const helpers = new Set();
  const blocking = (/** @type {any} */ node) =>
    directNodes.has(node) ||
    (node.type === "CallExpression" && helpers.has(targets.get(node)));
  for (let grew = true; grew;) {
    grew = false;
    for (const fn of infos) {
      if (helpers.has(fn.node)) continue;
      const tainted = taintedLocals(fn, blocking);
      if (!fn.returns.some((expr) => reaches(expr, blocking, tainted)))
        continue;
      helpers.add(fn.node);
      grew = true;
    }
  }
  const fromPosture = (/** @type {any} */ node) =>
    posture !== undefined &&
    node.type === "CallExpression" &&
    targets.get(node) === posture;

  /** @returns {Site} */
  const toSite = (/** @type {Hit} */ { mod, node, ancestors }, kind) => {
    const names = ancestors
      .filter(isFunction)
      .flatMap((fn) => (mod.labels.get(fn) ?? "").split(">"));
    const fn = mod.functions.get(ancestors.findLast(isFunction));
    const path = functionPath(ancestors, mod.text);
    return {
      key: `${mod.file}#${path} ${kind}`,
      file: mod.file,
      line: mod.text({ start: 0, end: node.start }).split("\n").length,
      kind,
      path,
      node,
      ancestors,
      inCatch: ancestors.some((a) => a.type === "CatchClause"),
      inOpenArm: names.includes(OPEN_ARM),
      inClosedArm: names.includes(CLOSED_ARM),
      rendersPosture:
        fn !== undefined &&
        reaches(node, fromPosture, taintedLocals(fn, fromPosture)),
      detail: siteDetail(mod, node, ancestors),
    };
  };
  const labelOf = (/** @type {ModuleInfo} */ from, /** @type {any} */ fn) => {
    for (const mod of modules.values())
      if (mod.labels.has(fn))
        return mod === from
          ? mod.labels.get(fn)
          : `${mod.file}#${mod.labels.get(fn)}`;
    throw new Error("a blocking helper resolved to a function no module owns");
  };
  return disambiguate([
    ...direct.map((hit) => toSite(hit, hit.kind)),
    ...calls
      .filter((call) => helpers.has(call.target))
      .map((call) => toSite(call, `calls ${labelOf(call.mod, call.target)}`)),
  ]);
}

/**
 * The blocking kind `node` itself produces, or null: a blocking decision
 * pair, a stage-verdict object, an exit 2, an armed alert, or a withheld
 * placeholder put in a value's place.
 * @param {Map<string, ModuleInfo>} modules
 * @param {ModuleInfo} mod
 * @param {any} node
 * @param {any[]} ancestors
 * @returns {string | null}
 */
function directKind(modules, mod, node, ancestors) {
  const parent = ancestors.at(-2);
  if (node.type === "Property" && parent?.type === "ObjectExpression") {
    const key = node.computed ? undefined : keyName(node.key);
    if (key === undefined || !VERDICT_KEYS.has(key))
      return pairKind(key, node.value, mod.text);
    const faulted = parent.properties.some(
      (/** @type {any} */ p) =>
        p.type === "Property" && keyName(p.key) === "fault",
    );
    return faulted ? `{${key},fault}` : `{${key}}`;
  }
  if (
    node.type === "AssignmentExpression" &&
    node.left.type === "MemberExpression" &&
    !node.left.computed
  ) {
    const kind = pairKind(node.left.property.name, node.right, mod.text);
    return kind === null ? null : `${mod.text(node.left.object)}.${kind}`;
  }
  if (
    node.type === "CallExpression" &&
    mod.text(node.callee) === "process.exit" &&
    node.arguments.some((/** @type {any} */ arg) => literalOn(arg, 2))
  )
    return "process.exit(2)";
  if (node.type !== "Identifier" || !isMarkerSlot(parent, node)) return null;
  const bound = resolveName(modules, mod, node.name, ancestors);
  return bound.mod?.markers.has(bound.local ?? "")
    ? `withheld=${bound.local}`
    : null;
}

/**
 * Whether an Identifier sits where its value becomes the OUTPUT — a property
 * value, a return, an initializer or assignment, a branch of either, or an
 * argument to a local helper — rather than where it is only compared or
 * searched for (`x === C`, `text.includes(C)`).
 * @param {any} parent
 * @param {any} node
 * @returns {boolean}
 */
function isMarkerSlot(parent, node) {
  if (parent === undefined || !isRead(parent, node)) return false;
  if (parent.type === "CallExpression")
    return parent.callee.type === "Identifier" && parent.callee !== node;
  return [
    "Property",
    "ReturnStatement",
    "ArrowFunctionExpression",
    "VariableDeclarator",
    "AssignmentExpression",
    "ConditionalExpression",
  ].includes(parent.type);
}

/**
 * What tells a site apart from a same-kind sibling in the same function: its
 * catch position, then the verdict's value or reason (or, for a withheld
 * placeholder, the expression it is placed by).
 * @param {ModuleInfo} mod
 * @param {any} node
 * @param {any[]} ancestors
 * @returns {string}
 */
function siteDetail(mod, node, ancestors) {
  const parent = ancestors.at(-2);
  /** @type {any} */
  let shown;
  if (node.type === "Property" && VERDICT_KEYS.has(keyName(node.key) ?? ""))
    shown = node.value;
  else if (node.type === "Property" || node.type === "AssignmentExpression")
    shown = parent?.properties?.find(
      (/** @type {any} */ p) =>
        p.type === "Property" && REASON_KEYS.has(keyName(p.key) ?? ""),
    )?.value;
  else if (node.type === "Identifier") shown = parent;
  return [
    ancestors.some((a) => a.type === "CatchClause") ? "catch" : "",
    shown === undefined ? "" : summary(shown, mod.text),
  ]
    .filter(Boolean)
    .join(" ");
}

/**
 * Give every site a unique key: a key two sites share gains each one's
 * `detail`, and any still shared gains its source-order ordinal.
 * @param {Site[]} sites
 * @returns {Site[]}
 */
function disambiguate(sites) {
  for (const group of Map.groupBy(sites, (s) => s.key).values()) {
    if (group.length === 1) continue;
    for (const [detail, same] of Map.groupBy(group, (s) => s.detail)) {
      same.sort((a, b) => a.node.start - b.node.start);
      same.forEach((s, i) => {
        const tag = detail === "" ? "" : ` <${detail}>`;
        s.key = `${s.key}${tag}${same.length > 1 ? ` #${i + 1}` : ""}`;
      });
    }
  }
  // Code-unit order, not localeCompare: the keys must sort the same on every
  // machine, whatever its locale.
  return sites.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

// ── The rules ───────────────────────────────────────────────────────────────

/**
 * Every way a classified site contradicts where it sits, as `rule: key`:
 *
 *   - catch: a catch clause is a fault path, so it may hold CLOSED and
 *     RELEASABLE sites but never a CONTENT one.
 *   - open-arm: a policy's `open:` arm may hold only RELEASABLE sites.
 *   - content-placement: a CONTENT site may not sit in a closed arm.
 *   - closed-placement: a CLOSED site sits in a closed arm or a failClosed*
 *     helper, or renders a hookFaultOutcome result.
 *   - releasable-placement: a RELEASABLE site is inside releasableRefusal or
 *     an open arm, is a fault-tagged `{deny, fault}`, or renders a
 *     hookFaultOutcome result.
 *   - fault-tag: a fault-tagged `{deny, fault}` is RELEASABLE — the posture,
 *     not the site, decides whether it stands.
 *   - fault-branch: a branch that returns a fault-tagged deny holds no
 *     untagged CONTENT one, which no posture could ever release.
 * @param {Site[]} sites
 * @param {(site: Site) => string | undefined} categoryOf  undefined skips
 * @returns {string[]}
 */
function ruleViolations(sites, categoryOf) {
  const out = new Set();
  for (const site of sites) {
    const category = categoryOf(site);
    if (category === undefined) continue;
    const segments = site.path.split(">");
    const tagged = site.kind.endsWith(",fault}");
    const flag = (/** @type {string} */ rule) =>
      out.add(`${rule}: ${site.key}`);
    if (site.inCatch && category === CONTENT) flag("catch");
    if (site.inOpenArm && category !== RELEASABLE) flag("open-arm");
    if (category === CONTENT && site.inClosedArm) flag("content-placement");
    if (
      category === CLOSED &&
      !site.inClosedArm &&
      !site.rendersPosture &&
      !segments.some((name) => FAIL_CLOSED_HELPER.test(name))
    )
      flag("closed-placement");
    if (
      category === RELEASABLE &&
      !segments.includes("releasableRefusal") &&
      !site.inOpenArm &&
      !tagged &&
      !site.rendersPosture
    )
      flag("releasable-placement");
    if (tagged && category !== RELEASABLE) flag("fault-tag");
  }
  for (const tagged of sites.filter((s) => s.kind.endsWith(",fault}"))) {
    const at = tagged.ancestors.findLastIndex(
      (a) => a.type === "BlockStatement",
    );
    if (at < 1 || isFunction(tagged.ancestors[at - 1])) continue;
    const branch = tagged.ancestors[at];
    for (const sibling of sites)
      if (sibling.ancestors.includes(branch) && categoryOf(sibling) === CONTENT)
        out.add(`fault-branch: ${sibling.key}`);
  }
  return [...out].sort();
}

// ── The classification ──────────────────────────────────────────────────────

// Key prefixes, one per scanned module that has sites.
const PIPELINE = "claude-hooks/lib/layer-pipeline.mjs#";
const DROP = "claude-hooks/lib/secret-drop-guard.mjs#";
const DISPATCH = "claude-hooks/plugin-hooks.mjs#";
const PRE = "claude-hooks/pretooluse-sanitize.mjs#";
const POST = "claude-hooks/sanitize-output.mjs#";
const PROMPT = "claude-hooks/sanitize-user-prompt.mjs#";
const SESSION = "claude-hooks/scan-invisible-chars.mjs#";
const LOADED = "claude-hooks/scan-loaded-instructions.mjs#";
const HTML = "src/html.mjs#";
const OUTPUT = "src/output.mjs#";
const REHYDRATE = "src/rehydrate.mjs#";
const VIEW_MAP = "src/view-map.mjs#";

const RELAY = "relay: forwards the verdict of the call it names";

/** `[key, category, reason]` for every legitimate blocking site in the tree. */
const ALLOWLIST = [
  // layer pipeline
  [
    `${PIPELINE}runLayerPipeline calls runLayerPipeline>step #1`,
    CONTENT,
    RELAY,
  ],
  [
    `${PIPELINE}runLayerPipeline calls runLayerPipeline>step #2`,
    CONTENT,
    RELAY,
  ],
  [
    `${PIPELINE}runLayerPipeline>step {deny}`,
    CONTENT,
    "relay: a stage's deny, fault denies already resolved by resolveStageDeny",
  ],
  // secret-drop guard
  [
    `${DROP}secretDropGuard {deny,fault}`,
    RELEASABLE,
    "the drop's confirmation could not be recorded, so the posture decides",
  ],
  [
    `${DROP}secretDropGuard {deny}`,
    CONTENT,
    "the Write drops redacted secrets from the file; its one-shot confirmation releases the identical re-issue",
  ],
  [
    `${DROP}withSecretDropGuard><anonymous> calls secretDropGuard`,
    CONTENT,
    RELAY,
  ],
  // dispatcher
  [
    `${DISPATCH}registerFaultPolicy:closed exitCode=2`,
    CLOSED,
    "an unknown --hook mode blocks only under AGENT_SANITIZER_FAIL_OPEN=0",
  ],
  // PreToolUse
  [
    `${PRE}assembleResponse calls gateVerdict`,
    CONTENT,
    "the instruction-file injection gate's one-time ask",
  ],
  [
    `${PRE}assembleResponse fields.permissionDecision=PermissionDecision.ASK`,
    CONTENT,
    "renders the gate's ask; a fault ask reaches it only from the closed arm",
  ],
  [`${PRE}buildPreToolUseResponse calls assembleResponse`, CONTENT, RELAY],
  [
    `${PRE}buildPreToolUseResponse calls claude-hooks/lib/layer-pipeline.mjs#runLayerPipeline`,
    CONTENT,
    RELAY,
  ],
  [
    `${PRE}buildPreToolUseResponse permissionDecision=PermissionDecision.DENY`,
    CONTENT,
    "renders the stage chain's deny",
  ],
  [
    `${PRE}cliMain>runJudgeCli(arg 1) calls judgePreToolUseSanitize`,
    CONTENT,
    RELAY,
  ],
  [
    `${PRE}failClosedFields permissionDecision=parsedOk ? unavailable : PermissionDecision.DENY`,
    CLOSED,
    "the knob-blind closed verdict, reached from the closed arm",
  ],
  [
    `${PRE}gateVerdict {ask} <gateAsk>`,
    CONTENT,
    "a loaded instruction file carries payload-capable characters, and the ask is recorded as shown",
  ],
  [
    `${PRE}gateVerdict {ask} <String(fields.permissionDecisionReason)>`,
    CLOSED,
    "renders the GATE_ACK fault verdict, an ask only from the closed arm",
  ],
  [
    `${PRE}judgePreToolUseSanitize calls buildPreToolUseResponse`,
    CONTENT,
    RELAY,
  ],
  [
    `${PRE}judgePreToolUseSanitize decision=Decision.DENY`,
    CONTENT,
    "a host gate's verdict on the call; a throwing gate takes the fault posture",
  ],
  [`${PRE}preToolUseLayers>resolveDeny calls resolveStageDeny`, CONTENT, RELAY],
  [
    `${PRE}preToolUseLayers>run[layer2-rehydrate] calls preToolUseLayers>resolveDeny`,
    CONTENT,
    RELAY,
  ],
  [
    `${PRE}preToolUseLayers>run[layer2-rehydrate] calls rehydrateLayer2`,
    CONTENT,
    RELAY,
  ],
  [
    `${PRE}preToolUseLayers>run[rehydrate] calls preToolUseLayers>resolveDeny`,
    CONTENT,
    RELAY,
  ],
  [
    `${PRE}registerFaultPolicy:closed calls failClosedFields`,
    CLOSED,
    "a hook-level fault under =0",
  ],
  [
    `${PRE}registerFaultPolicy:closed permissionDecision=PermissionDecision.ASK`,
    CLOSED,
    "a GATE_ACK fault keeps the gate's ask under =0",
  ],
  [
    `${PRE}registerFaultPolicy:closed permissionDecision=PermissionDecision.DENY <ctx.reason>`,
    CLOSED,
    "a STAGE fault deny stands under =0",
  ],
  [
    `${PRE}registerFaultPolicy:closed permissionDecision=PermissionDecision.DENY <err.reason>`,
    CLOSED,
    "an unclassifiable payload under =0",
  ],
  [
    `${PRE}registerFaultPolicy:open calls failClosedFields`,
    RELEASABLE,
    "only its reason sentence is read, as releasableRefusal's refusal",
  ],
  [
    `${PRE}registerFaultPolicy:open calls releasableRefusal #1`,
    RELEASABLE,
    "a STAGE fault deny",
  ],
  [
    `${PRE}registerFaultPolicy:open calls releasableRefusal #2`,
    RELEASABLE,
    "a hinted write on a hook fault would clobber the secret",
  ],
  [
    `${PRE}rehydrateLayer2 {deny} <"new_source contains a [hidden HTML…">`,
    CONTENT,
    "capability limit: a notebook cannot be rehydrated",
  ],
  [
    `${PRE}rehydrateLayer2 {deny} <"the edits carry [hidden HTML…">`,
    CONTENT,
    "capability limit: MultiEdit's sequential edits cannot be rehydrated",
  ],
  [`${PRE}rehydrateLayer2 calls substituteLayer2`, CONTENT, RELAY],
  [
    `${PRE}releasableRefusal permissionDecision=PermissionDecision.DENY`,
    RELEASABLE,
    "the refusal itself, issued only once its re-issue confirmation is recorded",
  ],
  [
    `${PRE}resolveStageDeny {deny} <result.deny>`,
    CONTENT,
    "an untagged stage deny is the stage's verdict",
  ],
  [
    `${PRE}resolveStageDeny {deny} <String(verdict.permissionDecisionReason)>`,
    RELEASABLE,
    "renders a fault deny's policy verdict: releasableRefusal by default",
  ],
  [
    `${PRE}substituteLayer2 {deny,fault}`,
    RELEASABLE,
    "a Layer-2 placeholder whose stored span is missing",
  ],
  [
    `${PRE}withSecretDropGuard(arg 0) calls src/rehydrate.mjs#rehydrateRedacted`,
    CONTENT,
    RELAY,
  ],
  // PostToolUse
  [
    `${POST}cliMain>runJudgeCli(arg 1) calls judgeSanitizeOutput`,
    CONTENT,
    RELAY,
  ],
  [
    `${POST}emitFailClosed calls failClosedParts`,
    CLOSED,
    "the knob-blind closed emitter a host wires; no hook path calls it",
  ],
  [`${POST}evaluateToolOutput calls sanitizeValue`, CONTENT, RELAY],
  [
    `${POST}failClosedParts calls failClosedReplacement`,
    CLOSED,
    "the shape-matching suppression",
  ],
  [
    `${POST}failClosedParts updatedToolOutput #1`,
    CLOSED,
    "the shallow fallback suppression",
  ],
  [
    `${POST}failClosedParts updatedToolOutput #2`,
    CLOSED,
    "the shape-matching suppression",
  ],
  [
    `${POST}failClosedReplacement suppressToolOutput()`,
    CLOSED,
    "replaces every string leaf with the placeholder",
  ],
  [`${POST}judgeSanitizeOutput calls evaluateToolOutput`, CONTENT, RELAY],
  [
    `${POST}registerFaultPolicy:closed calls failClosedParts`,
    CLOSED,
    "a hook fault suppresses the output only under =0",
  ],
  [
    `${POST}sanitizeValue calls src/output.mjs#sanitizeValueWith`,
    CONTENT,
    RELAY,
  ],
  // UserPromptSubmit
  [
    `${PROMPT}judgeSanitizeUserPrompt decision=Decision.DENY`,
    CONTENT,
    "the prompt carries payload-capable invisible or ANSI characters",
  ],
  [
    `${PROMPT}main>runJudgeCli(arg 1) calls judgeSanitizeUserPrompt`,
    CONTENT,
    RELAY,
  ],
  [
    `${PROMPT}registerFaultPolicy:closed decision="block"`,
    CLOSED,
    "a hook fault blocks the prompt only under =0",
  ],
  // SessionStart / InstructionsLoaded
  [
    `${SESSION}registerFaultPolicy:closed armAlert=true #1`,
    CLOSED,
    "a scanner fault arms the tool-call gate only under =0",
  ],
  [
    `${SESSION}registerFaultPolicy:closed armAlert=true #2`,
    CLOSED,
    "an unreadable instruction file arms the gate only under =0",
  ],
  [
    `${LOADED}registerFaultPolicy:closed armAlert=true`,
    CLOSED,
    "a scanner fault arms the tool-call gate only under =0",
  ],
  // library: Layer 2 and the structured-output walk
  [
    `${HTML}sanitizeHtml withheld=UNPARSEABLE_PLACEHOLDER <text: UNPARSEABLE_PLACEHOLDER>`,
    CONTENT,
    "a document that never settles within MAX_SPLICE_ROUNDS is withheld whole",
  ],
  [
    `${HTML}sanitizeHtml withheld=UNPARSEABLE_PLACEHOLDER <catch text: UNPARSEABLE_PLACEHOLDER>`,
    CONTENT,
    "a parse that throws is a property of the INPUT, which an attacker composes: failing open would turn any parser crash into a Layer-2 bypass",
  ],
  [`${OUTPUT}sanitizeObject calls sanitizeValueAt`, CONTENT, RELAY],
  [
    `${OUTPUT}sanitizeObject withheld=COLLISION_WITHHELD_MESSAGE <defineOwn(out, name.value, COLLISION_WITHHELD_MESSAGE)>`,
    CONTENT,
    "two field names collide after sanitization: the first is withheld",
  ],
  [
    `${OUTPUT}sanitizeObject withheld=COLLISION_WITHHELD_MESSAGE <defineOwn(out, slot(index), COLLISION_WITHHELD_MESSAGE)>`,
    CONTENT,
    "each later colliding field is withheld",
  ],
  [`${OUTPUT}sanitizeValue calls sanitizeValueWith`, CONTENT, RELAY],
  [`${OUTPUT}sanitizeValueAt calls sanitizeValueAt`, CONTENT, RELAY],
  [
    `${OUTPUT}sanitizeValueAt withheld=CYCLE_PLACEHOLDER`,
    CONTENT,
    "a reference cycle in structured output",
  ],
  [
    `${OUTPUT}sanitizeValueAt withheld=DEPTH_PLACEHOLDER`,
    CONTENT,
    "structured output nested past MAX_DEPTH",
  ],
  [`${OUTPUT}sanitizeValueWith calls sanitizeValueAt`, CONTENT, RELAY],
  // library: Layer-4 rehydration
  [
    `${REHYDRATE}anchorAmbiguityDeny {deny}`,
    CONTENT,
    "an edit beside stripped control sequences cannot be re-anchored unambiguously",
  ],
  [
    `${REHYDRATE}multiEditDeny {deny}`,
    CONTENT,
    "capability limit: MultiEdit cannot be re-anchored against a divergent view",
  ],
  [
    `${REHYDRATE}rehydrateEdit {deny} <"old_string contains ……] placeholders but…">`,
    CONTENT,
    "a placeholder-bearing old_string the view does not contain",
  ],
  [
    `${REHYDRATE}rehydrateEdit {deny} <"old_string does not appear in…">`,
    CONTENT,
    "old_string matches inside a hidden secret: the extraction oracle",
  ],
  [
    `${REHYDRATE}rehydrateEdit {deny} <"old_string matches … locations in…">`,
    CONTENT,
    "an ambiguous anchor in the view",
  ],
  [
    `${REHYDRATE}rehydrateEdit {deny} <"old_string starts or ends inside…">`,
    CONTENT,
    "old_string cuts a placeholder",
  ],
  [
    `${REHYDRATE}rehydrateEdit {deny} <"replace_all matched occurrences whose on-disk…">`,
    CONTENT,
    "replace_all spans distinct on-disk bytes",
  ],
  [
    `${REHYDRATE}rehydrateEdit {deny} <"replace_all would rewrite … on-disk…">`,
    CONTENT,
    "replace_all would touch occurrences hidden from the view",
  ],
  [
    `${REHYDRATE}rehydrateEdit {deny} <exposureDeny(exposed)>`,
    CONTENT,
    "the edit would expose a redacted secret",
  ],
  [`${REHYDRATE}rehydrateEdit calls anchorAmbiguityDeny`, CONTENT, RELAY],
  [
    `${REHYDRATE}rehydrateEdit calls src/view-map.mjs#rehydrateNewString #1`,
    CONTENT,
    RELAY,
  ],
  [
    `${REHYDRATE}rehydrateEdit calls src/view-map.mjs#rehydrateNewString #2`,
    CONTENT,
    RELAY,
  ],
  [
    `${REHYDRATE}rehydrateRedacted {deny,fault} <"cannot safely edit …: …;…">`,
    RELEASABLE,
    "the redactor's map failed validation",
  ],
  [
    `${REHYDRATE}rehydrateRedacted {deny,fault} <catch "could not read … to…">`,
    RELEASABLE,
    "the target could not be read to rehydrate it",
  ],
  [
    `${REHYDRATE}rehydrateRedacted {deny} <"cannot resolve redaction placeholders in…">`,
    CONTENT,
    "the file defeats mapping on every call (unmappable)",
  ],
  [
    `${REHYDRATE}rehydrateRedacted {deny} <"new_source contains a ……] placeholder,…">`,
    CONTENT,
    "capability limit: a notebook cannot be rehydrated",
  ],
  [
    `${REHYDRATE}rehydrateRedacted {deny} <catch "… does not exist, so…">`,
    CONTENT,
    "a hinted call creates the file, so its placeholder stands for no secret",
  ],
  [
    `${REHYDRATE}rehydrateRedacted calls multiEditDeny #1`,
    CONTENT,
    "an unmappable file defeats a MultiEdit",
  ],
  [
    `${REHYDRATE}rehydrateRedacted calls multiEditDeny #2`,
    CONTENT,
    "a MultiEdit on a map that fails validation: its escape (single Edits, each releasable) always works, so it never loops",
  ],
  [
    `${REHYDRATE}rehydrateRedacted calls multiEditDeny #3`,
    CONTENT,
    "a MultiEdit on a file whose view diverges from disk",
  ],
  [`${REHYDRATE}rehydrateRedacted calls rehydrateEdit`, CONTENT, RELAY],
  [`${REHYDRATE}rehydrateRedacted calls rehydrateWrite`, CONTENT, RELAY],
  [
    `${REHYDRATE}rehydrateWrite {deny} <"… mixes literal "…" text…">`,
    CONTENT,
    "literal placeholder text shares a placeholder with a secret",
  ],
  [
    `${REHYDRATE}rehydrateWrite {deny} <"multiple distinct secrets in ……">`,
    CONTENT,
    "distinct secrets share one placeholder",
  ],
  [
    `${REHYDRATE}rehydrateWrite {deny} <"the new content still carries…">`,
    CONTENT,
    "a foreign placeholder no secret in the file matches",
  ],
  [
    `${REHYDRATE}rehydrateWrite {deny} <exposureDeny(exposed)>`,
    CONTENT,
    "the write would expose a redacted secret",
  ],
  [`${REHYDRATE}rehydrateWrite calls restoreWriteRegion #1`, CONTENT, RELAY],
  [`${REHYDRATE}rehydrateWrite calls restoreWriteRegion #2`, CONTENT, RELAY],
  [`${REHYDRATE}restoreWriteRegion calls anchorAmbiguityDeny`, CONTENT, RELAY],
  [
    `${VIEW_MAP}rehydrateNewString {deny} <"multiple distinct secrets in the…">`,
    CONTENT,
    "distinct secrets share one placeholder",
  ],
  [
    `${VIEW_MAP}rehydrateNewString {deny} <"new_string contains "…", which stands…">`,
    CONTENT,
    "a foreign placeholder no secret in the file matches",
  ],
  [
    `${VIEW_MAP}rehydrateNewString {deny} <"the matched text mixes literal…">`,
    CONTENT,
    "literal placeholder text shares a placeholder with a secret",
  ],
];

/**
 * A rule violation by a site whose classification is still right, with why
 * its lexical position misleads the rule. `[rule: key, why]`.
 */
const RULE_EXCEPTIONS = [
  [
    `catch: ${HTML}sanitizeHtml withheld=UNPARSEABLE_PLACEHOLDER <catch text: UNPARSEABLE_PLACEHOLDER>`,
    "the catch is where parse5/remark report that THIS input cannot be parsed within bounds; the throw is input-composable, so the withhold is a verdict on the input",
  ],
  [
    `fault-branch: ${REHYDRATE}rehydrateRedacted calls multiEditDeny #2`,
    "MultiEdit has no releasable form there; it is refused with a working escape (single Edits) while the Edit/Write arm beside it is the fault release",
  ],
  [
    `catch: ${REHYDRATE}rehydrateRedacted {deny} <catch "… does not exist, so…">`,
    "ENOENT is a fact about the input (no such file), delivered as readFile's throw — not a fault",
  ],
  [
    `fault-branch: ${REHYDRATE}rehydrateRedacted {deny} <catch "… does not exist, so…">`,
    "the same site: it shares the catch body with the unreadable-target fault deny, and returns before it",
  ],
];

/**
 * The tests proving the releasable refusal cannot loop — refused once, the
 * exact re-issue proceeds, and an unrecordable confirmation proceeds at once.
 * `[test file, test name as written]` (a template name keeps its `${…}`).
 */
const RELEASABLE_PROOFS = [
  [
    "test/claude-hooks-fail-open.test.mjs",
    "refuses once under the OPEN posture, then lets the exact re-issue through with a warning",
  ],
  [
    "test/claude-hooks-fail-open.test.mjs",
    "lets the write through with a warning when the confirmation cannot be recorded",
  ],
  [
    "test/claude-hooks-guards.test.mjs",
    "${name}: refused once, the exact re-issue proceeds with a warning",
  ],
  [
    "test/claude-hooks-guards.test.mjs",
    "${name}: proceeds at once when the confirmation cannot be recorded",
  ],
  [
    "test/claude-hooks-guards.test.mjs",
    "lets the drop through with a warning by default",
  ],
  [
    "test/claude-hooks-layer2-rehydrate.test.mjs",
    "refuses a missing key once, then writes it literally on the exact re-issue",
  ],
  [
    "test/claude-hooks-layer2-rehydrate.test.mjs",
    "needs one confirmation per refusing stage, then lets the call through",
  ],
];

/** The names of every `it(…)`/`test(…)` in a test file, as written. */
function testNames(/** @type {string} */ file) {
  const source = readFileSync(join(repoRoot, file), "utf8");
  const ast = parse(source, { ecmaVersion: "latest", sourceType: "module" });
  const names = [];
  fullAncestor(ast, (node) => {
    if (node.type !== "CallExpression" || node.callee.type !== "Identifier")
      return;
    if (!["it", "test"].includes(node.callee.name)) return;
    const [name] = node.arguments;
    if (name?.type === "Literal") names.push(String(name.value));
    if (name?.type === "TemplateLiteral")
      names.push(source.slice(name.start + 1, name.end - 1));
  });
  return names;
}

// ── Tests ───────────────────────────────────────────────────────────────────

const classified = new Map(ALLOWLIST.map(([key, category]) => [key, category]));
const SITES = scanBlockingSites(repoRoot, SCANNED);
const where = (/** @type {Site} */ s) => `${s.file}:${s.line}`;

describe("hook blocking sites", () => {
  it("scans the shipped hook tree and every detector fires (non-vacuous)", () => {
    for (const known of [
      "claude-hooks/pretooluse-sanitize.mjs",
      "claude-hooks/sanitize-output.mjs",
      "claude-hooks/lib/hook-fault.mjs",
      "src/rehydrate.mjs",
      "src/output.mjs",
    ])
      assert.ok(SCANNED.includes(known), `${known} not scanned`);
    const kinds = SITES.map((s) => s.kind);
    for (const family of [
      "permissionDecision=",
      "decision=",
      "{deny}",
      "{deny,fault}",
      "{ask}",
      "updatedToolOutput",
      "suppressToolOutput()",
      "exitCode=2",
      "armAlert=true",
      "withheld=",
      "calls ",
    ])
      assert.ok(
        kinds.some((kind) => kind.includes(family)),
        `no ${family} site found: the detector for it is dead`,
      );
    for (const category of Object.values(Category))
      assert.ok(
        ALLOWLIST.some(([, c]) => c === category),
        `no allowlisted ${category} site`,
      );
  });

  it("classifies every blocking site exactly once", () => {
    const keys = SITES.map((s) => s.key);
    const unclassified = SITES.filter((s) => !classified.has(s.key)).map(
      (s) => `  ${s.key}  (${where(s)})`,
    );
    const listed = ALLOWLIST.map(([key]) => key);
    const stale = listed.filter((key) => !keys.includes(key));
    const doubled = listed.filter((key, i) => listed.indexOf(key) !== i);
    assert.deepEqual(
      { unclassified, stale, doubled },
      { unclassified: [], stale: [], doubled: [] },
      "Each blocking site needs exactly one ALLOWLIST entry naming WHY it may " +
        "block: CONTENT (a working sanitizer's verdict on the content, or a " +
        "relay of one), CLOSED (reached only under AGENT_SANITIZER_FAIL_OPEN=0: " +
        "a policy's closed arm or a failClosed* helper), or RELEASABLE (the " +
        "refuse-once re-issue path). A site that is a FAULT blocking under the " +
        "open default fits none of these: fix it (route it through " +
        "hookFaultOutcome) rather than listing it. A stale key means the site " +
        "moved or was removed — re-key or delete its entry.",
    );
  });

  it("binds each category to where its site sits", () => {
    const categoryOf = (/** @type {Site} */ s) => classified.get(s.key);
    assert.deepEqual(
      ruleViolations(SITES, categoryOf),
      RULE_EXCEPTIONS.map(([violation]) => violation).sort(),
      "A classification contradicts where its site sits (see ruleViolations " +
        "for each rule). A CONTENT site in a catch or an open arm is a fault " +
        "path blocking under the open default: route it through " +
        "hookFaultOutcome, or return it fault-tagged ({ deny, fault }).",
    );
  });

  it("names the non-looping proofs of the releasable refusal", () => {
    for (const [file, name] of RELEASABLE_PROOFS)
      assert.ok(testNames(file).includes(name), `${file}: no test "${name}"`);
  });
});

describe("the blocking-site scanner, on fixtures", () => {
  const root = mkdtempSync(join(tmpdir(), "blocking-sites-"));
  after(() => rmSync(root, { recursive: true, force: true }));
  /** Write `files` under the fixture root and scan exactly them. */
  const scan = (/** @type {Record<string, string>} */ files) => {
    for (const [name, body] of Object.entries(files))
      writeFileSync(join(root, name), body);
    return scanBlockingSites(root, Object.keys(files));
  };
  const keysOf = (/** @type {Site[]} */ sites) => sites.map((s) => s.key);
  const allAs = (/** @type {string} */ category) => () => category;

  it("flags a deny inside a catch block, and the catch rule rejects it as CONTENT", () => {
    const sites = scan({
      "catch.mjs": `export function onFault(input) {
        try {
          return judge(input);
        } catch {
          return { permissionDecision: PermissionDecision.DENY, permissionDecisionReason: "x" };
        }
      }`,
    });
    const key = "catch.mjs#onFault permissionDecision=PermissionDecision.DENY";
    assert.deepEqual(keysOf(sites), [key]);
    assert.equal(sites[0].inCatch, true);
    assert.deepEqual(ruleViolations(sites, allAs(CONTENT)), [`catch: ${key}`]);
  });

  it("flags a deny a helper returns, through a local and across modules, when called from a catch", () => {
    const sites = scan({
      "lib.mjs": `function refuse(reason) {
        return { permissionDecision: "deny", permissionDecisionReason: reason };
      }
      export function refusal(reason) {
        const fields = refuse(reason);
        return fields;
      }`,
      "hook.mjs": `import { refusal } from "./lib.mjs";
      export function onFault() {
        try {
          return null;
        } catch (err) {
          return refusal(String(err));
        }
      }`,
    });
    const call = "hook.mjs#onFault calls lib.mjs#refusal";
    assert.deepEqual(keysOf(sites), [
      call,
      "lib.mjs#refusal calls refuse",
      'lib.mjs#refuse permissionDecision="deny"',
    ]);
    assert.equal(sites[0].inCatch, true);
    assert.ok(ruleViolations(sites, allAs(CONTENT)).includes(`catch: ${call}`));
  });

  it("flags nothing in a corpus of non-blocking shapes", () => {
    const sites = scan({
      "benign.mjs": `// permissionDecision: "deny" in a comment is prose.
      const NOTE = "permissionDecision: deny";
      const PLACEHOLDER = "[withheld: example]";
      export function allow() {
        return { permissionDecision: PermissionDecision.ALLOW, decision: Decision.ALLOW };
      }
      export function compare(fields) {
        return fields.permissionDecision === PermissionDecision.DENY;
      }
      export function reasonOnly() {
        return { reason: "deny", note: NOTE, block: "ask" };
      }
      export function softExit() {
        process.exitCode = 1;
        process.exit(1);
        return { exitCode: 1, armAlert: false };
      }
      export function relay(outcome) {
        process.exitCode = outcome.exitCode;
        return outcome.armAlert ? outcome.stderr : null;
      }
      export function mentions(text) {
        return text.includes(PLACEHOLDER) || text === PLACEHOLDER;
      }
      export function judges(fields) {
        const denied = compare(fields);
        return denied ? null : fields;
      }`,
    });
    assert.deepEqual(keysOf(sites), []);
  });

  it("accepts a closed-arm deny as CLOSED, and rejects it or an open-arm ask as CONTENT", () => {
    const sites = scan({
      "policy.mjs": `registerFaultPolicy("hook", {
        event: null,
        guarded: "x",
        open: () => ({ fields: { permissionDecision: "ask" } }),
        closed: () => ({ fields: { permissionDecision: PermissionDecision.DENY } }),
      });`,
    });
    const closed =
      "policy.mjs#registerFaultPolicy:closed permissionDecision=PermissionDecision.DENY";
    const open = 'policy.mjs#registerFaultPolicy:open permissionDecision="ask"';
    assert.deepEqual(keysOf(sites), [closed, open]);
    const filed =
      (/** @type {string} */ asClosed) => (/** @type {Site} */ s) =>
        s.key === closed ? asClosed : RELEASABLE;
    assert.deepEqual(ruleViolations(sites, filed(CLOSED)), []);
    assert.deepEqual(ruleViolations(sites, filed(CONTENT)), [
      `content-placement: ${closed}`,
    ]);
    assert.deepEqual(ruleViolations(sites, allAs(CONTENT)), [
      `content-placement: ${closed}`,
      `open-arm: ${open}`,
    ]);
  });

  it("flags an untagged deny beside a fault-tagged one in the same fault branch", () => {
    const sites = scan({
      "branch.mjs": `function multiDeny() {
        return { deny: "cannot" };
      }
      export function rehydrate(defect, multi) {
        if (defect) {
          if (multi) return multiDeny();
          return { deny: "x", fault: "y" };
        }
        return null;
      }`,
    });
    const call = "branch.mjs#rehydrate calls multiDeny";
    assert.deepEqual(keysOf(sites), [
      "branch.mjs#multiDeny {deny}",
      call,
      "branch.mjs#rehydrate {deny,fault}",
    ]);
    const filed = (/** @type {Site} */ s) =>
      s.kind === "{deny,fault}" ? RELEASABLE : CONTENT;
    assert.deepEqual(ruleViolations(sites, filed), [`fault-branch: ${call}`]);
  });
});
