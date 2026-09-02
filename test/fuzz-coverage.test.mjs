/**
 * SSOT obligation gate: every public function that parses or transforms
 * untrusted input MUST be exercised by at least one property/fuzz suite. This
 * is the same one-test-per-member discipline the enumerated-member tests use
 * (each LINGUISTIC_SCRIPTS / CHECKS / REPORTED_TAGS entry), extended to "every
 * entry point that eats attacker-controlled bytes is fuzzed."
 *
 * Why an obligation gate rather than a coverage percentage: line coverage was
 * already 100% when a real under-stripping bug (U+009B passthrough) shipped,
 * because a passthrough executes the line without violating any asserted
 * invariant. A percentage can't catch "this parser has no security invariant";
 * requiring a named fuzz target for each one can.
 *
 * Each obligation list is one part of a PARTITION over the population it draws
 * from: FUZZ_REQUIRED + FUZZ_EXEMPT + FUZZ_TODO cover every exported function,
 * SEMANTIC_FUZZ_REQUIRED + SEMANTIC_FUZZ_EXEMPT cover every required name, and
 * IN_SCOPE + OUT_OF_SCOPE cover every discovered suite. A required list on its
 * own proves only what it names; the other parts are what make a new export or
 * a new suite impossible to land without a human choosing a side.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { parse } from "acorn";

import * as invisible from "../src/invisible.mjs";
import * as html from "../src/html.mjs";
import * as index from "../src/index.mjs";
import * as confusables from "../src/confusables.mjs";
import * as instructions from "../src/instructions.mjs";
import * as prompt from "../src/prompt.mjs";
import * as viewMap from "../src/view-map.mjs";
import * as rehydrate from "../src/rehydrate.mjs";
import * as output from "../src/output.mjs";
// Hook-layer entry points: the whole-process compositions that eat untrusted
// tool output / tool input owe fuzz targets exactly like the engine parsers.
import * as sanitizeOutputHook from "../claude-hooks/sanitize-output.mjs";
import * as pretooluseHook from "../claude-hooks/pretooluse-sanitize.mjs";

import { CHECKS } from "../src/invisible.mjs";
import {
  THREAT_CODEPOINTS,
  IN_SCOPE_MEMBERS,
  OUT_OF_SCOPE,
  acceptedSpellings,
  spellingMatches,
  threat,
} from "./threat-codepoints.mjs";

// Functions that ingest untrusted text/URLs/ranges and so owe a fuzz target.
const FUZZ_REQUIRED = [
  "stripInvisible",
  "stripInvisibleWithReport",
  "sanitize",
  "sanitizeHtml",
  "spliceRanges",
  "isHiddenStyle",
  "isHiddenElement",
  "detectExfil",
  "checkExfilUrl",
  "urlHost",
  "detectConfusableHosts",
  // Agent-pipeline transforms/parsers over untrusted input (one named fuzz
  // target each — the same obligation extended to the new entry points).
  "normalizeConfusables",
  "foldConfusables",
  "selectFoldableFindings",
  "scanText",
  "decodeRun",
  "classifyPrompt",
  "alignDeletions",
  "resolveSpan",
  "rehydrateNewString",
  "occurrences",
  "rehydrateRedacted",
  "sanitizeText",
  "sanitizeValue",
  "deleteVerbatimSpans",
  // The needle-splice primitive behind deleteVerbatimSpans, rehydrateNewString
  // and the whole-file Write substitution: it decides which bytes of untrusted
  // text are removed or replaced, so it owes the "only verbatim matches of the
  // ORIGINAL text are touched" property directly, not just via its callers.
  "spliceOrdered",
  // Whole-pipeline hook entry points (PostToolUse sanitize, PreToolUse
  // rehydration): fuzzed end-to-end — sanitize → adversarial model edits →
  // rehydrate, over multiple rounds — by claude-hooks-roundtrip.fuzz.test.mjs.
  "evaluateToolOutput",
  "buildPreToolUseResponse",
  "rehydrateLayer2",
];

/**
 * The DENIAL part of the export partition: every exported function that owes no
 * fuzz target, and the one-line reason it owes none. Every entry here is a
 * settled "no" — a name that owes a suite it does not have belongs in
 * {@link FUZZ_TODO}, so a deferral cannot ride in as a reason string.
 * @type {Readonly<Record<string, string>>}
 */
const FUZZ_EXEMPT = Object.freeze({
  // ── predicates and lookups: no parse or transform step of their own ──────
  announcedByInstructionsLoaded:
    "splits one path on its separators and looks the tail up in the kind table",
  closingTagName: "reads one tag name out of an already-tokenized HTML value",
  contextScopeContradiction:
    "maps a host-supplied load reason through a table, with no parse",
  excludeFromContextScan: "path-prefix predicate over one scan entry name",
  hasNonAscii: "code-unit range predicate over one string",
  isBenignAnsiKinds:
    "set membership over the TOKEN_KIND values Layer 1 removed",
  isHiddenOpen: "short-string predicate over one open tag",
  isIncidentalInvisible:
    "threshold read over counts the invisible analysis produced",
  isSgrOnly: "predicate over the tokens scanAnsi produced",
  isWalkableContainer: "shape predicate over one JSON value",
  looksLikeHtmlSource:
    "returns a verdict rather than a transform, and both branches it selects are fuzzed through sanitizeHtml",
  scopeFor: "looks a tool name up in the fold-scope table",

  // ── operator-facing prose built from an already-classified finding ───────
  composeContext: "assembles the context block from a computed warning list",
  describeExfil: "formats Layer 3's classified threats into prose",
  describeRemoved: "formats Layer 2's removal counts into prose",
  describeStripped: "formats Layer 1's CATEGORY codes into prose",
  describeWarned: "formats Layer 2's preserved-tag counts into prose",
  formatReason: "formats the prompt gate's block reason into prose",
  normalizeContext: "formats the folded field names into a model-facing note",
  withheldWarning:
    "formats one noun phrase into the withheld-artifact sentence",

  // ── filesystem entry points whose only parse is an already-required one ──
  ancestorInstructionFiles: "pure parent-path arithmetic over a directory path",
  atomicReplaceFile: "write primitive over text a required scan produced",
  cleanFile: "reads a file and delegates the parse to scanText",
  findInstructionFiles: "enumerates paths and reads no file content",
  scanInstructionFiles: "reads files and delegates the parse to scanText",

  // ── compositions and views fuzzed through the entry point above them ─────
  applyLayer1:
    "the Layer-1 composition, fuzzed through sanitize and sanitizeText",
  applyLayer1WellFormed:
    "applyLayer1 plus normalizeLoneSurrogates, both fuzzed above it",
  countEffectiveInvisible: "reads the analysis stripInvisible already ran",
  countPayloadInvisible: "reads the analysis stripInvisible already ran",
  findLongRuns: "one anchored scan, fuzzed through stripInvisibleWithReport",
  hasLongRun: "the yes/no of findLongRuns, over the same anchored scan",
  isBenignAnsi: "runs applyLayer1 and reads its kinds",
  layer2Placeholder:
    "derives a keyed placeholder by sha256; the round-trip fuzz oracle pins its grammar",
  makeFileView:
    "freezes a text and pair list into a view, validated at construction",
  normalizeLoneSurrogates:
    "one same-length substitution over LONE_SURROGATE_RE, fuzzed through sanitizeText",
  orderedMatches:
    "orders what occurrences found, and spliceOrdered consumes that order",
  pairsToUtf16:
    "converts pair offsets between spaces, fuzzed through resolveSpan",
  payloadInvisibleView:
    "the view the long-run probe reads, pinned by invisible-fast-path",
  payloadLongRunSample: "reads that same view, pinned by invisible-fast-path",
  scanHtmlFragment:
    "has no invariant of its own beyond what the sanitizeHtml round-trip and splice-fidelity properties assert on its output",
  stripAnsiFully: "the ANSI half of applyLayer1, fuzzed through layer1-ansi",
  suppressToolOutput: "substitutes a sentinel for a subtree and parses nothing",
  toUtf16View:
    "converts a view between offset spaces, validated at construction",
  viewMapDefect: "self-check over a view the pipeline built",
});

/**
 * The DEFERRAL part of the export partition: every exported function that owes
 * a property suite but does not have one yet, and the untrusted input it takes.
 *
 * A named list rather than a reason-string convention inside FUZZ_EXEMPT,
 * because both edits a deferral allows must be visible. Growing the deferred
 * set adds a line here; and demoting a name out of FUZZ_REQUIRED deletes its
 * suite obligation, which the partition forces to read as a deletion from one
 * list and an addition to another.
 * @type {Readonly<Record<string, string>>}
 */
const FUZZ_TODO = Object.freeze({
  anchorSpans: "anchors a prefix/suffix over untrusted Write content",
  matchesSecretHint: "a fail-open pre-gate for the secret scan",
  needsMarkdownPipeline: "a fail-open pre-gate for Layers 2 and 3",
  overlapAwareCount: "decides Edit ambiguity over untrusted needles",
  pairDiskSpans: "maps redaction pairs onto on-disk spans",
  sgrCarriesPayload:
    "a fail-open pre-gate for the write path's SGR carve-out, over a hand-rolled parameter grammar",
});

// Entry points that owe SEMANTIC-CORRECTNESS fuzzing, not just structural
// fuzzing: a structural property (never-throws, idempotent, shape-preserved)
// can hold in aggregate while a detector corrupts the wrong leaf or misses a
// specific payload shape — exactly the class of false positive that shipped
// in scanText's scatter floor (fixed alongside this gate).
const SEMANTIC_FUZZ_REQUIRED = [
  "stripInvisible",
  "sanitizeHtml",
  "detectExfil",
  "checkExfilUrl",
  "urlHost",
  "normalizeConfusables",
  "foldConfusables",
  "selectFoldableFindings",
  "scanText",
  "classifyPrompt",
  "sanitizeText",
  "sanitizeValue",
  "rehydrateRedacted",
  "occurrences",
];

/**
 * The other half of the semantic partition, over FUZZ_REQUIRED. Most entries
 * are named internal helpers a semantic suite drives only THROUGH their public
 * entry point, where the precision property is asserted: requiring their own
 * name here would be a false negative, not a stronger check.
 * @type {Readonly<Record<string, string>>}
 */
const SEMANTIC_FUZZ_EXEMPT = Object.freeze({
  alignDeletions:
    "driven through rehydrateRedacted, where precision is asserted",
  buildPreToolUseResponse:
    "a whole-process composition; each layer's precision is asserted at its own entry point",
  decodeRun: "driven through scanText, where precision is asserted",
  deleteVerbatimSpans:
    "driven through sanitizeText, where precision is asserted",
  detectConfusableHosts:
    "its precision is pinned exactly by the benign/attack corpus in confusable-host.test.mjs",
  evaluateToolOutput:
    "a whole-process composition; each layer's precision is asserted at its own entry point",
  isHiddenElement: "driven through sanitizeHtml, where precision is asserted",
  isHiddenStyle: "driven through sanitizeHtml, where precision is asserted",
  rehydrateLayer2:
    "a whole-process composition; each layer's precision is asserted at its own entry point",
  rehydrateNewString:
    "driven through rehydrateRedacted, where precision is asserted",
  resolveSpan: "driven through rehydrateRedacted, where precision is asserted",
  sanitize:
    "the top-level composition over layers that each carry their own semantic suite",
  spliceOrdered: "driven through sanitizeText, where precision is asserted",
  spliceRanges: "driven through sanitizeHtml, where precision is asserted",
  stripInvisibleWithReport:
    "driven through stripInvisible, where precision is asserted",
});

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();
const testDir = path.join(repoRoot, "test");

// A "fuzz suite" is any test file that actually drives fast-check. Discovered by
// content, not by name, so a renamed file or a new suite is picked up
// automatically and can't silently drop a required target. This gate file is
// excluded: it names every required function as a string literal (and contains
// the "fc.assert(" sentinel itself), so scanning it would pass vacuously.
const selfName = path.basename(fileURLToPath(import.meta.url));

// ─── JS structure, answered by the grammar ───────────────────────────────────
// Every question in this section is about the JS GRAMMAR — is this identifier
// inside a property invocation, where does this arrow body end, is this token
// code or the inside of a string — so acorn answers it. A depth counter over
// the text cannot: 69 string, template and regex literals in this repo's
// fast-check suites hold unbalanced parens, and one of them inside a property
// body moves the captured span off its real end in either direction.

const FC_PROPERTY_METHODS = new Set(["assert", "property", "asyncProperty"]);

const FUNCTION_TYPES = new Set([
  "ArrowFunctionExpression",
  "FunctionDeclaration",
  "FunctionExpression",
]);

// A `var` hoists to the nearest of these; everything else binds where it sits.
const FUNCTION_SCOPE_TYPES = new Set([...FUNCTION_TYPES, "Program"]);

const BLOCK_SCOPE_TYPES = new Set([
  "BlockStatement",
  "CatchClause",
  "ClassDeclaration",
  "ClassExpression",
  "ForInStatement",
  "ForOfStatement",
  "ForStatement",
  "StaticBlock",
  "SwitchStatement",
]);

/**
 * Parse one ES module, collecting its comment ranges.
 * @param {string} source
 * @returns {{ ast: any, comments: {start: number, end: number}[] }}
 */
const parseModule = (source) => {
  /** @type {{start: number, end: number}[]} */
  const comments = [];
  const ast = parse(source, {
    ecmaVersion: "latest",
    sourceType: "module",
    onComment: comments,
  });
  return { ast, comments };
};

/** Every child node of `node`. */
function* childNodes(node) {
  for (const key of Object.keys(node)) {
    const value = node[key];
    if (Array.isArray(value)) {
      for (const item of value)
        if (item && typeof item.type === "string") yield item;
    } else if (value && typeof value.type === "string") yield value;
  }
}

/** `node` and every node beneath it. */
const subtree = (node, out = []) => {
  out.push(node);
  for (const child of childNodes(node)) subtree(child, out);
  return out;
};

/** Every name a binding pattern introduces. */
function* patternNames(pattern) {
  if (pattern === null || pattern === undefined) return;
  if (pattern.type === "Identifier") yield pattern.name;
  else if (pattern.type === "ObjectPattern")
    for (const property of pattern.properties)
      yield* patternNames(
        property.type === "RestElement" ? property.argument : property.value,
      );
  else if (pattern.type === "ArrayPattern")
    for (const element of pattern.elements) yield* patternNames(element);
  else if (pattern.type === "AssignmentPattern")
    yield* patternNames(pattern.left);
  else if (pattern.type === "RestElement")
    yield* patternNames(pattern.argument);
}

/**
 * Resolve identifiers to the binding they name, so a call is matched by what it
 * REFERS to rather than by how it is spelled.
 * @param {any} ast
 * @returns {(name: string, node: any) => any} the local function a name is
 *   bound to, or null when the name is unbound, imported, or a parameter
 */
const identifierBindings = (ast) => {
  const scopeOf = new Map();
  const declare = (scope, name, definition) => {
    if (!scope.bindings.has(name)) scope.bindings.set(name, definition);
  };
  const enclosingFunction = (scope) =>
    scope.isFunction ? scope : enclosingFunction(scope.parent);

  const visit = (node, outer) => {
    scopeOf.set(node, outer);
    const isFunction = FUNCTION_SCOPE_TYPES.has(node.type);
    const scope =
      isFunction || BLOCK_SCOPE_TYPES.has(node.type)
        ? { parent: outer, isFunction, bindings: new Map() }
        : outer;
    if (node.type === "FunctionDeclaration" || node.type === "ClassDeclaration")
      declare(outer, node.id.name, node);
    if (isFunction && node.params)
      for (const param of node.params)
        for (const name of patternNames(param)) declare(scope, name, null);
    if (node.type === "CatchClause")
      for (const name of patternNames(node.param)) declare(scope, name, null);
    if (node.type === "VariableDeclaration")
      for (const declarator of node.declarations)
        for (const name of patternNames(declarator.id))
          declare(
            node.kind === "var" ? enclosingFunction(outer) : outer,
            name,
            declarator.init,
          );
    if (node.type === "ImportDeclaration")
      for (const specifier of node.specifiers)
        declare(outer, specifier.local.name, null);
    for (const child of childNodes(node)) visit(child, scope);
  };
  visit(ast, { parent: null, isFunction: true, bindings: new Map() });

  return (name, node) => {
    for (let scope = scopeOf.get(node); scope; scope = scope.parent)
      if (scope.bindings.has(name)) return scope.bindings.get(name);
    return null;
  };
};

/** True for a direct `fc.assert(…)` / `fc.property(…)` / `fc.asyncProperty(…)`. */
const isFcPropertyCall = (node) =>
  node.type === "CallExpression" &&
  node.callee.type === "MemberExpression" &&
  !node.callee.computed &&
  node.callee.object.type === "Identifier" &&
  node.callee.object.name === "fc" &&
  node.callee.property.type === "Identifier" &&
  FC_PROPERTY_METHODS.has(node.callee.property.name);

/**
 * True when `node` invokes `fc.assert`/`fc.property`/`fc.asyncProperty` in its
 * OWN body. A nested function is not descended into: a helper that merely
 * builds `it(…, () => fc.assert(…))` registers a test rather than running a
 * property, so calling it is not itself a property invocation.
 * @param {any} node
 * @returns {boolean}
 */
const callsFcDirectly = (node) => {
  if (isFcPropertyCall(node)) return true;
  for (const child of childNodes(node)) {
    if (FUNCTION_TYPES.has(child.type)) continue;
    if (callsFcDirectly(child)) return true;
  }
  return false;
};

/**
 * The identifier names a suite references from inside a property invocation.
 *
 * A name appearing anywhere in a file that merely CONTAINS a property call is
 * not evidence that a PROPERTY exercises it: this repo mixes a handful of
 * property tests into files that are otherwise hundreds of lines of ordinary
 * example-based `it(...)` tests, so an example test calling `sanitize(...)`
 * would otherwise satisfy the obligation after its property test was deleted.
 *
 * Three shapes count as a property invocation. A direct `fc.*` call; a call to
 * a LOCAL WRAPPER whose own body invokes one (several suites factor the
 * boilerplate into `const check = (arb, pred) => fc.assert(fc.property(…))`,
 * putting the predicate closure inside the wrapper's call rather than fc's);
 * and, transitively, the body of any local helper called from source already
 * included, since a name reached through a helper is exercised by the fuzz run
 * exactly as much as one referenced directly.
 * @param {any} ast
 * @returns {{ names: Set<string>, spanLength: number }}
 */
const propertyReferences = (ast) => {
  const definitionOf = identifierBindings(ast);
  const nodes = subtree(ast);

  const wrapperCache = new Map();
  const isWrapper = (definition) => {
    if (definition === null || !FUNCTION_TYPES.has(definition.type))
      return false;
    if (!wrapperCache.has(definition))
      wrapperCache.set(definition, callsFcDirectly(definition.body));
    return wrapperCache.get(definition);
  };
  const calledDefinition = (node) =>
    node.type === "CallExpression" && node.callee.type === "Identifier"
      ? definitionOf(node.callee.name, node.callee)
      : null;

  const roots = nodes.filter(
    (node) => isFcPropertyCall(node) || isWrapper(calledDefinition(node)),
  );
  // A nested root (fc.property inside fc.assert) already sits inside its
  // parent's span; counting only the outermost keeps spanLength a real
  // character count rather than one that double-counts.
  const outermost = roots.filter(
    (root) =>
      !roots.some(
        (other) =>
          other !== root && other.start <= root.start && root.end <= other.end,
      ),
  );

  const names = new Set();
  const visited = new Set();
  const queue = [...outermost];
  while (queue.length > 0) {
    const region = queue.pop();
    if (visited.has(region)) continue;
    visited.add(region);
    for (const node of subtree(region)) {
      if (node.type === "Identifier") names.add(node.name);
      const definition = calledDefinition(node);
      if (definition !== null && FUNCTION_TYPES.has(definition.type))
        queue.push(definition);
    }
  }
  return {
    names,
    spanLength: outermost.reduce(
      (sum, node) => sum + (node.end - node.start),
      0,
    ),
  };
};

/** Every identifier a module references outside its own import statements. */
const referencedIdentifiers = (ast) => {
  const names = new Set();
  const visit = (node) => {
    if (node.type === "ImportDeclaration") return;
    if (node.type === "Identifier") names.add(node.name);
    for (const child of childNodes(node)) visit(child);
  };
  visit(ast);
  return names;
};

/**
 * `source` with each `[start, end)` range blanked and every other offset
 * unmoved. Split by UTF-16 code UNIT, the space acorn's offsets index: an
 * astral character in a suite (this repo's tests are full of emoji) is two
 * units, and walking code points instead shifts every range after the first one.
 * @param {string} source
 * @param {{start: number, end: number}[]} ranges
 * @returns {string}
 */
const blankRanges = (source, ranges) => {
  const units = source.split("");
  for (const { start, end } of ranges)
    for (let i = start; i < end; i++) if (units[i] !== "\n") units[i] = " ";
  return units.join("");
};

/**
 * `source` with its comments and import statements blanked, so a name surviving
 * here is a real use — a function listed in an `import {…}` or named in a
 * comment is NOT evidence that a property exercises it.
 * @param {string} source
 * @param {any} ast
 * @param {{start: number, end: number}[]} comments
 * @returns {string}
 */
const strippedSource = (source, ast, comments) =>
  blankRanges(source, [
    ...comments,
    ...ast.body.filter((node) => node.type === "ImportDeclaration"),
  ]);

// The shared arbitraries in test-helpers.mjs (unicodeChar / loneSurrogate)
// carry their seed literals — the surrogate bounds 0xd800/0xdfff — in the
// helper, not in each importing suite. A suite that imports one still seeds
// that code point, so its effective source for the domain-coverage grep below
// must include the arbitrary's code; without this, extracting the shared
// arbitrary reads as every importer "never seeding" the surrogate class.
//
// Only the DECLARATION SPAN of each arbitrary a suite actually references is
// appended, never the whole helper: the helper also exports keptOutsideNeedles
// (whose body calls `occurrences`, a FUZZ_REQUIRED *and*
// SEMANTIC_FUZZ_REQUIRED name), so appending it wholesale let any importer
// satisfy that obligation transitively without ever fuzzing it.
const SHARED_ARBITRARIES = ["unicodeChar", "loneSurrogate"];

const helperText = readFileSync(path.join(testDir, "test-helpers.mjs"), "utf8");
const helperParse = parseModule(helperText);
const helperSource = strippedSource(
  helperText,
  helperParse.ast,
  helperParse.comments,
);

/**
 * The `[start, end)` range of the `export … <name> …` declaration in `ast`.
 * @param {any} ast
 * @param {string} name
 * @returns {{start: number, end: number}|null} null when no such export exists
 */
const exportRange = (ast, name) => {
  for (const node of ast.body) {
    if (node.type !== "ExportNamedDeclaration" || !node.declaration) continue;
    const declaration = node.declaration;
    const declared =
      declaration.type === "VariableDeclaration"
        ? declaration.declarations.flatMap((one) => [...patternNames(one.id)])
        : [declaration.id.name];
    if (declared.includes(name)) return { start: node.start, end: node.end };
  }
  return null;
};

/**
 * The source of one export declaration with its `.filter(…)` calls removed.
 *
 * A filter can only REMOVE values from an arbitrary's domain, so a code point
 * named inside one is evidence of an EXCLUSION, never of seeding: `unicodeChar`
 * spells the surrogate bounds 0xd800/0xdfff precisely because it cannot
 * generate them, and crediting its importers for the lone-surrogate class was
 * the false negative this guard exists to prevent. Dropping a narrowing filter
 * can only lose credit, which is the direction CLAUDE.md asks these heuristics
 * to fail.
 * @param {string} source  the comment-blanked module text
 * @param {any} ast
 * @param {{start: number, end: number}} range
 * @returns {string}
 */
const seedingSource = (source, ast, range) => {
  const declaration = subtree(ast).find(
    (node) => node.start === range.start && node.end === range.end,
  );
  const dropped = subtree(declaration)
    .filter(
      (node) =>
        node.type === "CallExpression" &&
        node.callee.type === "MemberExpression" &&
        !node.callee.computed &&
        node.callee.property.type === "Identifier" &&
        node.callee.property.name === "filter",
    )
    .map((node) => ({ start: node.callee.object.end, end: node.end }));
  // Outermost-first: a filter nested inside another goes with it.
  const outermost = dropped
    .filter(
      (one) =>
        !dropped.some(
          (other) =>
            other !== one && other.start <= one.start && one.end <= other.end,
        ),
    )
    .sort((a, b) => a.start - b.start);
  let kept = "";
  let cursor = range.start;
  for (const { start, end } of outermost) {
    kept += source.slice(cursor, start);
    cursor = end;
  }
  return (kept + source.slice(cursor, range.end)).trim();
};

/** Shared arbitrary name → the source that evidences what it SEEDS. */
const seedingSpans = new Map(
  SHARED_ARBITRARIES.map((name) => {
    const range = exportRange(helperParse.ast, name);
    if (range === null)
      throw new Error(
        `test-helpers.mjs has no 'export … ${name}' declaration — the ` +
          `shared-arbitrary extraction is stale. Fix it (or drop the name from ` +
          `SHARED_ARBITRARIES): silently appending nothing would re-create the ` +
          `false negative this credit exists to prevent.`,
      );
    const seeding = seedingSource(helperSource, helperParse.ast, range);
    if (seeding === "")
      throw new Error(
        `the extracted span for ${name} is empty after removing .filter(…) clauses`,
      );
    return [name, seeding];
  }),
);

const fuzzFiles = readdirSync(testDir)
  .filter((name) => name.endsWith(".test.mjs") && name !== selfName)
  .map((name) => ({
    name,
    source: readFileSync(path.join(testDir, name), "utf8"),
  }))
  .filter((file) => file.source.includes("fc.assert("))
  .map(({ name, source }) => {
    const { ast, comments } = parseModule(source);
    // Requiring the helper import too keeps a same-named local arbitrary from
    // claiming the shared one's credit.
    const identifiers = referencedIdentifiers(ast);
    const referencedArbitraries = source.includes('from "./test-helpers.mjs"')
      ? SHARED_ARBITRARIES.filter((arb) => identifiers.has(arb))
      : [];
    const code = [
      strippedSource(source, ast, comments),
      ...referencedArbitraries.map((arb) => seedingSpans.get(arb)),
    ].join("\n");
    const { names, spanLength } = propertyReferences(ast);
    return {
      name,
      code,
      identifiers,
      referencedArbitraries,
      fcNames: names,
      fcSpanLength: spanLength,
    };
  });

// A "semantic-fuzz suite" is a fuzz file following the `*-semantic-fuzz.
// test.mjs` naming convention this repo uses for precision fuzzing (fast-check
// generators that interleave known-good and known-bad tokens and assert each
// one's EXACT fate), as opposed to the structural `*-property.test.mjs`
// suites. Naming-based rather than content-sniffed: a heuristic for "asserts
// per-token precision" would be exactly the kind of guard that can't cleanly
// separate the real thing from a lookalike, and CLAUDE.md's guidance is to
// let that kind of check fail open rather than fabricate false confidence.
const semanticFuzzFiles = fuzzFiles.filter((file) =>
  file.name.endsWith("-semantic-fuzz.test.mjs"),
);

const exportedFunctions = new Map(
  [
    invisible,
    html,
    index,
    confusables,
    instructions,
    prompt,
    viewMap,
    rehydrate,
    output,
  ]
    .flatMap((mod) => Object.entries(mod))
    .filter(([, value]) => typeof value === "function"),
);

// The hook entry points are added BY NAME rather than by spreading the hook
// modules' exports: both hook modules define their own `sanitizeText` /
// `sanitizeValue` wrappers, and a bulk spread would silently retarget the
// existing engine obligations for those names at the wrappers (`new Map`
// lets the last entry win). Collisions are rejected outright so a future
// same-named hook export fails loud instead of shadowing an engine parser.
for (const [name, mod] of [
  ["evaluateToolOutput", sanitizeOutputHook],
  ["buildPreToolUseResponse", pretooluseHook],
  ["rehydrateLayer2", pretooluseHook],
]) {
  assert.ok(
    !exportedFunctions.has(name),
    `${name} collides with an engine export — adding it would retarget that obligation`,
  );
  exportedFunctions.set(name, mod[name]);
}

/**
 * Assert `parts` partition `population` exactly, so a member of the population
 * cannot exist without a human having classified it into exactly ONE part. The
 * concatenation is compared element-wise, so a name listed in two parts fails
 * here as loudly as a name listed in none.
 * @param {string[]} population
 * @param {string[][]} parts
 * @param {string} hint  what the reader must do about a mismatch
 */
const assertPartition = (population, parts, hint) => {
  assert.ok(
    population.length > 0,
    "empty population — the partition would hold vacuously",
  );
  assert.deepEqual([...population].sort(), parts.flat().sort(), hint);
};

/** The three parts of the export partition, in classification order. */
const exportParts = [
  FUZZ_REQUIRED,
  Object.keys(FUZZ_EXEMPT),
  Object.keys(FUZZ_TODO),
];

describe("fuzz-coverage obligation gate", () => {
  it("discovers at least one fast-check suite (gate is not vacuous)", () => {
    assert.ok(
      fuzzFiles.length > 0,
      "no fast-check suites found — the gate would pass vacuously",
    );
    assert.ok(FUZZ_REQUIRED.length > 0);
  });

  it("the fc-call span extractor actually finds spans (gate is not vacuous)", () => {
    // Guards against the extractor silently matching nothing (e.g. a callee
    // spelling isFcPropertyCall no longer recognizes), which would make every
    // "is referenced by a fast-check suite" check below fail closed for the
    // wrong reason instead of proving coverage.
    const totalSpanLength = fuzzFiles.reduce(
      (sum, file) => sum + file.fcSpanLength,
      0,
    );
    assert.ok(
      totalSpanLength > 0,
      "propertyReferences found no fc.assert/fc.property spans in any " +
        "discovered fuzz file — the span-narrowed match would pass vacuously",
    );
  });

  it("every exported function is fuzz-required, exempt, or deferred with a reason", () => {
    assertPartition(
      [...exportedFunctions.keys()],
      exportParts,
      "a new export must be classified: add it to FUZZ_REQUIRED and give it a " +
        "property suite, to FUZZ_EXEMPT with the one-line reason it owes none, " +
        "or to FUZZ_TODO with the untrusted input it takes",
    );
    for (const map of [FUZZ_EXEMPT, FUZZ_TODO])
      for (const [name, reason] of Object.entries(map))
        assert.ok(reason.length > 0, `${name} carries an empty reason`);
  });

  it("no FUZZ_EXEMPT reason reads as a deferral", () => {
    // FUZZ_EXEMPT is a denial; a promise written into a reason string is the
    // escape hatch FUZZ_TODO exists to make visible instead.
    const readsAsDeferral = (reason) => /^(todo|fixme)\b/i.test(reason);
    assert.ok(
      readsAsDeferral("TODO: owes a property suite"),
      "the deferral shape matches nothing — this assertion would pass vacuously",
    );
    assert.ok(
      Object.keys(FUZZ_TODO).length > 0,
      "FUZZ_TODO is empty, so no deferral has anywhere honest to go",
    );
    for (const [name, reason] of Object.entries(FUZZ_EXEMPT))
      assert.ok(
        !readsAsDeferral(reason),
        `${name}'s exemption reads as a deferral — move it to FUZZ_TODO`,
      );
  });

  it("the export partition rejects an unclassified name (assertion is not vacuous)", () => {
    const [required, exempt, todo] = exportParts;
    const population = [...exportedFunctions.keys(), "syntheticNewExport"];
    assert.throws(
      () =>
        assertPartition(
          population,
          exportParts,
          "an unclassified export must fail the partition",
        ),
      assert.AssertionError,
    );
    // Any ONE of the three classifications satisfies it, so a genuinely new or
    // undecided export has a side to be put on.
    for (const parts of [
      [[...required, "syntheticNewExport"], exempt, todo],
      [required, [...exempt, "syntheticNewExport"], todo],
      [required, exempt, [...todo, "syntheticNewExport"]],
    ])
      assertPartition(
        population,
        parts,
        "classifying the synthetic export must satisfy the same partition",
      );
  });

  it("the export partition rejects a name that is both required and deferred", () => {
    // The demotion this partition exists to make visible: moving a name out of
    // FUZZ_REQUIRED into FUZZ_TODO deletes its property-suite obligation, so a
    // copy that leaves the FUZZ_REQUIRED entry behind must fail rather than
    // read as a green no-op.
    const [required, exempt, todo] = exportParts;
    const population = [...exportedFunctions.keys()];
    const [demoted, ...stillRequired] = required;
    assert.throws(
      () =>
        assertPartition(
          population,
          [required, exempt, [...todo, demoted]],
          "a name in two parts must fail the partition",
        ),
      assert.AssertionError,
    );
    assertPartition(
      population,
      [stillRequired, exempt, [...todo, demoted]],
      "an honest demotion — one name moved, not copied — must still partition",
    );
  });

  for (const name of FUZZ_REQUIRED) {
    it(`'${name}' is a real exported function`, () => {
      assert.equal(
        typeof exportedFunctions.get(name),
        "function",
        `${name} is not an exported function — stale entry in FUZZ_REQUIRED`,
      );
    });

    it(`'${name}' is referenced by a fast-check suite`, () => {
      const hits = fuzzFiles.filter((file) => file.fcNames.has(name));
      assert.ok(
        hits.length > 0,
        `${name} handles untrusted input but no property/fuzz suite's ` +
          `fc.assert/fc.property call references it`,
      );
    });
  }
});

describe("property-span extraction runs on the grammar", () => {
  // A fixture whose property body carries every literal shape a paren-depth
  // scan mis-reads: a lone ")", a lone "(", a template holding a brace, and a
  // regex literal holding a paren. `insideProperty` sits AFTER the ")" (a
  // depth scan closes the call early and loses it) and `notFuzzed` sits after
  // the whole property (an over-long span hands it the credit it never earned).
  const FIXTURE = [
    'import fc from "fast-check";',
    'import { insideProperty, viaHelper, notFuzzed } from "../src/x.mjs";',
    "",
    "const check = (arbitrary, predicate) =>",
    "  fc.assert(fc.property(arbitrary, predicate), {});",
    "",
    "const helper = (value) => viaHelper(value);",
    "",
    "check(fc.string(), (text) => {",
    '  const closer = ")";',
    '  const opener = "look ![alt](";',
    "  const braced = `${text} { unmatched`;",
    "  const pattern = /\\(/;",
    "  return insideProperty(text, closer, opener, braced, pattern) && helper(text);",
    "});",
    "",
    'it("an ordinary example test", () => {',
    "  notFuzzed(inComment);",
    "});",
    "",
    "// a comment naming insideProperty is not a reference",
  ].join("\n");

  const wrapperCallStart = FIXTURE.indexOf("check(fc.string()");
  const { names, spanLength } = propertyReferences(parseModule(FIXTURE).ast);

  it("a paren-depth scan of the fixture closes early (fixture has teeth)", () => {
    // The discredited approximation, kept as the negative control this fixture
    // is aimed at: a depth counter cannot see string or regex literals.
    let depth = 0;
    let end = -1;
    for (
      let i = FIXTURE.indexOf("(", wrapperCallStart);
      i < FIXTURE.length;
      i++
    ) {
      if (FIXTURE[i] === "(") depth++;
      else if (FIXTURE[i] === ")" && --depth === 0) {
        end = i;
        break;
      }
    }
    assert.ok(end > wrapperCallStart, "the depth scan found no close paren");
    assert.ok(
      !FIXTURE.slice(wrapperCallStart, end).includes("insideProperty"),
      "the depth scan now reaches insideProperty — the fixture lost its teeth, " +
        "so it no longer discriminates the grammar from a text scan",
    );
  });

  it("resolves a name that follows an unbalanced literal", () => {
    assert.ok(names.has("insideProperty"));
  });

  it("resolves a name reached only through a local helper", () => {
    assert.ok(names.has("viaHelper"));
  });

  it("gives no credit to a name outside every property call", () => {
    assert.equal(names.has("notFuzzed"), false);
    assert.equal(names.has("inComment"), false);
  });

  it("blanks imports and comments past an astral character", () => {
    // The emoji is two UTF-16 units and one code point. Walking code points
    // shifts every range after it by one, so the import survives and real code
    // is blanked in its place — and this repo's suites are full of emoji.
    const source = [
      'const flag = "\u{1f3f4}";',
      'import fc from "fast-check";',
      "// insideProperty in a comment",
      "const kept = flag;",
    ].join("\n");
    const { ast, comments } = parseModule(source);
    const lines = strippedSource(source, ast, comments).split("\n");
    // Exact line equality, not `includes`: a one-unit shift still blanks most
    // of the import, and only the boundary characters show which way it moved.
    assert.equal(lines[0], 'const flag = "\u{1f3f4}";');
    assert.equal(lines[1].trim(), "", "the import line is not fully blanked");
    assert.equal(lines[2].trim(), "", "the comment line is not fully blanked");
    assert.equal(lines[3], "const kept = flag;");
  });

  it("captures both property invocations in full and no more", () => {
    // The fixture holds exactly two: the wrapper CALL, and the `fc.assert` in
    // the wrapper's own definition. A short span loses the tail of the first.
    const wrapperCall = FIXTURE.slice(
      wrapperCallStart,
      FIXTURE.indexOf("});", wrapperCallStart) + 2,
    );
    const wrapperBody = "fc.assert(fc.property(arbitrary, predicate), {})";
    assert.ok(
      wrapperCall.endsWith("})"),
      "the wrapper call slice is cut short",
    );
    assert.ok(FIXTURE.includes(wrapperBody));
    assert.equal(spanLength, wrapperCall.length + wrapperBody.length);
  });
});

describe("semantic-fuzz obligation gate", () => {
  it("discovers at least one *-semantic-fuzz.test.mjs suite (gate is not vacuous)", () => {
    assert.ok(
      semanticFuzzFiles.length > 0,
      "no *-semantic-fuzz.test.mjs suites found — the gate would pass vacuously",
    );
    assert.ok(SEMANTIC_FUZZ_REQUIRED.length > 0);
  });

  it("every fuzz-required name is either semantic-required or exempt with a reason", () => {
    // Semantic-fuzz coverage is a stricter obligation layered on top of the
    // structural one, so its population is FUZZ_REQUIRED itself: a name here
    // that isn't in FUZZ_REQUIRED is a drifted entry, and a required name in
    // neither list is an obligation nobody decided.
    assertPartition(
      FUZZ_REQUIRED,
      [SEMANTIC_FUZZ_REQUIRED, Object.keys(SEMANTIC_FUZZ_EXEMPT)],
      "every FUZZ_REQUIRED name must be in SEMANTIC_FUZZ_REQUIRED or in " +
        "SEMANTIC_FUZZ_EXEMPT with the reason its precision is asserted elsewhere",
    );
    for (const [name, reason] of Object.entries(SEMANTIC_FUZZ_EXEMPT))
      assert.ok(reason.length > 0, `${name} carries an empty exemption reason`);
  });

  for (const name of SEMANTIC_FUZZ_REQUIRED) {
    it(`'${name}' is referenced by a *-semantic-fuzz.test.mjs suite`, () => {
      const hits = semanticFuzzFiles.filter((file) => file.fcNames.has(name));
      assert.ok(
        hits.length > 0,
        `${name} is a precision-sensitive entry point (structural fuzzing alone ` +
          `can't catch it corrupting the wrong leaf or missing a payload shape) ` +
          `but no *-semantic-fuzz.test.mjs suite references it — add one ` +
          `(see test/invisible-semantic-fuzz.test.mjs for the pattern) or, if the ` +
          `precision property is truly only assertable through a different named ` +
          `entry point, move this name's coverage there and document why here`,
      );
    });
  }
});

// ─── Threat-alphabet domain coverage ─────────────────────────────────────────
// A fuzz target EXISTING (above) does not prove its input DOMAIN reaches the
// dangerous bytes — a uniform unicode draw lands on U+009B ~1-in-a-million, so a
// suite can run forever and never exercise the C1 passthrough class. This block
// asserts each in-scope suite's SOURCE seeds every THREAT_CODEPOINTS member it
// owes (by any hex/escape spelling), the trap the U+009B bug fell through.

const fuzzFileByName = new Map(fuzzFiles.map((file) => [file.name, file]));

describe("shared-arbitrary seeding credit", () => {
  it("extracts a non-empty span for every shared arbitrary", () => {
    // The Map construction throws on a missing span, so reaching here already
    // proves each one resolved; pin the shape so an extractor that started
    // returning a stray fragment (a lone `export` keyword) is caught too.
    for (const name of SHARED_ARBITRARIES) {
      const span = seedingSpans.get(name);
      assert.ok(span.length > 0, `${name}: empty seeding span`);
      assert.match(
        span,
        new RegExp(`^export const ${name} = fc\\b`),
        `${name}: span does not start at its own declaration`,
      );
      assert.ok(span.includes(".map("), `${name}: span is cut short`);
    }
  });

  it("unicodeChar's span does NOT carry the surrogate bounds it excludes", () => {
    const span = seedingSpans.get("unicodeChar").toLowerCase();
    // Positive markers first: this really is the unicodeChar declaration, so
    // the two negatives below cannot pass by looking at the wrong text.
    assert.ok(span.includes("0x10ffff"), "not the unicodeChar draw");
    assert.equal(
      spellingMatches(0xd800, span),
      false,
      "unicodeChar excludes surrogates, so its importers must not be credited " +
        "for seeding the lone-surrogate threat class",
    );
    assert.ok(!span.includes("0xdfff"));
  });

  it("loneSurrogate's span DOES carry the surrogate bounds it seeds", () => {
    const span = seedingSpans.get("loneSurrogate").toLowerCase();
    assert.ok(spellingMatches(0xd800, span));
    assert.ok(span.includes("0xdfff"));
  });

  it("credits a suite for exactly the shared arbitraries it references", () => {
    assert.ok(
      fuzzFiles.some((file) => file.referencedArbitraries.length > 0),
      "no discovered suite references a shared arbitrary — the credit path is " +
        "never taken, so these assertions would pass vacuously",
    );
    for (const file of fuzzFiles)
      for (const arb of SHARED_ARBITRARIES)
        assert.equal(
          file.code.includes(seedingSpans.get(arb)),
          file.referencedArbitraries.includes(arb),
          `${file.name}: ${arb}'s span is appended iff the suite references it`,
        );
  });

  it("no suite inherits an unreferenced helper export", () => {
    // keptOutsideNeedles' body calls `occurrences` — a name in both
    // FUZZ_REQUIRED and SEMANTIC_FUZZ_REQUIRED — so appending the whole helper
    // let any importer satisfy that obligation without fuzzing it.
    assert.match(
      helperSource,
      /export function keptOutsideNeedles\b[\s\S]*\boccurrences\(/,
      "the helper no longer exports keptOutsideNeedles calling occurrences — " +
        "this guard is now aimed at nothing; re-point it at the current " +
        "non-arbitrary export or delete it",
    );
    for (const file of fuzzFiles) {
      if (file.identifiers.has("keptOutsideNeedles")) continue;
      assert.ok(
        !file.code.includes("keptOutsideNeedles"),
        `${file.name} inherited keptOutsideNeedles' body from test-helpers.mjs`,
      );
    }
  });
});

describe("threat-alphabet domain coverage", () => {
  it("every invisible-detector category (CHECKS) has a representative cp", () => {
    const represented = new Set(
      THREAT_CODEPOINTS.map((entry) => entry.category),
    );
    for (const [category] of CHECKS)
      assert.ok(
        represented.has(category),
        `CHECKS category '${category}' has no THREAT_CODEPOINTS representative — add one so the gate exercises it`,
      );
  });

  it("every discovered fast-check suite is in scope or out of scope", () => {
    assertPartition(
      fuzzFiles.map((file) => file.name),
      [Object.keys(IN_SCOPE_MEMBERS), Object.keys(OUT_OF_SCOPE)],
      "a new fast-check suite must be classified in test/threat-codepoints.mjs: " +
        "add it to IN_SCOPE with the alphabet members it owes, or to " +
        "OUT_OF_SCOPE with the one-line reason it ingests none",
    );
    for (const [name, reason] of Object.entries(OUT_OF_SCOPE))
      assert.ok(
        reason.length > 0,
        `${name} carries an empty out-of-scope reason`,
      );
  });

  it("every IN_SCOPE member is a real THREAT_CODEPOINTS entry (no typo'd cp)", () => {
    for (const [name, members] of Object.entries(IN_SCOPE_MEMBERS))
      for (const cp of members)
        // threat() throws on an unknown cp, so a hand-typed 0x9bb in an in-scope
        // array fails loud here rather than as an unsatisfiable "never seeds" later.
        assert.equal(
          threat(cp).cp,
          cp,
          `IN_SCOPE['${name}'] names 0x${cp.toString(16)}, not in THREAT_CODEPOINTS`,
        );
  });

  it("spellingMatches anchors on hex boundaries (no prefix false positives)", () => {
    // Positive: each accepted spelling of a representative cp matches itself.
    assert.ok(spellingMatches(0x9b, "cp(0x9b)"));
    assert.ok(spellingMatches(0x9b, "cp(0x009b)"));
    assert.ok(spellingMatches(0x07, "cp(0x07)"));
    assert.ok(spellingMatches(0x1f600, "\\u{1f600}"));
    assert.ok(spellingMatches(0x200b, "\\u200b"));
    // Negative: a shorter cp must NOT match as a prefix of a longer hex literal —
    // the U+0007 (0x7) vs the 0x7e ASCII bound is the exact false positive the
    // boundary lookahead exists to kill.
    assert.equal(spellingMatches(0x07, "min: 0x20, max: 0x7e"), false);
    assert.equal(spellingMatches(0x9b, "cp(0x9bc)"), false);
    assert.equal(spellingMatches(0x9b, "\\u009bc"), false);
  });

  for (const [name, members] of Object.entries(IN_SCOPE_MEMBERS)) {
    it(`'${name}' seeds every in-scope threat code point`, () => {
      const file = fuzzFileByName.get(name);
      assert.ok(file, `suite ${name} not found`);
      // A non-empty in-scope set (asserted) over a non-empty source means each
      // pass below is a real per-member check, not a vacuous zero-iteration loop.
      assert.ok(members.length > 0, `${name} has an empty in-scope set`);
      assert.ok(file.code.length > 0, `${name} stripped to empty source`);
      const haystack = file.code.toLowerCase();
      for (const cp of members)
        assert.ok(
          spellingMatches(cp, haystack),
          `${name} never seeds threat cp 0x${cp.toString(16)} ` +
            `(no spelling of ${JSON.stringify(acceptedSpellings(cp))} in its source) — ` +
            `the fuzzer cannot reach it by chance, so the regression class is unguarded`,
        );
    });
  }
});
