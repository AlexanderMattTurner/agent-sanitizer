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
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

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
  acceptedSpellings,
  spellingMatches,
  threat,
} from "./threat-codepoints.mjs";

// Functions that ingest untrusted text/URLs/ranges and so owe a fuzz target.
// Intentionally excluded (documented so the omission is a choice, not a miss):
//   - isSgrOnly, isHiddenOpen, closingTagName: pure short-string predicates
//     with no transform/parse step, covered by example tests and indirectly
//     through their callers.
//   - looksLikeHtmlSource: parses, but returns a verdict rather than a
//     transform, so it has no fuzzable invariant of its own; the verdict is
//     pinned by the exact-verdict corpus in html.test.mjs and both branches it
//     selects are fuzzed through sanitizeHtml.
//   - scanHtmlFragment: has no invariant of its own beyond what the
//     sanitizeHtml round-trip / splice-fidelity properties already assert on
//     its output.
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

// Entry points that owe SEMANTIC-CORRECTNESS fuzzing, not just structural
// fuzzing: a structural property (never-throws, idempotent, shape-preserved)
// can hold in aggregate while a detector corrupts the wrong leaf or misses a
// specific payload shape — exactly the class of false positive that shipped
// in scanText's scatter floor (fixed alongside this gate). A subset of
// FUZZ_REQUIRED: named internal helpers (isHiddenStyle, decodeRun,
// resolveSpan, alignDeletions, rehydrateNewString, stripInvisibleWithReport,
// deleteVerbatimSpans; urlHost's sibling checkExfilUrl is kept since it's
// independently callable) are exercised only THROUGH their public entry
// point in these suites, so requiring their own name to appear here would be
// a false negative, not a stronger check — the precision property is
// asserted at the entry point.
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

// Strip import statements and comments so a required name only counts when it
// appears in actual test code — a function listed in an `import {…}` or named
// in a comment is NOT evidence that a property exercises it.
const stripImportsAndComments = (source) =>
  source
    .replace(/^import\b[\s\S]*?from\s+["'][^"']+["'];?[ \t]*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");

// A name appearing ANYWHERE in a file that merely CONTAINS an `fc.assert(`/
// `fc.property(` call somewhere is not evidence that a PROPERTY exercises
// that name — this repo mixes a handful of property tests into files that
// are otherwise hundreds of lines of ordinary example-based `it(...)` tests
// (test/cli.test.mjs, test/html.test.mjs, test/invisible.test.mjs), so an
// ordinary example test calling e.g. `sanitize(...)` would otherwise satisfy
// "coverage" for `sanitize` even after its actual property test was deleted.
// Narrow the match to only the source WITHIN each `fc.assert(...)` /
// `fc.property(...)` call (balanced-paren scan from the callee's opening
// paren to its matching close) so a name only counts when it is textually
// inside a real property/fuzz invocation.

// Several suites (confusables-property, html-property, prompt-property,
// view-map-property) factor the boilerplate into a one-line local wrapper —
// e.g. `const check = (arbitrary, predicate) =>\n  fc.assert(fc.property(arbitrary, predicate), runOptions);`
// — and drive every property through `check(arb, (x) => ...)`. The predicate
// closure (where a required name actually gets referenced) then sits inside
// the WRAPPER's call, not literally inside `fc.assert(...)`, so a matcher
// that only recognizes the literal fc.* callees would false-negative on
// every one of those suites. Detect such local wrappers by their definition
// (a same-line-or-wrapped arrow whose body directly calls fc.assert/
// fc.property/fc.asyncProperty) and treat calls to them as property
// invocations too.
const WRAPPER_DEF_RE =
  /\bconst\s+(\w+)\s*=\s*\([^)]*\)\s*=>\s*fc\.(?:assert|property|asyncProperty)\(/g;

// Other suites (html-property's containsForbiddenNode/isHiddenElement,
// rehydrate-semantic-fuzz's editCall/rehydrateRedacted and
// ioFor->mkView->occurrences) call the required name only from INSIDE a
// locally-defined helper function's own body, one or more indirection
// levels away from the fc.assert/property call site itself. A name used
// only via such a helper is exercised by the fuzz run exactly as much as one
// referenced directly, so its OWN definition body is pulled in transitively
// below (extractDefinitions + the fixpoint loop in extractFcCallSpans).
const FUNCTION_DEF_RE =
  /\bfunction\s+(\w+)\s*\(|\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(/g;

const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** @returns {number} index of the matching close paren, or -1 */
const findMatchingParen = (code, openIdx) => {
  let depth = 0;
  for (let i = openIdx; i < code.length; i++) {
    if (code[i] === "(") depth++;
    else if (code[i] === ")") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
};

/** @returns {number} index of the matching close brace, or -1 */
const findMatchingBrace = (code, openIdx) => {
  let depth = 0;
  for (let i = openIdx; i < code.length; i++) {
    if (code[i] === "{") depth++;
    else if (code[i] === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
};

/**
 * Finds every named `function NAME(...) {...}` and
 * `const/let/var NAME = (...) => ...` (block- or expression-bodied)
 * definition in `code` and returns a Map from name to its full [start, end)
 * source span (declaration keyword through the body's end).
 * @param {string} code
 * @returns {Map<string, [number, number]>}
 */
const extractDefinitions = (code) => {
  const defs = new Map();
  for (const match of code.matchAll(FUNCTION_DEF_RE)) {
    const name = match[1] ?? match[2];
    const isFunctionKeyword = match[1] !== undefined;
    const parenOpen = match.index + match[0].length - 1;
    const parenClose = findMatchingParen(code, parenOpen);
    if (parenClose === -1) continue;
    let i = parenClose + 1;
    while (i < code.length && /\s/.test(code[i])) i++;
    if (isFunctionKeyword) {
      if (code[i] !== "{") continue;
      const braceClose = findMatchingBrace(code, i);
      if (braceClose === -1) continue;
      defs.set(name, [match.index, braceClose + 1]);
      continue;
    }
    // const/let/var NAME = (...) — only a function definition if an arrow
    // follows the params; `const x = (a + b) * c;` must NOT match.
    if (code.slice(i, i + 2) !== "=>") continue;
    i += 2;
    while (i < code.length && /\s/.test(code[i])) i++;
    if (code[i] === "{") {
      const braceClose = findMatchingBrace(code, i);
      if (braceClose === -1) continue;
      defs.set(name, [match.index, braceClose + 1]);
      continue;
    }
    // Expression-bodied arrow: scan to the top-level (depth-0) terminating
    // semicolon so a body containing its own (), {}, [] doesn't cut short.
    let depth = 0;
    let j = i;
    for (; j < code.length; j++) {
      const c = code[j];
      if (c === "(" || c === "{" || c === "[") depth++;
      else if (c === ")" || c === "}" || c === "]") depth--;
      else if (c === ";" && depth === 0) break;
    }
    defs.set(name, [match.index, Math.min(j + 1, code.length)]);
  }
  return defs;
};

/**
 * Concatenates the source spanned by every `fc.assert(...)`, `fc.property(...)`,
 * `fc.asyncProperty(...)` call, every call to a local wrapper function whose
 * own body directly invokes one of those (WRAPPER_DEF_RE), AND — by
 * fixpoint — the full definition body of any locally-defined helper
 * function called from within source already pulled in (so a name used only
 * inside a helper-of-a-helper, e.g. an `editCall(...)` invoked inside a
 * property that itself calls `rehydrateRedacted(...)`, still counts). Each
 * direct call span runs from the callee's opening paren to its balanced
 * closing paren.
 * @param {string} code
 * @returns {string}
 */
const extractFcCallSpans = (code) => {
  const wrapperNames = new Set(
    [...code.matchAll(WRAPPER_DEF_RE)].map((m) => m[1]),
  );
  const calleeAlternation = [
    "fc\\.assert",
    "fc\\.property",
    "fc\\.asyncProperty",
    ...[...wrapperNames].map(escapeRegExp),
  ].join("|");
  const callStartRe = new RegExp(`\\b(?:${calleeAlternation})\\(`, "g");

  /** @type {[number, number][]} */
  const included = [];
  for (const match of code.matchAll(callStartRe)) {
    const start = match.index;
    const parenOpen = start + match[0].length - 1;
    const parenClose = findMatchingParen(code, parenOpen);
    if (parenClose === -1) continue;
    included.push([start, parenClose + 1]);
  }

  const defs = extractDefinitions(code);
  const pulledIn = new Set();
  let changed = true;
  while (changed) {
    changed = false;
    const currentText = included.map(([s, e]) => code.slice(s, e)).join("\n");
    for (const [name, span] of defs) {
      if (pulledIn.has(name)) continue;
      if (new RegExp(`\\b${escapeRegExp(name)}\\s*\\(`).test(currentText)) {
        pulledIn.add(name);
        included.push(span);
        changed = true;
      }
    }
  }

  return included.map(([s, e]) => code.slice(s, e)).join("\n");
};

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

const helperSource = stripImportsAndComments(
  readFileSync(path.join(testDir, "test-helpers.mjs"), "utf8"),
);

/**
 * The source span of a single `export … <name> …` declaration in `code`: from
 * the `export` keyword to just before the next top-level `export ` (or EOF).
 * @param {string} code
 * @param {string} name
 * @returns {string|null} null when no such declaration exists
 */
const extractExportSpan = (code, name) => {
  const decl = new RegExp(
    `^export\\s+(?:async\\s+)?(?:const|let|var|function)\\s+${escapeRegExp(name)}\\b`,
    "m",
  );
  const match = decl.exec(code);
  if (!match) return null;
  const bodyStart = match.index + match[0].length;
  const next = code.slice(bodyStart).search(/^export\s/m);
  return next === -1
    ? code.slice(match.index)
    : code.slice(match.index, bodyStart + next);
};

/**
 * `.filter(...)` clauses removed. A filter can only REMOVE values from an
 * arbitrary's domain, so a code point named inside one is evidence of an
 * EXCLUSION, never of seeding: `unicodeChar` spells the surrogate bounds
 * 0xd800/0xdfff precisely because it cannot generate them, and crediting its
 * importers for the lone-surrogate class was the false negative this guard
 * exists to prevent. Dropping a narrowing filter can only lose credit (a false
 * negative), which is the direction CLAUDE.md asks these heuristics to fail.
 * @param {string} span
 * @returns {string}
 */
const stripFilterClauses = (span) => {
  let out = span;
  for (;;) {
    const idx = out.indexOf(".filter(");
    if (idx === -1) return out;
    const close = findMatchingParen(out, idx + ".filter".length);
    if (close === -1)
      throw new Error(`unbalanced .filter( in shared-arbitrary span: ${out}`);
    out = out.slice(0, idx) + out.slice(close + 1);
  }
};

/** Shared arbitrary name → the source that evidences what it SEEDS. */
const seedingSpans = new Map(
  SHARED_ARBITRARIES.map((name) => {
    const span = extractExportSpan(helperSource, name);
    if (span === null)
      throw new Error(
        `test-helpers.mjs has no 'export … ${name}' declaration — the ` +
          `shared-arbitrary extraction is stale. Fix it (or drop the name from ` +
          `SHARED_ARBITRARIES): silently appending nothing would re-create the ` +
          `false negative this credit exists to prevent.`,
      );
    const seeding = stripFilterClauses(span).trim();
    if (seeding === "")
      throw new Error(
        `the extracted span for ${name} is empty after removing .filter(…) clauses`,
      );
    return [name, seeding];
  }),
);

const fuzzFiles = readdirSync(testDir)
  .filter((name) => name.endsWith(".test.mjs") && name !== selfName)
  .map((name) => {
    const source = readFileSync(path.join(testDir, name), "utf8");
    const stripped = stripImportsAndComments(source);
    // The import line itself is stripped, so a name surviving in `stripped` is
    // a real use; requiring the helper import too keeps a same-named local
    // arbitrary from claiming the shared one's credit.
    const referencedArbitraries = source.includes('from "./test-helpers.mjs"')
      ? SHARED_ARBITRARIES.filter((arb) =>
          new RegExp(`\\b${escapeRegExp(arb)}\\b`).test(stripped),
        )
      : [];
    const code = [
      stripped,
      ...referencedArbitraries.map((arb) => seedingSpans.get(arb)),
    ].join("\n");
    return {
      name,
      source,
      code,
      referencedArbitraries,
      fcCode: extractFcCallSpans(code),
    };
  })
  .filter((file) => file.source.includes("fc.assert("));

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
    sanitizeOutputHook,
    pretooluseHook,
  ]
    .flatMap((mod) => Object.entries(mod))
    .filter(([, value]) => typeof value === "function"),
);

describe("fuzz-coverage obligation gate", () => {
  it("discovers at least one fast-check suite (gate is not vacuous)", () => {
    assert.ok(
      fuzzFiles.length > 0,
      "no fast-check suites found — the gate would pass vacuously",
    );
    assert.ok(FUZZ_REQUIRED.length > 0);
  });

  it("the fc-call span extractor actually finds spans (gate is not vacuous)", () => {
    // Guards against the extractor silently matching nothing (e.g. a
    // refactor to a callee spelling FC_CALL_START_RE no longer matches),
    // which would make every "is referenced by a fast-check suite" check
    // below fail closed for the wrong reason instead of proving coverage.
    const totalSpanLength = fuzzFiles.reduce(
      (sum, file) => sum + file.fcCode.length,
      0,
    );
    assert.ok(
      totalSpanLength > 0,
      "extractFcCallSpans found no fc.assert/fc.property spans in any " +
        "discovered fuzz file — the span-narrowed match would pass vacuously",
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
      const wordRe = new RegExp(`\\b${name}\\b`);
      // Match only within the text spans of actual fc.assert(...)/
      // fc.property(...) calls, not anywhere in a file that merely contains
      // such a call elsewhere (see extractFcCallSpans above).
      const hits = fuzzFiles.filter((file) => wordRe.test(file.fcCode));
      assert.ok(
        hits.length > 0,
        `${name} handles untrusted input but no property/fuzz suite's ` +
          `fc.assert/fc.property call references it`,
      );
    });
  }
});

describe("semantic-fuzz obligation gate", () => {
  it("discovers at least one *-semantic-fuzz.test.mjs suite (gate is not vacuous)", () => {
    assert.ok(
      semanticFuzzFiles.length > 0,
      "no *-semantic-fuzz.test.mjs suites found — the gate would pass vacuously",
    );
    assert.ok(SEMANTIC_FUZZ_REQUIRED.length > 0);
  });

  it("every SEMANTIC_FUZZ_REQUIRED name is also in FUZZ_REQUIRED", () => {
    // Semantic-fuzz coverage is a stricter obligation layered on top of the
    // structural one; a name here that isn't in FUZZ_REQUIRED is a drifted
    // entry, not a real additional target.
    for (const name of SEMANTIC_FUZZ_REQUIRED)
      assert.ok(
        FUZZ_REQUIRED.includes(name),
        `${name} is in SEMANTIC_FUZZ_REQUIRED but not FUZZ_REQUIRED`,
      );
  });

  for (const name of SEMANTIC_FUZZ_REQUIRED) {
    it(`'${name}' is referenced by a *-semantic-fuzz.test.mjs suite`, () => {
      const wordRe = new RegExp(`\\b${name}\\b`);
      const hits = semanticFuzzFiles.filter((file) => wordRe.test(file.fcCode));
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
      if (stripImportsAndComments(file.source).includes("keptOutsideNeedles"))
        continue;
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

  it("every IN_SCOPE suite file actually exists and drives fast-check", () => {
    for (const name of Object.keys(IN_SCOPE_MEMBERS))
      assert.ok(
        fuzzFileByName.has(name),
        `IN_SCOPE names '${name}' but no such fast-check suite was discovered — stale entry or renamed file`,
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
