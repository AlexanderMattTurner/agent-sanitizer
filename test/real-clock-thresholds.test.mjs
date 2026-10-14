/**
 * A clock reading may decide a verdict only through the budget helper.
 *
 * A tight timing threshold reports on the machine as much as on the code: it
 * passes locally and goes red on a loaded runner, and every such flake this
 * repo has had was "fixed" by widening one number until the next load spike.
 * The class is closed at the root instead. A test of a deadline, a budget or a
 * timer drives an injected clock (`now`, `cpuNow`, a stubbed `remainingMs`);
 * a test of COST calls `assertUnderBudget` in `test/helpers/budget.mjs` — one
 * warm run against an absolute ceiling ten times or more above the linear
 * cost — which is the one module here allowed to read a clock for a verdict.
 *
 * What counts as a threshold: an assertion whose argument compares a real-clock
 * reading — directly, through a variable or property assigned from one, or
 * through a helper returning one — against something that is not itself a
 * clock reading. A reading also arrives through an ACCESSOR imported from a
 * module that reads the clock for the test (`timer.wallMs()`; see
 * {@link CLOCK_ACCESSORS}), because the taint is
 * per-file and the clock itself is not in sight. Reading a clock is fine
 * everywhere else: a polling deadline (`while (Date.now() < deadline)`), a
 * busy-wait standing in for slow work, a timestamp for an mtime, or a real clock
 * fed INTO the code under test. Those decide how long a test waits, never
 * whether it passes.
 *
 * The accessor vocabulary cannot rot silently: a test below fails when a listed
 * accessor stops existing, and when a clock-returning export of the harness or a
 * new reader on the hook timer is missing from it.
 *
 * The twin for `tests/**\/*.py` is `tests/test_real_clock_thresholds.py`.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "acorn";
import { full, fullAncestor } from "acorn-walk";
import * as budget from "./helpers/budget.mjs";
import { startHookTimer } from "../claude-hooks/lib/hook-timing.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

/** The budget helper: the one place a clock reading may decide a verdict. */
const HARNESS = new Set(["test/helpers/budget.mjs"]);

/**
 * Every real-clock read the scan recognizes, as `object.method` paths. The list
 * is the guard's whole vocabulary; a test below proves each entry is detected.
 */
const CLOCK_READS = [
  "Date.now",
  "performance.now",
  "process.hrtime",
  "process.hrtime.bigint",
  "process.cpuUsage",
];

/**
 * Functions that hand a test a clock reading without the test calling a clock,
 * matched by the last segment of the callee (`timer.wallMs()` and `wallMs()`
 * alike). The scan is per-file, so a reading surfaced by an imported accessor
 * would otherwise be invisible and every threshold on it would survive.
 * - the harness's: none. `assertUnderBudget` decides inside the harness and
 *   returns nothing, and a test below holds every other export to the same;
 * - the hook timer's readers, the four methods `startHookTimer()` returns. They
 *   are exact under an injected clock and a real reading otherwise, and a test
 *   cannot tell which from the call site, so any threshold on one is flagged.
 */
/** @type {string[]} */
const HARNESS_ACCESSORS = [];
const TIMER_ACCESSORS = ["wallMs", "cpuMs", "redactorMs", "hostMs"];
const CLOCK_ACCESSORS = [...HARNESS_ACCESSORS, ...TIMER_ACCESSORS];

const RELATIONAL = new Set(["<", "<=", ">", ">="]);

/** `a.b.c` for a member chain of plain identifiers, else null. */
function dotted(node) {
  if (node.type === "Identifier") return node.name;
  if (node.type === "ThisExpression") return "this";
  if (node.type !== "MemberExpression" || node.computed) return null;
  const head = dotted(node.object);
  return head === null ? null : `${head}.${node.property.name}`;
}

/** Is `callee` (a dotted path) a real-clock read or an imported clock accessor? */
function isClockCall(callee) {
  return (
    callee !== null &&
    (CLOCK_READS.includes(callee) ||
      CLOCK_ACCESSORS.includes(callee.split(".").pop() ?? ""))
  );
}

/** Every identifier a binding pattern (`{a, b: [c]}`, `[d, ...e]`) introduces. */
function boundNames(pattern) {
  switch (pattern.type) {
    case "Identifier":
      return [pattern.name];
    case "ObjectPattern":
      return pattern.properties.flatMap((p) =>
        boundNames(p.type === "RestElement" ? p.argument : p.value),
      );
    case "ArrayPattern":
      return pattern.elements.flatMap((e) => (e ? boundNames(e) : []));
    case "AssignmentPattern":
      return boundNames(pattern.left);
    case "RestElement":
      return boundNames(pattern.argument);
    default:
      return [];
  }
}

/** Is `node` an assertion call — `assert(...)`, `assert.x(...)`, `t.assert.x(...)`? */
function isAssertion(node) {
  if (node.type !== "CallExpression") return false;
  const callee = dotted(node.callee);
  return callee !== null && /(^|\.)assert(\.|$)/u.test(callee);
}

const FUNCTIONS = new Set([
  "ArrowFunctionExpression",
  "FunctionExpression",
  "FunctionDeclaration",
]);

/**
 * Does any node under `root` satisfy `test`, outside any function nested in
 * it? A function VALUE is not a reading: a clock inside a callback handed to
 * the code under test (`remainingMs: () => budget - (Date.now() - s)`) reaches
 * no assertion. What a named function RETURNS is followed separately.
 */
function contains(root, test) {
  let found = false;
  fullAncestor(root, (node, _state, ancestors) => {
    if (!ancestors.some((a) => FUNCTIONS.has(a.type))) found ||= test(node);
  });
  return found;
}

/**
 * The names in `program` that carry a real-clock reading: variables and
 * properties assigned from one, and functions returning one. Name-based and
 * file-wide, iterated to a fixed point, so a reading reaches an assertion
 * through any number of hops. Coarse on purpose: a name reused for something
 * unrelated is flagged, and renaming it is the fix.
 * @param {import("acorn").Program} program
 * @returns {(node: import("acorn").Node) => boolean} is `node` clock-derived?
 */
function clockDerived(program) {
  const tainted = new Set();
  const derived = (/** @type {any} */ root) =>
    contains(root, (/** @type {any} */ node) => {
      if (node.type === "CallExpression") {
        const callee = dotted(node.callee);
        if (isClockCall(callee)) return true;
        if (callee !== null && tainted.has(callee)) return true;
      }
      // A member read matches by its FULL path: the walker never visits a
      // non-computed property as an Identifier, so `timing.elapsed` is only
      // seen as the path "timing.elapsed".
      if (node.type === "MemberExpression") {
        const path = dotted(node);
        if (path !== null && tainted.has(path)) return true;
      }
      return node.type === "Identifier" && tainted.has(node.name);
    });
  for (let before = -1; tainted.size !== before;) {
    before = tainted.size;
    full(program, (/** @type {any} */ node) => {
      const mark = (/** @type {string | null} */ name, value) => {
        if (name === null || !value) return;
        // An object carries the readings stored on it (`best.wall = ...`), so
        // handing the object on (`return best`) hands the reading on.
        const holder =
          value.type === "Identifier" &&
          [...tainted].some((path) => path.startsWith(`${value.name}.`));
        if (holder || derived(value)) tainted.add(name);
      };
      if (node.type === "VariableDeclarator") {
        const init = node.init;
        const fn =
          init &&
          (init.type === "ArrowFunctionExpression" ||
            init.type === "FunctionExpression");
        if (fn && node.id.type === "Identifier")
          markReturns(node.id.name, init, mark);
        else for (const name of boundNames(node.id)) mark(name, init);
      }
      if (node.type === "AssignmentExpression") {
        // `store[key] = reading` has no dotted name of its own: taint the
        // container, so a later `store[other]` read is seen as derived too.
        const left = node.left;
        mark(
          left.type === "MemberExpression" && left.computed
            ? dotted(left.object)
            : dotted(left),
          node.right,
        );
      }
      if (node.type === "Property" && !node.computed && node.key.name)
        mark(node.key.name, node.value);
      if (node.type === "FunctionDeclaration" && node.id)
        markReturns(node.id.name, node, mark);
    });
  }
  return derived;
}

/** Taint a function's name when anything it returns is clock-derived. */
function markReturns(name, fn, mark) {
  if (fn.body.type !== "BlockStatement") {
    mark(name, fn.body);
    return;
  }
  // A return inside a nested function is that function's, not this one's.
  fullAncestor(fn.body, (/** @type {any} */ node, _state, ancestors) => {
    if (
      node.type === "ReturnStatement" &&
      !ancestors.some((a) => FUNCTIONS.has(a.type))
    )
      mark(name, node.argument);
  });
}

/**
 * Every real-clock threshold in `source`, as `line: text` strings, plus how many
 * clock reads the file holds at all.
 * @param {string} source
 * @returns {{thresholds: string[], reads: number}}
 */
export function scan(source) {
  const program = parse(source, {
    ecmaVersion: "latest",
    sourceType: "module",
    locations: true,
  });
  const derived = clockDerived(program);
  const thresholds = [];
  let reads = 0;
  full(program, (/** @type {any} */ node) => {
    if (
      node.type === "CallExpression" &&
      CLOCK_READS.includes(dotted(node.callee) ?? "")
    )
      reads++;
    if (!isAssertion(node)) return;
    for (const arg of node.arguments)
      full(arg, (/** @type {any} */ cmp) => {
        if (cmp.type !== "BinaryExpression" || !RELATIONAL.has(cmp.operator))
          return;
        // A clock against a clock (`after >= before`) is ordering, not a
        // threshold the machine's speed can push either side of.
        if (derived(cmp.left) !== derived(cmp.right))
          thresholds.push(
            `${cmp.loc.start.line}: ${source.slice(cmp.start, cmp.end)}`,
          );
      });
  });
  return { thresholds, reads };
}

/**
 * The functions `source` exports that reach a real clock, through any chain of
 * the module's own functions, AND hand a value back. By call graph rather than
 * by data flow: a pure helper (say, one fitting a curve to readings) shares
 * parameter names with the readings beside it and would be swept in, while an
 * `assert*` that probes a clock and returns nothing gives a test no reading to
 * compare.
 * @param {string} source
 * @returns {string[]}
 */
export function clockReadingExports(source) {
  const program = parse(source, {
    ecmaVersion: "latest",
    sourceType: "module",
  });
  /** @type {Map<string, any>} */
  const fns = new Map();
  const exported = [];
  for (const top of /** @type {any[]} */ (program.body)) {
    const decl = top.type === "ExportNamedDeclaration" ? top.declaration : top;
    if (!decl) continue;
    const entries =
      decl.type === "VariableDeclaration"
        ? decl.declarations.map((d) => [d.id.name, d.init])
        : [[decl.id?.name, decl]];
    for (const [name, fn] of entries)
      if (name && fn && FUNCTIONS.has(fn.type)) {
        fns.set(name, fn);
        if (top.type === "ExportNamedDeclaration") exported.push(name);
      }
  }
  const calls = (/** @type {any} */ fn) => {
    const names = [];
    full(fn.body, (/** @type {any} */ node) => {
      if (node.type === "CallExpression") names.push(dotted(node.callee) ?? "");
    });
    return names;
  };
  const reaches = new Set();
  for (let before = -1; reaches.size !== before;) {
    before = reaches.size;
    for (const [name, fn] of fns)
      if (calls(fn).some((c) => CLOCK_READS.includes(c) || reaches.has(c)))
        reaches.add(name);
  }
  const returnsValue = (/** @type {any} */ fn) => {
    if (fn.body.type !== "BlockStatement") return true;
    let found = false;
    fullAncestor(fn.body, (/** @type {any} */ node, _state, ancestors) => {
      if (
        node.type === "ReturnStatement" &&
        node.argument &&
        !ancestors.some((a) => FUNCTIONS.has(a.type))
      )
        found = true;
    });
    return found;
  };
  return exported.filter((n) => reaches.has(n) && returnsValue(fns.get(n)));
}

/** Every `.mjs` file under `test/`, as repo-relative paths. */
function testFiles(dir = join(ROOT, "test")) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return testFiles(path);
    return entry.name.endsWith(".mjs") ? [relative(ROOT, path)] : [];
  });
}

describe("real-clock thresholds", () => {
  const files = testFiles();
  const results = Object.fromEntries(
    files.map((file) => [file, scan(readFileSync(join(ROOT, file), "utf8"))]),
  );

  it("no test outside the cost-gate harness asserts against a real clock", () => {
    const offenders = Object.entries(results)
      .filter(([file]) => !HARNESS.has(file))
      .flatMap(([file, { thresholds }]) =>
        thresholds.map((hit) => `${file}:${hit}`),
      );
    assert.deepEqual(
      offenders,
      [],
      "drive an injected clock for a deadline/budget/timer test, or bound cost with assertUnderBudget from test/helpers/budget.mjs",
    );
  });

  it("the scan reads the real tree and finds the clock reads in it", () => {
    // Non-vacuity: a scan that parsed nothing, or a vocabulary that no longer
    // matches how this tree reads a clock, would report zero offenders forever.
    assert.ok(files.length > 50, `only ${files.length} test files found`);
    const outside = Object.entries(results)
      .filter(([file]) => !HARNESS.has(file))
      .reduce((n, [, { reads }]) => n + reads, 0);
    assert.ok(outside > 0, "no clock read found outside the harness");
    for (const file of HARNESS) {
      assert.ok(file in results, `${file} is exempt but no longer exists`);
      assert.ok(results[file].reads > 0, `${file} no longer reads a clock`);
      // Positive marker for the invariant itself: the harness holds exactly
      // one clock-against-ceiling verdict, and the scan sees it. A helper that
      // stopped deciding — or a scan that stopped recognizing its idiom —
      // would leave every budget in the tree checking nothing.
      assert.equal(
        results[file].thresholds.length,
        1,
        `${file} should decide in exactly one assertion: ${results[file].thresholds}`,
      );
    }
    // ...and that verdict is reached from the tests: a helper nothing calls
    // exempts a file for no reason.
    const callers = files.filter((file) =>
      /\bassertUnderBudget\(/u.test(readFileSync(join(ROOT, file), "utf8")),
    );
    assert.ok(
      callers.filter((file) => !HARNESS.has(file)).length >= 4,
      `assertUnderBudget is called from only: ${callers}`,
    );
  });

  it("every listed accessor exists in the module it names", () => {
    // A vocabulary entry for a function that was renamed away detects nothing
    // and says nothing, so each one is checked against the live module.
    for (const name of HARNESS_ACCESSORS)
      assert.equal(typeof budget[name], "function", name);
    assert.equal(typeof budget.assertUnderBudget, "function");
    const timer = startHookTimer(
      () => 0,
      () => 0,
    );
    for (const name of TIMER_ACCESSORS)
      assert.equal(typeof timer[name], "function", name);
  });

  it("no clock-returning accessor of those modules is missing from the vocabulary", () => {
    // The timer's readers are enumerated from the live object, the harness's
    // from a call-graph scan of its source, so a new accessor that
    // returns a reading fails here instead of escaping every file that imports it.
    const timer = startHookTimer(
      () => 0,
      () => 0,
    );
    assert.deepEqual(Object.keys(timer).sort(), [...TIMER_ACCESSORS].sort());
    const returning = clockReadingExports(
      readFileSync(join(ROOT, [...HARNESS][0]), "utf8"),
    );
    assert.deepEqual(returning.sort(), [...HARNESS_ACCESSORS].sort());
  });

  it("the accessor scan finds an export that returns a reading, and only that", () => {
    // Non-vacuity for the check above, which now expects the harness to
    // return no reading at all: an empty answer must come from the source,
    // not from a scan that finds nothing anywhere.
    const source = [
      "const cpuSince = (m) => process.cpuUsage(m).user;",
      "export function measure(fn) { const m = process.cpuUsage(); fn(); return cpuSince(m); }",
      "export function assertFast(fn) { const m = process.cpuUsage(); fn(); assert.ok(cpuSince(m) < 5); }",
      "export const pure = (x) => x * 2;",
    ].join("\n");
    assert.deepEqual(clockReadingExports(source), ["measure"]);
  });

  // Each idiom the guard must catch, built around every clock read in the
  // vocabulary, so a read that falls out of detection fails here by name.
  const OFFENDERS = {
    direct: (read) =>
      `const t0 = ${read}(); work(); assert.ok(${read}() - t0 < 2000);`,
    "via a variable": (read) =>
      `const t0 = ${read}(); work(); const ms = ${read}() - t0;\nassert.ok(ms < 2000, "slow");`,
    "via a returned property": (read) =>
      `async function timed() { const s = ${read}(); return { elapsedMs: ${read}() - s }; }\nconst { elapsedMs } = await timed();\nassert.ok(elapsedMs < 4000);`,
    "via a helper's return": (read) =>
      `const cost = () => { const s = ${read}(); work(); return ${read}() - s; };\nassert.ok(cost() / 8 <= LIMIT);`,
    "against a named constant": (read) =>
      `let spent = ${read}(); spent = ${read}() - spent; assert(spent > BUDGET / 2);`,
    "via an assigned member path": (read) =>
      `const timing = {}; const start = ${read}(); work(); timing.elapsed = ${read}() - start;\nassert.ok(timing.elapsed < LIMIT);`,
    "via an assigned this-member": (read) =>
      `class T { run() { const s = ${read}(); this.elapsed = ${read}() - s; assert.ok(this.elapsed < LIMIT); } }`,
  };
  const ACCESSOR_CALLS = [
    ...HARNESS_ACCESSORS,
    ...TIMER_ACCESSORS.map((name) => `timer.${name}`),
  ];
  for (const read of [...CLOCK_READS, ...ACCESSOR_CALLS])
    for (const [idiom, build] of Object.entries(OFFENDERS))
      it(`flags ${read} compared ${idiom}`, () => {
        assert.equal(scan(build(read)).thresholds.length, 1);
      });

  // The idioms that carry an imported accessor's reading to an assertion in a
  // file that never names a clock.
  const IMPORTED = {
    "a timer reader after a real wait":
      "const timer = startHookTimer(); await sleep(50);\nassert.ok(timer.wallMs() >= 45); assert.ok(timer.cpuMs() < 40);",
    "a timer reader's delta":
      "const before = timer.cpuMs(); run();\nassert.ok(timer.cpuMs() - before < 40);",
  };
  for (const [idiom, source] of Object.entries(IMPORTED))
    it(`flags ${idiom}`, () => {
      assert.ok(scan(source).thresholds.length >= 1);
    });

  // The hops a reading takes to an assertion inside one file, each of which
  // the taint has to follow — the shapes the cost gates themselves used before
  // every clock verdict moved into the budget helper.
  const HOPS = {
    "a field through a local wrapper":
      "const calibrate = async () => { const m = process.cpuUsage(); await pass(); return process.cpuUsage(m).user; };\nconst timing = {};\ntiming.unit = await calibrate();\nassert.ok(timing.unit > 0.1);",
    "a reading stored under a computed key":
      "const timing = { realistic: {} };\nconst s = performance.now(); run();\ntiming.realistic[entry] = performance.now() - s;\nassert.ok(timing.realistic[entry] <= CEILING);",
    "an object returned with a stored reading":
      "function sample() { const best = { cpu: Infinity }; best.cpu = performance.now(); return best; }\nconst s = sample();\nassert.ok(s.cpu < LIMIT);",
    "a destructured field of a returned reading":
      "function sample() { const s = performance.now(); run(); return { cpu: performance.now() - s }; }\nconst { cpu } = sample();\nassert.ok(cpu <= BUDGET);",
  };
  for (const [idiom, source] of Object.entries(HOPS))
    it(`flags ${idiom}`, () => {
      assert.equal(scan(source).thresholds.length, 1);
    });

  // The uses that decide how long a test waits, never whether it passes.
  const BENIGN = {
    "a polling deadline":
      "const deadline = Date.now() + 5000;\nwhile (Date.now() < deadline && !ready()) await sleep(10);\nassert.ok(ready());",
    "a busy-wait standing in for slow work":
      "const until = Date.now() + 60; while (Date.now() < until) spin();",
    "a timestamp for an mtime":
      "const old = new Date(Date.now() - TTL - 60_000); utimesSync(p, old, old); assert.equal(read(p), null);",
    "a real clock fed to the code under test":
      "const s = Date.now(); const r = run({ remainingMs: () => budget - (Date.now() - s) }); assert.match(r, /x/);",
    "a driven clock":
      "let now = 0; tick(() => now); now += 60; assert.equal(charged(), 60);",
    "clock ordering":
      "const a = Date.now(); const b = Date.now(); assert.ok(b >= a);",
    "a timer reader against a timer reader":
      "assert.ok(timer.cpuMs() < timer.hostMs());",
    "an exact equality on a driven timer":
      "const timer = startHookTimer(now, cpuNow); assert.equal(timer.wallMs(), 250);",
    "a harness verdict":
      "await assertUnderBudget(t, 'x', 500, (attempt) => input(attempt), run);",
    "an untainted member beside a tainted one":
      "const timing = {}; timing.elapsed = Date.now() - Date.now(); timing.count = 3; assert.ok(timing.count < LIMIT); assert.ok(other.elapsed < LIMIT);",
  };
  for (const [idiom, source] of Object.entries(BENIGN))
    it(`does not flag ${idiom}`, () => {
      assert.deepEqual(scan(source).thresholds, []);
    });
});
