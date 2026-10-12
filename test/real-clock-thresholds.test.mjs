/**
 * No test outside the cost-gate harness passes or fails on a real-clock reading.
 *
 * A wall-clock threshold reports on the machine as much as on the code: it
 * passes locally and goes red on a loaded runner, and every such flake this
 * repo has had was "fixed" by widening one number until the next load spike.
 * The class is closed at the root instead. A test of a deadline, a budget or a
 * timer drives an injected clock (`now`, `cpuNow`, a stubbed `remainingMs`);
 * a test of COST goes through `test/helpers/cpu-timing.mjs`, whose estimator
 * fits a growth exponent from interleaved CPU samples and is the one module
 * here allowed to read a clock for a verdict.
 *
 * What counts as a threshold: an assertion whose argument compares a real-clock
 * reading — directly, through a variable or property assigned from one, or
 * through a helper returning one — against something that is not itself a
 * clock reading. Reading a clock is fine everywhere else: a polling deadline
 * (`while (Date.now() < deadline)`), a busy-wait standing in for slow work, a
 * timestamp for an mtime, or a real clock fed INTO the code under test. Those
 * decide how long a test waits, never whether it passes.
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

const ROOT = fileURLToPath(new URL("..", import.meta.url));

/** The cost-gate harness: the one place a clock reading may decide a verdict. */
const HARNESS = new Set(["test/helpers/cpu-timing.mjs"]);

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

const RELATIONAL = new Set(["<", "<=", ">", ">="]);

/** `a.b.c` for a member chain of plain identifiers, else null. */
function dotted(node) {
  if (node.type === "Identifier") return node.name;
  if (node.type !== "MemberExpression" || node.computed) return null;
  const head = dotted(node.object);
  return head === null ? null : `${head}.${node.property.name}`;
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
        if (CLOCK_READS.includes(callee ?? "")) return true;
        if (callee !== null && tainted.has(callee)) return true;
      }
      return node.type === "Identifier" && tainted.has(node.name);
    });
  for (let before = -1; tainted.size !== before;) {
    before = tainted.size;
    full(program, (/** @type {any} */ node) => {
      const mark = (/** @type {string | null} */ name, value) => {
        if (name !== null && value && derived(value)) tainted.add(name);
      };
      if (node.type === "VariableDeclarator" && node.id.type === "Identifier") {
        const init = node.init;
        const fn =
          init &&
          (init.type === "ArrowFunctionExpression" ||
            init.type === "FunctionExpression");
        if (fn) markReturns(node.id.name, init, mark);
        else mark(node.id.name, init);
      }
      if (node.type === "AssignmentExpression") {
        const target = node.left;
        mark(
          target.type === "MemberExpression"
            ? (target.property.name ?? null)
            : (dotted(target) ?? null),
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
      "drive an injected clock for a deadline/budget/timer test, or measure cost through test/helpers/cpu-timing.mjs",
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
    }
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
  };
  for (const read of CLOCK_READS)
    for (const [idiom, build] of Object.entries(OFFENDERS))
      it(`flags ${read} compared ${idiom}`, () => {
        assert.equal(scan(build(read)).thresholds.length, 1);
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
  };
  for (const [idiom, source] of Object.entries(BENIGN))
    it(`does not flag ${idiom}`, () => {
      assert.deepEqual(scan(source).thresholds, []);
    });
});
