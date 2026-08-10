/**
 * Every engine name the hook layer binds must exist in the PINNED engine.
 *
 * The plugin bundle resolves the hooks' `agent-sanitizer` specifiers to the
 * `sanitizer-engine` npm alias — a published release that trails this repo — so
 * a hook may only use API the pin already ships. Reaching for an export added
 * on main binds `undefined` at load, and the hook then fails CLOSED on every
 * payload it was supposed to sanitize. Nothing in the source says which names
 * are safe, and the symptom (a hook that refuses everything) does not name the
 * missing export, so this resolves the question mechanically: destructure sites
 * are read off acorn's AST, and each name is looked up in the pinned engine's
 * real module namespace.
 *
 * A red here is not a reason to widen the pin's imports — it says either the
 * hook must derive the value from primitives the pin already exports, or the
 * `sanitizer-engine` pin in package.json has to move to a release carrying it.
 */
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import assert from "node:assert/strict";
import { describe, it, before } from "node:test";

import { parse } from "acorn";

import { BUNDLE_TARGETS } from "../scripts/lib/bundle-esbuild.mjs";

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();

/** The engine specifier prefix the bundle aliases, and what it aliases to. */
const ENGINE = "agent-sanitizer";
const PIN = "sanitizer-engine";

/** Hook-layer sources: what the plugin bundle is built from. */
const hookSources = () =>
  // Both pathspecs: git's `**/` requires an intermediate directory, so the
  // recursive form alone silently skips the hook entry points at the root.
  execFileSync(
    "git",
    ["ls-files", "claude-hooks/*.mjs", "claude-hooks/**/*.mjs"],
    {
      cwd: repoRoot,
      encoding: "utf8",
    },
  )
    .split("\n")
    .filter((path) => path && !path.endsWith(".test.mjs"));

/** Every node in the tree, so a binding nested in a function is seen too. */
function* nodes(node) {
  if (node === null || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const item of node) yield* nodes(item);
    return;
  }
  if (typeof node.type !== "string") return;
  yield node;
  for (const value of Object.values(node)) yield* nodes(value);
}

/** The engine specifier a `lazyImport("…")` / `import("…")` call names, if any. */
function engineSpecifier(node) {
  if (node.type === "ImportExpression") return engineLiteral(node.source);
  if (
    node.type !== "CallExpression" ||
    node.callee.type !== "Identifier" ||
    node.callee.name !== "lazyImport"
  )
    return null;
  return engineLiteral(node.arguments[0]);
}

/** The engine specifier `arg` is, as a string literal, or null. */
function engineLiteral(arg) {
  if (arg?.type !== "Literal" || typeof arg.value !== "string") return null;
  return arg.value === ENGINE || arg.value.startsWith(`${ENGINE}/`)
    ? arg.value
    : null;
}

/**
 * Every `{ A, B: local } = <engine load>` and `import { A } from "<engine>"` in
 * the hook layer, as {file, specifier, name} rows.
 *
 * Deliberately only these two forms: they are how the layer actually binds
 * engine API, and a namespace threaded through a variable and read by member
 * access later cannot be resolved without type inference — a guess there would
 * report names the engine never had to export.
 */
function engineBindings(file, source) {
  const rows = [];
  for (const node of nodes(
    parse(source, {
      ecmaVersion: "latest",
      sourceType: "module",
    }),
  )) {
    if (
      node.type === "ImportDeclaration" &&
      (node.source.value === ENGINE ||
        String(node.source.value).startsWith(`${ENGINE}/`))
    )
      for (const spec of node.specifiers)
        if (spec.type === "ImportSpecifier")
          rows.push({
            file,
            specifier: node.source.value,
            name: spec.imported.name,
          });
    if (node.type !== "VariableDeclarator" || node.id.type !== "ObjectPattern")
      continue;
    const specifier = [...nodes(node.init)]
      .map(engineSpecifier)
      .find((found) => found !== null);
    if (!specifier) continue;
    for (const property of node.id.properties)
      if (property.type === "Property" && property.key.type === "Identifier")
        rows.push({ file, specifier, name: property.key.name });
  }
  return rows;
}

/** @type {Array<{file: string, specifier: string, name: string}>} */
let bindings = [];
/** @type {Map<string, object>} */
const namespaces = new Map();

before(async () => {
  bindings = hookSources().flatMap((file) =>
    engineBindings(file, readFileSync(join(repoRoot, file), "utf8")),
  );
  for (const { specifier } of bindings)
    if (!namespaces.has(specifier))
      namespaces.set(specifier, await import(specifier.replace(ENGINE, PIN)));
});

describe("the hook layer against the pinned engine", () => {
  it("binds only names the pin exports", () => {
    const version = JSON.parse(
      readFileSync(join(repoRoot, "package.json"), "utf8"),
    ).devDependencies[PIN];
    const missing = bindings.filter(
      ({ specifier, name }) => !(name in namespaces.get(specifier)),
    );
    assert.deepEqual(
      missing,
      [],
      `these hook bindings do not exist in the pinned engine (${version}) — ` +
        "derive them from primitives the pin exports, or move the pin",
    );
  });

  // `claude-hooks/` is scanned because that is where the aliased bundle's entry
  // lives. Were a second target to adopt the alias — or this one to move — the
  // scan above would keep passing while checking the wrong tree.
  it("scans the tree the pin's alias actually applies to", () => {
    const aliased = BUNDLE_TARGETS.filter(
      (target) => target.alias?.[ENGINE] === PIN,
    );
    assert.equal(aliased.length, 1);
    // Compared as a tail, not against `repoRoot`: Stryker runs this from a
    // sandbox copy, where the target's absolute entry is under the sandbox
    // while `git rev-parse` still answers with the real checkout.
    assert.ok(
      aliased[0].entry.endsWith(join("claude-hooks", "plugin-hooks.mjs")),
      `the aliased bundle entry moved to ${aliased[0].entry}`,
    );
  });

  // The scan is a source read, so it keeps passing if the pattern it looks for
  // is refactored away: pin the sites it must still find.
  it("reads the sites it exists to check", () => {
    const seen = new Set(
      bindings.map(
        ({ file, specifier, name }) => `${file} ${specifier} ${name}`,
      ),
    );
    for (const site of [
      "claude-hooks/lib/authored-content.mjs agent-sanitizer/invisible STRIP",
      "claude-hooks/lib/authored-content.mjs agent-sanitizer/invisible LONG_RUN_THRESHOLD",
      "claude-hooks/lib/authored-content.mjs agent-sanitizer stripAnsiFully",
      "claude-hooks/scan-invisible-chars.mjs agent-sanitizer/instructions scanText",
    ])
      assert.ok(seen.has(site), `the AST scan no longer finds: ${site}`);
    assert.ok(
      new Set(bindings.map((row) => row.file)).size >= 3,
      `only ${new Set(bindings.map((row) => row.file)).size} hook files bind engine API`,
    );
  });
});
