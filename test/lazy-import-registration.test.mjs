/**
 * The registry↔lazyImport contract: every bare package a hook binds through
 * `lazyImport` must have a `LAZY_LOADERS` entry in `claude-hooks/plugin-hooks.mjs`.
 *
 * Why this needs a test rather than a comment. The plugin ships an esbuild
 * BUNDLE with no node_modules, and esbuild inlines only imports whose specifier
 * it can read statically. `await import("agent-sanitizer/prompt")` qualifies;
 * `lazyImport(spec)` does not, because the specifier is a variable inside a
 * helper. So the registry is the manual replacement for inlining the indirection
 * destroyed — and a hook that starts binding a new subpath through lazyImport
 * silently stops resolving it inside the bundle, failing that gate closed on
 * every payload with nothing red.
 *
 * That is not hypothetical: moving this hook's own two binds onto lazyImport did
 * exactly that, and what caught it was an end-to-end bundle case that happened to
 * exercise the prompt hook. Coverage luck, not a contract. This asserts the
 * contract directly, over the real source, so the next specifier is caught by
 * name at the point it is added.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const hooksDir = fileURLToPath(new URL("../claude-hooks", import.meta.url));

/** Every `.mjs` under claude-hooks/, read from disk so a new module is covered. */
function hookSources() {
  const files = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".mjs")) files.push(full);
    }
  };
  walk(hooksDir);
  return files;
}

/**
 * Bare package specifiers passed to `lazyImport("…")` as a literal. A relative
 * or `node:` specifier needs no registration — it is inlined or built in — so
 * only bare names are the contract.
 * @param {string} src
 * @returns {string[]}
 */
function lazyImportedPackages(src) {
  return [...src.matchAll(/\blazyImport\(\s*"([^"]+)"/gu)]
    .map((m) => m[1])
    .filter((spec) => /^[\w@]/u.test(spec) && !spec.includes(":"));
}

const registered = new Set(
  lazyLoaderKeys(readFileSync(path.join(hooksDir, "plugin-hooks.mjs"), "utf8")),
);

/**
 * The keys of the LAZY_LOADERS map, read out of the source rather than by
 * importing the module — importing it would run the binder's CLI-slot claim.
 * @param {string} src
 * @returns {string[]}
 */
function lazyLoaderKeys(src) {
  const body = src.slice(
    src.indexOf("const LAZY_LOADERS = {"),
    src.indexOf("\n};", src.indexOf("const LAZY_LOADERS = {")),
  );
  return [...body.matchAll(/^\s*"([^"]+)":/gmu)].map((m) => m[1]);
}

describe("every lazyImport specifier is registered for the bundle", () => {
  const found = new Map();
  for (const file of hookSources()) {
    for (const spec of lazyImportedPackages(readFileSync(file, "utf8"))) {
      if (!found.has(spec)) found.set(spec, []);
      found.get(spec).push(path.relative(hooksDir, file));
    }
  }

  it("finds lazyImport specifiers and registrations to check (non-vacuous)", () => {
    // Both halves must be non-empty, or a regex that stopped matching would make
    // every assertion below pass by finding nothing.
    assert.ok(found.size > 0, "no lazyImport package specifiers found");
    assert.ok(registered.size > 0, "no LAZY_LOADERS keys parsed");
  });

  for (const [spec, files] of found) {
    it(`${spec} has a LAZY_LOADERS entry`, () => {
      assert.ok(
        registered.has(spec),
        `${spec} is lazy-imported by ${files.join(", ")} but has no LAZY_LOADERS ` +
          `entry in claude-hooks/plugin-hooks.mjs — inside the plugin bundle it ` +
          `will not resolve, and that hook fails closed on every payload.`,
      );
    });
  }
});
