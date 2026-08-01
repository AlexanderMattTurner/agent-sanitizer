/**
 * A CURATED slice of the hook modules is a public composition surface, reachable
 * as `agent-sanitizer/claude-hooks/<module>`. The slice is deliberate in BOTH
 * directions, so this file asserts both:
 *
 *   - the exported entries resolve and load (a consumer can compose them);
 *   - every other module stays REFUSED (ERR_PACKAGE_PATH_NOT_EXPORTED).
 *
 * The closed half is the load-bearing one. A wildcard would publish all fourteen
 * modules, turning internals like the redactor client and the reveal store into
 * a compatibility surface this package would then owe forever. The four hook
 * modules plus lib/hook-io and lib/control-plane are what a consumer needs to
 * compose the hooks; hook-io in particular MUST be shared rather than copied,
 * because it owns the lazy-module registry and the CLI-slot singleton — two
 * inlined copies would double-fire the inlined CLIs. A host that cannot share it
 * because its own hook-io module is not a copy — it exports names this one does
 * not have — reconciles the two through `adoptHookIoSharedState` instead, which
 * puts both instances on one state object.
 *
 * These drive Node's real exports resolution via `import.meta.resolve` against
 * the package's own name — the same resolution a consumer's bare import
 * performs — and then import the resolved module, so both halves are asserted:
 * the subpath resolves AND the module behind it loads. A relative import would
 * pass even with the exports map broken, which is exactly the regression that
 * shipped.
 *
 * The tarball half (declarations paired with every exposed module) is asserted
 * in package-exports.test.mjs, which drives `npm pack`.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const hooksDir = fileURLToPath(new URL("../claude-hooks", import.meta.url));
const pkg = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);

/**
 * Every hook module on disk, as its `claude-hooks/*` subpath suffix
 * (`sanitize-output`, `lib/hook-io`, …), read from the directory so a module
 * added later is classified rather than silently ignored.
 */
function hookModules() {
  const mjs = (dir, prefix) =>
    readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isFile() && e.name.endsWith(".mjs"))
      .map((e) => `${prefix}${e.name.replace(/\.mjs$/u, "")}`);
  return [
    ...mjs(hooksDir, ""),
    ...mjs(path.join(hooksDir, "lib"), "lib/"),
  ].sort();
}

// The EXPORTED subset, read from the package's own map rather than restated:
// the map is the contract under test, so a curated entry added or dropped moves
// both the allow list and the deny list in one edit.
const EXPORTED = Object.keys(pkg.exports)
  .filter((k) => k.startsWith("./claude-hooks/"))
  .map((k) => k.slice("./claude-hooks/".length))
  .sort();

// A named export each module must carry, so the test asserts a usable surface
// rather than "the import didn't throw". These are the entry points a consumer
// composes with; a module that resolves but exports nothing is a fail-open this
// closes.
const REQUIRED_EXPORT = {
  "plugin-hooks": "main",
  "pretooluse-sanitize": "judgePreToolUseSanitize",
  "sanitize-output": "sanitizeText",
  "sanitize-user-prompt": "judgeSanitizeUserPrompt",
  "scan-invisible-chars": "scanFile",
  "lib/authored-content": "sanitizeAuthoredContent",
  "lib/control-plane": "runJudgeCli",
  "lib/env-config": "looksLikeCredentialVar",
  "lib/hook-io": "lazyImport",
  "lib/invisible-alert": "invisibleCharAlert",
  "lib/redactor-client": "redactViaDaemon",
  "lib/reveal": "persistReveal",
  "lib/secret-annotate": "hasEnvBoundSecret",
  "lib/trace": "trace",
};

describe("claude-hooks composition surface resolves through the exports map", () => {
  const modules = hookModules();

  it("finds hook modules to check (non-vacuous)", () => {
    assert.ok(modules.length > 0, "no .mjs modules found under claude-hooks/");
    assert.ok(EXPORTED.length > 0, "no ./claude-hooks/* subpaths in the map");
    // Every module on disk must be named above, or a new one silently escapes
    // the per-module assertions below.
    assert.deepEqual(
      modules.filter((m) => !REQUIRED_EXPORT[m]),
      [],
      "hook modules with no REQUIRED_EXPORT entry — add one",
    );
    // Every exported subpath must name a module that exists — a curated entry
    // pointing at a deleted file resolves to nothing and fails only at import.
    assert.deepEqual(
      EXPORTED.filter((e) => !modules.includes(e)),
      [],
      "exports name claude-hooks modules that are not on disk",
    );
  });

  for (const name of EXPORTED) {
    const subpath = `agent-sanitizer/claude-hooks/${name}`;
    it(`${subpath} resolves and exports ${REQUIRED_EXPORT[name]}`, async () => {
      // Self-reference: a package with an `exports` map resolves its own name,
      // so this throws ERR_PACKAGE_PATH_NOT_EXPORTED on an unmapped subpath.
      const resolved = import.meta.resolve(subpath);
      assert.equal(fileURLToPath(resolved), path.join(hooksDir, `${name}.mjs`));
      const mod = await import(resolved);
      assert.ok(
        typeof mod[REQUIRED_EXPORT[name]] === "function",
        `${subpath} does not export ${REQUIRED_EXPORT[name]} as a function`,
      );
    });
  }

  // The closed half of the contract: a module the curated list omits must stay
  // unreachable. Iterated over the real on-disk set minus the exported set, so
  // adding a module without exporting it is covered automatically, and widening
  // the map to a wildcard — which would re-publish every internal — reds here.
  for (const name of modules.filter((m) => !EXPORTED.includes(m))) {
    const subpath = `agent-sanitizer/claude-hooks/${name}`;
    it(`${subpath} stays de-exported`, () => {
      assert.throws(() => import.meta.resolve(subpath), {
        code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
      });
    });
  }

  // A traversal is refused for the same reason every internal is: under a curated
  // map an unlisted subpath has no target at all, so `..` never gets a chance to
  // be resolved relative to anything. Asserted because that guarantee comes from
  // the map's shape, and a move to a wildcard would hand it back to Node's
  // specifier parser instead.
  it("refuses a traversal out of claude-hooks/", () => {
    assert.throws(
      () =>
        import.meta.resolve("agent-sanitizer/claude-hooks/../../package.json"),
      { code: "ERR_PACKAGE_PATH_NOT_EXPORTED" },
    );
  });

  // The bare `./claude-hooks` subpath is the documented CLI entry and stays
  // resolvable on its own, beside the curated subpaths.
  it("keeps the bare ./claude-hooks entry pointing at the CLI dispatcher", async () => {
    const resolved = import.meta.resolve("agent-sanitizer/claude-hooks");
    assert.equal(
      fileURLToPath(resolved),
      path.join(hooksDir, "plugin-hooks.mjs"),
    );
    const { main } = await import(resolved);
    assert.equal(typeof main, "function");
  });
});
