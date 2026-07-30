/**
 * The hook modules are a PUBLIC composition surface, reachable as
 * `agent-sanitizer/claude-hooks/<module>` and
 * `agent-sanitizer/claude-hooks/lib/<module>`.
 *
 * 2.4.1 shipped the hooks with a single `"./claude-hooks"` subpath pointing at
 * plugin-hooks.mjs, whose only export is the `--hook=` CLI dispatcher. Every
 * composable piece — sanitizeText, evaluateToolOutput, the whole hook-io
 * toolkit — was packed in the tarball but unreachable: an exports map with no
 * matching subpath makes Node refuse the deep import outright
 * (ERR_PACKAGE_PATH_NOT_EXPORTED), so a consumer wanting to reuse one of these
 * hooks had to vendor a copy.
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
import { readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const hooksDir = fileURLToPath(new URL("../claude-hooks", import.meta.url));

/**
 * Every hook module on disk, as its `claude-hooks/*` subpath suffix
 * (`sanitize-output`, `lib/hook-io`, …). Enumerated from the directory rather
 * than hard-coded so a module added later is covered without editing this file
 * — the failure mode a fixed list has is passing while the new module sits
 * unreachable.
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
    // Every module on disk must be named above, or a new one silently escapes
    // the per-module assertions below.
    assert.deepEqual(
      modules.filter((m) => !REQUIRED_EXPORT[m]),
      [],
      "hook modules with no REQUIRED_EXPORT entry — add one",
    );
  });

  for (const name of modules) {
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

  // The one hazard a `*` subpath adds over a hand-listed set: it must not become
  // a reader for arbitrary files in the package. Node refuses a `..` segment in
  // the specifier itself, so the pattern cannot be walked out of `claude-hooks/`
  // — asserted here because the guarantee lives in Node's resolver, not in our
  // map, and a future move to a hand-rolled loader would silently lose it.
  it("refuses a traversal out of claude-hooks/", () => {
    assert.throws(
      () =>
        import.meta.resolve("agent-sanitizer/claude-hooks/../../package.json"),
      { code: "ERR_INVALID_MODULE_SPECIFIER" },
    );
  });

  // The bare `./claude-hooks` subpath is the documented CLI entry and stays
  // resolvable on its own — the wildcard must not have displaced it.
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
