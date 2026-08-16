/**
 * The one hardened esbuild configuration every shipped bundle is built with.
 *
 * Both artifacts this repo ships — the Claude Code plugin hook bundle and the
 * Python wheel's CLI — are single files that run where no `node_modules` and no
 * sibling data file exists. A bundle that keeps a runtime `require()` therefore
 * throws on first use, and it does so INSIDE a layer: css-tree pulls its CSS
 * syntax tables in through `createRequire(import.meta.url)("../data/patch.json")`,
 * which esbuild leaves intact, and the plugin shipped that way once — Layer 2
 * failed closed and every WebFetch result was suppressed rather than sanitized.
 * The wheel's CLI shipped the same defect: `html: true` died with "failed to load
 * HTML module", so Layers 2 and 3 were dead for every `pip install` user.
 *
 * Rather than repeat the two mitigations per build script, every entry goes
 * through `bundleHardened` here, which owns them:
 *
 *   1. `inlineRuntimeJsonRequires` rewrites those requires into static imports,
 *      handing the data to esbuild so it inlines them like anything else.
 *   2. `assertNoRuntimeRequires` THROWS at build time on any survivor outside the
 *      entry's declared allowlist — a bundle that would fail at runtime is
 *      unwritable, so the next dependency that invents a new shape is caught by
 *      the build rather than by a user.
 *
 * `BUNDLE_TARGETS` is the single list of shipped entries; add an entry here and
 * the contract test in `bundle-hardening.test.mjs` beside it covers that entry
 * automatically.
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parse } from "acorn";
import { simple } from "acorn-walk";
import { build } from "esbuild";

/** Repo root (this module lives at scripts/lib/). */
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/**
 * Inline the JSON data files that dependencies pull in through
 * `createRequire(import.meta.url)("…json")`.
 *
 * Written against the PATTERN, not against the two css-tree files that exhibit
 * it today, so a dependency bump that moves the tables is covered — and
 * `assertNoRuntimeRequires` fails the build if any survive regardless.
 * @type {import("esbuild").Plugin}
 */
const inlineRuntimeJsonRequires = {
  name: "inline-runtime-json-requires",
  setup(build) {
    build.onLoad({ filter: /\.m?js$/, namespace: "file" }, (args) => {
      if (!args.path.includes("node_modules")) return null;
      const source = readFileSync(args.path, "utf8");
      if (!source.includes("createRequire")) return null;
      const calls = [...source.matchAll(/require\((['"])([^'"]+\.json)\1\)/g)];
      if (calls.length === 0) return null;

      /** @type {string[]} */
      const imports = [];
      let contents = source;
      calls.forEach(([call, , specifier], index) => {
        const binding = `__inlinedJson${index}`;
        imports.push(`import ${binding} from ${JSON.stringify(specifier)};`);
        contents = contents.replace(call, binding);
      });
      return {
        contents: `${imports.join("\n")}\n${contents}`,
        loader: "js",
        resolveDir: dirname(args.path),
      };
    });
  },
};

/**
 * Reported in place of a specifier whose value the bundle decides at runtime.
 * No allowlist may contain it, so such a call always fails the build: a
 * specifier the build cannot read is a specifier the build cannot prove
 * resolvable in a deployment that has no node_modules.
 */
export const COMPUTED_SPECIFIER = "<computed>";

/**
 * Fail the build on any runtime require the shipped artifact could not resolve.
 * This is the general guard: the rewrite above handles the shape we know, and
 * this refuses to ship the shape we do not.
 * @param {string} text
 * @param {readonly string[]} allowedRuntimeRequires
 */
export function assertNoRuntimeRequires(text, allowedRuntimeRequires) {
  const allowed = new Set(allowedRuntimeRequires);
  const survivors = runtimeRequires(text).filter((spec) => !allowed.has(spec));
  if (survivors.length === 0) return;
  const computed = survivors.includes(COMPUTED_SPECIFIER)
    ? ` ${COMPUTED_SPECIFIER} means the call's argument is not a string literal, so the build cannot prove what it resolves to.`
    : "";
  throw new Error(
    `bundle keeps runtime require() of: ${survivors.join(", ")}. ` +
      "A shipped bundle has no node_modules and no sibling data files, so " +
      "these throw on first use. Inline them at build time." +
      computed,
  );
}

/** esbuild renames the require shim (`require2(…)`), hence the digit suffix. */
const RUNTIME_REQUIRE_CALLEE = /^require\d*$/;

/**
 * The specifier a `require()` call names, or `COMPUTED_SPECIFIER` when the
 * argument is anything other than a single string literal — a variable, a
 * template literal, a concatenation, or no argument at all.
 * @param {import("acorn").CallExpression} node
 * @returns {string}
 */
function requireSpecifier(node) {
  const [arg, ...rest] = node.arguments;
  if (
    rest.length === 0 &&
    arg?.type === "Literal" &&
    typeof arg.value === "string"
  )
    return arg.value;
  return COMPUTED_SPECIFIER;
}

/**
 * The distinct specifiers the artifact still hands to a runtime `require()`.
 *
 * Parses the bundle rather than scanning it, because "is this a call" is a
 * question about JavaScript structure. A text scan answers it wrong in both
 * directions on inputs this build produces: `inlineRuntimeJsonRequires` splices
 * dependency JSON into the bundle and `legalComments: "eof"` appends third-party
 * comments to it, so a `require("x")` mentioned inside a string or a comment
 * reads as a real call; and `minify: false` lets esbuild wrap a long argument
 * list onto its own line, so a real call reads as nothing at all.
 *
 * A parse error propagates: a bundle that is not valid ESM is a build failure,
 * not a bundle with no requires.
 *
 * @param {string} text
 * @returns {string[]}
 */
export function runtimeRequires(text) {
  /** @type {Set<string>} */
  const found = new Set();
  simple(parse(text, { sourceType: "module", ecmaVersion: "latest" }), {
    CallExpression(node) {
      if (
        node.callee.type === "Identifier" &&
        RUNTIME_REQUIRE_CALLEE.test(node.callee.name)
      )
        found.add(requireSpecifier(node));
    },
  });
  return [...found];
}

/**
 * Bundle one entry into a self-contained ESM string. Deterministic: no minify
 * (the shipped bytes stay auditable), `node:` builtins left external (present in
 * every target runtime). esbuild's output for a given version + inputs is
 * byte-stable, which is what lets the plugin's reproducibility test compare
 * committed vs freshly built.
 *
 * Throws rather than returning a bundle that keeps an unresolvable runtime
 * require — the caller writes the file, so a throw here means nothing is
 * written.
 *
 * @param {object} target
 * @param {string} target.entry Absolute path of the entry module.
 * @param {readonly string[]} target.allowedRuntimeRequires Specifiers the
 *   artifact may still `require()` at runtime, each because a host that has them
 *   is the only place that code path runs.
 * @param {Record<string, string>} [target.alias] esbuild `alias` map.
 * @param {"eof" | "none" | "inline" | "linked" | "external"} [target.legalComments]
 * @returns {Promise<string>}
 */
export async function bundleHardened({
  entry,
  allowedRuntimeRequires,
  alias,
  legalComments = "eof",
}) {
  const result = await build({
    entryPoints: [entry],
    bundle: true,
    // Target the Node runtime the package requires (>=22): emits the modern
    // syntax the sources rely on (top-level await, dynamic import) and preserves
    // `import.meta.url`, which the CLI compares against process.argv[1] to
    // decide whether it was invoked as a script.
    platform: "node",
    format: "esm",
    target: "node22",
    // Only Node's own builtins may remain as imports; everything else is
    // inlined. A bare (non-node:) import surviving would mean the artifact needs
    // a node_modules — the exact thing these bundles exist to avoid.
    external: ["node:*"],
    minify: false,
    write: false,
    logLevel: "silent",
    plugins: [inlineRuntimeJsonRequires],
    legalComments,
    ...(alias ? { alias } : {}),
  });
  const [file] = result.outputFiles;
  assertNoRuntimeRequires(file.text, allowedRuntimeRequires);
  return file.text;
}

/**
 * Every esbuild entry point this repo ships, as one list. The build scripts and
 * the hardening contract test all read it, so a new artifact cannot be added
 * with an unguarded esbuild call: the `no-restricted-imports` rule in
 * `eslint.config.mjs` lets only this directory import esbuild, so a new build
 * script has to come through `bundleHardened` and lands here.
 *
 * @typedef {{
 *   name: string,
 *   entry: string,
 *   outfile: string,
 *   allowedRuntimeRequires: readonly string[],
 *   alias?: Record<string, string>,
 *   legalComments?: "eof" | "none",
 * }} BundleTarget
 * @type {readonly BundleTarget[]}
 */
export const BUNDLE_TARGETS = [
  {
    name: "plugin-hooks",
    entry: join(ROOT, "claude-hooks", "plugin-hooks.mjs"),
    outfile: join(ROOT, "plugin", "dist", "hooks", "plugin-hooks.bundle.mjs"),
    // The hooks import the engine by its canonical name so the same sources are
    // publishable as `agent-sanitizer/claude-hooks`. That name resolves to THIS
    // repo (package.json devDependencies carries `agent-sanitizer: link:.`), so
    // the bundle inlines the same `src/` the suite runs against and the shipped
    // hooks cannot lag the engine they are tested with.
    // The committed artifact is byte-compared against a fresh build, and it was
    // generated without license comments; keeping them out also keeps the
    // shipped bytes reviewable.
    legalComments: "none",
    // The one runtime require this artifact may keep: confusableScan resolves
    // namespace-guard from the lazy-module registry first and only falls back to
    // require() on a host that has a node_modules.
    allowedRuntimeRequires: ["namespace-guard"],
  },
  {
    name: "python-cli",
    entry: join(ROOT, "bin", "sanitize-cli.mjs"),
    outfile: join(
      ROOT,
      "python",
      "agent_sanitizer",
      "_bundled",
      "sanitize-cli.mjs",
    ),
    // Nothing: the wheel ships this file alone next to the Python package, so
    // any survivor is a module the installed wheel does not have.
    allowedRuntimeRequires: [],
  },
];

/**
 * The target with this name. Throws on an unknown name so a renamed target
 * fails the build instead of silently bundling nothing.
 * @param {string} name
 * @returns {BundleTarget}
 */
export function bundleTarget(name) {
  const target = BUNDLE_TARGETS.find((t) => t.name === name);
  if (!target)
    throw new Error(
      `unknown bundle target ${JSON.stringify(name)}; known: ${BUNDLE_TARGETS.map((t) => t.name).join(", ")}`,
    );
  return target;
}
