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
import { isBuiltin } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parse } from "acorn";
import { ancestor } from "acorn-walk";
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
        contents = contents.replace(call, () => binding);
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
 * An allowlist may not contain it bare, so such a call outside a named function
 * always fails the build: a specifier the build cannot read is one it cannot
 * prove resolvable in a deployment with no node_modules. Inside a named
 * function it is reported as `<computed> in <name>`, which an allowlist may
 * name: a reviewed statement about ONE call site, never a blanket pass.
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
  if (allowedRuntimeRequires.includes(COMPUTED_SPECIFIER))
    throw new Error(
      `an allowlist may not contain a bare ${COMPUTED_SPECIFIER}: it would pass ` +
        "every computed load outside a named function. Name the one site as " +
        `"${COMPUTED_SPECIFIER} in <function>".`,
    );
  const allowed = new Set(allowedRuntimeRequires);
  const survivors = runtimeRequires(text).filter((spec) => !allowed.has(spec));
  if (survivors.length === 0) return;
  const computed = survivors.some((spec) => spec.startsWith(COMPUTED_SPECIFIER))
    ? ` ${COMPUTED_SPECIFIER} means the call's argument is not a string literal, so the build cannot prove what it resolves to.`
    : "";
  throw new Error(
    `bundle keeps runtime require() of: ${survivors.join(", ")}. ` +
      "A shipped bundle has no node_modules and no sibling data files, so " +
      "these throw on first use. Inline them at build time." +
      computed,
  );
}

/**
 * A callee that loads a module by name at runtime: the `require` binding
 * (esbuild renames it `require2`, and names its shim `__require`), or a
 * `createRequire(…)` (renamed `createRequire2`) result called immediately.
 */
const RUNTIME_REQUIRE_CALLEE = /^(?:__)?require\d*$/;
const CREATE_REQUIRE = /^createRequire\d*$/;

/**
 * Whether `callee` is a `createRequire(…)` call, bare or as `module.createRequire(…)`.
 * @param {import("acorn").Node} callee
 */
function isCreateRequireCall(callee) {
  if (callee.type !== "CallExpression") return false;
  const fn = /** @type {import("acorn").CallExpression} */ (callee).callee;
  if (fn.type === "Identifier") return CREATE_REQUIRE.test(fn.name);
  return (
    fn.type === "MemberExpression" &&
    !fn.computed &&
    fn.property.type === "Identifier" &&
    fn.property.name === "createRequire"
  );
}

/**
 * What one module-loading site reports: its string-literal specifier, else
 * `COMPUTED_SPECIFIER` (a variable, template, concatenation, or no argument)
 * qualified by the innermost named function it sits in.
 * @param {readonly import("acorn").Node[]} args
 * @param {readonly import("acorn").Node[]} ancestors outermost first, the node last
 * @returns {string}
 */
function reportedSpecifier(args, ancestors) {
  const [arg, ...rest] = args;
  const literal = /** @type {import("acorn").Literal | undefined} */ (arg);
  if (
    rest.length === 0 &&
    literal?.type === "Literal" &&
    typeof literal.value === "string"
  )
    return literal.value;
  for (let i = ancestors.length - 2; i >= 0; i--) {
    const fn = /** @type {import("acorn").Function} */ (ancestors[i]);
    if (
      (fn.type === "FunctionDeclaration" || fn.type === "FunctionExpression") &&
      fn.id
    )
      return `${COMPUTED_SPECIFIER} in ${fn.id.name}`;
  }
  return COMPUTED_SPECIFIER;
}

/**
 * The distinct specifiers the artifact still loads by name at runtime: through
 * `require()`, through a `createRequire(…)(…)` loader, or through a dynamic
 * `import()`. A literal Node builtin is left out — every target runtime has it.
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
  /** @param {string} spec */
  const record = (spec) => {
    if (!isBuiltin(spec)) found.add(spec);
  };
  ancestor(parse(text, { sourceType: "module", ecmaVersion: "latest" }), {
    CallExpression(node, _state, ancestors) {
      const { callee } = node;
      if (
        (callee.type === "Identifier" &&
          RUNTIME_REQUIRE_CALLEE.test(callee.name)) ||
        isCreateRequireCall(callee)
      )
        record(reportedSpecifier(node.arguments, ancestors));
    },
    ImportExpression(node, _state, ancestors) {
      record(reportedSpecifier([node.source], ancestors));
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
    // The two runtime loads this artifact may keep, each a registry-first
    // fallback that only runs on a host whose node_modules has the module:
    //   - "namespace-guard": confusableScan's require2() and src/confusables'
    //     createRequire(import.meta.url)(…) in resolveScan, both reached only
    //     when the lazy-module registry has no inlined copy.
    //   - "<computed> in lazyImport": hook-io's lazyImport(specifier), whose
    //     import() runs only for a specifier registerLazyModules never named.
    allowedRuntimeRequires: [
      "namespace-guard",
      `${COMPUTED_SPECIFIER} in lazyImport`,
    ],
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
