/**
 * Lazy-load invariant: importing the package root (`index.mjs`) must NOT pull
 * in the heavy HTML layer (`html.mjs` and its remark/rehype/unified graph,
 * ~200ms of module-load time). The root only `await import()`s that module
 * inside `sanitize({ html: true })`; everything it re-exports at module scope —
 * including the Layer 2/3 pre-gates — comes from the dependency-free
 * `gates.mjs`, never from `html.mjs`.
 *
 * This is the entire rationale for extracting `gates.mjs`, so it gets a
 * behavioral guard: a future `export … from "./html.mjs"` slipped into
 * `index.mjs` would silently reintroduce the eager load, and only this test
 * would catch it. We record the real module-resolution graph via a `module`
 * customization hook rather than grepping source, so the assertion tracks what
 * actually loads, not what the imports happen to look like.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import path from "node:path";
import os from "node:os";

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();
const srcUrl = (file) => new URL(`../src/${file}`, import.meta.url).href;

// What the Layer-1 root path must never trigger. The root re-exports only the
// zero-dependency `invisible.mjs` and `gates.mjs`, so its graph is expected to
// be dependency-free: ANY `node_modules` resolution is a leak, robust to future
// dependency renames (a brittle package-name allowlist would miss a heavy
// transitive copied straight into the root). The `html.mjs` arm names the one
// module that bridges the root to the heavy graph, for a clearer failure.
const LEAKED = (url) =>
  url.includes("/node_modules/") || /\/html\.mjs$/.test(url);

// Run `import(entryUrl)` in a fresh process under a resolve hook that appends
// every resolved module URL to `outPath`. The hook runs off-thread, but module
// resolution is awaited by the importer, so once `await import()` returns the
// file holds the complete graph — no timing race.
function resolvedGraph(entryUrl) {
  const outPath = path.join(
    os.tmpdir(),
    `llm-sanitizer-graph-${process.pid}-${Math.random().toString(36).slice(2)}.txt`,
  );
  const hookSrc = [
    'import { appendFileSync } from "node:fs";',
    "let outPath;",
    "export async function initialize(data) { outPath = data.outPath; }",
    "export async function resolve(specifier, context, next) {",
    "  const result = await next(specifier, context);",
    "  appendFileSync(outPath, result.url + String.fromCharCode(10));",
    "  return result;",
    "}",
  ].join("\n");
  const runner = [
    'import { register } from "node:module";',
    `register("data:text/javascript,${encodeURIComponent(hookSrc)}", {`,
    "  parentURL: import.meta.url,",
    `  data: { outPath: ${JSON.stringify(outPath)} },`,
    "});",
    `await import(${JSON.stringify(entryUrl)});`,
  ].join("\n");
  try {
    execFileSync(process.execPath, ["--input-type=module", "-e", runner], {
      cwd: repoRoot,
      encoding: "utf8",
    });
    return readFileSync(outPath, "utf8").split("\n").filter(Boolean);
  } finally {
    rmSync(outPath, { force: true });
  }
}

describe("lazy-load invariant", () => {
  it("importing the package root does not load the HTML/remark graph", () => {
    const graph = resolvedGraph(srcUrl("index.mjs"));
    // Positive markers: the recorder works and the root graph really loaded —
    // so a clean negative result below is "heavy graph absent", not "hook dead".
    assert.ok(
      graph.some((url) => url.endsWith("/index.mjs")),
      "recorder saw no index.mjs — the resolve hook is not working",
    );
    assert.ok(
      graph.some((url) => url.endsWith("/gates.mjs")),
      "root did not load gates.mjs — pre-gate re-export path changed",
    );
    const leaked = graph.filter(LEAKED);
    assert.deepEqual(
      leaked,
      [],
      `package root eagerly loaded the heavy HTML graph: ${leaked.join(", ")}`,
    );
  });

  // Every NON-html entry point must stay off the heavy graph too: the tool-output
  // pipeline (output.mjs) and the Edit-repair rehydrator only `await import()`
  // the HTML layer lazily, and the input/prompt/instruction modules never touch
  // it. A static `import … from "./html.mjs"` slipped into any of these would
  // tax every consumer with the ~200ms remark/rehype load on module evaluation.
  for (const file of [
    "output.mjs",
    "rehydrate.mjs",
    "confusables.mjs",
    "prompt.mjs",
    "instructions.mjs",
    "view-map.mjs",
  ]) {
    it(`importing ${file} does not eagerly load the HTML/remark graph`, () => {
      const graph = resolvedGraph(srcUrl(file));
      assert.ok(
        graph.some((url) => url.endsWith(`/${file}`)),
        `recorder saw no ${file} — the resolve hook is not working`,
      );
      const leaked = graph.filter(LEAKED);
      assert.deepEqual(
        leaked,
        [],
        `${file} eagerly loaded the heavy HTML graph: ${leaked.join(", ")}`,
      );
    });
  }

  // The `./layer1` subpath is the reason a consumer can take Layer 1 alone, so
  // it is covered here through the BARE SPECIFIER rather than by a `src/` entry
  // in the loop above. That is strictly more: the specifier resolves through the
  // exports map (a missing or misrouted entry fails here, where a relative
  // import would still pass), it lands on the same graph the file entry would
  // have recorded, and it applies the same LEAKED filter — so a loop entry for
  // `layer1.mjs` would spawn a second node process to assert a subset.
  it("agent-sanitizer/layer1 resolves and applyLayer1 works through it", async () => {
    const mod = await import("agent-sanitizer/layer1");
    assert.equal(typeof mod.applyLayer1, "function");
    // A zero-width space and an ANSI SGR run: the two halves Layer 1 composes,
    // so a subpath wired to the wrong module fails loudly rather than blankly.
    const { cleaned, found } = mod.applyLayer1(
      "a\u200Bb\u001B[31mred\u001B[0m",
    );
    assert.equal(cleaned, "abred");
    assert.deepEqual([...found].sort(), ["ansi", "cf-format"]);
  });

  it("importing agent-sanitizer/layer1 does not pull the HTML/remark graph", () => {
    const graph = resolvedGraph("agent-sanitizer/layer1");
    assert.ok(
      graph.some((url) => url.endsWith("/src/layer1.mjs")),
      "the subpath did not resolve to src/layer1.mjs — exports map entry is wrong or the recorder is dead",
    );
    assert.ok(
      graph.some((url) => url.endsWith("/src/invisible.mjs")),
      "subpath graph is missing invisible.mjs — Layer 1's own dependency did not load",
    );
    const leaked = graph.filter(LEAKED);
    assert.deepEqual(
      leaked,
      [],
      `agent-sanitizer/layer1 eagerly loaded the heavy HTML graph: ${leaked.join(", ")}`,
    );
  });

  it("importing the HTML subpath DOES load the heavy graph (negative test is not vacuous)", () => {
    const graph = resolvedGraph(srcUrl("html.mjs"));
    assert.ok(
      graph.some(LEAKED),
      "html.mjs loaded nothing LEAKED flags — the detector can never fire, so the root test would pass vacuously",
    );
  });
});
