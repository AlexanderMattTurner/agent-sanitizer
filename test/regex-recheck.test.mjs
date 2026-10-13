/**
 * Every RegExp a shipped module COMPILES at runtime, proven ReDoS-safe by
 * `recheck` — deterministically, with no timing in the verdict.
 *
 * The lint gates (`redos/no-vulnerable`, `regexp/no-super-linear-*` in
 * `eslint.config.mjs`) read regex LITERALS. A pattern assembled at runtime —
 * `new RegExp(\`[${VS}]\`, "u")`, `new RegExp(STRIP.source + …)` — is invisible
 * to them, and `tests/test_redos_js_static_guard.py` reaches it only where its
 * extractor can resolve the source statically. This suite reads the live value
 * instead: it wraps the global `RegExp` constructor, imports every shipped
 * module, drives the function-local construction sites with a few samples, and
 * hands every pattern a shipped file built to `recheck`.
 *
 * Attribution is by the constructing stack frame, so a pattern a dependency
 * (parse5, micromark) builds while a shipped module loads is not ours to judge
 * and is not collected.
 */
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { check } from "recheck";

import { shippedSources } from "../scripts/shipped-sources.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

/**
 * recheck's fuzz checker (which `auto` picks for lookbehinds, among others)
 * counts a wall-clock overrun during incubation or attack validation as a
 * successful attack, so on a loaded runner a linear pattern can read
 * "vulnerable" on one run and "safe" on the next. With both timeouts off, the
 * step-count limits (`incubationLimit`, `attackLimit`) are the only criteria and
 * the PRNG seed is recheck's fixed default, so the verdict depends on the
 * pattern alone. The overall `timeout` still bounds a runaway analysis, which
 * reports "unknown" — and "unknown" fails below.
 * @type {import("recheck").Parameters}
 */
const RECHECK_PARAMETERS = {
  timeout: 60_000,
  incubationTimeout: null,
  attackTimeout: null,
};

/**
 * Shipped files this suite does not import, each with the reason. A file here
 * is still read by the lint gates and the static extractor guard.
 */
const NOT_IMPORTED = {
  // No `isMain` guard: importing it runs the CLI against this process's argv
  // and stdin. It builds no RegExp at runtime, which the test below holds it to.
  "bin/sanitize-cli.mjs": "a CLI entry point that runs on import",
};

/** `{source, flags, file}` for every pattern a shipped file constructed. */
const compiled = new Map();

/** The shipped file a construction ran in: the first stack frame inside the
 * repo that is not this suite. Null for a dependency's own construction. */
function constructingFile(shipped) {
  const frames = (new Error().stack ?? "").split("\n").slice(1);
  for (const frame of frames) {
    const match =
      /\((file:\/\/[^)]+?):\d+:\d+\)$|at (file:\/\/\S+?):\d+:\d+$/u.exec(frame);
    if (!match) continue;
    const path = fileURLToPath(match[1] ?? match[2]);
    if (path === fileURLToPath(import.meta.url)) continue;
    const rel = path.startsWith(ROOT) ? path.slice(ROOT.length) : null;
    return rel !== null && shipped.has(rel) ? rel : null;
  }
  return null;
}

before(async () => {
  const shipped = new Set(shippedSources(ROOT));
  const record = (/** @type {RegExp} */ re) => {
    const file = constructingFile(shipped);
    if (file !== null)
      compiled.set(`/${re.source}/${re.flags}`, {
        source: re.source,
        flags: re.flags,
        file,
      });
    return re;
  };
  const Native = globalThis.RegExp;
  globalThis.RegExp = new Proxy(Native, {
    construct: (target, args) => record(Reflect.construct(target, args)),
    apply: (target, _this, args) =>
      record(Reflect.apply(target, undefined, args)),
  });
  try {
    for (const rel of [...shipped].sort())
      if (!(rel in NOT_IMPORTED))
        await import(pathToFileURL(join(ROOT, rel)).href);
    // Function-local construction sites run only when called: the raw-text
    // close-tag pattern is built per `<style>`/`<script>` region the HTML walk
    // enters, and only from inside a markdown document's inline html.
    const { sanitizeText } = await import("../src/output.mjs");
    await sanitizeText("text <style>a { color: red }</style> more\n", {
      html: true,
      exfilScan: true,
    });
  } finally {
    globalThis.RegExp = Native;
  }
});

describe("regex safety (runtime recheck)", () => {
  it("collects the patterns shipped modules compile, and only those", (t) => {
    // Non-vacuity: a wrapper that stopped intercepting, or an attribution that
    // dropped every frame, would leave nothing to check and pass forever.
    const files = new Set([...compiled.values()].map((p) => p.file));
    t.diagnostic(
      `${compiled.size} patterns from ${[...files].sort().join(", ")}`,
    );
    assert.ok(compiled.size >= 15, `only ${compiled.size} patterns collected`);
    for (const file of ["src/invisible.mjs", "src/ansi.mjs", "src/html.mjs"])
      assert.ok(files.has(file), `nothing collected from ${file}`);
    assert.ok(
      [...compiled.values()].some((p) => p.source.startsWith("<\\/style")),
      "the sample never reached the raw-text close-tag construction",
    );
  });

  it("every excluded file builds no RegExp at runtime", () => {
    for (const file of Object.keys(NOT_IMPORTED))
      assert.doesNotMatch(readFileSync(join(ROOT, file), "utf8"), /RegExp\(/u);
  });

  it(
    "every compiled pattern is proven safe by recheck",
    { timeout: 600_000 },
    async () => {
      const notSafe = [];
      // One at a time, so concurrent analyses do not compete for the CPU.
      for (const { source, flags, file } of compiled.values()) {
        const result = await check(source, flags, RECHECK_PARAMETERS);
        // Anything short of "safe" fails: "unknown" (an analysis error or the
        // overall timeout) proves nothing about the pattern.
        if (result.status !== "safe")
          notSafe.push(
            `${file}: [${result.status}${result.status === "unknown" ? `: ${result.error.message}` : ""}] /${source.slice(0, 120)}/${flags}`,
          );
      }
      assert.deepEqual(notSafe, []);
    },
  );

  // Guards against RECHECK_PARAMETERS silencing the checker: genuine ReDoS must
  // still be reported by both the automaton and the fuzzing checker.
  for (const [name, source, checker] of [
    ["nested quantifier (automaton)", "^(a+)+$", "automaton"],
    ["nested quantifier behind a lookbehind (fuzz)", "(?<![ ])(a+)+b", "fuzz"],
  ])
    it(`recheck still flags real ReDoS: ${name}`, async () => {
      const result = await check(source, "", RECHECK_PARAMETERS);
      assert.equal(result.status, "vulnerable");
      assert.equal(result.checker, checker);
    });
});
