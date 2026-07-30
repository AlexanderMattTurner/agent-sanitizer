/**
 * Consumer-perspective type contract. `pnpm check` type-checks the `.mjs`
 * SOURCE, where a regex literal is unambiguously `RegExp`; it can never see a
 * declaration-EMIT regression — a generated `.d.mts` that widened an export to
 * `any` (exactly the 1.0.1 `SECRET_HINT` bug) — because that only surfaces when
 * something resolves the package BY NAME through its `exports` map. `tsconfig`
 * even sets `skipLibCheck`, so our own build never inspects the declarations.
 *
 * This test closes that gap: it emits the declarations the same way `prepack`
 * does, assembles a throwaway package install in a temp dir (real package.json,
 * so the real `exports` map drives resolution), and type-checks the fixtures in
 * `type-fixtures/consumer/` against it — a faithful, offline downstream
 * typecheck. Each fixture imports the package by name and asserts the public
 * types via `IsAny` guards that fail closed on `any`.
 *
 * The throwaway install deliberately runs WITHOUT `skipLibCheck`, so the shipped
 * declarations are checked for internal resolution too: a `.d.mts` that names a
 * module the package does not declare as a dependency — the failure a consumer
 * hits and we never would — is a TS2307 here.
 *
 * The build emits into the temp dir, never the repo's `types/`, so it cannot
 * race the concurrent `npm pack` in package-exports.test.mjs (node:test runs
 * test files in parallel).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  copyFileSync,
  writeFileSync,
  symlinkSync,
  realpathSync,
} from "node:fs";
import path from "node:path";
import os from "node:os";

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();

const tsc = path.join(repoRoot, "node_modules", ".bin", "tsc");

/** Run tsc with the given args, returning combined output and pass/fail. */
function runTsc(args, cwd) {
  try {
    execFileSync(tsc, args, { cwd, encoding: "utf8", stdio: "pipe" });
    return { ok: true, output: "" };
  } catch (err) {
    // tsc exits non-zero on type errors; its diagnostics go to stdout.
    return { ok: false, output: `${err.stdout ?? ""}${err.stderr ?? ""}` };
  }
}

// Both declaration builds prepack runs, each with its outDir redirected into the
// temp package. `types/claude-hooks` must land under the same `types/` root the
// exports map names, so the hooks build's outDir is the subdirectory rather than
// a second root.
const BUILDS = [
  { config: "tsconfig.build.json", outSubdir: "" },
  { config: "tsconfig.build-hooks.json", outSubdir: "claude-hooks" },
];

// Fixtures type-checked together in one tsc run: the library subpaths and the
// claude-hooks composition surface. tsc names the offending file in its
// diagnostics, so one run still says which surface regressed.
const FIXTURES = ["consumer.mts", "hooks-consumer.mts"];

// What a real install of this package resolves alongside it, and nothing more:
// agent-control-plane-core is a declared dependency (the hooks' judge signatures
// are typed by its ToolCallEvent/Verdict), and @types/node backs the `node:*`
// references the declarations carry. Linking exactly these is what makes the
// no-skipLibCheck run meaningful — anything else a declaration reaches for is a
// missing dependency, and reds.
const LINKED_DEPS = ["agent-control-plane-core", "@types/node"];

describe("public types: downstream consumer typecheck", () => {
  it("type-checks name-resolved consumers against the emitted declarations", () => {
    const tmp = mkdtempSync(path.join(os.tmpdir(), "ais-consumer-"));
    // Lay the package out as it installs: node_modules/<name>/{package.json,types}.
    const nodeModules = path.join(tmp, "node_modules");
    const pkgDir = path.join(nodeModules, "agent-sanitizer");
    mkdirSync(path.join(pkgDir, "types"), { recursive: true });

    // Emit declarations into the temp package, never the repo's types/ — that
    // would race the concurrent npm pack in package-exports.test.mjs.
    for (const { config, outSubdir } of BUILDS) {
      const build = runTsc(
        [
          "-p",
          path.join(repoRoot, config),
          "--outDir",
          path.join(pkgDir, "types", outSubdir),
        ],
        repoRoot,
      );
      assert.ok(
        build.ok,
        `declaration emit failed (${config}):\n${build.output}`,
      );
    }

    // The real package.json so resolution honors the actual `exports` map
    // (subpath -> .d.mts), exactly as a downstream install would.
    copyFileSync(
      path.join(repoRoot, "package.json"),
      path.join(pkgDir, "package.json"),
    );

    for (const dep of LINKED_DEPS) {
      const link = path.join(nodeModules, dep);
      mkdirSync(path.dirname(link), { recursive: true }); // scoped name: @types/node
      symlinkSync(
        realpathSync(path.join(repoRoot, "node_modules", dep)),
        link,
        "dir",
      );
    }

    // Fixtures + their tsconfig must sit inside tmp so bare-specifier resolution
    // finds tmp/node_modules/agent-sanitizer.
    for (const fixture of FIXTURES)
      copyFileSync(
        path.join(repoRoot, "type-fixtures", "consumer", fixture),
        path.join(tmp, fixture),
      );
    writeFileSync(
      path.join(tmp, "tsconfig.json"),
      JSON.stringify({
        compilerOptions: {
          target: "ES2022",
          module: "NodeNext",
          moduleResolution: "NodeNext",
          lib: ["ES2022"],
          strict: true,
          noEmit: true,
          forceConsistentCasingInFileNames: true,
          types: ["node"],
        },
        include: FIXTURES,
      }),
    );

    const consumer = runTsc(["-p", "tsconfig.json"], tmp);
    assert.ok(
      consumer.ok,
      "consumer typecheck failed — a public type regressed at the package " +
        `boundary (e.g. an export widened to \`any\`):\n${consumer.output}`,
    );
  });
});
