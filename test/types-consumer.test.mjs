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
 * so the real `exports` map drives resolution), and type-checks
 * `type-fixtures/consumer/consumer.mts` against it — a faithful, offline
 * downstream typecheck. The fixture imports the package by name and asserts the
 * public types via `IsAny` guards that fail closed on `any`.
 *
 * The build emits into the temp dir, never the repo's `types/`, so it cannot
 * race the concurrent `npm pack` in package-exports.test.mjs (node:test runs
 * test files in parallel).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync } from "node:fs";
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

describe("public types: downstream consumer typecheck", () => {
  it("type-checks a name-resolved consumer against the emitted declarations", () => {
    const tmp = mkdtempSync(path.join(os.tmpdir(), "ais-consumer-"));
    // Lay the package out as it installs: node_modules/<name>/{package.json,types}.
    const pkgDir = path.join(tmp, "node_modules", "agent-sanitizer");
    mkdirSync(path.join(pkgDir, "types"), { recursive: true });

    // Emit declarations into the temp package, not the repo's types/ — same
    // config prepack uses, just a redirected outDir.
    const build = runTsc(
      [
        "-p",
        path.join(repoRoot, "tsconfig.build.json"),
        "--outDir",
        path.join(pkgDir, "types"),
      ],
      repoRoot,
    );
    assert.ok(build.ok, `declaration emit failed:\n${build.output}`);

    // The real package.json so resolution honors the actual `exports` map
    // (subpath -> .d.mts), exactly as a downstream install would.
    copyFileSync(
      path.join(repoRoot, "package.json"),
      path.join(pkgDir, "package.json"),
    );

    // Consumer + its tsconfig must sit inside tmp so bare-specifier resolution
    // finds tmp/node_modules/agent-sanitizer.
    copyFileSync(
      path.join(repoRoot, "type-fixtures", "consumer", "consumer.mts"),
      path.join(tmp, "consumer.mts"),
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
          skipLibCheck: true,
          forceConsistentCasingInFileNames: true,
          types: [],
        },
        include: ["consumer.mts"],
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
