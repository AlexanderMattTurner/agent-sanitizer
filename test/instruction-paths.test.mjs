/**
 * The write-path invariant of the instruction-file scanners, held at ONE
 * chokepoint and partitioned over every site that needs it:
 *
 *   - WRITES: every rewrite of an instruction file goes through cleanFile's
 *     realpath containment, so a directory symlink in the project cannot carry
 *     an auto-clean to a file outside it.
 *
 * Each partition pairs a behavioral check per site with an acorn enumeration of
 * the live sites, so a new site cannot land without a decision here.
 */
import { describe, it, after, before } from "node:test";
import assert from "node:assert/strict";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { parse } from "acorn";
import { simple } from "acorn-walk";

import { repoRoot } from "./helpers/repo-root.mjs";
import { withCapturedStdout } from "./helpers/capture-stdout.mjs";

// Set before the hooks import: the SessionStart scan walks CLAUDE_PROJECT_DIR
// and rewrites what it flags, so it must never point at this checkout.
const sandbox = mkdtempSync(join(tmpdir(), "sanitizer-instr-paths-"));
const projectDir = join(sandbox, "proj");
const outsideDir = join(sandbox, "home", ".claude", "rules");
mkdirSync(join(projectDir, ".claude"), { recursive: true });
mkdirSync(outsideDir, { recursive: true });
process.env.CLAUDE_PROJECT_DIR = projectDir;
const emptyConfigDir = join(sandbox, "empty-config");
mkdirSync(emptyConfigDir);
process.env.CLAUDE_CONFIG_DIR = emptyConfigDir;

const { cleanFile, scanText } = await import("../src/instructions.mjs");
const scanInvisible = await import("../claude-hooks/scan-invisible-chars.mjs");
const { scanLoadedFile } =
  await import("../claude-hooks/scan-loaded-instructions.mjs");
const { OPS } = await import("../bin/sanitize-cli.mjs");
const { alertDir } = await import("../claude-hooks/lib/invisible-alert.mjs");

after(() => {
  rmSync(sandbox, { recursive: true, force: true });
  rmSync(alertDir(), { recursive: true, force: true });
});

const tags = (/** @type {string} */ ascii) =>
  [...ascii]
    .map((ch) => String.fromCodePoint(0xe0000 + ch.charCodeAt(0)))
    .join("");

/**
 * Every parsed module under `dirs`, as `{ rel, src, ast }`.
 * @param {string[]} dirs  repo-relative
 */
function modules(dirs) {
  const out = [];
  const walk = (/** @type {string} */ dir) => {
    for (const entry of readdirSync(join(repoRoot, dir), {
      withFileTypes: true,
    })) {
      const rel = join(dir, entry.name);
      if (entry.isDirectory()) walk(rel);
      else if (/\.m?js$/.test(entry.name)) {
        const src = readFileSync(join(repoRoot, rel), "utf8");
        const ast = parse(src, {
          ecmaVersion: "latest",
          sourceType: "module",
          allowHashBang: true,
        });
        out.push({ rel: rel.split("\\").join("/"), src, ast });
      }
    }
  };
  for (const dir of dirs) walk(dir);
  return out;
}

/**
 * @param {() => Promise<unknown>} fn
 * @returns {Promise<string>}
 */
async function captureStderr(fn) {
  /** @type {string[]} */
  const chunks = [];
  const real = process.stderr.write;
  process.stderr.write = /** @type {any} */ (
    (/** @type {unknown} */ chunk) => {
      chunks.push(String(chunk));
      return true;
    }
  );
  try {
    await fn();
  } finally {
    process.stderr.write = real;
  }
  return chunks.join("");
}

// ─── writes ──────────────────────────────────────────────────────────────────

describe("every instruction-file write stays inside its root", () => {
  // The committable relative link from the audit repro: `.claude/rules` in the
  // project pointing at the user's global rules directory. O_NOFOLLOW guards
  // only the final component, so it alone lets this rewrite through.
  const original = `user rule ${tags("abcdefghijkl")}\n`;
  const outsideFile = join(outsideDir, "mine.md");
  const viaLink = join(projectDir, ".claude", "rules", "mine.md");

  before(() => {
    symlinkSync(
      relative(join(projectDir, ".claude"), outsideDir),
      join(projectDir, ".claude", "rules"),
      "dir",
    );
  });

  const reset = () => {
    writeFileSync(outsideFile, original);
    assert.ok(
      scanText(readFileSync(viaLink, "utf8")).length > 0,
      "precondition: flagged",
    );
  };
  const untouched = () =>
    assert.equal(
      readFileSync(outsideFile, "utf8"),
      original,
      "the outside file was rewritten",
    );

  it("cleanFile itself refuses it", () => {
    reset();
    assert.throws(
      () => cleanFile(viaLink, { root: projectDir }),
      /refusing to clean outside the root/,
    );
    untouched();
  });

  // One entry per module that USES cleanFile, checked against the acorn
  // enumeration below: a new write site lands here or the partition fails.
  /** @type {Record<string, () => Promise<void> | void>} */
  const WRITE_SITES = {
    "claude-hooks/scan-invisible-chars.mjs": async () => {
      reset();
      const stderr = await captureStderr(() =>
        withCapturedStdout(() =>
          scanInvisible.cliMain({ sessionId: "instr-paths-write" }),
        ),
      );
      untouched();
      // Positive marker: the scan reached the clean and reported the refusal,
      // rather than never seeing the file.
      assert.match(
        stderr,
        /could not clean \.claude\/rules\/mine\.md: refusing to clean outside the root/,
      );
    },
    "claude-hooks/scan-loaded-instructions.mjs": () => {
      reset();
      const result = scanLoadedFile(viaLink, { projectDir });
      assert.ok(result !== null, "the loaded file was not flagged");
      assert.equal(result.cleaned, false);
      assert.match(
        /** @type {string} */ (result.reason),
        /refusing to clean outside the root/,
      );
      untouched();
    },
    "bin/sanitize-cli.mjs": async () => {
      reset();
      await assert.rejects(
        OPS.cleanFile({ path: viaLink, root: projectDir }),
        /refusing to clean outside the root/,
      );
      untouched();
    },
  };

  for (const [site, check] of Object.entries(WRITE_SITES))
    it(
      `${site} refuses a rewrite through a directory symlink out of the project`,
      check,
    );

  it("covers every module that names cleanFile", () => {
    const live = modules(["src", "claude-hooks", "bin"])
      .filter(({ ast }) => {
        let named = false;
        simple(ast, {
          Identifier(node) {
            if (node.name === "cleanFile") named = true;
          },
        });
        return named;
      })
      .map(({ rel }) => rel)
      .sort();
    assert.deepEqual(live, Object.keys(WRITE_SITES).sort());
  });
});
