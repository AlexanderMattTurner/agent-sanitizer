/**
 * The two path invariants of the instruction-file scanners, each held at ONE
 * chokepoint and partitioned over every site that needs it:
 *
 *   - WRITES: every rewrite of an instruction file goes through cleanFile's
 *     realpath containment, so a directory symlink in the project cannot carry
 *     an auto-clean to a file outside it.
 *   - RENDERS: every file path a scanner renders into a report, stderr or model
 *     context goes through displayUntrusted, so a hostile filename cannot carry its
 *     own payload (tag characters, an OSC sequence) into the report.
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
const { contextScopeContradiction, displayUntrusted } =
  await import("../src/claude-context.mjs");
const { formatReport } =
  await import("../claude-hooks/lib/invisible-report.mjs");
const scanInvisible = await import("../claude-hooks/scan-invisible-chars.mjs");
const { scanLoadedFile, loadedFileMessage } =
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

// ─── renders ─────────────────────────────────────────────────────────────────

const ESC = "\u001b";
const BEL = "\u0007";
// A filename that tries every channel: an OSC title-set, tag characters
// spelling an instruction, a bidi override, and a newline forging a report line.
const HOSTILE = `x${ESC}]0;pwned${BEL}${tags("obey")}\u202e\nLine 1: fake.md`;
const RAW_UNSAFE = /[\p{Cc}\u202a-\u202e\u2066-\u2069\u{e0000}-\u{e007f}]/u;

/**
 * The rendered text carries the hostile string only in its escaped form, and
 * its newline forged no line. The report's own newlines are its layout, so
 * only the remaining bytes are checked for raw controls.
 * @param {string} rendered
 */
function rendersNeutralized(rendered) {
  assert.ok(
    rendered.includes(displayUntrusted(HOSTILE)),
    "the escaped text is missing",
  );
  assert.doesNotMatch(rendered, /^Line 1: fake\.md/m, "a line was forged");
  assert.doesNotMatch(rendered.split("\n").join(""), RAW_UNSAFE);
}

describe("every scanner-rendered untrusted string goes through displayUntrusted", () => {
  const finding = { line: 1, charCount: 12, method: "m", decoded: "d" };

  // A finding on a file that does not exist: the auto-clean fails with an fs
  // error quoting the hostile name, so both halves of the line are exercised.
  const couldNotClean = async () => {
    const stderr = await captureStderr(() =>
      withCapturedStdout(() =>
        scanInvisible.cliMain({
          sessionId: "instr-paths-render",
          scan: () => ({
            targets: [],
            scanned: 1,
            skipped: [],
            absent: [],
            findings: [{ file: HOSTILE, findings: [finding] }],
          }),
        }),
      ),
    );
    assert.match(stderr, /could not clean .*ENOENT/);
    rendersNeutralized(stderr);
  };
  const skipped = (/** @type {string} */ file, /** @type {string} */ reason) =>
    rendersNeutralized(scanInvisible.formatSkipped([{ file, reason }]));
  const loaded = (
    /** @type {boolean} */ cleaned,
    /** @type {string | null} */ reason,
  ) =>
    rendersNeutralized(
      loadedFileMessage({ report: "r", cleaned, reason }, HOSTILE),
    );

  // One entry per displayUntrusted call site, keyed `module::argument`, checked
  // against the acorn enumeration below.
  /** @type {Record<string, () => Promise<void> | void>} */
  const RENDER_SITES = {
    "claude-hooks/lib/invisible-report.mjs::file": () =>
      rendersNeutralized(
        formatReport([{ file: HOSTILE, findings: [finding] }]),
      ),
    "claude-hooks/scan-invisible-chars.mjs::file#formatSkipped": () =>
      skipped(HOSTILE, "EACCES"),
    "claude-hooks/scan-invisible-chars.mjs::reason#formatSkipped": () =>
      skipped("a.md", HOSTILE),
    "claude-hooks/scan-invisible-chars.mjs::file#could-not-clean":
      couldNotClean,
    "claude-hooks/scan-invisible-chars.mjs::safeErrMessage(err)#could-not-clean":
      couldNotClean,
    "claude-hooks/scan-loaded-instructions.mjs::filePath#cleaned": () =>
      loaded(true, null),
    "claude-hooks/scan-loaded-instructions.mjs::filePath#still": () =>
      loaded(false, "x"),
    "claude-hooks/scan-loaded-instructions.mjs::reason#still": () =>
      rendersNeutralized(
        loadedFileMessage(
          { report: "r", cleaned: false, reason: HOSTILE },
          "a",
        ),
      ),
    "src/claude-context.mjs::tail[0]": () => {
      const notice = contextScopeContradiction(
        join(projectDir, ".claude", HOSTILE, "x.md"),
        "nested_traversal",
      );
      assert.ok(notice !== null, "the scope notice did not fire");
      rendersNeutralized(notice);
    },
  };

  for (const [site, check] of Object.entries(RENDER_SITES))
    it(`${site} escapes a hostile string`, check);

  // Untrusted-shaped interpolations that are NOT a scanned tree's text, each
  // with the reason it may render raw. Keyed by module and expression, so a new
  // raw use of an exempt expression shares its reason and anything else fails.
  const EXEMPT = new Set([
    // The hook's own $TMPDIR store, composed by this package.
    "claude-hooks/lib/invisible-alert.mjs::dir",
    "claude-hooks/lib/reveal.mjs::dir",
    "claude-hooks/lib/reveal.mjs::path",
    // A JSON key path inside the model's own tool input.
    "claude-hooks/lib/placeholder-grammar.mjs::path",
    // A JSON key path built from Layer-1-cleaned keys.
    "claude-hooks/sanitize-output.mjs::path",
    // The model's own Write/Edit file_path, echoed back in its own verdict.
    "claude-hooks/lib/secret-drop-guard.mjs::filePath",
    "src/rehydrate.mjs::filePath",
    "src/rehydrate.mjs::ti.file_path",
    "src/rehydrate.mjs::toolInput.file_path",
    // A hook FAULT's text, reduced by safeErrMessage to printable ASCII, tab
    // and newline: no invisible, bidi or escape character survives it.
    "claude-hooks/lib/hook-io.mjs::safeErrMessage(err)",
    "claude-hooks/pretooluse-sanitize.mjs::safeErrMessage(err)",
    // A link/image threat's engine-authored classification, not file text.
    "src/warnings.mjs::threat.reason",
    // A ±1 scan direction in index arithmetic, not a path.
    "src/invisible.mjs::dir",
  ]);

  it("covers every untrusted-shaped interpolation in the hooks and the engine", () => {
    const SHAPED =
      /^(?:\w+\.)?(?:file|filePath|file_path|absPath|path|dir|tail\[0\]|reason)$|^safeErrMessage\(/;
    /** @type {Set<string>} */
    const raw = new Set();
    /** @type {string[]} */
    const wrapped = [];
    for (const { rel, src, ast } of modules(["claude-hooks", "src"])) {
      const text = (/** @type {any} */ n) => src.slice(n.start, n.end);
      const classify = (/** @type {any} */ expr) => {
        if (
          expr.type === "CallExpression" &&
          expr.callee.type === "Identifier" &&
          expr.callee.name === "displayUntrusted"
        )
          wrapped.push(`${rel}::${text(expr.arguments[0])}`);
        else if (SHAPED.test(text(expr))) raw.add(`${rel}::${text(expr)}`);
      };
      simple(ast, {
        TemplateLiteral(node) {
          node.expressions.forEach(classify);
        },
        BinaryExpression(node) {
          if (node.operator !== "+") return;
          for (const side of [node.left, node.right])
            if (
              side.type !== "TemplateLiteral" &&
              side.type !== "BinaryExpression"
            )
              classify(side);
        },
      });
    }
    assert.deepEqual([...raw].sort(), [...EXEMPT].sort());
    assert.deepEqual(
      wrapped.sort(),
      Object.keys(RENDER_SITES)
        .map((key) => key.replace(/#.*$/, ""))
        .sort(),
    );
  });
});
