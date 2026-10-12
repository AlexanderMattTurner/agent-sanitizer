/**
 * The two path invariants of the instruction-file scanners, each held at ONE
 * chokepoint and partitioned over every site that needs it:
 *
 *   - WRITES: every rewrite of an instruction file goes through cleanFile's
 *     realpath containment, so a directory symlink in the project cannot carry
 *     an auto-clean to a file outside it, and every other fs write in the
 *     package is a named hook store.
 *   - RENDERS: every file path or reason a scanner renders into a report,
 *     stderr or model context goes through displayUntrusted, so a hostile
 *     filename cannot carry its own payload (tag characters, an OSC sequence).
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
import { ancestor, simple } from "acorn-walk";

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
const { describeExfil } = await import("../src/warnings.mjs");
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

  // Every node:fs call in src/ and claude-hooks/ that can create, change or
  // remove a file, keyed `module::enclosingFunction`. The instruction-file
  // rewrite is the first group; every other site writes the hooks' own state,
  // never a scanned tree, and carries its reason.
  // Base names; each is checked in both its callback/promise spelling
  // (`node:fs/promises` imports are mapped by `fsBindings`) and its `Sync` one.
  const FS_MUTATOR_BASES = [
    "appendFile",
    "chmod",
    "chown",
    "copyFile",
    "cp",
    "fchmod",
    "fchown",
    "ftruncate",
    "futimes",
    "link",
    "mkdir",
    "mkdtemp",
    "open",
    "rename",
    "rm",
    "rmdir",
    "symlink",
    "truncate",
    "unlink",
    "utimes",
    "write",
    "writeFile",
  ];
  const FS_MUTATORS = new Set([
    "createWriteStream",
    ...FS_MUTATOR_BASES,
    ...FS_MUTATOR_BASES.map((name) => `${name}Sync`),
  ]);
  const INSTRUCTION_WRITE = [
    "src/atomic-replace.mjs::atomicReplaceFile",
    // The O_RDONLY|O_NOFOLLOW open of the already-contained target.
    "src/instructions.mjs::cleanFile",
  ];
  /** @type {Record<string, string>} */
  const FS_EXEMPT = {
    "claude-hooks/lib/hook-io.mjs::writeFileNoFollow":
      "a hook state file under $TMPDIR, created O_EXCL after unlinking a squatter",
    "claude-hooks/lib/hook-io.mjs::writeSentinelFile":
      "an empty hook sentinel under $TMPDIR, created O_EXCL",
    "claude-hooks/lib/invisible-alert.mjs::appendAlert":
      "the alert store under alertDir() in $TMPDIR",
    "claude-hooks/lib/invisible-alert.mjs::drop":
      "removes a session's alert store under alertDir()",
    "claude-hooks/lib/invisible-alert.mjs::sweepStaleSessions":
      "expires session alert stores under alertDir()",
    "claude-hooks/lib/reveal.mjs::readSpan":
      "an O_RDONLY|O_NOFOLLOW read of a span in the reveal store",
    "claude-hooks/lib/reveal.mjs::revealDirIsSafe":
      "creates the reveal store in $TMPDIR",
    "claude-hooks/lib/reveal.mjs::sweepStaleReveals":
      "expires spans in the reveal store",
    "claude-hooks/lib/secret-drop-guard.mjs::consumeConfirm":
      "consumes a single-use confirm marker in $TMPDIR",
    "claude-hooks/lib/secret-drop-guard.mjs::sweepStaleConfirms":
      "expires confirm markers in $TMPDIR",
    "claude-hooks/lib/trace.mjs::trace":
      "the opt-in debug log at the operator's _AGENT_SANITIZER_TRACE_FILE",
  };

  it("routes every fs write in the package through atomicReplaceFile or an exempt store", () => {
    /** @type {Set<string>} */
    const live = new Set();
    for (const { rel, ast } of modules(["src", "claude-hooks"])) {
      const fsNames = fsBindings(ast);
      ancestor(ast, {
        CallExpression(node, _state, ancestors) {
          const callee = /** @type {any} */ (node).callee;
          if (callee.type !== "Identifier") return;
          if (!FS_MUTATORS.has(fsNames.get(callee.name) ?? "")) return;
          live.add(`${rel}::${enclosingFunction(ancestors)}`);
        },
      });
    }
    assert.ok(
      live.has(INSTRUCTION_WRITE[0]),
      "the rewrite itself was not found",
    );
    assert.deepEqual(
      [...live].sort(),
      [...INSTRUCTION_WRITE, ...Object.keys(FS_EXEMPT)].sort(),
    );
  });

  it("reaches atomicReplaceFile only from cleanFile", () => {
    // acorn-walk visits a binding (declaration name, import specifier) as a
    // pattern, not an Identifier expression, so only USES land here.
    /** @type {string[]} */
    const callers = [];
    for (const { rel, ast } of modules(["src", "claude-hooks", "bin"]))
      ancestor(ast, {
        Identifier(node, _state, ancestors) {
          if (node.name === "atomicReplaceFile")
            callers.push(`${rel}::${enclosingFunction(ancestors)}`);
        },
      });
    assert.deepEqual(callers, ["src/instructions.mjs::cleanFile"]);
  });
});

/**
 * Local name → node:fs export name, for every named import from node:fs.
 * Throws on a namespace or default import, whose calls this map cannot see.
 * @param {any} ast
 * @returns {Map<string, string>}
 */
function fsBindings(ast) {
  const names = new Map();
  for (const node of ast.body) {
    if (node.type !== "ImportDeclaration") continue;
    if (!/^(?:node:)?fs(?:\/promises)?$/.test(node.source.value)) continue;
    for (const spec of node.specifiers) {
      if (spec.type !== "ImportSpecifier")
        throw new Error(`unhandled fs import shape: ${spec.type}`);
      names.set(spec.local.name, spec.imported.name);
    }
  }
  return names;
}

/**
 * Name of the innermost named function around the node `ancestors` ends at:
 * a declaration's own name, or the binding a function expression is assigned
 * to. Module scope is `<module>`.
 * @param {any[]} ancestors
 * @returns {string}
 */
function enclosingFunction(ancestors) {
  for (let i = ancestors.length - 2; i >= 0; i--) {
    const node = ancestors[i];
    if (node.type === "FunctionDeclaration") return node.id.name;
    if (
      node.type !== "FunctionExpression" &&
      node.type !== "ArrowFunctionExpression"
    )
      continue;
    const parent = ancestors[i - 1];
    if (parent.type === "VariableDeclarator") return parent.id.name;
    if (parent.type === "Property" || parent.type === "MethodDefinition")
      return parent.key.name;
  }
  return "<module>";
}

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
    "src/warnings.mjs::threat.target": () =>
      rendersNeutralized(
        describeExfil([{ isImage: false, target: HOSTILE, reason: "r" }]),
      ),
  };

  for (const [site, check] of Object.entries(RENDER_SITES))
    it(`${site} escapes a hostile string`, check);

  // The modules whose output carries text from a scanned tree. In these EVERY
  // interpolated or concatenated expression is either wrapped in
  // displayUntrusted or listed in STRICT_EXEMPT with its reason: no name filter
  // decides what counts as untrusted-shaped, so a hole spelled `target` or `rel`
  // fails here instead of slipping past a list of spellings.
  const STRICT_MODULES = [
    "claude-hooks/lib/invisible-report.mjs",
    "claude-hooks/scan-invisible-chars.mjs",
    "claude-hooks/scan-loaded-instructions.mjs",
    "src/claude-context.mjs",
    "src/warnings.mjs",
  ];
  // Keyed `module` then expression source (whitespace collapsed). An expression
  // is exempt by its spelling, so a variable named like an exempt one inherits
  // the exemption: each pass-through below is the output of a formatter whose
  // own sites are in RENDER_SITES and exercised with a hostile string.
  /** @type {Record<string, Record<string, string>>} */
  const STRICT_EXEMPT = {
    "claude-hooks/lib/invisible-report.mjs": {
      "BAR.slice(0, 11)": "the report's own rule glyphs",
      "finding.line": "a line number or null, from scanText",
      where: "'Whole file' or 'Line <number>'",
      "finding.charCount": "a count",
      "finding.method":
        "one of decodeRun's fixed method labels, never file text",
      "JSON.stringify(finding.decoded)":
        "decodeRun's output: tag bytes rendered through neutralizeTagBytes (printable ASCII or a \\xNN escape), counts, and U+XXXX labels",
    },
    "claude-hooks/scan-invisible-chars.mjs": {
      HOOK_NAME: "this hook's own name",
      "ctx.message":
        "a hook FAULT's text, reduced by safeErrMessage to printable ASCII, tab and newline",
      "faultLine(ctx)": "HOOK_NAME plus the fault text above",
      notice: "formatSkipped's output, whose file and reason are wrapped",
      cleaned: "a count of cleaned files",
      report: "formatReport's output, whose file names are wrapped",
    },
    "claude-hooks/scan-loaded-instructions.mjs": {
      HOOK_NAME: "this hook's own name",
      "ctx.message":
        "a hook FAULT's text, reduced by safeErrMessage to printable ASCII, tab and newline",
      "faultLine(ctx)": "HOOK_NAME plus the fault text above",
      stale:
        "contextScopeContradiction's notice, whose one path segment is wrapped",
      report: "formatReport's output, whose file names are wrapped",
      tail: "loadedFileMessage's closing paragraph, whose path and reason are wrapped",
      notice: "scopeNotice's output: HOOK_NAME around the wrapped notice",
      message: "loadedFileMessage's output: the wrapped report and tail",
    },
    "src/claude-context.mjs": {
      prefix: "'' or '**/', chosen by claudeDirPatterns' callers",
      sub: "an entry of CLAUDE_CONTEXT_SUBDIRS, a constant table",
      name: "an entry of CLAUDE_DIR_INSTRUCTION_FILES, a constant table",
      sep: "the platform path separator",
      "STRIP.source": "the escape set's own regex source, not file text",
      "(ch.codePointAt(0)).toString(16).toUpperCase()":
        "hex digits of a code point, inside the escape itself",
      "row.name": "a row of CLAUDE_CONTEXT_KINDS, a constant table",
    },
    "src/warnings.mjs": {
      "removed.comments": "a count",
      "removed.hidden": "a count",
      "describeRemoved(removed)": "counts and fixed nouns",
      count: "a count",
      tag: "a key of warned.tags, which html.mjs fills only from REPORTED_TAGS",
      "warned.dataSrc": "a count",
      'parts.join(", ")': "counts and fixed nouns",
      'threat.isImage ? "image" : "link"': "a fixed word",
      "threat.reason":
        "a link/image threat's engine-authored classification (html.mjs paramExfilReason and its fixed literals), never file text",
      'reasons.join("; ")': "the sentences built above, target wrapped",
      'hosts.join("; ")':
        "confusable-host descriptions: the host as the WHATWG URL parser normalized it, which rejects or strips invisible and control code points; the look-alike letters are shown on purpose",
    },
  };

  // Untrusted-shaped interpolations in every OTHER module that are NOT a
  // scanned tree's text, each with the reason it may render raw. Keyed by module
  // and expression, so a new raw use of an exempt expression shares its reason
  // and anything else fails.
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
  ]);

  it("covers every untrusted-shaped interpolation in the hooks and the engine", () => {
    const SHAPED =
      /^(?:\w+\.)?(?:file|filePath|file_path|absPath|path|dir|tail\[0\]|reason)$|^safeErrMessage\(/;
    const strictModules = new Set(STRICT_MODULES);
    // True for a `+` that builds a string: a string literal or template sits
    // somewhere in its left spine or on its right. Numeric `+` is arithmetic.
    const concatenates = (/** @type {any} */ node) =>
      (node.type === "Literal" && typeof node.value === "string") ||
      node.type === "TemplateLiteral" ||
      (node.type === "BinaryExpression" &&
        node.operator === "+" &&
        (concatenates(node.left) || concatenates(node.right)));
    /** @type {Set<string>} */
    const raw = new Set();
    /** @type {Set<string>} */
    const strictRaw = new Set();
    /** @type {string[]} */
    const wrapped = [];
    /** @type {Map<string, {classified: number, wrapped: number}>} */
    const strictSeen = new Map();
    for (const { rel, src, ast } of modules(["claude-hooks", "src"])) {
      const strict = strictModules.has(rel);
      const seen = { classified: 0, wrapped: 0 };
      if (strict) strictSeen.set(rel, seen);
      const text = (/** @type {any} */ n) =>
        src.slice(n.start, n.end).replace(/\s+/g, " ");
      const classify = (/** @type {any} */ expr) => {
        seen.classified++;
        if (
          expr.type === "CallExpression" &&
          expr.callee.type === "Identifier" &&
          expr.callee.name === "displayUntrusted"
        ) {
          seen.wrapped++;
          wrapped.push(`${rel}::${text(expr.arguments[0])}`);
        } else if (strict) strictRaw.add(`${rel}::${text(expr)}`);
        else if (SHAPED.test(text(expr))) raw.add(`${rel}::${text(expr)}`);
      };
      simple(ast, {
        TemplateLiteral(node) {
          node.expressions.forEach(classify);
        },
        BinaryExpression(node) {
          if (node.operator !== "+" || !concatenates(node)) return;
          for (const side of [node.left, node.right])
            if (
              side.type !== "TemplateLiteral" &&
              side.type !== "BinaryExpression" &&
              !(side.type === "Literal" && typeof side.value === "string")
            )
              classify(side);
        },
      });
    }
    assert.deepEqual([...raw].sort(), [...EXEMPT].sort());
    assert.deepEqual(
      [...strictRaw].sort(),
      Object.entries(STRICT_EXEMPT)
        .flatMap(([rel, exprs]) =>
          Object.keys(exprs).map((e) => `${rel}::${e}`),
        )
        .sort(),
    );
    // Positive markers: every strict module was parsed, rendered something, and
    // wraps at least one string, so an emptied or renamed module cannot pass by
    // contributing nothing.
    assert.deepEqual([...strictSeen.keys()].sort(), [...STRICT_MODULES].sort());
    for (const [rel, { classified, wrapped: n }] of strictSeen) {
      assert.ok(classified > 0, `${rel} classified no expression`);
      assert.ok(n > 0, `${rel} wraps no untrusted string`);
    }
    assert.deepEqual(
      wrapped.sort(),
      Object.keys(RENDER_SITES)
        .map((key) => key.replace(/#.*$/, ""))
        .sort(),
    );
  });
});
