/**
 * Static inventory of every regex in the JS that runs over untrusted input, for
 * the ReDoS guard (tests/test_redos_js_static_guard.py). Parses each source with
 * the TypeScript compiler (a dev dependency — a real JS parser, not a
 * hand-rolled regex-over-regex approximation) and emits, as JSON on stdout:
 *
 *   { "roots":    { "src": ["src/html.mjs", ...], ... },
 *     "patterns": [{ "file": "src/html.mjs", "line": 12, "pattern": "...",
 *                    "flags": "..." }] }
 *
 * Collected forms:
 *   - regex literals: /pattern/flags
 *   - `new RegExp("pattern")` / `RegExp("pattern", "flags")` where the pattern
 *     is a plain string literal (a dynamically built pattern has no static
 *     text to analyze; none exist in these roots today, and the paired guard
 *     test asserts the total inventory count so a new dynamic construction site
 *     shows up as a count change, not a silent hole).
 */
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

// The roots whose regexes meet input an attacker chooses: the engine, the hooks
// that hand it tool output and prompts, and the CLI the wheel ships. All three
// are inlined into the shipped plugin bundle, so a super-linear pattern here
// runs inside a host's hook and can push it past the kill that reads as a
// non-blocking error. Build and CI tooling (scripts/, .github/scripts/,
// .claude/hooks/, .hooks/) is deliberately out: it reads what this repo
// produces, not what a remote sent, and a runaway there stops at the job's
// timeout-minutes rather than at a user's session.
const ROOTS = ["src", "claude-hooks", "bin"];

/** Every non-test `.mjs` under `dir`, recursively, repo-relative. */
function sources(dir) {
  const out = [];
  for (const entry of readdirSync(join(repoRoot, dir), {
    withFileTypes: true,
  }).sort((a, b) => a.name.localeCompare(b.name))) {
    const rel = `${dir}/${entry.name}`;
    if (entry.isDirectory()) out.push(...sources(rel));
    else if (entry.name.endsWith(".mjs") && !entry.name.endsWith(".test.mjs"))
      out.push(rel);
  }
  return out;
}

// Reported alongside the patterns so the guard test can assert each root was
// actually walked. A total count cannot: src alone carries more patterns than
// any floor worth setting, so a root dropping out of ROOTS — or a walk that
// stops descending — leaves the guard green over a surface nobody analyzed.
const walked = Object.fromEntries(ROOTS.map((root) => [root, sources(root)]));

/** @type {{file: string, line: number, pattern: string, flags: string}[]} */
const found = [];

for (const rel of Object.values(walked).flat()) {
  const text = readFileSync(join(repoRoot, rel), "utf8");
  const sf = ts.createSourceFile(rel, text, ts.ScriptTarget.ESNext, true);

  /** @param {import("typescript").Node} node */
  const visit = (node) => {
    if (ts.isRegularExpressionLiteral(node)) {
      const lastSlash = node.text.lastIndexOf("/");
      found.push({
        file: rel,
        line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1,
        pattern: node.text.slice(1, lastSlash),
        flags: node.text.slice(lastSlash + 1),
      });
    } else if (
      (ts.isNewExpression(node) || ts.isCallExpression(node)) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "RegExp" &&
      node.arguments?.length &&
      ts.isStringLiteralLike(node.arguments[0])
    ) {
      const flagsArg = node.arguments[1];
      found.push({
        file: rel,
        line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1,
        pattern: node.arguments[0].text,
        flags:
          flagsArg && ts.isStringLiteralLike(flagsArg) ? flagsArg.text : "",
      });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}

process.stdout.write(
  JSON.stringify({ roots: walked, patterns: found }, null, 2) + "\n",
);
