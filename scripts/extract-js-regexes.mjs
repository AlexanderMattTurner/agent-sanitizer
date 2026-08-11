/**
 * Static inventory of every regex in the JS that runs over untrusted input, for
 * the ReDoS guard (tests/test_redos_js_static_guard.py). Parses each source with
 * the TypeScript compiler (a dev dependency — a real JS parser, not a
 * hand-rolled regex-over-regex approximation) and emits, as JSON on stdout:
 *
 *   { "patterns": [{ "file": "src/html.mjs", "line": 12, "pattern": "...",
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
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

import { shippedSources } from "./shipped-sources.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

// Every .mjs this package SHIPS, from the one place that answers that question
// (scripts/shipped-sources.mjs, which resolves package.json's `files`). Shipped
// is exactly the scope that matters here: those modules are inlined into the
// plugin bundle and run inside a host's hook over tool output and prompts, so a
// super-linear pattern there can push the hook past the kill a host reads as a
// non-blocking error. Build and CI tooling is not shipped and so is not walked;
// it reads what this repo produces under a job timeout, not what a remote sent.
//
// Reading the manifest rather than a hardcoded root list is what keeps this
// honest: a newly shipped module, or a whole new shipped directory, joins the
// inventory with no edit here.
const analyzed = shippedSources(repoRoot);

/** @type {{file: string, line: number, pattern: string, flags: string}[]} */
const found = [];

for (const rel of analyzed) {
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

process.stdout.write(JSON.stringify({ patterns: found }, null, 2) + "\n");
