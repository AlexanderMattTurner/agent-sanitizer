/**
 * Partition tests over the hooks' two run-level decisions, read off acorn's
 * AST of every claude-hooks module (never a regex over source text):
 *
 *   - the secret opt-in (`secretsEnabled`) is decided ONCE per hook run and
 *     threaded down. Every other call is a direct caller's default parameter,
 *     or the fault-policy arm that runs when there was no run to thread from.
 *     A new body-level call is a second decision site — exactly the split that
 *     let the span loop dial the daemon while the walk treated the layer as off.
 *   - the fault posture (`failOpenEnabled`) is consulted only by the
 *     hook-fault registry, and the two env knobs are read only by their own
 *     accessor, so no hook can hard-code a fail-open/closed decision of its own.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "acorn";
import { ancestor } from "acorn-walk";
import { repoRoot } from "./helpers/repo-root.mjs";

/** Every hook module, as a repo-relative path. */
const HOOK_MODULES = readdirSync(join(repoRoot, "claude-hooks"), {
  recursive: true,
})
  .map(String)
  .filter((path) => path.endsWith(".mjs"))
  .map((path) => join("claude-hooks", path))
  .sort();

/**
 * Name the innermost function enclosing the last node of `ancestors`, suffixed
 * `(default)` when the node sits in that function's parameter list.
 * @param {any[]} ancestors
 * @returns {string}
 */
function siteName(ancestors) {
  for (let i = ancestors.length - 2; i >= 0; i--) {
    const node = ancestors[i];
    if (!node.type.includes("Function")) continue;
    const parent = ancestors[i - 1];
    const name =
      node.id?.name ??
      (parent?.type === "VariableDeclarator" ? parent.id.name : undefined) ??
      (parent?.type === "Property" ? parent.key.name : "<anonymous>");
    return node.params.includes(ancestors[i + 1]) ? `${name}(default)` : name;
  }
  return "<module>";
}

/**
 * `file#function` for every node `match` accepts, across every hook module.
 * @param {(node: any) => boolean} match
 * @param {string} type  the AST node type to visit
 * @returns {string[]}
 */
function sites(type, match) {
  const found = [];
  for (const file of HOOK_MODULES) {
    const ast = parse(readFileSync(join(repoRoot, file), "utf8"), {
      ecmaVersion: "latest",
      sourceType: "module",
    });
    ancestor(ast, {
      [type](node, _state, ancestors) {
        if (match(node)) found.push(`${file}#${siteName(ancestors)}`);
      },
    });
  }
  return found.sort();
}

const calls = (name) =>
  sites(
    "CallExpression",
    (node) => node.callee.type === "Identifier" && node.callee.name === name,
  );

/** Reads of `env[KEY]`, `env["literal"]` or `env.literal` for one knob. */
const envReads = (constName, literal) =>
  sites("MemberExpression", ({ computed, property }) =>
    computed
      ? (property.type === "Identifier" && property.name === constName) ||
        (property.type === "Literal" && property.value === literal)
      : property.name === literal,
  );

describe("hook decision sites", () => {
  it("scans the hook tree (non-vacuous)", () => {
    for (const known of [
      "claude-hooks/pretooluse-sanitize.mjs",
      "claude-hooks/sanitize-output.mjs",
      "claude-hooks/lib/hook-fault.mjs",
      "claude-hooks/lib/env-config.mjs",
    ])
      assert.ok(HOOK_MODULES.includes(known), `${known} not scanned`);
  });

  it("decides the secret opt-in once per run, defaulting only direct callers", () => {
    assert.deepEqual(calls("secretsEnabled"), [
      // PreToolUse: THE decision for a run, threaded into the stage table.
      "claude-hooks/pretooluse-sanitize.mjs#buildPreToolUseResponse",
      // The registered fault policy's open arm: a fault has no run to thread
      // a decision from.
      "claude-hooks/pretooluse-sanitize.mjs#open",
      "claude-hooks/pretooluse-sanitize.mjs#preToolUseLayers(default)",
      "claude-hooks/pretooluse-sanitize.mjs#rehydrateLayer2(default)",
      // PostToolUse: THE decision for a run, threaded through the walk and
      // the reveal/span persistence.
      "claude-hooks/sanitize-output.mjs#evaluateToolOutput",
      "claude-hooks/sanitize-output.mjs#sanitizeText(default)",
      "claude-hooks/sanitize-output.mjs#sanitizeValue(default)",
    ]);
  });

  it("consults the fault posture only in the hook-fault registry", () => {
    assert.deepEqual(calls("failOpenEnabled"), [
      "claude-hooks/lib/hook-fault.mjs#hookFaultOutcome",
    ]);
  });

  it("reads each knob only through its own accessor", () => {
    assert.deepEqual(envReads("FAIL_OPEN_ENV", "AGENT_SANITIZER_FAIL_OPEN"), [
      "claude-hooks/lib/hook-io.mjs#failOpenEnabled",
    ]);
    assert.deepEqual(
      envReads("SECRETS_ENABLED_ENV", "AGENT_SANITIZER_SECRETS_ENABLED"),
      ["claude-hooks/lib/env-config.mjs#secretsEnabled"],
    );
  });
});
