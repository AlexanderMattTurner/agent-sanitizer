/**
 * Layer 3's TOOL SCOPE is a declared partition, not a silent fallthrough.
 *
 * `sanitizeAuthoredContent` sanitizes the model-authored fields of the tools in
 * `AUTHORED_FIELDS` and returns null for everything else. Returning null is the
 * right BEHAVIOUR for a tool with no authored free-text field — but before this
 * file existed, "no field to sanitize" and "nobody has looked at this tool" were
 * the same line of code, so an unlisted tool (every `mcp__*` server tool among
 * them) left no record that a decision had been made.
 *
 * The partition below is that record: every tool the package elsewhere claims to
 * know must be either COVERED (a field list) or EXEMPT (a stated reason), and
 * never both, and never neither. A new tool that lands in neither side fails the
 * partition assertion at review time rather than passing through unremarked
 * forever.
 *
 * Paired with a POSITIVE MARKER per covered tool — a payload carrying a raw ESC
 * must come back CHANGED — so the partition cannot be satisfied by the field map
 * going empty, and with a NEGATIVE one per exempt tool proving the exemption is
 * a real pass-through and not an untested claim.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AUTHORED_FIELDS,
  EXEMPT_TOOLS,
  EXEMPT_TOOL_PATTERNS,
  authoredScopeDecision,
  sanitizeAuthoredContent,
} from "../claude-hooks/lib/authored-content.mjs";
import { liveToolSurface } from "./helpers/tool-surface.mjs";

// A raw ESC built in-language: a literal one in a shell string trips this repo's
// own PreToolUse guard, which is the layer under test.
const ESC = "\u001b";
const ANSI_PAYLOAD = `before${ESC}[2Jafter`;

/**
 * A tool_input carrying `value` in the field `spec` addresses, so the positive
 * marker is built from the live field map instead of a second hand-kept copy.
 * @param {string} spec
 * @param {string} value
 */
function inputFor(spec, value) {
  const nested = /^(?<arr>\w+)\[\]\.(?<sub>\w+)$/u.exec(spec);
  if (!nested) return { [spec]: value };
  return { [nested.groups.arr]: [{ [nested.groups.sub]: value }] };
}

/** The field `spec` addresses, read back out of a sanitized tool_input. */
function readField(spec, input) {
  const nested = /^(?<arr>\w+)\[\]\.(?<sub>\w+)$/u.exec(spec);
  if (!nested) return input[spec];
  return input[nested.groups.arr][0][nested.groups.sub];
}

test("the tool surface is partitioned: every tool is covered or exempt, never both", () => {
  const unclassified = [];
  const doubleClassified = [];
  for (const tool of liveToolSurface()) {
    const covered = Object.hasOwn(AUTHORED_FIELDS, tool);
    const exempt = authoredScopeDecision(tool).kind === "exempt";
    if (!covered && !exempt) unclassified.push(tool);
    if (covered && exempt) doubleClassified.push(tool);
  }
  assert.deepEqual(
    unclassified,
    [],
    "tools Layer 3 has taken no position on — add a field list to AUTHORED_FIELDS " +
      "or an entry (with a reason) to EXEMPT_TOOLS / EXEMPT_TOOL_PATTERNS",
  );
  assert.deepEqual(
    doubleClassified,
    [],
    "tools that are both sanitized and exempt — the partition is ambiguous",
  );
});

test("every exemption states a reason", () => {
  const entries = Object.entries(EXEMPT_TOOLS);
  assert.ok(
    entries.length > 0,
    "EXEMPT_TOOLS is empty — the partition is vacuous",
  );
  for (const [tool, reason] of entries)
    assert.ok(
      typeof reason === "string" && reason.length > 20,
      `EXEMPT_TOOLS.${tool} carries no usable rationale`,
    );
  assert.ok(EXEMPT_TOOL_PATTERNS.length > 0, "EXEMPT_TOOL_PATTERNS is empty");
  for (const { pattern, reason } of EXEMPT_TOOL_PATTERNS)
    assert.ok(
      pattern instanceof RegExp &&
        typeof reason === "string" &&
        reason.length > 20,
      `EXEMPT_TOOL_PATTERNS entry for ${pattern} carries no usable rationale`,
    );
});

test("positive marker: every covered tool strips a raw ESC from every declared field", () => {
  const tools = Object.entries(AUTHORED_FIELDS);
  assert.ok(
    tools.length > 0,
    "AUTHORED_FIELDS is empty — the markers are vacuous",
  );
  for (const [tool, specs] of tools) {
    assert.ok(specs.length > 0, `${tool} declares no fields`);
    for (const spec of specs) {
      const result = sanitizeAuthoredContent(
        tool,
        inputFor(spec, ANSI_PAYLOAD),
      );
      assert.ok(result, `${tool}.${spec} left a raw ESC in place`);
      assert.equal(readField(spec, result.updatedInput), "beforeafter");
      assert.ok(
        result.changed.some((entry) => entry.startsWith(spec.split("[]")[0])),
      );
    }
  }
});

test("negative marker: an exempt tool is a real pass-through, not an untested claim", () => {
  const exempt = [
    ...Object.keys(EXEMPT_TOOLS),
    "mcp__github__create_issue",
    "mcp__slack__post_message",
  ];
  // Every field name any covered tool declares, so the pass-through is proven
  // against the shapes the layer knows how to rewrite — not just an empty input.
  const everyField = {};
  for (const specs of Object.values(AUTHORED_FIELDS))
    Object.assign(everyField, inputFor(specs[0], ANSI_PAYLOAD));
  for (const tool of exempt) {
    assert.equal(authoredScopeDecision(tool).kind, "exempt", tool);
    assert.equal(sanitizeAuthoredContent(tool, everyField), null, tool);
  }
});

test("a tool on neither side is reported as undeclared, not silently covered", () => {
  // The decision helper is what makes the miss legible; the BEHAVIOUR for an
  // undeclared tool stays the historical pass-through, so naming one here is
  // not a claim that it should be sanitized.
  const decision = authoredScopeDecision("SomeToolNobodyClassified");
  assert.equal(decision.kind, "undeclared");
  assert.equal(sanitizeAuthoredContent("SomeToolNobodyClassified", {}), null);
});

test("a prototype-chain tool name is undeclared, not a field list", () => {
  // `FIELDS["constructor"]` on a plain object literal answers Object, which the
  // field loop would then try to iterate. Both maps are null-prototype.
  for (const tool of [
    "constructor",
    "__proto__",
    "toString",
    "hasOwnProperty",
  ]) {
    assert.equal(authoredScopeDecision(tool).kind, "undeclared", tool);
    assert.equal(
      sanitizeAuthoredContent(tool, { content: ANSI_PAYLOAD }),
      null,
    );
  }
});
