/**
 * Every tool name the package elsewhere claims to know, plus a representative
 * `mcp__*` sample. Shared by the two declared-scope partition tests (the
 * authored-content layer and the confusable fold), each of which must have taken
 * a position on every tool in it — one universe, so a tool added to the package
 * cannot be classified by one partition and missed by the other.
 *
 * The hook-side sets are IMPORTED, not source-read. Stryker instruments exactly
 * these files, so a regex over their `new Set([...])` literals reads rewritten
 * source and fires the partition assertion on a healthy tree. A hand-copied list
 * would be the drift these tests exist to catch, so importing the live objects
 * is the only spelling that is neither a copy nor a parser approximation.
 */
import assert from "node:assert/strict";
import { REHYDRATED_TOOLS } from "../../claude-hooks/lib/placeholder-grammar.mjs";
import { WRITE_SHAPED_TOOLS } from "../../claude-hooks/pretooluse-sanitize.mjs";
import { DEFAULT_FIELDS } from "../../src/confusables.mjs";

/** @returns {Set<string>} */
export function liveToolSurface() {
  // Non-vacuity: an emptied set would silently shrink the surface and make the
  // partition assertion pass over almost nothing.
  assert.ok(REHYDRATED_TOOLS.size > 0, "REHYDRATED_TOOLS is empty");
  assert.ok(WRITE_SHAPED_TOOLS.size > 0, "WRITE_SHAPED_TOOLS is empty");
  assert.ok(
    Object.keys(DEFAULT_FIELDS).length > 0,
    "DEFAULT_FIELDS is empty — the surface would collapse to the hook sets",
  );
  return new Set([
    ...Object.keys(DEFAULT_FIELDS),
    ...REHYDRATED_TOOLS,
    ...WRITE_SHAPED_TOOLS,
    // MCP tool names are server-defined, so no list can enumerate them; a
    // sample is enough to pin which SIDE of a partition they land on.
    "mcp__github__create_issue",
    "mcp__slack__post_message",
    "mcp__linear__create_comment",
  ]);
}
