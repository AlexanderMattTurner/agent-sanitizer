/**
 * The file-editing tools whose input fields are the bytes persisted to disk, as
 * ONE table, and the reader for the field specs it holds.
 *
 * PROBLEM CLASS — the set of file-writing tools restated per consumer. The
 * fault carve-out that refuses a placeholder-bearing write, the advisories that
 * stay silent on rehydrated tools, the authored-content sanitizer and the
 * rehydration layer each kept their own list. A tool added to one list (a new
 * write-shaped tool, or a renamed field) left the others silently stale, which
 * is a placeholder persisted over a secret on disk. Every consumer reads this
 * table instead.
 *
 * Package-free and dependency-free by construction: the PreToolUse fault path
 * imports it relatively and must work exactly when the agent-sanitizer package
 * failed to load.
 *
 * Each entry:
 *   - `authored` — the fields the model writes, which Layer 3 sanitizes.
 *   - `placeholders` — every field a redaction placeholder can sit in.
 *   - `rehydrates` — whether the rehydration layer re-anchors the call onto
 *     disk bytes (`false`: it refuses a placeholder-bearing call instead).
 *
 * A field spec is `key`, or `key[].sub` for `sub` on every element of the
 * array at `key` (MultiEdit batches its writes as `edits[]`).
 */

/** @typedef {{ authored: readonly string[], placeholders: readonly string[], rehydrates: boolean }} FileWriteTool */

/**
 * Null-prototype: the tool name comes from an untrusted payload, and on a plain
 * object literal `TABLE["constructor"]` answers a truthy inherited value.
 * @type {Readonly<Record<string, FileWriteTool>>}
 */
export const FILE_WRITE_TOOLS = Object.freeze(
  Object.assign(Object.create(null), {
    Write: Object.freeze({
      authored: Object.freeze(["content"]),
      placeholders: Object.freeze(["content"]),
      rehydrates: true,
    }),
    Edit: Object.freeze({
      authored: Object.freeze(["new_string"]),
      placeholders: Object.freeze(["old_string", "new_string"]),
      rehydrates: true,
    }),
    MultiEdit: Object.freeze({
      authored: Object.freeze(["edits[].new_string"]),
      placeholders: Object.freeze(["edits[].old_string", "edits[].new_string"]),
      rehydrates: true,
    }),
    NotebookEdit: Object.freeze({
      authored: Object.freeze(["new_source"]),
      placeholders: Object.freeze(["new_source"]),
      rehydrates: false,
    }),
  }),
);

/**
 * True when `tool` is one of {@link FILE_WRITE_TOOLS}.
 * @param {unknown} tool
 * @returns {boolean}
 */
export function isFileWriteTool(tool) {
  return typeof tool === "string" && FILE_WRITE_TOOLS[tool] !== undefined;
}

const NESTED_SPEC = /^(?<arr>\w+)\[\]\.(?<sub>\w+)$/u;

/**
 * A field spec, parsed: `{ key }` for a top-level field, or `{ arr, sub }` for
 * `sub` on every element of the array at `arr`.
 * @param {string} spec
 * @returns {{ key: string } | { arr: string, sub: string }}
 */
export function parseFieldSpec(spec) {
  const nested = NESTED_SPEC.exec(spec);
  if (!nested?.groups) return { key: spec };
  return { arr: nested.groups.arr, sub: nested.groups.sub };
}

/**
 * Every value the field `spec` addresses in `input`: one for a top-level
 * field, one per array element for a nested one. `null` when the array a
 * nested spec names is absent, not an array, or empty.
 * @param {string} spec
 * @param {any} input
 * @returns {unknown[] | null}
 */
export function fieldValues(spec, input) {
  const parsed = parseFieldSpec(spec);
  if ("key" in parsed) return [input?.[parsed.key]];
  const arr = input?.[parsed.arr];
  if (!Array.isArray(arr) || arr.length === 0) return null;
  return arr.map((/** @type {any} */ element) => element?.[parsed.sub]);
}
