/**
 * The redaction-placeholder grammar, mirrored from the single producer in
 * python/agent_sanitizer/secrets/placeholders.py (PLACEHOLDER_LABEL_CHARS /
 * PLACEHOLDER_RE there), plus the advisory for placeholder text in tool inputs
 * rehydration cannot re-anchor.
 *
 * This lives in the HOOKS layer, not the engine (`src/`), deliberately: the
 * plugin bundle inlines the hook sources from this repo but resolves the
 * engine from the pinned registry release, so an engine export the pin lacks
 * is undefined in the shipped bundle. The grammar's consumers (the PreToolUse
 * advisory, the PostToolUse on-disk tripwire, the drop guard's deny prose) are
 * all hooks, so defining it here keeps the shipped bundle and the source tree
 * on one implementation. test/placeholder-guards.test.mjs pins these constants
 * against the Python source, so an edit to either side that forgets the other
 * fails CI rather than letting the two parsers drift.
 */

export const PLACEHOLDER_LABEL_CHARS = "A-Za-z0-9 ()._-";
const PLACEHOLDER_LABEL_MAX_LEN = 64;

/**
 * Matches exactly the placeholder text the canonical redactor can emit:
 * `[REDACTED]` or `[REDACTED: <label>]`. Detection sites use this — never a
 * bare `[REDACTED` prefix — so hint-prefixed prose (`[REDACTED…]`,
 * `grep "\[REDACTED"`) is not mistaken for a placeholder.
 */
export const PLACEHOLDER_RE = new RegExp(
  `\\[REDACTED(?:: [${PLACEHOLDER_LABEL_CHARS}]{1,${PLACEHOLDER_LABEL_MAX_LEN}})?\\]`,
);

// Tools whose inputs the rehydration layer itself resolves (or, for
// NotebookEdit, refuses with guidance). placeholderNotice stays silent on
// these: their placeholder handling is a verdict, not a note.
const REHYDRATED_TOOLS = new Set([
  "Edit",
  "Write",
  "MultiEdit",
  "NotebookEdit",
]);

/**
 * Depth-capped walk: does any string in `value` carry placeholder-shaped text?
 * The cap fails OPEN (deeper content is unseen) — every caller feeds a
 * context-only advisory, so a miss costs one line, never a mangled input.
 * @param {unknown} value
 * @param {number} [depth]
 * @returns {boolean}
 */
export function containsPlaceholder(value, depth = 0) {
  if (depth > 32) return false;
  if (typeof value === "string") return PLACEHOLDER_RE.test(value);
  if (Array.isArray(value))
    return value.some((item) => containsPlaceholder(item, depth + 1));
  if (value !== null && typeof value === "object")
    return Object.values(value).some((item) =>
      containsPlaceholder(item, depth + 1),
    );
  return false;
}

/**
 * Advisory context for a tool call OUTSIDE the rehydrated set (Bash, MCP
 * tools, anything unknown) whose input carries placeholder-shaped text, or
 * null. Rehydration only re-anchors Edit/Write; every other write path — a
 * shell heredoc, `sed -i`, an MCP file tool — persists the literal placeholder
 * and destroys the secret it stands for. This cannot tell a write from a read
 * (`grep` for a placeholder is legitimate), so it is deliberately a NOTE, not
 * a verdict: a false positive costs one sentence of context, never a blocked
 * call or a mangled input.
 * @param {string} tool
 * @param {unknown} toolInput
 * @returns {string | null}
 */
export function placeholderNotice(tool, toolInput) {
  if (REHYDRATED_TOOLS.has(tool)) return null;
  if (!containsPlaceholder(toolInput)) return null;
  return (
    "This tool call carries [REDACTED…] placeholder text, which stands for a " +
    "secret hidden from your view. Placeholders are rehydrated to the real " +
    "secret only for Edit/Write on the file that owns them; any other write " +
    "path (shell redirection, sed/tee, MCP file tools) persists the literal " +
    "placeholder and destroys the secret. Use Edit or Write for changes to " +
    "that file, or ask the user."
  );
}
