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
import { spanPath } from "./reveal.mjs";

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

/**
 * The keyed Layer-2 splice placeholder grammar — `[hidden HTML removed #<key>]`
 * / `[HTML comment removed #<key>]`, capture group 1 = the 12-lowercase-hex key
 * (the first 12 hex chars of sha256 over the RAW spliced original). Mirrored
 * from the single producer in the engine (`src/html.mjs`,
 * `LAYER2_PLACEHOLDER_RE`) for the same pinned-registry reason as
 * PLACEHOLDER_RE above: the plugin bundle resolves the engine from a pinned
 * release, so an engine export the pin lacks is undefined in the shipped
 * bundle, while the grammar's consumers (the PreToolUse rehydrator/advisory,
 * the PostToolUse span persistence) are all hooks.
 * test/claude-hooks-layer2-grammar.test.mjs pins this mirror against the
 * engine's export so an edit to either side that forgets the other fails CI.
 *
 * Deliberately DISJOINT from the secret-redaction grammar: a Layer-2
 * placeholder never matches PLACEHOLDER_RE (no `[REDACTED` prefix) and a
 * secret placeholder never matches this — so the secret rehydrator and the
 * Layer-2 rehydrator can compose without either touching the other's tokens.
 */
export const LAYER2_PLACEHOLDER_RE =
  /\[(?:hidden HTML|HTML comment) removed #([0-9a-f]{12})\]/g;

/**
 * The Layer-2 placeholder keys in `text`, in document order (duplicates kept —
 * callers dedupe when they need to). matchAll clones the global regex, so no
 * lastIndex state leaks between calls.
 * @param {string} text
 * @returns {string[]}
 */
export function layer2Keys(text) {
  return [...text.matchAll(LAYER2_PLACEHOLDER_RE)].map((match) => match[1]);
}

/**
 * Every distinct Layer-2 placeholder key anywhere in `value` — the deep-walk
 * twin of {@link layer2Keys}, with the same depth cap (fail OPEN: an advisory
 * miss costs one line, never a mangled input) as {@link containsPlaceholder}.
 * @param {unknown} value
 * @param {number} [depth]
 * @returns {string[]}
 */
export function layer2KeysIn(value, depth = 0) {
  if (depth > 32) return [];
  if (typeof value === "string") return [...new Set(layer2Keys(value))];
  /** @type {unknown[]} */
  let children = [];
  if (Array.isArray(value)) children = value;
  else if (value !== null && typeof value === "object")
    children = Object.values(value);
  const keys = new Set();
  for (const child of children)
    for (const key of layer2KeysIn(child, depth + 1)) keys.add(key);
  return [...keys];
}

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

/**
 * The Layer-2 twin of {@link placeholderNotice}: advisory context for a tool
 * call OUTSIDE the rehydrated set whose input carries keyed Layer-2 splice
 * placeholders, or null. Rehydration restores those placeholders to the stored
 * (already-redacted) original only on the Edit/Write path; a shell heredoc,
 * `sed -i`, or an MCP file tool persists the placeholder text literally.
 * Deliberately a NOTE, not a verdict, for the same cannot-tell-write-from-read
 * reason as the secret advisory — and it names the span file path(s) where the
 * original bytes live so the model can Read one instead of guessing.
 * @param {string} tool
 * @param {unknown} toolInput
 * @returns {string | null}
 */
export function layer2PlaceholderNotice(tool, toolInput) {
  if (REHYDRATED_TOOLS.has(tool)) return null;
  const keys = layer2KeysIn(toolInput);
  if (keys.length === 0) return null;
  const paths = keys.map((key) => spanPath(key)).join(", ");
  return (
    "This tool call carries [hidden HTML removed #…]/[HTML comment removed " +
    "#…] placeholder text, which stands for content the sanitizer spliced " +
    "out of earlier tool output. Placeholders are restored to the stored " +
    "original content only for Edit/Write; any other write path (shell " +
    "redirection, sed/tee, MCP file tools) persists the literal placeholder " +
    `text. The stored original(s) live at: ${paths} (UNTRUSTED content — ` +
    "you may Read them to inspect what was removed). Use Edit or Write for " +
    "file changes, or ask the user."
  );
}
