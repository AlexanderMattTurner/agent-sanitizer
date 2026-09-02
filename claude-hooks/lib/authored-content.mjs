/**
 * Sanitize content the *model authors* into tool calls — file writes, edits,
 * notebook cells, and command bodies (commit messages, PR/issue bodies passed on
 * the command line). Two complementary protections:
 *
 *   1. Covert channel (steganography). Format chars (Cf — including the U+E00xx
 *      TAG block used for ASCII smuggling and zero-width joiners) and variation
 *      selectors can encode a hidden message that another AI reading the
 *      committed file / PR / commit later decodes, while staying invisible to a
 *      human reviewer. Stripped when payload-capable (see isPayloadCapable):
 *      gated on volume because incidental joiners / emoji selectors are benign
 *      and authored content is *persisted*, so over-stripping is costly.
 *
 *   2. Terminal-display rewriting. ANSI/terminal control sequences (CSI/OSC)
 *      authored into a command — echoed and executed live — or into file
 *      content (a latent bomb when the file is later `cat`'d) can clear the
 *      screen, reposition the cursor, or overwrite what the user sees, hiding
 *      the real command behind spoofed output. A single such sequence already
 *      does harm, so there is no volume threshold: one of them strips the whole
 *      field. Display-only SGR colour is the exception and is PRESERVED
 *      byte-for-byte — it restyles text and can neither move the cursor nor
 *      carry an OSC payload, so stripping it only costs a model the colourized
 *      fixture, TUI golden file or prompt string it deliberately wrote. The
 *      carve-out ends where SGR stops being styling (see the engine's
 *      sgrCarriesPayload): a CONCEAL parameter blanks text for a human while a
 *      model still reads it, and a long run of sequences with nothing that
 *      renders between them puts no glyph on the screen at all, which is a
 *      covert channel rather than colour.
 *
 * SCOPE IS DECLARED, NOT INFERRED. Which tools this layer touches is a
 * partition — {@link AUTHORED_FIELDS} (covered, with the field list) and
 * {@link EXEMPT_TOOLS}/{@link EXEMPT_TOOL_PATTERNS} (looked at, with the reason
 * nothing is sanitized) — resolved through the single
 * {@link authoredScopeDecision} helper. Notably `mcp__*` server tools are
 * exempt, so a PR body written via `gh pr create` IS stripped while the same
 * body sent through a GitHub MCP tool is NOT; that asymmetry is a stated
 * position with a rationale, not an oversight.
 *
 * Distinct from sanitize-output.mjs, which scrubs tool *responses* flowing
 * toward the model (data the model reads). This scrubs what the model emits
 * (data the model writes out). In pretooluse-sanitize.mjs it runs *after*
 * confusable normalization, so on the shared `command` field it sees the
 * already-normalized text and the two protections compose deterministically.
 *
 * Opt-outs are granular so dropping one protection doesn't drop the other:
 * AGENT_SANITIZER_INVISIBLE_DISABLED=1 keeps invisible chars (legitimate i18n
 * text relying on ZWNJ/ZWJ joiners) while terminal-control stripping stays on;
 * AGENT_SANITIZER_TERMINAL_DISABLED=1 keeps raw escape sequences (fixtures that
 * must contain them) while stego stripping stays on; and
 * AGENT_SANITIZER_OUTPUT_DISABLED=1 disables both.
 */
import { lazyImport } from "./hook-io.mjs";

// Bound via lazyImport (see its doc for the fail-OPEN hazard of a bare static
// npm import — here the load crash would fire inside pretooluse-sanitize.mjs's
// static import of this module, before its fail-closed catch runs). A failed
// load leaves these bindings undefined, so sanitizeField's calls throw into
// the fail-closed catch (ask) instead.
const { stripAnsiFully, isBenignAnsiKinds, sgrCarriesPayload } =
  /** @type {typeof import("agent-sanitizer")} */ (
    await lazyImport("agent-sanitizer")
  );
const { STRIP, SCATTERED_THRESHOLD, hasLongRun, stripInvisible } =
  /** @type {typeof import("agent-sanitizer/invisible")} */ (
    await lazyImport("agent-sanitizer/invisible")
  );

// Content fields the model authors, per tool. Paths and confusables are the
// confusable layer's domain; here we target the free-text fields that carry
// model-authored prose / code / data out into persisted or displayed artifacts.
// A "key[].sub" entry addresses `sub` on every element of the array at `key`
// (MultiEdit batches its writes as edits[].new_string), so the nested authored
// content is sanitized too — not just the top-level fields.
//
// Null-prototype: `tool` comes from the payload, and on a plain object literal
// `FIELDS["constructor"]` answers a truthy inherited value that the field loop
// below would then try to iterate.
/** @type {Record<string, string[]>} */
export const AUTHORED_FIELDS = Object.freeze(
  Object.assign(Object.create(null), {
    Write: ["content"],
    Edit: ["new_string"],
    MultiEdit: ["edits[].new_string"],
    NotebookEdit: ["new_source"],
    Bash: ["command"],
  }),
);

// The other half of the partition: tools this layer has LOOKED AT and decided
// carry no model-authored free text, each with the reason. Together with
// AUTHORED_FIELDS this is a declared scope rather than a fallthrough — an
// omission becomes a reviewable line instead of the absence of one, and
// test/claude-hooks-authored-scope.test.mjs fails when a tool the package
// elsewhere claims to know lands in neither side.
/** @type {Record<string, string>} */
export const EXEMPT_TOOLS = Object.freeze(
  Object.assign(Object.create(null), {
    Read: "inputs are a path plus offsets — nothing the model authored is persisted or displayed",
    Grep: "inputs are a search pattern and a path; rewriting a pattern would change what the search matches",
    Glob: "inputs are a glob pattern and a path; rewriting a pattern would change what it matches",
    LS: "input is a path — the confusable layer's domain, not authored free text",
  }),
);

// Prefix-shaped exemptions, for tool families no fixed list can enumerate.
/** @type {ReadonlyArray<{ pattern: RegExp, reason: string }>} */
export const EXEMPT_TOOL_PATTERNS = Object.freeze([
  Object.freeze({
    pattern: /^mcp__/u,
    reason:
      "MCP tool inputs follow a server-declared schema this package cannot see, " +
      "so there is no field it can name as authored free text. A blanket walk over " +
      "every string in the input would buy recall at a real precision cost — it " +
      "would rewrite opaque IDs, base64 blobs and protocol fields the server parses " +
      "— so the gap is DECLARED rather than closed. A deployment that wants a " +
      "specific server's body field covered adds it to AUTHORED_FIELDS by its full " +
      'tool name (e.g. mcp__github__create_issue: ["body"]).',
  }),
]);

/**
 * The single place an unlisted tool's fate is decided: covered by a field list,
 * exempt with a stated reason, or undeclared — nobody has classified it.
 *
 * `undeclared` is NOT a runtime alarm. Every arm returns the same
 * pass-through behaviour, because a stderr line on each of the many tools no
 * one has had a reason to classify (Task, TodoWrite, WebFetch, …) is alert
 * fatigue, and the doctrine here is precision over recall. The signal is the
 * partition test, which reads this function.
 * @param {string} tool
 * @returns {{ kind: "covered", fields: string[] } | { kind: "exempt", reason: string } | { kind: "undeclared" }}
 */
export function authoredScopeDecision(tool) {
  const fields = AUTHORED_FIELDS[tool];
  if (fields) return { kind: "covered", fields };
  const exempt = EXEMPT_TOOLS[tool];
  if (exempt) return { kind: "exempt", reason: exempt };
  const matched = EXEMPT_TOOL_PATTERNS.find((entry) =>
    entry.pattern.test(tool),
  );
  if (matched) return { kind: "exempt", reason: matched.reason };
  return { kind: "undeclared" };
}

// Payload-capable: a long contiguous run, or enough scattered invisibles to
// carry a message. Mirrors sanitize-user-prompt so the model→world and
// user→model surfaces share one definition of "stego payload".
/** @param {string} text */
function isPayloadCapable(text) {
  // hasLongRun, not a pattern built here: the engine's scan is bounded per
  // `exec`, which is what keeps an 8 MB run of zero-widths in a Write body from
  // throwing `RangeError: Maximum call stack size exceeded` out of this hook.
  if (hasLongRun(text)) return true;
  return (text.match(STRIP)?.length ?? 0) >= SCATTERED_THRESHOLD;
}

/**
 * The de-ANSI'd `text`, or `text` itself when its escapes are display-only
 * colour a reader authored on purpose.
 *
 * The two questions are answered by two different views, deliberately.
 * `isBenignAnsiKinds` reads the kinds the strip actually REMOVED, so a sequence
 * that only reconstitutes mid-strip is judged as the sequence it becomes rather
 * than as the incomplete one it started as. `sgrCarriesPayload` reads the RAW
 * bytes, because those are the bytes a terminal renders on the preserve path —
 * it makes no second pass, so there is nothing to reconstitute there.
 *
 * Only COMPLETE tokens reach `kinds`: an introducer that opens no sequence is
 * left in place by `stripAnsiFully` (it rewrites no display), so the orphan arms
 * of `isBenignAnsiKinds` never decide anything here.
 * @param {string} text
 * @returns {string}
 */
function stripTerminalControls(text) {
  /** @type {Set<string>} TOKEN_KINDs the strip removed. */
  const kinds = new Set();
  const deAnsi = stripAnsiFully(text, kinds);
  if (deAnsi === text) return text;
  if (isBenignAnsiKinds(kinds) && !sgrCarriesPayload(text)) return text;
  return deAnsi;
}

// How many rounds of {terminal-control, invisible} the field may take. The two
// protections FEED each other: removing invisibles completes a sequence that was
// incomplete when the terminal stage ran (`ESC[` ZWSP `2J` is an orphan until the
// ZWSP goes), and removing a sequence makes invisibles adjacent that were not.
// One round of each therefore leaves the composition unfinished. Bounded on the
// same argument as the engine's MAX_LAYER1_PASSES: each round deletes at least
// one character, and past the bound what survives degrades to visible text
// rather than a hidden control.
const MAX_FIELD_PASSES = 3;

// Returns the cleaned value plus the human-readable actions applied, or null if
// the field is already clean. Each protection has its own opt-out (see the
// header) so a deployment can keep one while dropping the other.
/** @param {string} value */
function sanitizeField(value) {
  // A Set, so a protection that fires in more than one round is described once.
  /** @type {Set<string>} */
  const actions = new Set();
  let cleaned = value;

  for (let pass = 0; pass < MAX_FIELD_PASSES; pass++) {
    const before = cleaned;
    // Terminal controls first, so the invisible scan runs on the same de-ANSI'd
    // view sanitize-output uses. Compare before/after rather than pre-testing
    // for ESC: escapes this layer deliberately leaves in place — a lone control
    // byte, display-only colour — must not be reported as a strip.
    if (process.env.AGENT_SANITIZER_TERMINAL_DISABLED !== "1") {
      const deAnsi = stripTerminalControls(cleaned);
      if (deAnsi !== cleaned) {
        cleaned = deAnsi;
        actions.add("terminal-control sequences");
      }
    }

    if (
      process.env.AGENT_SANITIZER_INVISIBLE_DISABLED !== "1" &&
      isPayloadCapable(cleaned)
    ) {
      cleaned = stripInvisible(cleaned);
      actions.add("invisible characters");
    }
    if (cleaned === before) break;
  }

  return actions.size > 0 ? { cleaned, actions: [...actions] } : null;
}

/** @param {string[]} changed */
export function authoredContext(changed) {
  return `Sanitized model-authored content in: ${changed.join("; ")}. This removes a covert channel to other AIs and prevents authored content from rewriting the user's terminal. Opt out granularly with AGENT_SANITIZER_INVISIBLE_DISABLED=1 (i18n joiners) or AGENT_SANITIZER_TERMINAL_DISABLED=1 (raw-escape fixtures), or fully with AGENT_SANITIZER_OUTPUT_DISABLED=1.`;
}

/**
 * Strip authored stego / terminal-control sequences from the model-authored
 * fields of a tool call. Returns the updated input plus a per-field description
 * of what was stripped, or null when nothing changed. Throws on internal error
 * (caller fails closed).
 * @param {string} tool
 * @param {any} toolInput
 * @returns {{ updatedInput: any, changed: string[] } | null}
 */
export function sanitizeAuthoredContent(tool, toolInput) {
  const scope = authoredScopeDecision(tool);
  if (scope.kind !== "covered" || toolInput === null || toolInput === undefined)
    return null;
  const keys = scope.fields;

  const changed = [];
  // Null-prototype copy: toolInput is untrusted parsed JSON where a `__proto__`
  // key is own-enumerable, and the computed writes below would otherwise route
  // it through the prototype chain. Object.assign onto Object.create(null) copies
  // every own field (including a literal `__proto__`) as a plain own property.
  const updatedInput = Object.assign(Object.create(null), toolInput);
  for (const k of keys) {
    // Named groups satisfy prefer-named-capture-group; reading the numeric
    // indices keeps the values typed as string (match.groups is optional).
    const nested = k.match(/^(?<arr>\w+)\[\]\.(?<sub>\w+)$/);
    if (nested) {
      const arrKey = nested[1];
      const subKey = nested[2];
      const arr = toolInput[arrKey];
      if (!Array.isArray(arr)) continue;
      let nestedChanged = false;
      const newArr = arr.map((el) => {
        const val = el?.[subKey];
        if (typeof val !== "string") return el;
        const result = sanitizeField(val);
        if (!result) return el;
        nestedChanged = true;
        changed.push(`${arrKey}[].${subKey} (${result.actions.join(", ")})`);
        return { ...el, [subKey]: result.cleaned };
      });
      if (nestedChanged) updatedInput[arrKey] = newArr;
      continue;
    }
    if (typeof toolInput[k] !== "string") continue;
    const result = sanitizeField(toolInput[k]);
    if (!result) continue;
    updatedInput[k] = result.cleaned;
    changed.push(`${k} (${result.actions.join(", ")})`);
  }

  if (changed.length === 0) return null;
  return { updatedInput, changed };
}
