/**
 * Sanitize content the *model authors* into tool calls — file writes, edits,
 * notebook cells, and command bodies (commit messages, PR/issue bodies passed on
 * the command line). Two complementary protections:
 *
 *   1. Covert channel (steganography). Format chars (Cf — including the U+E00xx
 *      TAG block used for ASCII smuggling and zero-width joiners) and variation
 *      selectors can encode a hidden message that another AI reading the
 *      committed file / PR / commit later decodes, while staying invisible to a
 *      human reviewer. Stripped when the engine's payloadVerdict calls the field
 *      payload-capable: gated on volume because incidental joiners / emoji
 *      selectors are benign and authored content is *persisted*, so
 *      over-stripping is costly.
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
 *      sgrCarriesPayload): a CONCEAL parameter or a foreground painted in its
 *      own background blanks text for a human while a model still reads it,
 *      and a long run of sequences with nothing that
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
import { readKnob } from "./knobs.mjs";

// Bound via lazyImport (see its doc for the fail-OPEN hazard of a bare static
// npm import — here the load crash would fire inside pretooluse-sanitize.mjs's
// static import of this module, before its fail-closed catch runs). A failed
// load leaves these bindings undefined, so sanitizeField's calls throw into
// the fail-closed catch (ask) instead.
const { stripAnsiFully, stripTerminalFully, escapesPreservable } =
  /** @type {typeof import("agent-sanitizer")} */ (
    await lazyImport("agent-sanitizer")
  );
const { payloadVerdict, stripInvisibleWithReport } =
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

/**
 * The de-ANSI'd `text`, or `text` itself when its escapes are display-only
 * colour a reader authored on purpose — the engine's `escapesPreservable`, the
 * same answer the prompt gate gives, judged on the kinds THIS strip removed.
 *
 * Only COMPLETE tokens reach `kinds`: an introducer that opens no sequence is
 * left in place by `stripAnsiFully` (it rewrites no display), so the orphan arms
 * of the inert-kind test never decide anything here.
 * @param {string} text
 * @returns {string}
 */
function stripTerminalControls(text) {
  /** @type {Set<string>} TOKEN_KINDs the strip removed. */
  const kinds = new Set();
  const deAnsi = stripAnsiFully(text, kinds);
  if (deAnsi === text) return text;
  if (escapesPreservable(text, kinds)) return text;
  return deAnsi;
}

// How many rounds of {terminal-control, invisible} the field may take. The two
// protections FEED each other: removing invisibles completes a sequence that was
// incomplete when the terminal stage ran (`ESC[` ZWSP `2J` is an orphan until the
// ZWSP goes), and removing a sequence makes invisibles adjacent that were not.
// One round of each therefore leaves the composition unfinished. Each round
// deletes at least one character, so the loop converges on its own; the bound is
// a DoS guard. Reaching it still changing falls back to settleField, never to
// the unconverged value, which could persist a live sequence into the file.
const MAX_FIELD_PASSES = 3;

/**
 * The carve-out-free strip a field that did not converge falls back to: every
 * invisible, then every escape and raw introducer, each only where its
 * protection is on. Its output holds nothing either stage would remove, so it
 * is a fixed point of sanitizeField — the guarantee the bounded loop could not
 * give, bought by giving up the joiner carve-out and the colour carve-out on
 * adversarial input only.
 * @param {string} value  the field as the caller sent it (for the leading-BOM rule)
 * @param {string} cleaned  the loop's last state
 * @param {Set<string>} actions  collects the protections that changed the field
 * @returns {string}
 */
function settleField(value, cleaned, actions) {
  let settled = cleaned;
  if (!readKnob("AGENT_SANITIZER_INVISIBLE_DISABLED")) {
    const bulk = stripInvisibleWithReport(settled, value, {
      carveOut: false,
    }).cleaned;
    if (bulk !== settled) actions.add("invisible characters");
    settled = bulk;
  }
  if (!readKnob("AGENT_SANITIZER_TERMINAL_DISABLED")) {
    const swept = stripTerminalFully(settled);
    if (swept !== settled) actions.add("terminal-control sequences");
    settled = swept;
  }
  return settled;
}

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
    if (!readKnob("AGENT_SANITIZER_TERMINAL_DISABLED")) {
      const deAnsi = stripTerminalControls(cleaned);
      if (deAnsi !== cleaned) {
        cleaned = deAnsi;
        actions.add("terminal-control sequences");
      }
    }

    // The engine's payloadVerdict, so a Write body is stego exactly when the
    // same text would block a prompt — judged, as the prompt gate judges it, on
    // the de-ANSI'd view: the colour carve-out above leaves SGR in `cleaned`,
    // and its parameter bytes render nothing, so they must not count as the
    // visible cover that buys preserved joiners and selectors.
    if (!readKnob("AGENT_SANITIZER_INVISIBLE_DISABLED")) {
      const view = stripAnsiFully(cleaned);
      if (payloadVerdict(view).payloadCapable) {
        // A field carrying a payload forfeits the colour carve-out: the strip
        // must read the view the verdict read, or the same SGR bytes would fund
        // the preserve budget the verdict refused. Under the terminal opt-out
        // the escapes are the author's to keep, so the strip reads the raw
        // field and only the invisibles go.
        const source = readKnob("AGENT_SANITIZER_TERMINAL_DISABLED")
          ? cleaned
          : view;
        const stripped = stripInvisibleWithReport(source, cleaned).cleaned;
        if (source !== cleaned) actions.add("terminal-control sequences");
        if (stripped !== source) actions.add("invisible characters");
        cleaned = stripped;
      }
    }
    if (cleaned === before) break;
    // This fallback is what blocks a still-changing value — one whose next round
    // would remove another live sequence — from being written to the file.
    if (pass === MAX_FIELD_PASSES - 1)
      cleaned = settleField(value, cleaned, actions);
  }

  return cleaned === value ? null : { cleaned, actions: [...actions] };
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
