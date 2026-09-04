/**
 * PreToolUse content-protection orchestrator. Runs five layers in ONE process:
 *
 *   1. Invisible-char injection gate (lib/invisible-alert.mjs)
 *   2. Confusable/homoglyph normalization of paths & commands
 *      (agent-sanitizer/confusables, namespace-guard scanner injected)
 *   3. Stego / terminal-control stripping of model-authored fields
 *      (lib/authored-content.mjs)
 *   4. Rehydration of secret-redaction placeholders in Edit/Write inputs
 *      (agent-sanitizer/rehydrate, redactor-daemon io injected)
 *   5. Rehydration of keyed Layer-2 splice placeholders in Edit/Write inputs
 *      ({@link rehydrateLayer2}, span store in lib/reveal.mjs) — disjoint
 *      grammar from step 4, run after it
 *
 * WHY ONE PROCESS: Claude Code runs PreToolUse hooks in parallel and does NOT
 * chain their `updatedInput` — each hook sees the original input and the last to
 * finish wins. Registered as three separate hooks, layers 2 and 3 both rewrite
 * the shared Bash `command` field from the original text, so a command carrying
 * BOTH a confusable AND a stego payload had one fix non-deterministically
 * clobbered by the other. Composing them here makes the rewrite deterministic
 * (normalize, then strip the normalized text) and pays a single Node start
 * instead of three on the hottest path. Layers 2-4 run through the declared
 * pipeline in lib/layer-pipeline.mjs, which is what keeps the confusable fold's
 * skip decisions sound once the erasing strip follows it.
 *
 * Layers 2 and 4 are the provider-agnostic transforms in the agent-sanitizer
 * package; this file binds its peers (namespace-guard, the redactor daemon, the
 * filesystem) into them.
 */
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { dirname } from "node:path";
import {
  isMain,
  lazyImport,
  lazyImportErrorFor,
  failedLazyPackages,
  missingPackageMessage,
  DEFAULT_MISSING_PACKAGE_REMEDY,
  registeredLazyModule,
  emitHookResponse,
  safeErrMessage,
  HookEvent,
  PermissionDecision,
} from "./lib/hook-io.mjs";
import {
  registerFaultPolicy,
  hookFaultOutcome,
  defaultOpen,
} from "./lib/hook-fault.mjs";
import { runLayerPipeline } from "./lib/layer-pipeline.mjs";
import { controlPlane, runJudgeCli } from "./lib/control-plane.mjs";
import {
  invisibleCharAlert,
  gateAskReason,
  gateReminderContext,
  alertAcknowledged,
  acknowledgeAlert,
  recordInstructionsLoadedNotice,
  instructionsLoadedGapNotice,
} from "./lib/invisible-alert.mjs";
import {
  sanitizeAuthoredContent,
  authoredContext,
} from "./lib/authored-content.mjs";
import { redactViaDaemon } from "./lib/redactor-client.mjs";
import { secretsEnabled } from "./lib/env-config.mjs";
import { withSecretDropGuard } from "./lib/secret-drop-guard.mjs";
import {
  placeholderNotice,
  layer2PlaceholderNotice,
  layer2Keys,
  LAYER2_PLACEHOLDER_RE,
} from "./lib/placeholder-grammar.mjs";
import { readSpan, spanPath } from "./lib/reveal.mjs";
import { bestEffortTrace, hostChargedTrace, TraceEvent } from "./lib/trace.mjs";

const HOOK_NAME = "pretooluse-sanitize";

/**
 * A host-supplied deny gate: given the PreToolUse input, the reason this call
 * must be blocked, or null to let the pipeline continue. Hosts use these for
 * policy the package has no view of (a required workflow step, a project-local
 * rule); the package ships none.
 * @typedef {(input: { tool_name: string | null, tool_input: any, session_id?: string,
 *   permission_mode?: string })
 *   => string | null | undefined} HostGate
 */

/**
 * The reasons this hook emits, as a table a host overrides. A host that knows
 * which of ITS files wires the adapter, and what a reader should do about a
 * failure, can say so — the package cannot, since it has no idea where it is
 * installed.
 * @type {Readonly<{
 *   unknownEvent: string,
 *   failed: (cause: string) => string,
 *   unparsable: (cause: string) => string,
 *   remedy: string,
 * }>}
 */
export const PRE_TOOL_USE_MESSAGES = Object.freeze({
  unknownEvent:
    "PreToolUse sanitization blocked (fail-closed): unrecognized hook payload.",
  failed: (cause) => `PreToolUse sanitization failed (fail-closed): ${cause}`,
  unparsable: (cause) => `PreToolUse input unparsable (fail-closed): ${cause}`,
  // What a reader should run when a dependency is what is missing. It rides in
  // this table rather than a separate argument because it is host text exactly
  // like the reasons above, and one channel means a host cannot supply its
  // wording in one place and forget it in the other.
  remedy: DEFAULT_MISSING_PACKAGE_REMEDY,
});

// Layers 2 & 4 come from the agent-sanitizer package, bound via lazyImport (see
// its doc for the fail-OPEN hazard of a bare static npm import); a failed load
// leaves these bindings undefined, so the layer calls below throw into the CLI's
// fail-closed catch (ask) instead.
const { normalizeConfusables, normalizeContext } =
  /** @type {typeof import("agent-sanitizer/confusables")} */ (
    await lazyImport("agent-sanitizer/confusables")
  );
const { rehydrateRedacted } =
  /** @type {typeof import("agent-sanitizer/rehydrate")} */ (
    await lazyImport("agent-sanitizer/rehydrate")
  );
// The one sound multi-needle splice primitive (see its doc in the engine): the
// Layer-2 rehydrator below substitutes every keyed placeholder in one ordered
// pass, so a stored original whose bytes happen to contain another placeholder
// is never re-matched and re-expanded.
const { spliceOrdered } =
  /** @type {typeof import("agent-sanitizer/view-map")} */ (
    await lazyImport("agent-sanitizer/view-map")
  );

// Injection seams binding the peer dependencies into the provider-agnostic
// package functions. namespace-guard (the confusable vision map) and the
// redactor daemon are external to the package; it imports neither.
// namespace-guard is lazy-required so its map loads only on the first field that
// actually carries a non-ASCII glyph — normalizeConfusables applies its ASCII
// fast-path before ever calling scan.
const require = createRequire(import.meta.url);
// Registry first, so a build-time bundle (which has no node_modules for the
// require to resolve from) reaches its statically-inlined, pre-registered copy;
// running from source keeps the lazy require. The lookup must stay synchronous —
// normalizeConfusables calls the scan inline.
/** @param {string} text */
const confusableScan = (text) =>
  (registeredLazyModule("namespace-guard") ?? require("namespace-guard")).scan(
    text,
  );

/**
 * File + redactor-daemon I/O the package's rehydrateRedacted runs against:
 * `redactMap` yields the redacted view plus ordered (placeholder, original,
 * start) pairs, `redact` the plain redacted text or null. Both go through the
 * long-lived redactor daemon so detect-secrets stays the only engine.
 * @type {import("agent-sanitizer/rehydrate").RehydrateIo}
 */
const redactorIo = {
  readFile: (path) => readFileSync(path, "utf8"),
  redactMap: async (text) =>
    /** @type {any} */ (await redactViaDaemon(text, { map: true })),
  redact: async (text) => {
    const out = await redactViaDaemon(text, {});
    return out ? /** @type {string} */ (out.text) : null;
  },
};

/**
 * Default Layer-4 rehydrator: the package's rehydrateRedacted bound to the
 * redactor-daemon io, composed (via withSecretDropGuard, where the ordering
 * logic lives and is unit-tested) with the clobber-by-omission guard. Hoisted
 * (not an inline default-param arrow) so tests can still inject a fake as the
 * second argument to buildPreToolUseResponse.
 */
const guardedRehydrate = withSecretDropGuard(
  (tool, toolInput) => rehydrateRedacted(tool, toolInput, redactorIo),
  redactorIo,
);

/**
 * Substitute every keyed Layer-2 placeholder in `text` with the stored original
 * from the reveal store's span files, in ONE ordered pass (spliceOrdered).
 * A key with NO stored span fails CLOSED — the placeholder stands for real
 * content this store cannot produce, so writing it through literally would
 * silently persist the loss the keyed grammar exists to prevent.
 * @param {string} text
 * @param {string} field the tool-input field being rehydrated, for the deny prose
 * @returns {{ text: string, restored: number } | { deny: string } | null}
 */
function substituteLayer2(text, field) {
  const matches = [...text.matchAll(LAYER2_PLACEHOLDER_RE)].map((match) => ({
    text: match[0],
    index: /** @type {number} */ (match.index),
    key: match[1],
  }));
  if (matches.length === 0) return null;
  /** @type {Map<string, string>} */
  const byKey = new Map();
  /** @type {string[]} */
  const missing = [];
  for (const key of new Set(matches.map((match) => match.key))) {
    const stored = readSpan(key);
    if (stored === null) missing.push(key);
    else byKey.set(key, stored);
  }
  if (missing.length > 0)
    return {
      deny:
        `${field} contains Layer-2 removed-content placeholder(s) whose original is not ` +
        `in the span store (missing key(s): ${missing.join(", ")}; expected file(s): ` +
        `${missing.map((key) => spanPath(key)).join(", ")}), so the removed content ` +
        `cannot be restored automatically. Reconstruct that content yourself, ` +
        `deliberately drop the placeholder(s) if the removed content should stay ` +
        `removed, or ask the user to make this change`,
    };
  // `i` is the match's index in `matches` (stable across spliceOrdered's
  // overlap skips — impossible here, distinct non-overlapping literals), so the
  // key rides positionally.
  const spliced = spliceOrdered(
    text,
    matches,
    (_match, i) => /** @type {string} */ (byKey.get(matches[i].key)),
  );
  return { text: spliced.text, restored: matches.length };
}

/**
 * Layer-2 placeholder rehydration on the write path: an Edit `new_string` or a
 * Write `content` carrying `[hidden HTML removed #<key>]` / `[HTML comment
 * removed #<key>]` placeholders (copied from sanitized tool output) has each
 * one restored to the stored original bytes from the reveal store's span files.
 *
 * SECURITY invariant: the stored span content was REDACTED before persistence
 * (sanitize-output runs strict web-ingress redaction on each splice original
 * before persistSpan), so this rehydration can never write a raw secret — the
 * worst it can restore is `[REDACTED…]` placeholder text standing where the
 * secret was, which the on-disk tripwire then flags on later Reads.
 *
 * Composition with the secret rehydrator: this runs AFTER it (a later terminal
 * layer), and the two grammars are disjoint — a Layer-2 placeholder never
 * matches the `[REDACTED…]` grammar and vice versa — so neither can touch the
 * other's tokens. Running second also means a restored original that contains
 * `[REDACTED…]` text is never re-fed to the secret resolver (which would deny
 * it as a foreign placeholder).
 *
 * `old_string` is deliberately NOT rehydrated: a Layer-2 placeholder there
 * exists in the model's view of PRIOR TOOL OUTPUT, not on disk, so unless the
 * file literally contains the placeholder text, Edit's ordinary no-match
 * failure is the right outcome — no re-anchoring. MultiEdit/NotebookEdit with a
 * Layer-2 placeholder are denied (parity with the secret path: sequential
 * edits / notebook JSON cannot be rehydrated).
 * @param {string} tool
 * @param {any} toolInput
 * @returns {{ updatedInput: any, context: string } | { deny: string } | null}
 */
export function rehydrateLayer2(tool, toolInput) {
  const hasL2 = (/** @type {unknown} */ text) =>
    typeof text === "string" && layer2Keys(text).length > 0;
  if (
    tool === "MultiEdit" &&
    Array.isArray(toolInput?.edits) &&
    toolInput.edits.some(
      (/** @type {any} */ edit) =>
        hasL2(edit?.old_string) || hasL2(edit?.new_string),
    )
  )
    return {
      deny:
        `the edits carry [hidden HTML removed #…]/[HTML comment removed #…] ` +
        `placeholders, which stand for content spliced out of earlier tool output; ` +
        `MultiEdit's sequential edits cannot be rehydrated. Use single Edit calls — ` +
        `each restores the stored original individually — or ask the user to make ` +
        `this change`,
    };
  if (tool === "NotebookEdit" && hasL2(toolInput?.new_source))
    return {
      deny:
        `new_source contains a [hidden HTML removed #…]/[HTML comment removed #…] ` +
        `placeholder, which stands for content spliced out of earlier tool output; ` +
        `rehydration is not supported for notebooks. Reconstruct the content, ` +
        `deliberately drop the placeholder if the removed content should stay ` +
        `removed, or ask the user to edit the cell`,
    };
  /** @type {"new_string" | "content" | null} */
  const field =
    tool === "Edit" && typeof toolInput?.new_string === "string"
      ? "new_string"
      : tool === "Write" && typeof toolInput?.content === "string"
        ? "content"
        : null;
  if (field === null) return null;
  const result = substituteLayer2(toolInput[field], field);
  if (result === null) return null;
  if ("deny" in result) return result;
  return {
    updatedInput: { ...toolInput, [field]: result.text },
    context:
      `${result.restored} Layer-2 removed-content placeholder(s) in ${field} ` +
      `were restored to the stored original content (secrets inside were ` +
      `redacted before storage, so no raw secret is written).`,
  };
}

/**
 * The wired default gates the whole rehydration layer on the secret opt-in:
 * with secrets off the output hook never inserts placeholders, so there is
 * nothing to re-anchor — and skipping here (rather than inside the layer)
 * means an Edit on a plain file never touches the file system twice or spawns
 * the daemon. Consulted per call, not at module load, so a knob set after the
 * bundle loads still governs the next tool call.
 * @param {string} tool
 * @param {any} toolInput
 */
const defaultRehydrate = async (tool, toolInput) =>
  secretsEnabled() ? guardedRehydrate(tool, toolInput) : null;

/**
 * Trace the response on the way out — "noop" (clean pass-through), "deny",
 * "ask", or "modified" (input rewritten and/or context attached) — and return
 * it unchanged. The trace lives on this in-process, mutation-tested path, not in
 * the CLI block, so engagement is announced (hook_ran — metadata only: hook
 * name, tool, outcome) for every exit.
 * @param {import("./lib/trace.mjs").TraceFn} emitTrace
 * @param {string} toolName
 * @param {Record<string, unknown> | null} fields
 * @returns {Record<string, unknown> | null}
 */
function emitTraced(emitTrace, toolName, fields) {
  let outcome = "modified";
  if (fields === null) outcome = "noop";
  else if (fields.permissionDecision === PermissionDecision.DENY)
    outcome = "deny";
  else if (fields.permissionDecision === PermissionDecision.ASK)
    outcome = "ask";
  emitTrace(TraceEvent.HOOK_RAN, { hook: HOOK_NAME, tool: toolName, outcome });
  return fields;
}

/**
 * The declared layer chain, layers 2-4. Every entry states the two properties
 * the driver reasons about — whether it ERASES code points another layer reads,
 * and whether its own decision is SKIP-BASED and therefore invalidated by such
 * an erasure — so the confusable fold's ordering precondition is enforced by the
 * table instead of restated as a comment.
 *
 * Layer 3 is dropped from the table (not merely skipped at run time) when
 * AGENT_SANITIZER_OUTPUT_DISABLED=1, so the driver sees the chain that will
 * actually run: with no erasing layer left after the fold there is no fixed
 * point to reach and no extra pass to pay for.
 * @param {(tool: string, toolInput: any) => ReturnType<typeof rehydrateRedacted>} rehydrate
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 * @returns {import("./lib/layer-pipeline.mjs").Layer[]}
 */
export function preToolUseLayers(rehydrate, env = process.env) {
  /** @type {import("./lib/layer-pipeline.mjs").Layer[]} */
  const layers = [
    {
      name: "confusables",
      // Folding SUBSTITUTES a glyph for its ASCII canon, which drops the
      // original code point; and it SKIPS any token still holding an unmapped
      // glyph, which is the decision an erasure can invalidate.
      erases: true,
      skipBased: true,
      run: (tool, toolInput) => {
        const norm = normalizeConfusables(tool, toolInput, {
          scan: confusableScan,
        });
        return norm === null
          ? null
          : {
              updatedInput: norm.updatedInput,
              context: normalizeContext(norm.normalized),
            };
      },
    },
    {
      name: "authored-content",
      // Erases payload-capable invisible characters, and skips below the
      // payload-capable floor — the erasure that broke the fold's precondition.
      erases: true,
      skipBased: true,
      run: (tool, toolInput) => {
        const authored = sanitizeAuthoredContent(tool, toolInput);
        return authored === null
          ? null
          : {
              updatedInput: authored.updatedInput,
              context: authoredContext(authored.changed),
            };
      },
    },
    {
      name: "rehydrate",
      erases: true,
      skipBased: false,
      // Terminal by contract, not by luck: it re-anchors Edit/Write inputs onto
      // the on-disk bytes, and the secrets it restores must NOT be re-stripped
      // by layer 3 or re-folded by layer 2 on a later pass.
      terminal: true,
      run: async (tool, toolInput) => {
        const rehydrated = await rehydrate(tool, toolInput);
        if (!rehydrated) return null;
        if ("deny" in rehydrated) return { deny: rehydrated.deny };
        return {
          updatedInput: rehydrated.updatedInput,
          context: rehydrated.context,
        };
      },
    },
    {
      name: "layer2-rehydrate",
      erases: true,
      skipBased: false,
      // Terminal, AFTER the secret rehydrator: the grammars are disjoint (see
      // rehydrateLayer2's doc), and the stored bytes it restores — which may
      // legitimately contain [REDACTED…] text — must not be re-fed to the
      // secret resolver or re-stripped by an earlier layer.
      terminal: true,
      run: (tool, toolInput) => rehydrateLayer2(tool, toolInput),
    },
  ];
  return env.AGENT_SANITIZER_OUTPUT_DISABLED === "1"
    ? layers.filter((layer) => layer.name !== "authored-content")
    : layers;
}

// The tools whose path field Claude Code sends as an absolute path by
// contract, so reading it needs no cwd to resolve against. Bounded to these:
// Glob/Grep's `path` can be relative or omitted (defaults to a cwd this
// payload does not carry), and Bash has no reliable target at all — the same
// carve-out WRITE_SHAPED_TOOLS below takes for Bash writes.
const PATH_FIELD_BY_TOOL = /** @type {Record<string, string>} */ (
  Object.freeze({
    Read: "file_path",
    Edit: "file_path",
    Write: "file_path",
    MultiEdit: "file_path",
    NotebookEdit: "notebook_path",
  })
);

/**
 * The directory THIS tool call targets, for the InstructionsLoaded gap-notice
 * check — or undefined when the tool carries no reliable absolute path. An
 * imprecise guess here only ever WIDENS coverage (see instructionsLoadedGapNotice's
 * `touchedDir`): missing a real target loses nothing this check did not
 * already lack, and there is no wrong-directory case that suppresses a real
 * finding.
 * @param {string} tool
 * @param {any} toolInput
 * @returns {string | undefined}
 */
function toolTargetDir(tool, toolInput) {
  const field = PATH_FIELD_BY_TOOL[tool];
  const path = field && toolInput?.[field];
  return typeof path === "string" && path.startsWith("/")
    ? dirname(path)
    : undefined;
}

/**
 * Compose the four protections. Returns the `hookSpecificOutput` fields to
 * emit, or null for a clean no-op. Throws only if a layer's engine throws; the
 * caller fails closed (ask) on any throw. Every exit routes through emitTraced.
 * @param {any} input parsed PreToolUse event
 * @param {(tool: string, toolInput: any) => ReturnType<typeof rehydrateRedacted>} [rehydrate]
 * injectable for tests; the default binds the real redactor-daemon io (the
 * layer reads the target file and maps secrets through the daemon)
 * @param {import("./lib/trace.mjs").TraceFn} [sink]  where engagement is
 * announced; a host with its own trace channel passes its sink (see lib/trace.mjs)
 * @returns {Promise<Record<string, unknown> | null>}
 */
export async function buildPreToolUseResponse(
  input,
  rehydrate = defaultRehydrate,
  sink,
) {
  // Every path into the announcement runs through here, so this is the one place
  // a host sink has to be made best-effort (see bestEffortTrace) and charged to
  // the host window (see hostChargedTrace).
  const emitTrace = bestEffortTrace(hostChargedTrace(sink));
  const asks = [];
  const contexts = [];

  // Layer 1: gate. Persists across the session until the injected files are
  // cleaned. It asks ONCE (a hard checkpoint, recorded once emitted) then
  // degrades to a passive reminder, so it doesn't prompt on every tool call.
  const findings = invisibleCharAlert(input.session_id);
  let pendingGateAck = false;
  if (findings) {
    if (alertAcknowledged(input.session_id)) {
      contexts.push(gateReminderContext());
    } else {
      asks.push(gateAskReason(findings));
      pendingGateAck = true;
    }
  }

  const { tool_name: tool, tool_input: toolInput } = input;

  // Reported here because this is the first hook that runs after the launch-time
  // loads would have happened. assembleResponse — not this call — records that
  // the notice was surfaced: a rehydrate deny below returns before the response
  // is assembled, and recording here would burn the session's one report on a
  // call that never carried it.
  const gapNotice = instructionsLoadedGapNotice(
    input.session_id,
    undefined,
    toolTargetDir(tool, toolInput),
  );
  if (gapNotice !== null) contexts.push(gapNotice);

  // Layers 2-4, run by the declared pipeline: the driver — not this call order —
  // is what keeps the confusable fold's soundness precondition true once an
  // erasing layer follows it (see lib/layer-pipeline.mjs).
  const {
    updatedInput: current,
    changed,
    contexts: layerContexts,
    deny,
  } = await runLayerPipeline(tool, toolInput, preToolUseLayers(rehydrate));
  if (deny !== undefined)
    return emitTraced(emitTrace, input.tool_name, {
      permissionDecision: PermissionDecision.DENY,
      permissionDecisionReason: deny,
    });
  contexts.push(...layerContexts);

  // Placeholder advisory for tools OUTSIDE the rehydrated set (Bash, MCP,
  // anything unknown): rehydration cannot re-anchor these, so a placeholder in
  // their input would be persisted literally by any write they perform. It
  // cannot tell a write from a read, so it is context-only — never a verdict
  // (see placeholderNotice). Evaluated on the pipeline's FINAL input, matching
  // what the tool will actually receive.
  // Gated on the secret opt-in like the layer itself: with secrets off,
  // placeholder-shaped text is ordinary prose and the advisory is noise.
  const notice = secretsEnabled() ? placeholderNotice(tool, current) : null;
  if (notice !== null) contexts.push(notice);
  // Same advisory for keyed Layer-2 splice placeholders (disjoint grammar, own
  // store): a Bash/MCP write path would persist them literally too, and the
  // note names the span file(s) where the original bytes live.
  const layer2Notice = layer2PlaceholderNotice(tool, current);
  if (layer2Notice !== null) contexts.push(layer2Notice);

  return emitTraced(
    emitTrace,
    input.tool_name,
    assembleResponse({
      changed,
      current,
      asks,
      contexts,
      pendingGateAck,
      pendingGapNotice: gapNotice !== null,
      sessionId: input.session_id,
    }),
  );
}

/**
 * Assemble the hookSpecificOutput fields from the per-layer results, or null
 * for a clean no-op (nothing asked, changed, or annotated). Records the gate
 * acknowledgement and the coverage-gap notice only when they actually land in
 * the response.
 * @param {{ changed: boolean, current: any, asks: string[], contexts: string[],
 *   pendingGateAck: boolean, pendingGapNotice: boolean, sessionId?: string }} parts
 * @returns {Record<string, unknown> | null}
 */
function assembleResponse({
  changed,
  current,
  asks,
  contexts,
  pendingGateAck,
  pendingGapNotice,
  sessionId,
}) {
  if (asks.length === 0 && !changed && contexts.length === 0) return null;

  /** @type {Record<string, unknown>} */
  const fields = {};
  // Include the rewritten input even alongside an ask: applying it can only
  // surface a *cleaner* call to the user than the original (and is ignored if
  // Claude Code doesn't apply updatedInput under an ask).
  if (changed) fields.updatedInput = current;
  if (asks.length > 0) {
    fields.permissionDecision = PermissionDecision.ASK;
    // Stryker disable next-line StringLiteral: the gate is the only source that
    // pushes onto `asks`, so the array never holds more than one reason and the
    // separator is unobservable — join("") is equivalent. The paragraph break is
    // kept for the day a second ask source is added.
    fields.permissionDecisionReason = asks.join("\n\n");
  }
  if (contexts.length > 0) fields.additionalContext = contexts.join(" ");
  // Record the gate ack only now that the ask is actually in the response — a
  // rehydrate deny above returns first, so a preempted ask is not marked seen.
  if (pendingGateAck) acknowledgeAlert(sessionId);
  if (pendingGapNotice) recordInstructionsLoadedNotice(sessionId);
  return fields;
}

/**
 * Agent-agnostic judge over the four protections: consumes a control-plane
 * ToolCallEvent and returns a Verdict, so a non-Claude host can run the same
 * sanitization pipeline through its own adapter. The wired Claude CLI below
 * routes through this judge and renders the Verdict with the Claude adapter; on
 * any throw (a control-plane package-load failure included) it falls back to
 * failClosedFields — a native response that needs no package — so the
 * fail-closed posture holds even when the adapter never loaded.
 * @param {import("agent-control-plane-core").ToolCallEvent} event
 * @param {(tool: string, toolInput: any) => ReturnType<typeof rehydrateRedacted>} [rehydrate]
 * @param {{
 *   messages?: Partial<typeof PRE_TOOL_USE_MESSAGES>,
 *   gates?: HostGate[],
 *   trace?: import("./lib/trace.mjs").TraceFn,
 * }} [opts]
 *   messages are merged over the defaults, so a partial table is supported
 * @returns {Promise<import("agent-control-plane-core").Verdict>}
 */
export async function judgePreToolUseSanitize(event, rehydrate, opts = {}) {
  // Forwarded UNRESOLVED: substituting the package sink for an absent one here
  // would hand hostChargedTrace a truthy sink, charging this package's own
  // trace write to the host window — the misattribution the split exists to
  // prevent. Only buildPreToolUseResponse's binding may pick the default.
  const { gates = [], trace: sink } = opts;
  // MERGED over the defaults, never substituted for them. A host that overrides
  // one field would otherwise leave the rest undefined, and the miss lands in
  // the fail-closed path: failClosedFields runs inside runJudgeCli's catch, so a
  // TypeError on a missing field escapes the handler, the hook exits with no
  // stdout, and Claude reads a PreToolUse hook that produced no response as
  // non-blocking — the fail-closed ask becomes a fail-OPEN pass.
  const messages = { ...PRE_TOOL_USE_MESSAGES, ...opts.messages };
  const { Decision, EventKind } = controlPlane();
  // A payload the adapter cannot classify (a missing/unexpected hook_event_name)
  // would drive the pipeline with an empty event and no-op to ALLOW — a silent
  // fail-OPEN of the gate. This hook is wired only to PreToolUse, so an
  // unclassifiable payload is harness-contract drift or an out-of-band caller,
  // never a real call: deny-when-blind. Rewarding an unclassifiable payload with
  // a pass is the one incentive a gate must never create.
  if (event.event === EventKind.UNKNOWN)
    return { decision: Decision.DENY, reason: messages.unknownEvent };
  // The session identity and the permission mode travel in `meta`, not alongside
  // the tool input. A gate keyed on the session (a once-per-session checkpoint)
  // cannot tell two sessions apart without the first, and a gate keyed on the
  // mode reads `undefined` without the second — so it fires in EVERY mode, which
  // is the safe direction but not the intended one.
  const input = {
    tool_name: event.tool,
    tool_input: event.input,
    session_id: event.meta?.session_id,
    permission_mode: event.meta?.permission_mode,
  };
  // Host gates run BEFORE any rewriting layer, because they decide whether the
  // call may happen at all rather than what its input contains — and returning
  // early keeps a denied call from also being reported as a sanitized one.
  for (const gate of gates) {
    const denyReason = gate(input);
    if (denyReason) return { decision: Decision.DENY, reason: denyReason };
  }
  const fields = await buildPreToolUseResponse(input, rehydrate, sink);
  if (fields === null) return { decision: Decision.ALLOW };
  /** @type {Record<string, unknown>} */
  const verdict = {
    decision: fields.permissionDecision ?? Decision.ALLOW,
  };
  if (fields.permissionDecisionReason !== undefined)
    verdict.reason = fields.permissionDecisionReason;
  if (fields.updatedInput !== undefined)
    verdict.mutated_input = fields.updatedInput;
  if (fields.additionalContext !== undefined)
    verdict.additional_context = fields.additionalContext;
  return /** @type {import("agent-control-plane-core").Verdict} */ (verdict);
}

/**
 * The dependency-load failure hiding behind a hook error, or "". A binding that
 * never loaded surfaces at use time as a bare TypeError ("X is not a function")
 * that names neither the package nor the remedy; when any lazily-loaded package
 * has a recorded load error, name it — the failed set is derived from the
 * loader's own records, so a future dependency is covered without editing a list
 * here. An error already reporting a missing package (missingPackageError's
 * `DEP_UNAVAILABLE` tag) gets no second copy.
 * @param {unknown} err
 * @param {string} [remedy]  what a reader should run; hosts pass their own
 * @param {() => string[]} [failedPackages]
 * @param {(pkg: string) => unknown} [loadErrorFor]
 * @returns {string}
 */
export function depLoadHint(
  err,
  remedy = DEFAULT_MISSING_PACKAGE_REMEDY,
  failedPackages = failedLazyPackages,
  loadErrorFor = lazyImportErrorFor,
) {
  if (/** @type {{code?: unknown}} */ (err)?.code === "DEP_UNAVAILABLE")
    return "";
  // Only a TypeError. The recorded-failure set is process-wide and carries no
  // link to THIS error, so naming a package from it is an inference — sound only
  // for the failure this hint exists to explain, where an unloaded binding is
  // called and V8 raises a TypeError ("X is not a function", "Cannot read
  // properties of undefined"). Any other throw is a layer engine reporting its
  // own problem, and appending a package name there sends the reader to a
  // reinstall that fixes nothing.
  if (!(err instanceof TypeError)) return "";
  const [pkg] = failedPackages();
  return pkg === undefined
    ? ""
    : ` ${missingPackageMessage(pkg, loadErrorFor(pkg), remedy)}`;
}

/**
 * The fail-closed hookSpecificOutput fields for a hook-level failure, chosen by
 * WHICH failure it was. Corrupt/unparsable INPUT (`parsedOk` false — a JSON parse
 * error or the oversize-body cap) is a state an adversary can induce with no
 * upside to failing, so it hard-DENIES: no human to talk past, no approval
 * fatigue, no latency. A LAYER/engine throw after a clean parse (`parsedOk` true
 * — redactor daemon down, package not loaded) is the sanitizer being UNAVAILABLE,
 * so it ASKS to keep a human in the loop rather than hard-block on infrastructure.
 *
 * An UNATTENDED host has no human for that ask to reach, so the ask stops the
 * call and buys no review. Such a host passes `unavailableDecision: DENY` and
 * gets a hard refusal on the clean-parse arm too, with the same reason text.
 * The default stays ASK, so a host that wires nothing keeps today's behavior.
 *
 * Deliberately knob-blind: this is the fail-CLOSED posture itself, so it ignores
 * AGENT_SANITIZER_FAIL_OPEN — a host that wires it directly keeps strictness by
 * construction, with no env var to remember. A host that instead wants the
 * caller's posture (fail-open by default) wires {@link hookFailureFields},
 * which delegates here when the posture is closed.
 * @param {boolean} parsedOk whether the input parsed before the failure
 * @param {unknown} err
 * @param {{
 *   messages?: Partial<typeof PRE_TOOL_USE_MESSAGES>,
 *   hint?: string,
 *   unavailableDecision?: (typeof PermissionDecision)[keyof typeof PermissionDecision],
 * }} [opts]
 * @returns {Record<string, unknown>}
 */
export function failClosedFields(parsedOk, err, opts = {}) {
  const { hint = depLoadHint(err), unavailableDecision } = opts;
  // Merged, not substituted — see judgePreToolUseSanitize. This is the call site
  // where a missing field would throw out of the catch and fail OPEN.
  const messages = { ...PRE_TOOL_USE_MESSAGES, ...opts.messages };
  const cause = `${safeErrMessage(err)}${hint}`;
  // An unknown or absent override falls back to ASK rather than being trusted:
  // a typo must not silently widen this arm past the two closed verdicts.
  const unavailable =
    unavailableDecision === PermissionDecision.DENY
      ? PermissionDecision.DENY
      : PermissionDecision.ASK;
  return {
    permissionDecision: parsedOk ? unavailable : PermissionDecision.DENY,
    permissionDecisionReason: parsedOk
      ? messages.failed(cause)
      : messages.unparsable(cause),
  };
}

// The redaction-placeholder prefix, restated as a literal rather than imported:
// this check belongs to the FAILURE posture and must work exactly when the
// agent-sanitizer package (which exports it as DEFAULT_HINT) failed to load.
// Exported so test/claude-hooks-fail-open.test.mjs can pin the two spellings
// together with exact equality — a prefix-only behavioral check would keep
// passing if this literal drifted shorter and the carve-out over-triggered.
export const REDACTION_HINT = "[REDACTED";
// The file-editing tools whose input fields ARE the bytes persisted to disk.
// Deliberately NOT exhaustive over every clobber path: Bash can also write a
// placeholder to disk (`>`, `tee`, `sed -i`, a heredoc), but command strings
// mention "[REDACTED" benignly far too often — grepping for it, discussing
// it — for an ask to hold precision there. That is an accepted gap, named in
// THREAT-MODEL.md's carve-out paragraph, not a completeness claim.
export const WRITE_SHAPED_TOOLS = new Set([
  "Write",
  "Edit",
  "MultiEdit",
  "NotebookEdit",
]);

/**
 * True when a faulting PreToolUse call is the one case the OPEN posture must
 * still not pass: a write-shaped tool whose input carries the
 * redaction-placeholder prefix. Such a placeholder stands for a secret the
 * sanitizer redacted out of the model's view; with the sanitizer down,
 * rehydration cannot translate it back, so letting the call through would
 * persist the literal placeholder text over the real secret on disk — a
 * destructive clobber, not a missed scan. Package-free by construction (a Set
 * lookup and a substring test on the already-parsed payload), so it holds when
 * the failure IS the missing package.
 * @param {unknown} input raw parsed PreToolUse payload (undefined if unparsed)
 * @returns {boolean}
 */
export function hintedWriteFault(input) {
  const payload =
    /** @type {{tool_name?: unknown, tool_input?: unknown} | undefined} */ (
      input
    );
  if (!WRITE_SHAPED_TOOLS.has(/** @type {string} */ (payload?.tool_name)))
    return false;
  // A parsed-JSON payload can hold no circular reference, so stringify cannot
  // throw; `?? null` keeps a missing tool_input from stringifying to undefined.
  return JSON.stringify(payload?.tool_input ?? null).includes(REDACTION_HINT);
}

/**
 * The hookSpecificOutput fields for a hook-level failure under the CALLER's
 * chosen posture: fail-OPEN by default — a warning context and no
 * permissionDecision, so the tool call proceeds unsanitized — or the
 * fail-CLOSED verdict of {@link failClosedFields} when the caller set
 * AGENT_SANITIZER_FAIL_OPEN=0. The open default has ONE carve-out, declared in
 * this hook's fault policy below: a write-shaped call whose input carries a
 * `[REDACTED…]` placeholder asks instead of passing (see
 * {@link hintedWriteFault}) — pass `input` so the policy can see it.
 *
 * The posture covers this hook's own failures, whatever their cause. What it
 * does NOT cover is the verdict of a sanitizer that ran: a payload
 * judgePreToolUseSanitize denied is denied in both postures.
 * @param {boolean} parsedOk whether the input parsed before the failure
 * @param {unknown} err
 * @param {{
 *   messages?: Partial<typeof PRE_TOOL_USE_MESSAGES>,
 *   hint?: string,
 *   env?: NodeJS.ProcessEnv | Record<string, string | undefined>,
 *   input?: unknown,
 * }} [opts]
 * @returns {Record<string, unknown>}
 */
export function hookFailureFields(parsedOk, err, opts = {}) {
  return /** @type {Record<string, unknown>} */ (
    hookFaultOutcome(HOOK_NAME, err, {
      parsedOk,
      env: opts.env,
      messages: opts.messages,
      hint: opts.hint,
      input: opts.input,
    }).fields
  );
}

// This hook's entry in the one posture table (lib/hook-fault.mjs). The OPEN arm
// keeps the shared default — a warning context and no verdict — with ONE
// carve-out: a write-shaped input carrying a [REDACTED… placeholder asks
// instead. The open posture trades enforcement for availability on the
// sanitizer's own breakage, and that trade is sound for a missed SCAN; a
// placeholder-bearing write is not a scan but a guaranteed clobber — the
// placeholder would be persisted literally over the secret it stands for (see
// hintedWriteFault). The ask keeps a human in the loop exactly as the closed
// posture's clean-parse arm does.
registerFaultPolicy(HOOK_NAME, {
  event: HookEvent.PRE_TOOL_USE,
  guarded: "tool input",
  open: (ctx) => {
    // Non-carve-out faults take the SHARED open rendering, not a copy of it —
    // hook-fault.mjs owns that body, and a restated one would silently drift.
    // The carve-out itself rides the secret opt-in: with secrets off no
    // sanitized view ever handed the model a placeholder, so hint-shaped text
    // in a write is literal prose and holding it would be a false positive.
    if (!secretsEnabled(ctx.env) || !hintedWriteFault(ctx.input))
      return defaultOpen(ctx);
    // parsedOk is hardcoded true (the ASK arm): hintedWriteFault(undefined)
    // is false, so an unparsed input can never reach this line — reaching it
    // proves the payload parsed.
    const closed = failClosedFields(true, ctx.err, {
      messages: ctx.messages,
      hint: ctx.hint,
    });
    return {
      fields: {
        ...closed,
        permissionDecisionReason:
          `${closed.permissionDecisionReason} This input would write ` +
          `${REDACTION_HINT}…] placeholder text, which stands for a redacted ` +
          `secret the unavailable sanitizer cannot translate back; proceeding ` +
          `would overwrite the real secret with the placeholder, so the call ` +
          `is held even under the fail-open posture. Retry once the sanitizer ` +
          `recovers, or ask the user to make this change.`,
      },
    };
  },
  closed: (ctx) => ({
    fields: failClosedFields(ctx.parsedOk, ctx.err, {
      messages: ctx.messages,
      hint: ctx.hint,
    }),
  }),
});

// Stryker disable all: CLI wiring — it runs only in the spawned hook
// subprocess, never in-process, so every mutant from here down is NoCoverage.
// The exported judgePreToolUseSanitize and failClosedFields above carry the
// real, mutation-tested logic.
/**
 * The hook's CLI: parse → judge → render, under the caller's failure posture.
 * Exported so a bundle entry (which must claim the CLI slot before this module
 * loads) can run the exact same wiring instead of duplicating the onError
 * posture.
 * @param {{
 *   messages?: Partial<typeof PRE_TOOL_USE_MESSAGES>,
 *   gates?: HostGate[],
 *   trace?: import("./lib/trace.mjs").TraceFn,
 * }} [opts]
 * @returns {Promise<void>}
 */
export async function cliMain(opts = {}) {
  // Unresolved, for the reason judgePreToolUseSanitize states.
  const { gates = [], trace: sink } = opts;
  const messages = { ...PRE_TOOL_USE_MESSAGES, ...opts.messages };
  await runJudgeCli(
    HOOK_NAME,
    (event) =>
      judgePreToolUseSanitize(event, undefined, {
        messages,
        gates,
        trace: sink,
      }),
    {
      // The caller's posture, WITHOUT the package: pass through with a warning
      // by default, or — under AGENT_SANITIZER_FAIL_OPEN=0 — hard-deny an
      // unparsable INPUT (`input` undefined; adversary-inducible, no benefit to
      // failing) and ASK on any throw after a clean parse, keeping a human in
      // the loop. emitHookResponse renders natively, so either posture holds
      // even when the adapter never loaded.
      onError: (err, input) =>
        emitHookResponse(
          HookEvent.PRE_TOOL_USE,
          hookFailureFields(input !== undefined, err, {
            messages,
            hint: depLoadHint(err, messages.remedy),
            input,
          }),
        ),
    },
  );
}

if (isMain(import.meta.url)) {
  await cliMain();
}
