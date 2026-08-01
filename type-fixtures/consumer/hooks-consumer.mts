// Consumer-perspective type fixture for the CURATED `claude-hooks` composition
// surface — the six subpaths the exports map publishes, and only those. A module
// this file cannot import is the point, not an omission: the de-exports are
// asserted in test/claude-hooks-exports.test.mjs. Companion to consumer.mts (which covers the library subpaths); this
// file imports each hook module BY NAME through the published `exports` map, so
// it fails both when a subpath stops resolving and when its generated `.d.mts`
// widens an export to `any`. The accompanying types-consumer.test.mjs builds the
// declarations and type-checks this file against a real package layout.

import { main } from "agent-sanitizer/claude-hooks";
import {
  sanitizeText,
  evaluateToolOutput,
  composeContext,
  failClosedReplacement,
  SECRET_HINT,
} from "agent-sanitizer/claude-hooks/sanitize-output";
import { judgePreToolUseSanitize } from "agent-sanitizer/claude-hooks/pretooluse-sanitize";
import { judgeSanitizeUserPrompt } from "agent-sanitizer/claude-hooks/sanitize-user-prompt";
import {
  scanFile,
  LONG_RUN_THRESHOLD,
} from "agent-sanitizer/claude-hooks/scan-invisible-chars";
import {
  lazyImport,
  registerLazyModules,
  hookIoSharedState,
  adoptHookIoSharedState,
  makeDeadline,
  readFlag,
  HookEvent,
  PermissionDecision,
} from "agent-sanitizer/claude-hooks/lib/hook-io";
import { runJudgeCli } from "agent-sanitizer/claude-hooks/lib/control-plane";

// `0 extends 1 & T` is only true when T is `any` — see consumer.mts for why a
// plain annotation cannot catch a declaration that collapsed to `any`.
type IsAny<T> = 0 extends 1 & T ? true : false;

// One guard per module, so a single module's declaration collapsing to `any`
// (or vanishing) is a compile error rather than a silently untyped import.
const _mainNotAny: IsAny<typeof main> = false;
const _sanitizeTextNotAny: IsAny<typeof sanitizeText> = false;
const _evaluateToolOutputNotAny: IsAny<typeof evaluateToolOutput> = false;
const _judgePreToolUseNotAny: IsAny<typeof judgePreToolUseSanitize> = false;
const _judgePromptNotAny: IsAny<typeof judgeSanitizeUserPrompt> = false;
const _scanFileNotAny: IsAny<typeof scanFile> = false;
const _lazyImportNotAny: IsAny<typeof lazyImport> = false;
const _runJudgeCliNotAny: IsAny<typeof runJudgeCli> = false;

// SECRET_HINT is re-exported from the package root through a destructured
// lazyImport — the shape most at risk of emitting as `any`.
const _secretNotAny: IsAny<typeof SECRET_HINT> = false;
const _secret: RegExp = SECRET_HINT;

// sanitize-output: the per-blob and whole-event entry points a composer wraps.
// The deadline argument is the documented shared-budget shape.
const _text = await sanitizeText("x", "Bash", { remainingMs: () => 1000 });
const _textCleaned: string = _text.cleaned;
const _textWarnings: string[] = _text.warnings;
const _textModified: boolean = _text.modified;
const _textSgrNote: boolean = _text.sgrNote;

// evaluateToolOutput answers the PostToolUse contract fields, or null when the
// output needed no intervention — the nullability is part of the contract.
const _evaluated: {
  mutated_output?: unknown;
  additional_context?: string;
} | null = await evaluateToolOutput({ tool_name: "Bash" });

const _context: string = composeContext(true, ["w"], "Bash");
const _failClosed = failClosedReplacement("raw", "why");

// The host-extension bag, at the shape a composer actually writes it: the
// callbacks must type-check against the generated declaration, so a `.d.mts`
// that dropped or widened the parameter is a compile error here rather than a
// runtime surprise in the composing repo.
const _extended = await sanitizeText("x", "Bash", undefined, {
  postText: async (cleaned, ctx) => {
    const _toolName: string = ctx.toolName;
    const _webIngress: boolean = ctx.webIngress;
    const _budget: number = ctx.deadline.remainingMs();
    return cleaned.length > 0 ? { warning: "host note" } : null;
  },
  redactNote: (raw) => (raw.length > 0 ? " (host)" : undefined),
  audit: async (record) => {
    const _modified: boolean = record.modified;
    void record.tool;
    void record.output;
  },
});
const _extendedCleaned: string = _extended.cleaned;

// hook-io: the frozen enums must keep their literal-keyed types, so a typo is a
// compile error rather than an undefined lookup.
const _event: "PostToolUse" = HookEvent.POST_TOOL_USE;
const _decision: "deny" = PermissionDecision.DENY;
// @ts-expect-error — an unknown event key must not type-check.
HookEvent.NOT_A_REAL_EVENT;

const _remaining: number = makeDeadline(1000).remainingMs();
const _flag: string | undefined = readFlag(["--hook=x"], "hook");
const _lazy: Record<string, any> = await lazyImport("agent-sanitizer");
registerLazyModules({});
// The cross-instance seam, at the shape a host bundle uses it: read one
// instance's state object and hand it to another.
adoptHookIoSharedState(hookIoSharedState());

// The remaining exported pieces, called at their documented signatures.
const _threshold: number = LONG_RUN_THRESHOLD;

// Reference every binding so readers (and noUnusedLocals, if ever enabled) see
// them as load-bearing assertions rather than dead code.
export const _assertions = [
  _mainNotAny,
  _sanitizeTextNotAny,
  _evaluateToolOutputNotAny,
  _judgePreToolUseNotAny,
  _judgePromptNotAny,
  _scanFileNotAny,
  _lazyImportNotAny,
  _runJudgeCliNotAny,
  _secretNotAny,
  _secret,
  _textCleaned,
  _textWarnings,
  _textModified,
  _textSgrNote,
  _evaluated,
  _context,
  _failClosed,
  _extendedCleaned,
  _event,
  _decision,
  _remaining,
  _flag,
  _lazy,
  _threshold,
] as const;
