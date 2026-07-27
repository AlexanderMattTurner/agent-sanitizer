// Consumer-perspective type fixture. This file is NOT part of the library; it
// imports the package by name (resolving through the published `exports` map to
// the GENERATED `.d.mts` declarations, exactly as a downstream project does)
// and asserts the public types are what we promise. The accompanying
// types-consumer.test.mjs builds the declarations and type-checks this file.
//
// Crucially this catches declaration-EMIT regressions our own `pnpm check`
// cannot: `pnpm check` type-checks the `.mjs` source (where a regex literal is
// obviously `RegExp`), but the bug class here is a `.d.mts` that emits `any` at
// the package boundary — invisible until something resolves the package by name.

import {
  sanitize,
  CATEGORY,
  SECRET_HINT,
  SECRET_HINT_EXT,
  matchesSecretHint,
} from "agent-sanitizer";
import { STRIP, SGR_RE, stripInvisible } from "agent-sanitizer/invisible";
import { HTML_TAG_PRESENT, MD_LINK_HINT } from "agent-sanitizer/html";
import { hasNonAscii, normalizeConfusables } from "agent-sanitizer/confusables";
import { scanInstructionFiles } from "agent-sanitizer/instructions";
import { classifyPrompt } from "agent-sanitizer/prompt";
import { sanitizeText } from "agent-sanitizer/output";
import { occurrences } from "agent-sanitizer/view-map";
import { rehydrateRedacted, DEFAULT_HINT } from "agent-sanitizer/rehydrate";

// `0 extends 1 & T` is only true when T is `any`, so this flags the exact
// regression that shipped in 1.0.1: a declaration that widened to `any`. A bare
// `const r: RegExp = X` would NOT catch it, because `any` is assignable to
// anything — the whole point is to fail when the type has collapsed to `any`.
type IsAny<T> = 0 extends 1 & T ? true : false;

// Regex exports must stay `RegExp`, never `any`.
const _secretNotAny: IsAny<typeof SECRET_HINT> = false;
const _secretExtNotAny: IsAny<typeof SECRET_HINT_EXT> = false;
const _stripNotAny: IsAny<typeof STRIP> = false;
const _sgrNotAny: IsAny<typeof SGR_RE> = false;
const _tagNotAny: IsAny<typeof HTML_TAG_PRESENT> = false;
const _mdNotAny: IsAny<typeof MD_LINK_HINT> = false;
const _secret: RegExp = SECRET_HINT;
const _secretExt: RegExp = SECRET_HINT_EXT;

// The remaining six exports subpaths (/confusables, /instructions, /prompt,
// /output, /view-map, /rehydrate) get the same `any`-leak guard: IsAny on the
// imported binding itself catches a declaration collapse for a *function*
// export too, not just the regex constants above.
const _hasNonAsciiNotAny: IsAny<typeof hasNonAscii> = false;
const _normalizeConfusablesNotAny: IsAny<typeof normalizeConfusables> = false;
const _scanInstructionFilesNotAny: IsAny<typeof scanInstructionFiles> = false;
const _classifyPromptNotAny: IsAny<typeof classifyPrompt> = false;
const _sanitizeTextNotAny: IsAny<typeof sanitizeText> = false;
const _occurrencesNotAny: IsAny<typeof occurrences> = false;
const _rehydrateRedactedNotAny: IsAny<typeof rehydrateRedacted> = false;
const _defaultHintNotAny: IsAny<typeof DEFAULT_HINT> = false;

// CATEGORY keeps its literal-keyed type, so a code typo is a compile error.
const _cf: "cf-format" = CATEGORY.CF;
// @ts-expect-error — an unknown category key must not type-check.
CATEGORY.NOT_A_REAL_CATEGORY;

const _hint: boolean = matchesSecretHint("token=abc");
const _stripped: string = stripInvisible("x");

// sanitize resolves to the documented result shape.
const result = await sanitize("x", { html: true });
const _cleaned: string = result.cleaned;
const _found: string[] = result.found;
const _warnings: string[] = result.warnings;

// /confusables — hasNonAscii is a plain predicate; normalizeConfusables takes
// an injected `{ scan }` (the homoglyph engine is never bundled) and returns
// the updated input plus the fields touched, or null.
const _nonAscii: boolean = hasNonAscii("аpt"); // Cyrillic "а"
const _normalized: { updatedInput: any; normalized: string[] } | null =
  normalizeConfusables(
    "Bash",
    { command: "/аpt update" },
    { scan: (_text: string) => ({ findings: [] }) },
  );

// /instructions — scanInstructionFiles returns one entry per file with hits.
const _instructionFindings: Array<{ file: string; findings: unknown[] }> =
  scanInstructionFiles([]);

// /prompt — classifyPrompt's action is a closed pass/note/block union.
const _verdict = classifyPrompt("hello");
const _action: "pass" | "note" | "block" = _verdict.action;

// /output — sanitizeText takes the documented SanitizeTextOptions shape
// (redact/filterInjection are the injected Layer-4/5 seams) and resolves to
// { cleaned, warnings, modified, sgrNote }.
const _textResult = await sanitizeText("x", {
  html: false,
  exfilScan: false,
  redact: async (_text: string) => null,
  filterInjection: (_text: string) => null,
});
const _textCleaned: string = _textResult.cleaned;
const _textModified: boolean = _textResult.modified;
const _textSgrNote: boolean = _textResult.sgrNote;

// /view-map — pure offset machinery consumed by /rehydrate.
const _occ: number[] = occurrences("ababab", "ab");

// /rehydrate — rehydrateRedacted's `io` is the injected RehydrateIo (file
// reads + the redactor's map/plain contract); the call resolves to an
// updated-input/context pair, a deny, or null.
const _rehydrated:
  { updatedInput: any; context: string } | { deny: string } | null =
  await rehydrateRedacted(
    "Edit",
    { file_path: "/tmp/x", old_string: "a", new_string: "b" },
    {
      readFile: (_path: string) => "a",
      redactMap: (text: string) => ({ text, pairs: [] }),
      redact: (_text: string) => null,
    },
  );
const _defaultHint: string = DEFAULT_HINT;

// Reference the bindings so noUnusedLocals (if ever enabled) and readers both
// see them as load-bearing assertions, not dead code.
export const _assertions = [
  _secretNotAny,
  _secretExtNotAny,
  _stripNotAny,
  _sgrNotAny,
  _tagNotAny,
  _mdNotAny,
  _secret,
  _secretExt,
  _cf,
  _hint,
  _stripped,
  _cleaned,
  _found,
  _warnings,
  _hasNonAsciiNotAny,
  _normalizeConfusablesNotAny,
  _scanInstructionFilesNotAny,
  _classifyPromptNotAny,
  _sanitizeTextNotAny,
  _occurrencesNotAny,
  _rehydrateRedactedNotAny,
  _defaultHintNotAny,
  _nonAscii,
  _normalized,
  _instructionFindings,
  _action,
  _textCleaned,
  _textModified,
  _textSgrNote,
  _occ,
  _rehydrated,
  _defaultHint,
] as const;
