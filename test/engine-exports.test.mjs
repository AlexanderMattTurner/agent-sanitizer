/**
 * The ENGINE half of the published surface: `agent-sanitizer` itself and its
 * `./invisible`, `./html`, … subpaths, which consumers import directly and
 * which downstream generators read.
 *
 * claude-hooks-exports.test.mjs owns the hook half — its curated map, its
 * refused subpaths, and its README table. This file asserts the one property
 * that half proved worth having: each published module's named exports are
 * exactly the snapshotted set, so a symbol added or dropped is caught here
 * instead of in a consumer's build after the release.
 *
 * `./credential-names` is data, not a module: it resolves to a JSON file with
 * no export surface to pin. package-exports.test.mjs is what proves it ships.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const pkg = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);

// The engine subpaths, read from the package's own map: every non-hook entry
// that resolves through conditions (a bare-string entry names a data file).
const EXPORTED = Object.entries(pkg.exports)
  .filter(
    ([sub, target]) => !sub.startsWith("./claude-hooks") && target.default,
  )
  .map(([sub]) => sub)
  .sort();

// Every named export of every engine subpath. Removing an entry is the edit
// that marks the removal deliberate and breaking; adding one belongs in the
// same commit as the export.
const PUBLISHED_EXPORTS = {
  ".": [
    "BLANK_NON_CF",
    "CATEGORY",
    "CATEGORY_LABELS",
    "CHECKS",
    "HTML_TAG_PRESENT",
    "LINGUISTIC_SCRIPTS",
    "LONE_SURROGATE_RE",
    "LONG_RUN_RE",
    "LONG_RUN_THRESHOLD",
    "MD_LINK_HINT",
    "SCATTERED_THRESHOLD",
    "SECRET_HINT",
    "SECRET_HINT_EXT",
    "SGR_RE",
    "STRIP",
    "VS",
    "applyLayer1",
    "applyLayer1WellFormed",
    "findLongRuns",
    "hasLongRun",
    "isBenignAnsi",
    "isBenignAnsiKinds",
    "isSgrOnly",
    "matchesSecretHint",
    "normalizeLoneSurrogates",
    "sanitize",
    "stripAnsiFully",
    "stripInvisible",
    "stripInvisibleWithReport",
  ],
  "./invisible": [
    "BLANK_NON_CF",
    "BRAHMIC_CONSONANT_RANGES",
    "CATEGORY",
    "CATEGORY_LABELS",
    "CHECKS",
    "CONSECUTIVE_JOINER_CAP",
    "CONSECUTIVE_SELECTOR_CAP",
    "LINGUISTIC_SCRIPTS",
    "LONG_RUN_RE",
    "LONG_RUN_THRESHOLD",
    "PRESERVED_BLANK_PER_ANCHOR",
    "PRESERVED_JOINER_PER_VISIBLE",
    "PRESERVE_HARD_CAP",
    "SCATTERED_THRESHOLD",
    "SGR_RE",
    "STRIP",
    "TOTAL_PRESERVED_BLANK_BUDGET",
    "TOTAL_PRESERVED_JOINER_BUDGET",
    "VS",
    "ZERO_WIDTH_MN",
    "countEffectiveInvisible",
    "countPayloadInvisible",
    "describeStripped",
    "findLongRuns",
    "hasLongRun",
    "isIncidentalInvisible",
    "isSgrOnly",
    "payloadInvisibleView",
    "payloadLongRunSample",
    "stripInvisible",
    "stripInvisibleWithReport",
  ],
  "./layer1": [
    "INERT_ANSI_NOTE",
    "LONE_SURROGATE_RE",
    "applyLayer1",
    "applyLayer1WellFormed",
    "isBenignAnsi",
    "isBenignAnsiKinds",
    "normalizeLoneSurrogates",
    "stripAnsiFully",
  ],
  "./html": [
    "COMMENT_PLACEHOLDER",
    "DATA_URI_LENGTH_THRESHOLD",
    "HIDDEN_PLACEHOLDER",
    "HTML_TAG_PRESENT",
    "LAYER2_PLACEHOLDER_RE",
    "MD_LINK_HINT",
    "REPORTED_TAGS",
    "SECRET_HINT",
    "SECRET_HINT_EXT",
    "UNPARSEABLE_PLACEHOLDER",
    "checkExfilUrl",
    "closingTagName",
    "detectConfusableHosts",
    "detectExfil",
    "isHiddenElement",
    "isHiddenOpen",
    "isHiddenStyle",
    "layer2Placeholder",
    "looksLikeHtmlSource",
    "matchesSecretHint",
    "sanitizeHtml",
    "scanHtmlFragment",
    "spliceRanges",
    "urlHost",
  ],
  "./confusables": [
    "DEFAULT_FIELDS",
    "EXEMPT_TOOLS",
    "EXEMPT_TOOL_PATTERNS",
    "foldConfusables",
    "hasNonAscii",
    "normalizeConfusables",
    "normalizeContext",
    "scopeFor",
    "selectFoldableFindings",
  ],
  "./instructions": [
    "CLAUDE_CONTEXT_KINDS",
    "CLAUDE_CONTEXT_SUBDIRS",
    "CLAUDE_DIR_INSTRUCTION_FILES",
    "CLAUDE_INSTRUCTION_GLOBS",
    "CLAUDE_LAUNCH_GLOBS",
    "CLAUDE_MEMORY_FILES",
    "USER_GLOBAL_EVENT_NAMED_GLOBS",
    "ancestorInstructionFiles",
    "announcedByInstructionsLoaded",
    "atomicReplaceFile",
    "cleanFile",
    "contextScopeContradiction",
    "decodeRun",
    "excludeFromContextScan",
    "findInstructionFiles",
    "scanInstructionFiles",
    "scanText",
  ],
  "./prompt": ["classifyPrompt", "formatReason"],
  "./output": [
    "FILTER_WARNING",
    "MAX_DEPTH",
    "REDACTION_DOCTRINE",
    "composeContext",
    "deleteVerbatimSpans",
    "describeExfil",
    "describeRemoved",
    "describeWarned",
    "isWalkableContainer",
    "needsMarkdownPipeline",
    "sanitizeText",
    "sanitizeValue",
    "suppressToolOutput",
    "withheldWarning",
  ],
  "./credential-names-matcher": [
    "credentialNameMatcher",
    "credentialNames",
    "parseCredentialNames",
  ],
  "./view-map": [
    "alignDeletions",
    "anchorSpans",
    "makeFileView",
    "occurrences",
    "orderedMatches",
    "overlapAwareCount",
    "pairDiskSpans",
    "pairsToUtf16",
    "rehydrateNewString",
    "resolveSpan",
    "spliceOrdered",
    "toUtf16View",
    "viewMapDefect",
  ],
  "./rehydrate": ["DEFAULT_HINT", "rehydrateRedacted"],
};

describe("the engine's published export surface is exactly what is snapshotted", () => {
  it("snapshots every engine subpath, and only those (non-vacuous)", () => {
    assert.ok(EXPORTED.length > 0, "no engine subpaths found in the map");
    // Both directions in one equality: a subpath added to the map with no
    // snapshot would publish an unpinned surface, and a snapshot left behind by
    // a dropped subpath pins one nobody can import.
    assert.deepEqual(Object.keys(PUBLISHED_EXPORTS).sort(), EXPORTED);
  });

  for (const subpath of EXPORTED) {
    const specifier = subpath.replace(/^\./u, "agent-sanitizer");
    it(`${specifier} exports exactly its snapshotted set`, async () => {
      // Self-reference through the package's own name, the same resolution a
      // consumer's bare import performs — a relative import would pass even
      // with the exports map broken.
      const mod = await import(import.meta.resolve(specifier));
      assert.deepEqual(
        Object.keys(mod).sort(),
        PUBLISHED_EXPORTS[subpath],
        `${specifier}'s published exports moved — update PUBLISHED_EXPORTS, and release a removal as breaking`,
      );
    });
  }
});
