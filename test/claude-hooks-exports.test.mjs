/**
 * A CURATED slice of the hook modules is a public composition surface, reachable
 * as `agent-sanitizer/claude-hooks/<module>`. The slice is deliberate in BOTH
 * directions, so this file asserts both:
 *
 *   - the exported entries resolve and load (a consumer can compose them);
 *   - each one's named exports are exactly the snapshotted set;
 *   - every other module stays REFUSED (ERR_PACKAGE_PATH_NOT_EXPORTED);
 *   - the README's table of the surface is exactly that set.
 *
 * The closed half is the load-bearing one. A wildcard would publish every module
 * by construction, including any added later, turning each into a compatibility
 * surface this package would then owe forever; the curated map publishes only
 * what a composer was actually meant to reach. hook-io in particular MUST be
 * shared rather than copied, because it owns the lazy-module registry and the
 * CLI-slot singleton — two inlined copies would double-fire the inlined CLIs. A
 * host that cannot share it because its own hook-io module is not a copy — it
 * exports names this one does not have — reconciles the two through
 * `adoptHookIoSharedState` instead, which puts both instances on one state object.
 *
 * The documented half closes the third way this rots. The map widened to thirteen
 * subpaths while the README still advertised six, so a consumer reading the docs
 * could not see most of what shipped and a maintainer reading them could not see
 * what the package now owes. The README table is asserted to be exactly this map,
 * in both directions, so neither can move without the other.
 *
 * These drive Node's real exports resolution via `import.meta.resolve` against
 * the package's own name — the same resolution a consumer's bare import
 * performs — and then import the resolved module, so both halves are asserted:
 * the subpath resolves AND the module behind it loads. A relative import would
 * pass even with the exports map broken, which is exactly the regression that
 * shipped.
 *
 * The tarball half (declarations paired with every exposed module) is asserted
 * in package-exports.test.mjs, which drives `npm pack`.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const hooksDir = fileURLToPath(new URL("../claude-hooks", import.meta.url));
const pkg = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);

/**
 * Every hook module on disk, as its `claude-hooks/*` subpath suffix
 * (`sanitize-output`, `lib/hook-io`, …), read from the directory so a module
 * added later is classified rather than silently ignored.
 */
function hookModules() {
  const mjs = (dir, prefix) =>
    readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isFile() && e.name.endsWith(".mjs"))
      .map((e) => `${prefix}${e.name.replace(/\.mjs$/u, "")}`);
  return [
    ...mjs(hooksDir, ""),
    ...mjs(path.join(hooksDir, "lib"), "lib/"),
  ].sort();
}

// The EXPORTED subset, read from the package's own map rather than restated:
// the map is the contract under test, so a curated entry added or dropped moves
// both the allow list and the deny list in one edit.
const EXPORTED = Object.keys(pkg.exports)
  .filter((k) => k.startsWith("./claude-hooks/"))
  .map((k) => k.slice("./claude-hooks/".length))
  .sort();

/**
 * The subpaths the README's exports table advertises, as `claude-hooks/<name>`
 * (and the bare `claude-hooks`). Anchored on an HTML comment rather than a
 * heading so reformatting the prose around it cannot silently empty the parse —
 * and an empty parse is asserted against below.
 */
function documentedSubpaths() {
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
  const lines = readme.split("\n");
  const start = lines.findIndex((line) =>
    line.startsWith("<!-- exports-table:"),
  );
  assert.notEqual(start, -1, "README lost the <!-- exports-table: --> marker");
  const rows = [];
  for (const line of lines.slice(start + 1)) {
    if (!line.startsWith("|")) {
      if (rows.length > 0) break;
      continue;
    }
    rows.push(line);
  }
  return rows
    .map((row) => /^\|\s*`(?<subpath>[^`]+)`/u.exec(row)?.groups.subpath)
    .filter((subpath) => subpath !== undefined)
    .sort();
}

// A named export each module must carry, so the test asserts a usable surface
// rather than "the import didn't throw". These are the entry points a consumer
// composes with; a module that resolves but exports nothing is a fail-open this
// closes.
const REQUIRED_EXPORT = {
  "plugin-hooks": "main",
  "pretooluse-sanitize": "judgePreToolUseSanitize",
  "sanitize-output": "sanitizeText",
  "sanitize-user-prompt": "judgeSanitizeUserPrompt",
  "scan-invisible-chars": "scanFile",
  "scan-loaded-instructions": "scanLoadedFile",
  "lib/authored-content": "sanitizeAuthoredContent",
  "lib/control-plane": "runJudgeCli",
  "lib/env-config": "looksLikeCredentialVar",
  "lib/hook-fault": "hookFaultOutcome",
  "lib/hook-io": "lazyImport",
  "lib/hook-timing": "slowHookNotice",
  "lib/layer-pipeline": "runLayerPipeline",
  "lib/invisible-alert": "invisibleCharAlert",
  "lib/invisible-report": "formatReport",
  "lib/redactor-client": "redactViaDaemon",
  "lib/reveal": "persistReveal",
  "lib/placeholder-grammar": "placeholderNotice",
  "lib/secret-annotate": "hasEnvBoundSecret",
  "lib/secret-drop-guard": "secretDropGuard",
  "lib/trace": "trace",
};

// Every named export of every PUBLISHED module. The entry symbol above proves a
// module is usable; this proves the whole surface a consumer can import is the
// surface this package meant to publish. Without it a symbol can leave a
// published module unremarked, and a consumer's build breaks on what its
// version range says is a compatible upgrade — `formatReport` left
// `scan-invisible-chars` that way. Removing an entry here is the edit that says
// the removal is deliberate, which is the point to release it as breaking.
// Adding one is cheap and belongs in the same commit as the export.
const PUBLISHED_EXPORTS = {
  "plugin-hooks": ["HOOK_MODES", "main"],
  "pretooluse-sanitize": [
    "PRE_TOOL_USE_MESSAGES",
    "REDACTION_HINT",
    "WRITE_SHAPED_TOOLS",
    "buildPreToolUseResponse",
    "cliMain",
    "depLoadHint",
    "failClosedFields",
    "hintedWriteFault",
    "hookFailureFields",
    "judgePreToolUseSanitize",
    "preToolUseLayers",
    "rehydrateLayer2",
  ],
  "sanitize-output": [
    "COLLISION_WITHHELD_MESSAGE",
    "ON_DISK_PLACEHOLDER_WARNING",
    "REVEAL_WITHHELD_WARNING",
    "SECRET_HINT",
    "SECRET_HINT_EXT",
    "applyLayer1",
    "cliMain",
    "collisionWarning",
    "composeContext",
    "describeRemoved",
    "describeWarned",
    "emitFailClosed",
    "emitHookFailure",
    "evaluateToolOutput",
    "failClosedContext",
    "failClosedReplacement",
    "judgeSanitizeOutput",
    "matchesSecretHint",
    "sanitizeText",
    "sanitizeValue",
    "sanitizerDepsLoaded",
    "suppressToolOutput",
    "withPostToolUseDefault",
  ],
  "sanitize-user-prompt": [
    "USER_PROMPT_MESSAGES",
    "classifyPrompt",
    "judgeSanitizeUserPrompt",
    "main",
  ],
  "scan-invisible-chars": [
    "ALERT_ACK_FILE",
    "ALERT_FILE",
    "CLAUDE_CONTEXT_SUBDIRS",
    "CLAUDE_INSTRUCTION_GLOBS",
    "CLAUDE_LAUNCH_GLOBS",
    "LONG_RUN_RE",
    "LONG_RUN_THRESHOLD",
    "TOTAL_INVISIBLE_THRESHOLD",
    "cliMain",
    "decodeRun",
    "findInstructionFiles",
    "formatSkipped",
    "scanFile",
    "scanProject",
  ],
  "scan-loaded-instructions": [
    "HOOK_NAME",
    "cliMain",
    "loadedFileMessage",
    "readLoadedFile",
    "scanLoadedFile",
    "scopeNotice",
  ],
  "lib/authored-content": [
    "AUTHORED_FIELDS",
    "EXEMPT_TOOLS",
    "EXEMPT_TOOL_PATTERNS",
    "authoredContext",
    "authoredScopeDecision",
    "sanitizeAuthoredContent",
  ],
  "lib/control-plane": ["controlPlane", "nativeStdout", "runJudgeCli"],
  "lib/env-config": [
    "SECRETS_ENABLED_ENV",
    "configureEnvConfigSource",
    "dynamicSecretVars",
    "envBoundSecretVars",
    "extraSecretVars",
    "inferenceKeyVars",
    "looksLikeCredentialVar",
    "minEnvSecretLen",
    "secretsEnabled",
  ],
  "lib/hook-io": [
    "DEFAULT_MISSING_PACKAGE_REMEDY",
    "DISABLED_HOOKS_ENV",
    "FAIL_CLOSED_VALUES",
    "FAIL_OPEN_ENV",
    "HookEvent",
    "MAX_STDIN_BYTES",
    "PermissionDecision",
    "adoptHookIoSharedState",
    "awaitLazyDependency",
    "claimCliEntry",
    "configureHookgateMarker",
    "configureMissingPackageRemedy",
    "disabledHooks",
    "emitHookResponse",
    "errMessage",
    "failOpenContext",
    "failOpenEnabled",
    "failedLazyPackages",
    "hookIoSharedState",
    "hookgateMarkerPath",
    "isMain",
    "lastStdinByteLength",
    "lazyImport",
    "lazyImportErrorFor",
    "makeDeadline",
    "markerIsTrusted",
    "missingPackageError",
    "missingPackageMessage",
    "probeSetupAlive",
    "readFlag",
    "readStdinJson",
    "registerLazyModules",
    "registeredLazyModule",
    "safeErrMessage",
    "scrubUntrustedText",
    "writeFileNoFollow",
    "writeSentinelFile",
  ],
  "lib/invisible-alert": [
    "ALERT_ACK_FILE",
    "ALERT_FILE",
    "PROJECT_DIR",
    "PROJECT_HASH",
    "acknowledgeAlert",
    "alertAcknowledged",
    "appendAlert",
    "gateAskReason",
    "gateReminderContext",
    "instructionsLoadedFile",
    "instructionsLoadedGapNotice",
    "instructionsLoadedNoticeFile",
    "instructionsLoadedSeen",
    "invisibleCharAlert",
    "recordInstructionsLoaded",
  ],
  "lib/redactor-client": [
    "DEFAULT_SOCKET_PATH",
    "FRAME_CAP",
    "classifySocket",
    "connectAndRequest",
    "positiveMsOr",
    "redactViaDaemon",
    "spawnDaemon",
    "waitForSocket",
  ],
  "lib/reveal": [
    "REVEAL_READ_ENVELOPE",
    "SPAN_ROUNDTRIP_NOTICE",
    "isRevealRead",
    "persistReveal",
    "persistSpan",
    "readSpan",
    "revealDir",
    "spanPath",
  ],
  "lib/secret-annotate": ["envValueRegex", "hasEnvBoundSecret"],
  "lib/trace": ["TraceEvent", "bestEffortTrace", "trace", "traceThreshold"],
};

describe("claude-hooks composition surface resolves through the exports map", () => {
  const modules = hookModules();

  it("finds hook modules to check (non-vacuous)", () => {
    assert.ok(modules.length > 0, "no .mjs modules found under claude-hooks/");
    assert.ok(EXPORTED.length > 0, "no ./claude-hooks/* subpaths in the map");
    // Every module on disk must be named above, or a new one silently escapes
    // the per-module assertions below.
    assert.deepEqual(
      modules.filter((m) => !REQUIRED_EXPORT[m]),
      [],
      "hook modules with no REQUIRED_EXPORT entry — add one",
    );
    // Every PUBLISHED module must carry a full-surface snapshot, in both
    // directions: an export added to the map with no snapshot would publish an
    // unpinned surface, and a snapshot left behind by a dropped export pins one
    // nobody can import. `plugin-hooks` is published as the bare
    // `./claude-hooks` entry, so it is snapshotted beside the curated subpaths.
    assert.deepEqual(
      Object.keys(PUBLISHED_EXPORTS).sort(),
      [...EXPORTED, "plugin-hooks"].sort(),
      "PUBLISHED_EXPORTS and the published modules disagree",
    );
    // Every exported subpath must name a module that exists — a curated entry
    // pointing at a deleted file resolves to nothing and fails only at import.
    assert.deepEqual(
      EXPORTED.filter((e) => !modules.includes(e)),
      [],
      "exports name claude-hooks modules that are not on disk",
    );
  });

  it("is documented in the README, exactly", () => {
    // Both directions in one equality: an export added without a row, and a row
    // left behind by an export that was renamed or dropped, are the same failure.
    assert.deepEqual(
      documentedSubpaths(),
      [
        "claude-hooks",
        ...EXPORTED.map((name) => `claude-hooks/${name}`),
      ].sort(),
      "the README exports table and package.json's ./claude-hooks* exports disagree",
    );
  });

  for (const name of EXPORTED) {
    const subpath = `agent-sanitizer/claude-hooks/${name}`;
    it(`${subpath} resolves and exports ${REQUIRED_EXPORT[name]}`, async () => {
      // Self-reference: a package with an `exports` map resolves its own name,
      // so this throws ERR_PACKAGE_PATH_NOT_EXPORTED on an unmapped subpath.
      const resolved = import.meta.resolve(subpath);
      assert.equal(fileURLToPath(resolved), path.join(hooksDir, `${name}.mjs`));
      const mod = await import(resolved);
      assert.ok(
        typeof mod[REQUIRED_EXPORT[name]] === "function",
        `${subpath} does not export ${REQUIRED_EXPORT[name]} as a function`,
      );
      assert.deepEqual(
        Object.keys(mod).sort(),
        PUBLISHED_EXPORTS[name],
        `${subpath}'s published exports moved — update PUBLISHED_EXPORTS, and release a removal as breaking`,
      );
    });
  }

  // The closed half of the contract: a module the curated list omits must stay
  // unreachable. Iterated over the real on-disk set minus the exported set, so
  // adding a module without exporting it is covered automatically, and widening
  // the map to a wildcard — which would re-publish every internal — reds here.
  for (const name of modules.filter((m) => !EXPORTED.includes(m))) {
    const subpath = `agent-sanitizer/claude-hooks/${name}`;
    it(`${subpath} stays de-exported`, () => {
      assert.throws(() => import.meta.resolve(subpath), {
        code: "ERR_PACKAGE_PATH_NOT_EXPORTED",
      });
    });
  }

  // A traversal is refused for the same reason every internal is: under a curated
  // map an unlisted subpath has no target at all, so `..` never gets a chance to
  // be resolved relative to anything. Asserted because that guarantee comes from
  // the map's shape, and a move to a wildcard would hand it back to Node's
  // specifier parser instead.
  it("refuses a traversal out of claude-hooks/", () => {
    assert.throws(
      () =>
        import.meta.resolve("agent-sanitizer/claude-hooks/../../package.json"),
      { code: "ERR_PACKAGE_PATH_NOT_EXPORTED" },
    );
  });

  // The bare `./claude-hooks` subpath is the documented CLI entry and stays
  // resolvable on its own, beside the curated subpaths.
  it("keeps the bare ./claude-hooks entry pointing at the CLI dispatcher", async () => {
    const resolved = import.meta.resolve("agent-sanitizer/claude-hooks");
    assert.equal(
      fileURLToPath(resolved),
      path.join(hooksDir, "plugin-hooks.mjs"),
    );
    const mod = await import(resolved);
    assert.equal(typeof mod.main, "function");
    assert.deepEqual(
      Object.keys(mod).sort(),
      PUBLISHED_EXPORTS["plugin-hooks"],
      "the CLI dispatcher's published exports moved — update PUBLISHED_EXPORTS, and release a removal as breaking",
    );
  });
});
