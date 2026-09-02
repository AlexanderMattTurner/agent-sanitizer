# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to
adhere to [Semantic Versioning](https://semver.org/).

<!-- Do NOT hand-edit this file. On push to main the auto-version workflow drafts the next release's notes from the Conventional Commit subjects since the last tag, then promotes "## Unreleased" to a dated version section. Your commit messages are the source of truth — keep the empty "## Unreleased" heading below in place. -->

## Unreleased

## [2.54.2] - 2026-09-02

### Changed
- Enhanced README with improved usage details and library features documentation.

## [2.54.1] - 2026-09-01

### Added
- New `template-sync-marker-gate.sh` script to validate and handle template sync conflicts.
- New `lib-post-review-with-retry.sh` library for managing PR review retries.
- New `merge-driver-probe.sh` script and tests to detect and probe merge driver capabilities.
- Additional Claude rules and documentation for prompt authoring and shell styling.
- Expanded test coverage with new test files for merge conflict handling and merge driver probing.

### Changed
- Updated GitHub Actions setup and Claude run workflow components for improved reliability.
- Enhanced merge conflict handling libraries with expanded conflict marker resolution.
- Reorganized GitHub Actions scripts structure with improved modularity.

### Fixed
- Fixed dangling workflow references in CI configuration.
- Resolved template synchronization conflicts and marker validation.
- Fixed pre-push hook execution in template-sync workflow.
- Improved sparse-checkout handling for retry library dependencies.

## [2.54.0] - 2026-09-01

### Fixed

- **Autolink fix:** The GFM autolink-literal extension is now vendored rather than patched, ensuring a more robust solution for autolink detection.
- **Autolink memo validation:** Fixed validation of the autolink memo to check against the events array instead of relying on a flag alone.
- **Performance:** Improved performance of micromark's autolink-literal bracket walk by eliminating quadratic behavior.

## [2.53.0] - 2026-09-01

### Added
- `flagDigestValues` option to re-report digest-shaped URL values in HTML sanitization.
- `flag_digest_values` parameter in Python `sanitize_text` function.

### Changed
- Refactored `rawUrlKeywordExfil` to remove the `flagDigestValues` argument.

## [2.52.0] - 2026-09-01

### Changed

- Hook performance reports now include the agent-sanitizer version for better diagnostics.

### Removed

- Removed mutation shard testing from every PR; now runs on a daily schedule instead for efficiency.

## [2.51.0] - 2026-08-31

### Added
- Host-extension share naming in slow-hook notices for better debugging visibility.

### Fixed
- Hooks now properly charge every host callback to ensure all hooks are tracked.
- Host-extension window is kept disjoint and the sync seam is properly charged for accurate timing measurements.

## [2.50.0] - 2026-08-31

### Fixed

- Stop SIGPIPE from aborting a release once the changelog grows past a certain size.

### Changed

- Auto-merge on pull requests now arms when the reviewer skips the review, instead of on the reviewer side.

## [2.49.2] - 2026-08-30

### Fixed

- Keep the redactor daemon alive across SIGHUP signal handling.

## [2.49.1] - 2026-08-30

### Added
- Linear-time algorithmic complexity guarantee for confusables and HTML sanitization, documented in THREAT-MODEL.md.
- Linting rule via eslint-plugin-redos to detect and report super-linear regexes at build time.

### Changed
- HTML regex scans optimized to run in linear time relative to input size.
- Confusables folding refactored to avoid rebuilding the tail on overlapping findings.

### Fixed
- Confusables finding span calculation now correctly counts in UTF-16 units at the fold gate.

## [2.49.0] - 2026-08-30

### Fixed

- Improved credential detection in prose position by refusing key/value interpretation for credential nouns.
- Enhanced prose skip logic to require proper env-name value shape and same-line determiner.
- Refined prose skip detection to trust only determiners immediately before credential nouns.
- Fixed over-redaction by stopping redaction of prose lines where English function words precede the credential noun.

## [2.48.6] - 2026-08-29

### Fixed

- Stop digest exemption from covering credential-named parameters
- Keep the hex blob floor below base64's to prevent unnecessary base64 encoding
- Treat a bare digest as a fingerprint instead of an exfiltration payload

## [2.48.5] - 2026-08-29

### Changed

- Copy gate's repeat cost is now documented against the linear sites.

## [2.48.4] - 2026-08-29

### Fixed

- Template sync now runs its own scripts from a staged copy with the tooling path passed through environment variables, improving reliability of the sync process.

## [2.48.3] - 2026-08-29

### Fixed

- Resolved security scan failures caused by unset Claude credential by properly scoping OAuth credentials to the step that uses them.
- Cleared four advisories reported by pnpm audit in the development dependency tree.

## [2.48.2] - 2026-08-29

### Fixed

- HTML redaction no longer rewrites example key IDs in comments.
- Signed-URL field recognition now covers all providers, not just Azure.
- Signed-CDN queries are now properly bounded to prevent hiding from long-query checks.
- Signed-URL `expires` timestamps are now treated as short parameters instead of blobs.
- Azure SAS URL false positives are eliminated and signed-name blob dodges are closed.

## [2.48.1] - 2026-08-28

### Fixed

- The InstructionsLoaded gap notice is now silenced during cold starts when a live setup has not yet been established.

## [2.48.0] - 2026-08-27

### Added

- Export `is_bare_pem_header` function for use by whole-file callers in the secrets engine.

## [2.47.15] - 2026-08-27

### Fixed

- Fix claude-hooks to only expect an InstructionsLoaded event for kinds it announces, preventing spurious events from other announcement types.

## [2.47.14] - 2026-08-27

### Fixed

- Fixed claude-hooks to count the user-global ~/.claude root as launch content, ensuring instructions are properly recognized.
- Fixed InstructionsLoaded gap notice to remain visible past an empty launch when there is content to load.
- Fixed InstructionsLoaded gap notice to be suppressed when there is nothing to load.

## [2.47.13] - 2026-08-26

### Fixed

- Fixed test detector JSON reads to properly use UTF-8 encoding.
- Updated CI tool pin for the stale agent-resolve-merge-conflicts and ci-truth-serum tooling to resolve their findings.
- Fixed remerge-diff report's size cap configuration to properly wire into the comment step.

## [2.47.12] - 2026-08-26

### Fixed
- Relaxed and re-clipped the trailing boundary in secret detection; now fails loudly on unrecognized guards.
- Fixed boundary lookbehind to correctly handle wrapped tokens.

### Changed
- Improved performance of secret detection by translating newline seams lazily in cross-line matching.

## [2.47.11] - 2026-08-26

### Fixed
- Secrets detector now requires a token boundary before every prefix-anchored detector pattern, and only matches token prefixes on word boundaries.

### Changed
- HTML parsing now operates in linear time for improved performance when processing HTML fragments.

## [2.47.10] - 2026-08-26

### Changed
- Hide generated files from the PR reviewer's diff by filtering artifacts and splitting diffs on headers.

### Fixed
- Refuse omitting claims for directories in CI review preparation.
- Ensure the reviewer omit list is driven through `--owned --rederived-only` flags.
- Only omit artifacts that a required check re-derives.
- Prevent diff content lines from starting a new section.

## [2.47.9] - 2026-08-26

### Changed

- HTML plugin now imports css-tree by subpath, reducing bundle size by dropping mdn-data from shipped bundles.

## [2.47.8] - 2026-08-25

### Changed

- Documentation improvements: clarified which channels the lead strips and which it reports, and reordered README content to describe the library's functionality before comparing it to classifiers.

## [2.47.7] - 2026-08-24

### Changed
- Consolidated the automated-review and review-findings gates into a single review-findings gate.
- Updated gate status links to reference their corresponding workflow runs for better traceability when status descriptions are truncated.

### Fixed
- Fixed CI gate status descriptions being rejected by GitHub.

## [2.47.6] - 2026-08-24

### Fixed

- Report the review-findings gate as a commit status instead of a check run.

## [2.47.5] - 2026-08-24

### Fixed

- Improved secrets detectors to better distinguish legitimate text patterns from actual secrets, enhancing detection accuracy for JWT shapes and other detector regex patterns.

## [2.47.4] - 2026-08-23

### Fixed

- **claude-hooks**: Corrected wiring checks to use `/hooks` endpoint instead of path grep, and now point checks at the hook config rather than the entire `~/.claude` tree.
- **claude-hooks**: Extended wiring check to recognize hooks in installed plugins' `hooks.json` files.
- **claude-hooks**: Added a dedicated check command for wiring cause in gap notices and properly named the CLI version floor in the InstructionsLoaded gap notice.

## [2.47.3] - 2026-08-23

### Fixed

- claude-hooks: forward the permission mode to PreToolUse host gates

## [2.47.2] - 2026-08-21

### Changed

- The grapheme segmenter is now built on first use rather than at import, reducing initial load time.
- Hook bundle compiled code is now reused between tool calls for improved performance.
- Updated threat model documentation to account for V8 compile cache under `CLAUDE_PLUGIN_DATA`.

## [2.47.1] - 2026-08-20

### Fixed
- Redacted values are now reported in left-to-right order for each line.

### Changed
- Improved performance of redaction splicing by processing each line's redactions in a single pass.

## [2.47.0] - 2026-08-19

### Added

- Export `applyLayer1WellFormed` function from the layer1 module, exposing the view transformation that the pipeline applies to models.

### Changed

- Refactored alert handling to use `applyLayer1WellFormed` for consistent well-formedness validation across the library.

## [2.46.0] - 2026-08-19

### Added
- Add `./layer1` subpath export so `applyLayer1` skips the HTML graph.

## [2.45.8] - 2026-08-19

### Changed

- Performance improvements to the secrets scanning engine with optimized line-walking behavior, field-value probe logic, and per-line invisible-character validation.

## [2.45.7] - 2026-08-19

### Fixed
- Prevent daemon teardown from masking the actual reason the daemon died.

## [2.45.6] - 2026-08-19

### Changed
- Performance improvements to the secrets engine: gated character stripping on ASCII checks, optimized regex matching to attempt matches only at valid positions, and refactored invisible character detection to use class scanning instead of character translation.

### Fixed
- Fixed empty invisible charset handling to return empty string instead of raising an error.
- Fixed word boundary preservation inside candidate windows during secrets detection.

## [2.45.5] - 2026-08-18

### Changed
- Improved performance of secrets scanning by probing payloads for each pattern's required literals before full scanning.

### Fixed
- Fixed multi-line required literal detection to correctly identify every line a literal can start on.

### Performance
- Made candidate-line probing linear in payload size.
- Optimized strip offset mapping to use deletion shift instead of one entry per character.

## [2.45.4] - 2026-08-18

### Fixed
- Secrets engine now fails loudly when a covered plugin supplies no denylist.

### Changed
- Improved performance of secrets scanning by skipping line processing when no plugin denylist can match it.
- Corrected compute-budget documentation comment's throughput claim.

## [2.45.3] - 2026-08-18

### Fixed

- Report the review-findings gate red instead of leaving it unreported.

## [2.45.2] - 2026-08-18

### Fixed

- Corrected hook timing reports to describe the redactor round trip as a window rather than attributing delays to the daemon's fault.
- Improved error messaging in hook timing to use "largest share" instead of "most" and added test coverage for error-path redactor timing.
- Hook wait times are now properly attributed to the redactor daemon by name in timing reports.

## [2.45.0] - 2026-08-18

### Changed

- **auto-resolve**: The resolver workflow is now called from its own dedicated repository rather than being invoked inline, improving separation of concerns and maintainability.

### Fixed

- **auto-resolve**: The resolver no longer receives a metered API key, preventing potential rate-limiting issues.
- **auto-resolve**: Restored protected-set coverage and removed orphaned composite configurations.
- **auto-resolve**: Added a permissions ceiling to the called workflow to enforce principle of least privilege.
- **auto-resolve**: Fixed RESOLVER_DIR documentation comment alignment.

## [2.44.1] - 2026-08-18

### Fixed
- Keep a session's own fallback findings and reap its scan markers to prevent stale data accumulation.
- Bound the session-less alert store so a stale finding cannot re-arm the gate.
- Stop a refused directory fsync from incorrectly reporting a write operation.
- Grant the review-gate the permission required for label removal operations.

### Changed
- Match the review-gate's SECURITY header to its updated permission set.
- Document the lock-before-marker ordering that the cold-start probe depends on.

## [2.44.0] - 2026-08-18

### Fixed
- Prevented race conditions where multiple sessions could simultaneously rebuild virtual environments by serializing provisioner operations.
- Fixed unsafe registry write operations by staging auto-update writes through atomic O_EXCL temporary files.
- Corrected doubly-wrapped redactor failure messages and improved wait handling in hooks.
- Improved Layer-2 reveal store isolation by keying it to the project for proper multi-tenant support.
- Fixed cold-start marker detection to use lock identity instead of reusable PIDs, improving reliability across sessions.
- Made redactor socket publishing atomic to ensure live daemons are never unlinked during service lifecycle.

### Changed
- Keyed instruction-file alerts and acknowledgements by session ID instead of reusable identifiers for better isolation.
- Enhanced TMPDIR store lifecycle management in hooks with age-out behavior for both stores.

## [2.43.12] - 2026-08-18

### Fixed

- Secrets scanning now enforces compute budgets during the scan phase and eliminates quadratic overlap detection that could cause performance degradation.
- HTML payload handling now properly flags paths chunked across separators and corrects overly permissive SAS name validation for blob detection.

## [2.43.11] - 2026-08-18

### Fixed

- Shape-test parameter names in HTML exfiltration detection to reduce false positives.
- Detect base64-encoded values with two-padding characters in bare exfiltration query parameters.

## [2.43.10] - 2026-08-17

### Changed
- CI now reviews each PR only once on open, not on ordinary pushes.

### Fixed
- Prevent duplicate review purchases when a push occurs during the first review.

### Removed
- Removed model-judged review-thread resolver and associated cost calculation logic.

## [2.43.9] - 2026-08-17

### Fixed

- **claude-hooks**: Corrected the slow-hook notice to attribute delays to the hook itself rather than the sanitizer, and removed the misleading cause description.

## [2.43.8] - 2026-08-17

### Fixed

- Slow hook CPU time is now accurately reported instead of being masked by sanitizer overhead detection on busy hosts.

## [2.43.6] - 2026-08-16

### Fixed

- Bundle parsing now correctly identifies runtime `require()` calls within bundled code.

## [2.43.4] - 2026-08-16

### Fixed

- redos-guard now refuses to resolve regexes built from mutable bindings, improving security against regular expression denial of service (ReDoS) attacks.
- redos-guard now analyzes regexes built from constants, not just string literals, providing more comprehensive ReDoS detection.

## [2.43.2] - 2026-08-16

### Added
- README now describes both fail-closed channels for tool output.

### Fixed
- Hook sandboxes no longer commit into the real repository during testing.
- Git location overrides are now stripped from guard-suite child processes.

## [2.43.1] - 2026-08-16

### Fixed

- Fix CI path gate to properly handle empty derived file lists.
- Fix CI diff-gate fetch to scope git's auth header to github.com, improving security and preventing credential leakage to other hosts.

## [2.43.0] - 2026-08-16

### Fixed
- Plugin now correctly checks node validity before applying hook-binary refusals.
- Secrets detection: removed cubic-backtracking regex patterns and fixed over-redaction of credential-named function calls.
- Plugin shell handler now correctly emits block decision in fail-closed PostToolUse mode.
- Plugin verifies hook binary's cryptographic digest and installation directory before execution.
- Layer 3 scanning now processes plain-text URLs and CSS values by shape rather than position.

## [2.41.4] - 2026-08-16

### Fixed

- Review gate now requires a non-empty body in addition to verifying the correct author.
- PR reviews from forks are no longer able to skip and approve their own review gates.

## [2.41.3] - 2026-08-16

### Fixed

- HTML sanitization now settles in a single pass for correctness.
- HTML coverage-ignore blocks are now properly respected for round-cap branches.

### Changed

- Performance improvements to HTML splice-offset remapping and scan/splice round management through bisection.

## [2.41.2] - 2026-08-16

### Fixed
- Warn about stale hook-binary manifests at commit time instead of blocking the commit or deferring the check to CI.

## [2.41.1] - 2026-08-16

### Fixed
- Empty hook stdin is now reported as its own distinct error instead of being conflated with a failed scan.

## [2.41.0] - 2026-08-16

### Added
- Report confusable look-alike hosts under a new `confusable-host` code in HTML reports.

### Fixed
- CI: Fixed escape sequence handling when fetching PR diffs for review input preparation.

## [2.40.5] - 2026-08-15

### Fixed

- CI: improved PR review input preparation by fetching the PR diff with curl instead of gh api, which resolves escape-sequence handling issues.

## [2.40.4] - 2026-08-15

### Fixed

- Improved PR review process to fetch diffs through the API, preventing escape sequences from blocking review operations.

## [2.40.3] - 2026-08-15

### Fixed
- Close review-found holes in the Secret Keyword redaction and bound the redaction span for more accurate secret detection.
- Fixed redaction span boundaries for the Secret Keyword detector to prevent over-redaction and ensure precision.

## [2.40.2] - 2026-08-15

### Added
- Literature-cited invisible-injection benchmark corpus for testing injection vulnerabilities.

### Fixed
- Escape raw control bytes in the injection corpus test source to prevent parsing issues.

## [2.40.1] - 2026-08-15

### Fixed

- CI now reports zero mutation shards instead of an ENOENT error when applicable.
- The `InstructionsLoaded` event in claude-hooks is now properly named in coverage notices.

## [2.40.0] - 2026-08-15

### Fixed

- Fixed PyPI publish workflow and backfilled the orphaned 2.38.0 release.
- Improved credential ladder handling in claude-pr-review to properly reach the metered rung.

## [2.39.0] - 2026-08-15

### Added
- Slow-hook notices now report payload size and triggering tool for better observability.
- Per-pattern regex flags are now preserved in the cross-line prefilter for secrets detection.

### Changed
- NpmDetector's whitespace bound has been widened to improve detection accuracy.

### Fixed
- Prefilter cache is now cleared on reconfiguration to ensure consistent secret detection behavior.

### Performance
- Redaction latency on large payloads has been significantly improved, reducing processing time from 7.4s to approximately 3.4s.

## [2.37.4] - 2026-08-14

### Fixed
- Auto-resolve now requires rewrite evidence before staging regenerated files, preventing spurious regeneration attempts.
- Auto-resolve preserves the merged-history guard on the default branch during conflict resolution.
- Auto-resolve correctly stages regenerated files to resolve generated-file conflicts.

### Changed
- Pre-push hooks now run concurrently for improved performance.

## [2.37.3] - 2026-08-14

### Added
- Opt-in metered Anthropic API key support as an additional tier in claude-run's authentication ladder.

### Fixed
- Disable the allowlist filter for secret redaction to prevent pragma comments from suppressing redaction.

### Changed
- Rename the metered-key secret to `FAR_ANTHROPIC_API_KEY` for consistency.

## [2.37.2] - 2026-08-12

### Fixed

- Context loading now correctly treats todos as storage items and judges nesting by the outermost tree structure.
- Event-blind report generation is now gated on a host-chosen load reason, preventing spurious reports in certain scenarios.
- Unlisted .claude directory reports are now only generated for host-chosen loads, not bulk context loads.
- Bulk .claude directory loads remain silent to reduce noise when loading as context.

### Changed

- Context scope handling has been refactored to derive from a single declarative kind table, improving maintainability.
- The InstructionsLoaded scan coverage is now bounded to only the kinds it fires for, making behavior more predictable.
- Documentation updated to clarify that the kind table carries non-context storage rows in addition to context rows.
- The loaded-instructions docstring in claude-hooks has been trimmed to comply with the 20-line cap.

### Added

- Auto-resolve regen rules added for both uv lockfiles.

## [2.37.1] - 2026-08-12

### Changed
- ANSI escape sequence handling now generates Python escape grammar from the JavaScript scanner for consistency across implementations.
- Improved ANSI escape sequence processing by refactoring the introducer class to use the shared charClass helper.
- Control-string abort set behavior is now explicitly pinned to ESC/CAN/SUB/LF/CR characters.

## [2.37.0] - 2026-08-12

### Fixed

- Fixed `claude-hooks` scan to correctly read the `InstructionsLoaded` file names instead of attempting to access a field that is never sent.

## [2.36.0] - 2026-08-12

### Added
- New `scan-loaded-instructions.mjs` module to scan instruction files as they load, rather than walking the tree at startup.
- New `invisible-report.mjs` module for reporting invisible character detection results.
- New test helpers `capture-stdout.mjs` for improved stdout capture without interfering with TAP streams.

### Fixed
- InstructionsLoaded coverage marker now keyed to the correct session.
- Host-seams marker now keyed to the session its events carry, improving session tracking accuracy.

### Changed
- Refactored auto-clean containment test to use the scope SSOT (Single Source of Truth).
- Instruction file scanning moved to load-time instead of startup tree walk, improving efficiency.
- Documentation updated to name the user-global `~/.claude` tree in lazy scan coverage.

## [2.35.0] - 2026-08-11

### Added
- Hook binaries can now run on a bun-compiled binary when the host environment has no Node.js available.

### Fixed
- Closed a time-of-check-time-of-use (TOCTOU) vulnerability in the hook-binary download process.
- Hook binaries now compile reproducibly regardless of the checkout path.
- Hardened the hook-binary provisioner and its release build process.

## [2.34.14] - 2026-08-11

### Changed

- Hooks now load Decision and EventKind from the /contract subpath, improving performance.

## [2.34.13] - 2026-08-11

### Added
- Node launcher now searches for Node.js outside the interactive shell's PATH, improving compatibility with non-standard installations.
- Added validation to identify and name Node.js versions that are too old for the plugin.

### Fixed
- Fixed degraded warning that incorrectly promised silence it could not keep.

### Changed
- Improved launcher documentation to state its rationale in present tense.

## [2.34.12] - 2026-08-10

### Changed
- Revised agent-sanitizer auto-update instructions.

## [2.34.11] - 2026-08-10

### Fixed

- Layer 2/3 sanitization now properly refuses to run when the time budget is already spent, and re-checks the budget before Layer 3.

## [2.34.10] - 2026-08-10

### Fixed

- ANSI control string escaping at line breaks to prevent incomplete introducers from affecting output
- Plugin wheel now builds reproducibly, independent of the builder's filesystem state
- Plugin engine components now built from the current tree instead of pinned published versions
- CI provenance gate now correctly includes `src/` and `python/` directories as build inputs

## [2.34.8] - 2026-08-10

### Changed
- HTML parse tree traversal now uses iterative walking instead of unist-util-visit for improved performance.

### Fixed
- Reduced blocking-hook latency on large documents in the invisible module.

## [2.34.7] - 2026-08-10

### Fixed

- Improved error reporting in hooks to clearly indicate what was cleaned up and provide guidance on verification.
- Stopped erroneously reporting nonexistent instruction files as unscanned.

## [2.34.6] - 2026-08-10

### Fixed

- Hidden runs can now be scanned without hitting regexp stack limits, even at sizes up to 8 MB.
- Run scan now correctly handles partial final chunks in invisible mode.
- Bundle entry pinning now uses tail reference instead of repo root to avoid aliasing issues.

## [2.34.5] - 2026-08-10

### Changed
- Confusables are now folded in a single pass rather than processing each finding separately, improving performance.
- Line counting for findings now proceeds forward from the current position instead of from the file start, reducing computation overhead.

### Fixed
- Test suite now properly gates latency checks for instruction scan and confusable fold operations.

## [2.34.4] - 2026-08-10

### Fixed
- Fixed CI sweep checks permissions and prevented review gates from aborting each other.

### Changed
- Review gates are now re-derived whenever review state changes and reconciled on a scheduled cron job.

## [2.34.2] - 2026-08-10

### Changed
- Stop scanning prompts with regex per code point for improved performance in the invisible module.

### Fixed
- Stand the latency gates down under the mutation run in tests.

## [2.34.1] - 2026-08-10

### Fixed
- `enable-auto-update`: gracefully handle refused temporary file cleanup instead of crashing <!-- allow-graceful: logs a warning and continues instead of crashing -->
- `enable-auto-update`: provide a pasteable command when registry write is refused
- `enable-auto-update`: gracefully handle refused registry write instead of crashing <!-- allow-graceful: logs a warning and continues instead of crashing -->

## [2.34.0] - 2026-08-10

### Added
- New `AGENT_SANITIZER_DISABLED_HOOKS` environment variable to selectively disable individual sanitizer hooks.

### Changed
- Plugin description in README is now sourced directly from plugin.json for consistency.

## [2.33.1] - 2026-08-10

### Changed

- Mutation shard membership and scopes are now derived automatically from shipped sources rather than manually listed, reducing maintenance overhead and improving consistency.
- Gate scope rationale is now documented once at each scope's definition point in configuration.

## [2.33.0] - 2026-08-09

### Added
- Git hooks now reject pushes that only re-land already-merged history
- Git hooks refuse to tear down a worktree that still holds uncommitted work
- Repository now declares generated artifacts for auto-resolution
- Dry-run-only oracle for detecting instrumentation failures in mutation testing

### Fixed
- Fixed sandbox helper escaping mutation scope in CI
- Git hooks now properly resolve the hook library with builtins and let fixtures follow the data
- Git hooks now find tools that session-setup installs for them
- Stale worktree registration is now contained to the worktree that caused it
- Test comparison now uses the SHIPPED generated module instead of the instrumented copy
- Sandboxed module paths are now correctly mapped back onto the real checkout
- Generated fail-open library is now paired correctly and scan count is re-pinned
- Invisible charset generation now emits byte-stable output that Prettier will not repack

### Changed
- Repository root resolution now uses a single sandbox-aware helper

## [2.32.3] - 2026-08-09

### Changed

- Updated README with agent-sanitizer installation steps

## [2.32.2] - 2026-08-09

### Fixed

- CI: Fixed guard-pair suite to use correct repository root instead of module root.
- CI: Fixed sanitizer installation order to run before GitHub script suites.
- CI: Fixed mutation.yaml path parsing to preserve comments in the paths list.

## [2.32.1] - 2026-08-09

### Added
- New skill-gates system for Claude hooks with dedicated gate types for plan, PR, and tests validations
- Support for safe-launch bootstrap wrapper around skill-gates hook
- New CI review gate with GitHub token authorization and status posting
- Review thread resolver for CI workflows
- Multiple library modules for hook I/O, skill gate logic, and path matching in CI scripts

### Fixed
- Fix skill-gate marker directory to be namespaced by UID to avoid conflicts
- Fix merge-queue review gate to include required statuses scope
- Fix derived-closure path gate misinterpreting grep failures as no-match verdicts
- Fix decide gate to be included in hook-lifecycle watched paths
- Fix review-thread resolver to properly resolve onto the token ladder

## [2.32.0] - 2026-08-09

### Added
- New guard-pair scanner implementations for data and Python files to improve guard verification.

### Changed
- Guard-pair map is now derived from tests instead of being manually maintained in configuration.

### Fixed
- Scheduled deletion's guard and missing tool naming issues in hooks.

## [2.31.6] - 2026-08-09

### Fixed
- Consume all five ECMA-48 control strings (SOS, PM, APC, DM, ST), not OSC alone, to properly handle a broader range of ANSI sequences.

## [2.31.5] - 2026-08-09

### Fixed

- Registration of the generated fail-open shell library now completes successfully so main health checks pass.

## [2.31.4] - 2026-08-09

### Fixed

- Fixed CI routing to properly handle post-merge failures that were not being reported.
- Fixed coverage hook-scope ratchet to work bidirectionally instead of one-directionally.
- Fixed automation layer linting so that it is no longer ignored.

## [2.31.3] - 2026-08-09

### Fixed

- The launcher now correctly gates on the hook verdict's shape rather than relying on stdout being non-empty.
- The generated fail-open posture library no longer includes a shebang line.
- The launcher now gates on the bundle's post-condition check instead of using `node --check` as a proxy.
- Layer 3's tool scope is now correctly declared as a partition instead of a silent fallthrough.

### Changed

- The fail-open shell posture is now generated from its JavaScript source of truth, ensuring parity between implementations.

### Removed

- Dropped stale `node --check` preflight references from plugin documentation.

## [2.31.2] - 2026-08-09

### Fixed

- HTML processing now correctly resolves hex colors and logical box properties during extent checks.
- Fixed border box validation to verify empty state before splicing zero-size elements.
- Secrets redactor no longer rewrites a security codebase's own source files.
- CLI sanitize command now forwards the complete sanitize result pinned against the Python client.
- Secrets engine now peels value terminators at the mint point instead of per gate, improving correctness.

## [2.31.1] - 2026-08-09

### Changed

- Skills workflow now requires an explore-plan gate before audit fan-outs.

## [2.31.0] - 2026-08-09

### Added
- New Layer-2 round-trip fuzz harness for whole-pipeline testing with keyed span identifiers.
- Fuzz coverage requirements for hook entry points.

### Changed
- HTML comment and hidden element splicing now uses round-trippable keyed placeholders instead of anonymous ones.
- Placeholder grammar and rehydration logic updated to support keyed Layer-2 placeholders.

### Fixed
- Gitleaks allowlist now reads both spelling variants to maintain compatibility.
- Test suite corrected to handle per-scope gitleaks allowlist tables.
- HTML_TAG_PRESENT documentation note corrected to reflect comment splicing behavior.

## [2.30.0] - 2026-08-09

### Added
- New warning when a reveal sidecar is dropped unvetted in claude-hooks.
- Distinct warning category for unparseable-HTML withholding in output.
- Layer-1 restoration capability for whole-file Writes of existing files, recovering stripped bytes from the rehydration layer.

### Changed
- The unparseable-HTML warning no longer promises a reveal sidecar will be provided.
- Improved hint handling in rehydrate when processing unreadable targets.

### Fixed
- Fixed hint-free Write propagation through rehydrate on unreadable targets.
- Corrected Write restoration through the claude-hooks layer pipeline and drop guard logic.

## [2.29.1] - 2026-08-09

### Fixed

- CI: Preserve PR-input report wording for flagged-not-neutralized status.
- CI: Prevent GitHub stderr from interfering with fork-of-self slug comparison.
- CI: Ensure review-findings gate clears even when auto-approval fails.

## [2.29.0] - 2026-08-09

### Added
- Named every placeholder and splice marker in the non-rehydrated-tool advisory for improved clarity and debugging.

### Fixed
- Fixed CI workflows to set up pnpm before installing the local sanitizer, ensuring proper dependency resolution.
- Fixed hooks to withhold only colliding fields when sanitized key names collapse, preventing unintended data loss.

## [2.28.3] - 2026-08-09

### Fixed

- Fixed manifest re-stamping during release to ensure the version is correctly updated and published.
- Fixed CI conflict resolver to properly handle fallback credentials.

## [2.28.2] - 2026-08-09

### Fixed

- CI sanitizer installation no longer runs the checkout's pnpm build.

## [2.28.1] - 2026-08-09

### Fixed
- CI: corrected repo-root lint behavior in the helper's post-merge shape.

### Changed
- Performance: memoized the env-value pre-gate regex to improve efficiency.
- Build: updated prettier configuration to ignore tool cache directories.

### Removed
- Removed the conformance corpus from shipping, streamlining the codebase.

## [2.28.0] - 2026-08-09

### Added
- Expose `exfilScan` on the facade for direct access to exfiltration scanning functionality.

### Changed
- HTML sanitization now implies the exfiltration scan unconditionally.
- Converge the PR-input script onto the unified `exfilScan` interface.

### Fixed
- Repair the sanitize-pr-input merge resolution and tier exfiltration findings as notes.

## [2.27.0] - 2026-08-08

### Changed

- Secret redaction layer is now opt-in; enable via environment configuration to activate hooks-based secret filtering.
- MultiEdit operations are now gated and require verification of redactor maps; placeholder writes are held until hook processing completes successfully.

### Added

- New threat model documentation outlining security considerations for the secret redaction system.

## [2.26.3] - 2026-08-08

### Added
- Added threat model documentation with dedicated Layer 4 section detailing security boundaries.
- Added comprehensive Python floor provisioning tests and reporting for operator clarity.
- Added partition guards for self-referential GitHub URLs across the codebase.

### Changed
- Updated README.md to reflect the real claude-hooks exports surface and maintain consistency with package mapping.
- Made release-age exclusion version-less in pnpm configuration to prevent staleness.

### Fixed
- Fixed plugin provisioning to report the accurate Python floor version to operators when provisioning fails.

## [2.26.2] - 2026-08-08

### Fixed

- Fixed propagation of real registry errors in automated engine-pin bump workflows.

### Changed

- Refactored view-map to brand file views with their offset space for improved type safety and consistency.

## [2.26.0] - 2026-08-08

### Added
- Severity tiers (warnings and notes) for every scanning layer's findings
- Timing instrumentation for SessionStart shell entry points and judge error path
- Claude Code context whitelist exported from the library for external use

### Fixed
- CI: retry the review-thread resolver past PAT rate limits
- CI: prevent pack-smoke from flagging types/src declarations as src/ leaks
- CI: anchor pack-smoke src/ scan and keep sanitize-pr-input on published API
- Hooks: preserve note-only tool results as flagged instead of cleaning them

### Changed
- Refactored scope handling to export Claude Code's context whitelist

## [2.25.0] - 2026-08-08

### Added

- Ship `/agent-sanitizer:enable-auto-update` flag to turn on auto-update for the sanitizer plugin.
- Install and auto-update the sanitizer plugin in this repository's sessions.

### Changed

- Auto-update for the sanitizer plugin is off by default; installers should enable it via the new flag.

## [2.24.2] - 2026-08-08

### Fixed
- Fixed credential guard execution in CI workflows and pinned security vulnerability scan configuration.

### Changed
- Removed metered API-key credential from the Claude authentication ladder in CI.

## [2.24.1] - 2026-08-08

### Changed

- Engine pin freshness is now managed by Renovate instead of custom CI scripts, with automated alerts when the pinned Node.js engine stops tracking the latest npm version.

## [2.24.0] - 2026-08-08

### Added

- Hook timing budget warnings: hooks that exceed their one-second budget now trigger a warning to help identify performance issues.
- Hook scan scope optimization: scanning now focuses only on `.claude` subdirectories loaded as context, improving performance.

### Fixed

- Incomplete CSI sequences in ANSI processing are now logged as notices instead of warnings, reducing spurious alerts.
- One-time provisioning is excluded from slow-hook timer measurements to avoid skewing performance metrics.
- Anchored blank fillers in invisible character carve-outs are now correctly handled during testing and validation.

## [2.23.2] - 2026-08-08

### Fixed

- Budget preserved blank fillers per script, not pooled
- Stop clipping word spaces out of long Braille and Korean text

## [2.23.1] - 2026-08-08

### Security
- Enforce a 3-day minimum release age on dependencies to reduce supply-chain risks.

## [2.23.0] - 2026-08-08

### Added
- Guard redaction placeholders against clobbering outside the Edit/Write path in the rehydrate module.
- Automated daily engine pin bumping via CI workflow.

### Fixed
- Hardened placeholder-clobber guards from review findings.

## [2.21.1] - 2026-08-08

### Fixed

- **guard-pairs**: Enumerate the syntax tree directly instead of shelling out to git, improving performance and reliability.

### Changed

- **guard-pairs**: Resolve guarded data using acorn parser instead of regex parsing for more accurate analysis.
- **guard-pairs**: Drop the ambiguity-ban pass cap to prevent stale bindings.
- **guard-pairs**: Remove the unreachable import-cycle stack guard and simplify the guard detection logic.

## [2.21.0] - 2026-08-08

### Changed

- Refactored layer implementation: Layers 1-3 are now implemented once internally, with sanitize operating as a facade over the unified implementation.

## [2.20.2] - 2026-08-08

### Changed

- Bumped pinned sanitizer engine to 2.20.0

## [2.20.0] - 2026-08-08

### Changed
- CI now enforces reachability of all `.github/scripts` files, surfacing abandoned scripts and clearing the backlog.
- Node dependencies are installed before pre-commit checks to enable proto-pollution linting.

### Fixed
- CI now discovers `.github/scripts` test suites automatically instead of requiring manual listing.
- Restored and structurally guarded the `claude-run` action's credential ladder.

## [2.19.8] - 2026-08-08

### Fixed

- Fixed code coverage annotations in view-map to properly exclude guard branches.
- Restored safety guard assertions in view-map that were previously replaced with unsafe casts.
- Consolidated duplicated warning prose in HTML output generation.
- Corrected Brahmic consonant detection by deriving tables directly from Unicode Character Database.
- Fixed guard-pair naming to support both pytest and Node.js test frameworks.
- Corrected file view construction in rehydrate module through branded carrier type.
- Fixed lone surrogate handling in output redactor and sanitizer to normalize surrogates consistently across all code paths.
- Ensured comprehensive string vetting in sanitizer return values and cached subtree reuse.
- Aligned warning messages across both Layer-2 and Layer-3 entry points.

### Changed

- Improved test daemon lifecycle to wait for active listening rather than just socket file existence.

## [2.19.6] - 2026-08-08

### Fixed
- HTML parser now correctly routes bare indented code blocks to the markdown branch.
- HTML-vs-markdown detection now uses the real tokenizer instead of a heuristic tag-line ratio for more accurate parsing.
- Python wheel CLI bundle is now self-contained.
- Secrets redaction no longer targets public endpoints; placeholder language support has been closed.

### Changed
- Test corpus enumeration for HTML now walks the tree instead of using git ls-files.

## [2.19.4] - 2026-08-08

### Fixed
- Fixed invisible character processing to judge each cluster's preserve caps on the run its own leading gap resets, and to derive Unicode script gates and charge the preserve budget per grapheme cluster.
- Fixed output layer to ignore non-string Layer-5 spans instead of hanging, and prevent Layer-5 span deletion from creating later span matches.
- Fixed hooks to report unreadable instruction files instead of discarding the scan, and close the confusable-fold ordering gap with unified failure posture.
- Fixed layer 1 ANSI/invisible strip iteration to a fixed point.
- Fixed HTML styling to read uppercase and escaped CSS units so hidden styles cannot be spelled past Layer 2.

### Changed
- Collapsed needle-splice implementations in view-map into one primitive.
- Dropped unused ANSI tokenizer re-export from layer1.

### Added
- Added comprehensive test coverage for layer pipeline, posture handling, scan coverage, HTML styling, layer 1 ANSI processing, and Unicode invisible character tables.

## [2.19.2] - 2026-08-08

### Fixed

- Fixed reading of pristine hook sources in the lazyImport registry contract.
- Fixed c8's `--src` roots derivation to use the include set and pin the gate floors correctly.

### Changed

- Scoped coverage, mutation and type gates to only what the package ships, reducing unnecessary test overhead.

## [2.19.1] - 2026-08-08

### Changed

- **Skills documentation**: Updated parallel-audit skill documentation to clarify read-only rule behavior with execute-to-confirm and make parallel-audit hunt eliminators by default.

## [2.19.0] - 2026-08-08

### Added

- Add `/agent-sanitizer:enable-auto-update` skill to enable marketplace auto-update functionality for the plugin.
- Document marketplace auto-update and manual refresh commands in plugin documentation.

### Changed

- Type-annotate the auto-update script for `tsc --noEmit` compatibility.
- Update plugin documentation to include the auto-update command in the install block.

## [2.18.1] - 2026-08-08

### Fixed

- Fixed release canary incorrectly reporting its own crash as a release finding.
- Fixed version pin synchronization in install scripts.
- Fixed health sweep timing to run after each scheduled job it reports on.
- Sweep the default branch nightly instead of every two hours for more efficient monitoring.

## [2.18.0] - 2026-08-07

### Added

- Re-alert every two hours while the default branch is red.

### Fixed

- Fix CI page-only workflow on ci-failure-notify pages.

## [2.17.1] - 2026-08-07

### Fixed

- Plugin manifest no longer advertises a fail-closed default behavior.
- Removed incorrect fail-closed claim from the marketplace entry.

## [2.17.0] - 2026-08-07

### Added

- Hook states that are only reachable on bug conditions now prompt to file an issue, improving bug detection and reporting workflows.

## [2.16.0] - 2026-08-07

### Changed
- PreToolUse hook degradation is now gated on the `AGENT_SANITIZER_FAIL_OPEN` environment variable for safer fail-open behavior.
- Hook stdout is now preserved byte-identical and fail-open ask fallbacks are rejected for more predictable hook execution.

### Fixed
- PreToolUse hook faults are now degraded to ask verdicts instead of hard blocks for improved resilience.
- Shell posture handling in exit scenarios now correctly survives backslashes and properly handles fail-open configurations.

## [2.15.0] - 2026-08-07

### Changed
- Claude Code hooks now fail open by default when they cannot run, rather than preventing execution.

### Fixed
- Fixed incorrect claim that output was suppressed when it was not suppressed.
- Reinstall remedy guidance is now included in fail-open warnings.

### Added
- New opt-in `AGENT_SANITIZER_FAIL_OPEN` posture knob for customizing hook failure behavior.

## [2.14.13] - 2026-08-05

### Fixed

- Remove superseded CI workflows that were causing cancellation conflicts with their replacements.

## [2.14.10] - 2026-08-05

### Fixed

- Stop Renovate from editing the hashed lock file; widen the lock guard to prevent unintended modifications.
- Lock the redactor's Python dependency tree with hashes for improved supply chain security.

## [2.14.9] - 2026-08-05

### Fixed

- Stop folding one-letter non-Latin words and genuine non-Latin text into ASCII confusables, improving accuracy for mixed-script content.

## [2.14.8] - 2026-08-05

### Changed
- Removed duplicate reviewer workflow from CI configuration.

### Fixed
- Regenerated the redactor zipapp plugin to ensure reproducible builds.

## [2.14.6] - 2026-08-05

### Fixed

- Fixed CI workflow step IDs that were dropped during template sync, and added guard to prevent regression.
- Fixed nightly-fuzz issue script to properly quote failing test names instead of coverage tail output.

## [2.14.5] - 2026-08-05

### Added
- Claude review workflow for automated PR analysis and approval decisions
- Automated conflict resolution workflow with self-review and retry logic
- New CI skills and rules documentation for Claude automation
- Threat model documentation with security layer details
- Support for Claude OAuth and reviewer hold management

### Changed
- README installation section now clearly documents setup steps and failure modes
- Threat model layer count corrected and sync rules documented
- Enhanced CI reviewer logic with template sync restoration

### Fixed
- Restored review thread query to unblock autofix push
- Fixed reviewer merge-lever contract settlement on threads
- Restored CI reviewer logic dropped by template sync
- Fixed local work clobbered by template sync

## [2.14.3] - 2026-08-03

### Changed
- Documented the Claude Code plugin installation method alongside the npm install instructions in the README.

## [2.14.2] - 2026-08-03

### Fixed
- The published version number is now correctly stamped into the Claude Code plugin manifest during release.

## [2.14.1] - 2026-08-01

### Fixed
- Claude hooks shared state now fills in missing slots when a host root object omits them, preventing gaps in the derived defaults.

## [2.14.0] - 2026-08-01

### Added
- claude-hooks: hosts can now share a single lazy-module registry across multiple hook-io instances.

### Fixed
- claude-hooks: all four host-visible hook-io slots are now shared, instead of only two.

## [2.13.0] - 2026-08-01

### Changed
- Advanced the pinned plugin engine version and removed the second (redundant) hook matcher, simplifying hook matching behavior.

## [2.12.0] - 2026-08-01

### Fixed
- Fixed non-secret exclusion matching in claude-hooks to only apply at name boundaries, preventing unintended matches within longer variable names.
- Claude-hooks now uses the package's own credential matcher to decide credential names, improving consistency of detection.

## [2.11.0] - 2026-08-01

### Added
- Claude hooks now support a host registry that drives env-bound secret configuration, and the missing-package remedy message is host-configurable.

### Fixed
- Claude hooks now validate the env-config host source lazily and completely, avoiding premature or partial validation errors.

## [2.10.1] - 2026-07-31

### Changed

- fix(layers): stop Layer 1 and Layer 2 deleting text a reader can see
- fix(secrets): stop two paths that forwarded credentials in cleartext
- docs: release 2.10.0 [skip ci]

## [2.10.0] - 2026-07-31

### Changed

- fix(claude-hooks): keep a throwing host trace sink from aborting a hook
- feat(claude-hooks): let a host supply the trace sink and the hookgate marker
- docs: release 2.9.1 [skip ci]

## [2.9.1] - 2026-07-31

### Changed

- fix(claude-hooks): guard both prompt bindings, reach the third gate's remedy
- fix(repo): stop shipping a packed tarball in the published tree
- fix(claude-hooks): give the prompt gate a real load error and a host remedy
- docs: release 2.9.0 [skip ci]

## [2.9.0] - 2026-07-31

### Changed

- test(claude-hooks): compose the three seams the way a real host would
- test(claude-hooks): pin the last marker-path case to an explicit argument
- fix(claude-hooks): stop a partial reason table from failing the gate OPEN
- refactor(claude-hooks): move the cold-start wait into hook-io, name it for what it waits on
- feat(claude-hooks): let a host inject its own fail-closed reasons and deny gates
- docs: release 2.8.0 [skip ci]

## [2.8.0] - 2026-07-30

### Changed

- feat(ci): give claude-run the six-credential OAuth ladder
- docs: release 2.7.2 [skip ci]
- fix(ci): raise every agent model to at least Sonnet 5, and make the gh stub reject --slurp with --
- fix(ci): stop the review trigger from failing closed on every push
- ci(node-tests): install the sanitizer before the PR-review script tests
- fix(ci): route claude-run's model input through claude_args
- fix(ci): fail the PR reviewer when its agent run errored, and drop a dead model input

## [2.7.2] - 2026-07-30

### Changed

- fix(release): tag the published SHA so a raced merge still releases

## [2.7.1] - 2026-07-30

### Changed

- fix(secrets): read URL userinfo with the URL parser, not a user:pass@ regex

## [2.7.0] - 2026-07-30

### Changed

- test(secrets): assert the linearity bound by count, not by wall clock
- feat(secrets): export the credential-name matcher, not just the vocabulary

## [2.6.0] - 2026-07-30

### Changed

- fix(hooks): repair the merge-dropped comma and rename the guard-pair map
- fix(ci): make the gate script executable and stop tracking gh CLI state
- feat(ci): gate merges on unresolved review findings instead of a minted approval

## [2.5.0] - 2026-07-30

### Changed

- feat: publish the claude-hooks composition surface as typed subpaths

## [2.4.1] - 2026-07-30

### Changed

- docs(readme): cut the README by a quarter and unbury the examples

## [2.4.0] - 2026-07-30

### Changed

- fix(ci): drop the claude-hooks coverage floor, which cannot fail for its stated reason
- feat: publish the Claude Code hooks as agent-sanitizer/claude-hooks

## [2.3.0] - 2026-07-30

### Changed

- feat(plugin): announce prompt-gate engagement on the trace channel
- test(plugin): revert the deliberate red; isolate the live-engine socket
- test(plugin): deliberate red to observe node-tests-passed fail
- feat(plugin): ship the redaction engine as a committed zipapp
- chore(plugin): regenerate dist for the pinned engine
- test(plugin): dist-only corruption to observe node-tests-passed go red
- chore(plugin): regenerate dist for the pinned engine
- test(plugin): corrupt the bundle to observe node-tests-passed go red
- fix(plugin): inline the JSON data css-tree requires at runtime
- fix(ci): commit the lockfile the bundle's reproducibility gate depends on
- fix(plugin): commit the bundle the .gitignore was swallowing
- fix(plugin): drop JSONC comments from tsconfig.hooks.json
- chore(plugin): drop unused shebangs and mark the dist autofix never-required
- chore(plugin): ship the Claude Code plugin from this repo

## [2.2.2] - 2026-07-30

### Changed

- fix(secrets): stop a lone PEM header from redacting the rest of the file

## [2.2.1] - 2026-07-30

### Changed

- docs(skills): carry the current-head rule into the update-after-commits skeleton
- docs(skills): trim the current-head rule to substitutions, not additions
- docs(skills): require PR bodies to state the current head, never their own history

## [2.2.0] - 2026-07-30

### Changed

- test(secrets): name the dedup test for what it asserts
- feat(secrets): publish the credential-noun vocabulary as a shared export

## [2.1.0] - 2026-07-29

### Changed

- test(ci): strip every pnpm from PATH and assert the absent-tool premise
- fix(ci): seed lockfile regeneration from the base side and scrub credentials
- style(ci): apply shfmt case-indent formatting to auto-resolve-lib
- feat(ci): auto-regenerate conflicted lockfiles instead of refusing them

## [2.0.3] - 2026-07-28

### Changed

- fix(ci): stop the zizmor hook failing closed on an unreachable advisory API
- fix(ci): restore the executable bit on version-bump.sh
- fix(release): name the tag that actually released HEAD when skipping
- test(release): cover a re-run against an already-released SHA
- fix(release): skip re-runs against an already-released SHA

## [2.0.1] - 2026-07-28

### Changed

- fix(secrets): make unknown assignment operators fail wholesale, never partially match
- fix(secrets): stop redacting shell parameter-expansion defaults and secret-location fields
- ci: print PyPI's rejection reason on publish failures
- fix(hooks): stop tag pushes from rebuilding the whole pre-commit suite
- fix(ci): give the conflict resolver uvx so the pre-push hook can run
- ci: approve with the org PAT in the reviewer-hold clear paths
- style: apply prettier
- ci: source the org PAT (TEMPLATE_SYNC_TOKEN_ORG) in every workflow

## [1.47.14] - 2026-07-23

### Changed

- test(ci): stop leaking GITHUB_REF_NAME into the release-race test, annotate rebase marker
- test(ci): drop incompatible template-synced version-bump test
- ci: skip pushed-range pre-commit run when a hook can't be provisioned
- fix(ci): repair botched auto-merge of release-docs push logic
- fix(ci): rebase release-docs push when main advances mid-run
- docs: release 1.47.13 [skip ci]
- chore: resolve template-sync merge conflicts
- chore: sync from template repository (f2b22de)

## [1.47.13] - 2026-07-23

### Changed

- chore: resolve template-sync merge conflicts
- chore: sync from template repository (f2b22de)

## [1.47.11] - 2026-07-23

### Changed

- test(python): make the suite run on the 3.10 floor in CI
- fix(python): lower requires-python to 3.10 by removing 3.11-only regex

## [1.47.10] - 2026-07-22

### Changed

- style: satisfy ruff-format blank-line rule in test_template_sync
- fix(coverage): restore 100% — drop dead fill check, revert unreachable branches
- fix(html): measure query from parsed.search; keep meta-refresh ;-query tail
- fix(instructions): cleanFile null signal, temp cleanup on rename fail, CLI cwd
- refactor(prompt): drop dead SGR-only conjunct and correct its false comment
- fix(output): normalize lone surrogates on the Layer-5 re-redact path
- fix(html): kill same-color false positives, multi-arg scale collapse, base64url beacon

## [1.47.9] - 2026-07-21

### Changed

- ci: use TEMPLATE_SYNC_TOKEN_ORG as the primary template-sync token

## [1.47.8] - 2026-07-21

### Changed

- ci: add TEMPLATE_SYNC_TOKEN_ORG as template-sync token fallback

## [1.47.7] - 2026-07-21

### Changed

- ci: re-exec template-sync from immutable copy and add self-overwrite regression test

## [1.47.6] - 2026-07-21

### Changed

- docs(gates): call the SECRET_HINT drift guard what it is
- test(gates): pin SECRET_HINT pre-gate to the detect-secrets SSOT
- refactor(html): parse hidden-style CSS with css-tree instead of hand-rolled tokenizer

## [1.47.5] - 2026-07-21

### Changed

- test(html): exclude the static NAMED_COLORS table from mutation
- fix(html): close browser-honored hidden-content detection gaps

## [1.47.4] - 2026-07-21

### Changed

- fix(security): replace unverified webi curl|sh bootstrap with pinned, verified installs
- chore(lint): ignore the uv-managed .venv in eslint
- docs(claude): check open PRs before fixing a red main
- ci: add a daily release canary that alerts on npm/tag/changelog drift
- chore(hooks): run paired SSOT guard tests at commit time; warn on skipped lint-staged
- test(redos): extend the static ReDoS guard to every src/*.mjs regex
- fix(html): detect hidden styles whose property name is CSS-escaped

## [1.47.3] - 2026-07-21

### Changed

- style: satisfy eslint/prettier on mutation-kill tests
- test(rehydrate): kill surviving mutants in hidden-span and placeholder guards
- test(output): kill surviving mutants in filter-enum and value-walk paths
- test(instructions): kill surviving mutants in decode/scan/TOCTOU paths
- test(invisible): kill surviving mutants in range/joiner boundary checks
- test(gates): kill surviving mutants in secret/markdown gate regexes

## [1.47.2] - 2026-07-21

### Changed

- test(ci): match release-token guard to the org ruleset-bypass form
- refactor(instructions): drop now-unused stripInvisible test import
- refactor(instructions): drop dead cleanFile return-null branch

## [1.47.0] - 2026-07-21

### Changed

- style(textstrip): collapse monkeypatch call to one line
- fix(textstrip): union pinned charset with live Cf so neither Unicode skew under-strips
- style(textstrip): apply ruff-format to test module
- feat(textstrip): add stdlib-only ANSI+invisible strip for no-Node consumers

## [1.46.0] - 2026-07-19

### Changed

- ci: run template sync daily instead of weekly (#152)
- ci: notify on Sync from Template workflow failures (#151)
- fix(ci): read the Claude key from GH_ACTION_ANTHROPIC_API_KEY (#150)
- fix(ci): push release-docs + tag with the ruleset-bypass org token
- style(secrets): ruff-format the metavariable parametrize table
- fix(invisible): tighten the tag/joiner/selector carve-out against smuggled invisibles
- style: apply prettier
- test(rehydrate): cover the unclosed foreign-placeholder deny branch
- fix(rehydrate): fail closed on preserved payloads, foreign placeholders, and unsorted pairs
- fix(invisible): pin the Cf charset cross-language so JS and Python strip an identical set
- fix(secrets): drop plaintext-value cache, propagate __exit__ errors, unblock daemon loop
- refactor(secrets): drop passphrase-common metavariable tokens
- fix(secrets): skip lowercase metavariables, timestamps, and versions
- fix(secrets): treat documentation sentinel values as placeholders
- fix(secrets): stop redacting bare credential-noun words as secret keywords
- fix(ci): base the auto-publish bump on the highest live version, not the lagging latest tag
- feat(output): surface Layer-2 reveal (pre-splice text) from sanitizeText and sanitizeValue
- ci: notify via ntfy when a build or publish workflow fails (#138)
- fix(ci): drop unworkable pnpm cache in setup-base-env (lockfile is gitignored)
- ci: fix pnpm cache write, pin pre-commit via uv, drop for-loop word-split

## [1.6.4] - 2026-07-01

### Fixed

- Expanded control character blocking to prevent all C1 control introducers in prompts, not just CSI and OSC sequences.

## [1.6.1] - 2026-07-01

### Added

- Added parallel-audit skill documentation.

## [1.6.0] - 2026-06-30

### Added
- CLI now supports `--help` and `-h` flags to display help information.

### Changed
- CLI now rejects unknown flags instead of hanging on stdin.

## [1.5.0] - 2026-06-30

### Added

- Add support for additional CSS techniques to hide elements: `content-visibility:hidden`, `filter:opacity(0)`, and two-axis offscreen translate.

## [1.4.10] - 2026-06-30

### Fixed
- Reject non-ASCII fold and out-of-range index in confusables to prevent input corruption.
- Strip the whole C1 control block so DCS/SOS/PM/APC strings can't survive in layer1.

## [1.4.9] - 2026-06-30

### Changed

- Raise the supported Node.js floor to >=22

## [1.4.6] - 2026-06-30

### Changed

- CLI now assembles worker input lines with improved performance (O(n) instead of O(n²)).

## [1.4.5] - 2026-06-30

### Added

- Added audit-and-parallelize skill for verified hunt-and-fix audits.

## [1.4.4] - 2026-06-30

### Added

- SECURITY.md is now included in npm tarball distributions
- Documentation of input size cap

## [1.4.2] - 2026-06-29

### Changed

- ci(hooks): add auto-fixing pre-push hook; strip README trailing whitespace
- chore(package): add author field for attribution

## [1.4.1] - 2026-06-29

### Changed

- Update README.md

## [1.4.0] - 2026-06-29

### Changed

- test(golden): re-record cross-language golden for the hex-dump hint
- feat(sanitize): point agents to a hex dump for Layer-1 stripped bytes

## [1.3.5] - 2026-06-29

### Changed

- fix(html): own-key named-color lookup so prototype values don't poison isHiddenStyle
- ci(mutation): shard the run across parallel jobs with aggregated gate
- perf(mutation): enable Stryker incremental mode with CI cache

## [1.3.4] - 2026-06-29

### Changed

- docs(readme): wrap THREAT-MODEL.md filename in code

## [1.3.3] - 2026-06-29

### Fixed

- Build types in prepare so git-dependency installs ship .d.mts files.
- Treat C1 OSC (U+009D) as a non-SGR introducer in isSgrOnly to fix invisible character handling.

## [1.3.2] - 2026-06-29

### Fixed

- HTML parser now fails closed on overflow and detects exponent/negative CSS and base64url exfiltration attempts.

## [1.3.0] - 2026-06-29

### Added

- Python client is now installable via `pyproject.toml`, with a README for setup and usage.
- Cross-language golden tests for process lifecycle validation across Python and Node.js implementations.

### Fixed

- Named regex group for grandchild-pid matching in test utilities.

## [1.2.16] - 2026-06-29

### Fixed

- Prompt classification now blocks 8-bit C1 CSI/OSC ANSI introducers to maintain consistent security with the sanitizer's ANSI detection.

## [1.2.15] - 2026-06-29

### Added
- SECURITY.md file documenting security policies and responsible disclosure.
- CONTRIBUTING.md file with contribution guidelines.
- GitHub issue and pull request templates to standardize submissions.
- Documentation for the ./view-map utility.
- Fuzz coverage testing with property-suite input domain validation against threat codepoints.
- Smoke test for pack-and-install with OS and Node version matrix coverage.

### Changed
- Improved release publishing to match npm publish-conflict errors by error code instead of stderr text matching.

### Fixed
- Instructions: exclusive temp write without symlink following, and reporting of mixed-encoding runs.
- Rehydrate: fail gracefully on empty old_string instead of throwing RangeError. <!-- allow-graceful: returns an empty result instead of raising RangeError -->
- Invisible: capped and flagged carve-out-preserved joiners to close zero-width covert channel.
- Dependabot configuration with cooldown settings across all ecosystems.
- Python-client CI matrix pinned to Node 22 for pnpm compatibility.

### Removed
- Unused bin/lib/retry.bash script.

## [1.2.10] - 2026-06-29

### Fixed

- CLI now correctly executes when launched through a `node_modules/.bin` symlink.
- Output handling improved with recursion depth bounding, cycle detection, and flagging of hidden characters in object keys.

## [1.2.8] - 2026-06-28

### Fixed
- Fixed npm package to stop shipping build artifacts, resolving issues with consumer installations.
- Fixed worker-mode buffering to respect the input size cap on a per-line basis.

## [1.2.6] - 2026-06-28

### Fixed

- HTML documents containing only processing instructions are now routed through the sanitizer correctly.

### Changed

- Documentation updated to prefer precision over recall in the detection layers.

## [1.2.5] - 2026-06-28

### Fixed

- Strip bogus comments in prose and value-gate keyword exfiltration parameters in HTML processing.

## [1.2.3] - 2026-06-28

### Fixed
- HTML text-hiding detection now catches more CSS techniques to prevent leaking of invisible text
- Layer1 processor now handles OSC payloads, strips zero-width combining marks, recognizes C1 SGR sequences, and caps joiner runs
- Instructions scanner now safely skips dangling symlinks in the working directory instead of aborting
- CLI/Python bridge is now hardened against hangs, crashes, and oversized input
- Instructions scanning is now contained to the working directory with symlink refusal and atomic writes

## [1.2.1] - 2026-06-28

### Fixed
- Fold search/list tool fields in confusables and fail loudly on scanner offset mismatch

## [1.2.0] - 2026-06-23

### Changed

- docs: rework README into a scannable entry-point table
- feat(cli): bridge classifyPrompt, sanitizeText, and instruction-file ops
- docs: compact the Non-JS pipelines README section
- fix(python): fork-safety, clearer errors, and transport fuzzing
- style: format cli.test.mjs with prettier
- fix(python): harden the persistent worker against stderr deadlock and leaks
- test: isolate session-setup git from ambient insteadOf rewriting
- feat(python): amortize HTML module-load via an auto-spun shared worker
- feat: add stdin/stdout CLI and Python client for non-JS pipelines

## [1.1.1] - 2026-06-23

### Changed

- ci(mutation): drop redundant fetch fallback in change gate
- ci(mutation): run Stryker as a required PR check
- test(mutation): kill surviving mutants with exact-assertion guards
- test(mutation): add Stryker mutation testing for src/*.mjs

## [1.1.0] - 2026-06-23

### Changed

- fix: bound ANSI_RE private-intro class to kill polynomial backtracking (CodeQL js/polynomial-redos
- feat: add agent-pipeline entry points (input, output, prompt, instructions, edit-repair)

## [1.0.4] - 2026-06-23

### Changed

- ci(format-autofix): skip cleanly when AUTOFIX_TOKEN is absent
- docs: generate changelog from commits, stop hand-editing Unreleased
- ci: auto-apply prettier on pull requests
- style: apply prettier to README
- test(types): typecheck the emitted declarations as a consumer
- fix(types): annotate SECRET_HINT regexes as RegExp

## [1.0.3] - 2026-06-23

### Changed

- ci: drop security-vulnerability-scan workflow
- ci: run security scan monthly instead of weekly
- ci: run template-sync weekly instead of daily
- ci: drop @claude responder, pin security scan to Sonnet

## [1.0.2] - 2026-06-23

### Changed

- fix(release): base version on the reachable tag, not the global highest
- docs: recommend opening a PR when work is complete; dedupe changelog
- fix(release): bump from max of npm and highest tag
- docs: release 1.0.1 [skip ci]
- fix(release): declare repository metadata for npm provenance
- ci(release): adopt punctilio auto-version flow
- docs(changelog): add fragment for version-update release rework
- ci(release): publish release without an explicit tag push
- Update README to format project title as code
- Update README by removing install and license sections
- ci: guard that a package.json bump ships its CHANGELOG section
- docs(changelog): roll changelog.d fragments into 1.0.1 section

## [1.0.1] - 2026-06-22

### Added

- `CATEGORY` (the stable `found` codes) and `CATEGORY_LABELS` (code→human-label map) exports, available from both the root and `./invisible` entries.
- `LINGUISTIC_SCRIPTS` is now re-exported from the root entry, matching the documented public surface.
- `typecheck` and `coverage` npm scripts, so the commands documented in the README resolve.

### Changed

- **BREAKING:** `found` (from `sanitize` and `stripInvisibleWithReport`) now reports **stable machine-readable codes** (`cf-format`, `variation-selectors`, `blank-fillers`, `ansi`, `lone-surrogates`, `html-comments`, `hidden-html`, `exfil-urls`) instead of human prose. Branch on these; display strings now live exclusively in `warnings` and in the new `CATEGORY_LABELS` map.

### Fixed

- Packaging: guard that the published tarball ships a `.d.mts` declaration for every `exports` subpath, so `agent-input-sanitizer`, `/html`, and `/invisible` resolve to real types under strict `checkJs` instead of silently falling back to untyped `.mjs` (the `v1.0.0` regression).

## [1.0.0] - 2026-06-22

### Added

- Layer 1 (`./invisible`, zero runtime deps): strips payload-capable invisible Unicode—format `Cf` characters, variation selectors, blank-rendering fillers, soft hyphens, interior BOMs, and Unicode tag characters—plus ANSI/SGR escape sequences, while preserving ZWNJ/ZWJ where an orthography requires them.
- Layer 2 (`./html`): byte-preserving splicing of human-invisible HTML—comments, CSS-hidden and attribute-hidden elements—reporting scripting/resource tags without removing them.
- Layer 3 (`./html`): detection-only reporting of data-exfil URLs in markdown links/images and HTML attributes.
- `sanitize` convenience entry point plus the `./invisible` and `./html` subpath exports.
