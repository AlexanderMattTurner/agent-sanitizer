# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to
adhere to [Semantic Versioning](https://semver.org/).

<!-- Do NOT hand-edit this file. On push to main the auto-version workflow drafts the next release's notes from the Conventional Commit subjects since the last tag, then promotes "## Unreleased" to a dated version section. Your commit messages are the source of truth — keep the empty "## Unreleased" heading below in place. -->

## Unreleased

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
- Rehydrate: fail gracefully on empty old_string instead of throwing RangeError.
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
