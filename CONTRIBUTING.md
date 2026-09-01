# Contributing

Thanks for helping improve `agent-sanitizer`. This is a security library,
so the bar for changes to the detection and transform layers is high—read the
notes below before opening a PR.

## Setup

Use [pnpm](https://pnpm.io/) (not npm) for all package operations.

```bash
pnpm install   # installs deps and configures git hooks (core.hooksPath .hooks)
```

## Workflow

```bash
pnpm test      # the JS test suite under c8, then the per-scope coverage floors
pnpm lint      # eslint .
pnpm check     # tsc --noEmit (type-check)
pnpm format    # prettier --write .
```

The coverage and mutation gates are scoped to what the package **ships**:
`scripts/shipped-sources.mjs` resolves `package.json`'s `files` + `exports` +
`bin` into the checked `.mjs` set, and `scripts/coverage.mjs`,
`scripts/mutate.mjs` and `.github/scripts/expand-shards.mjs` all consume it.
Publish a new module and it joins both gates on commit — the shard matrix is
derived, not listed, so there is nothing to add to `.github/mutation-shards.json`
(which declares only which big files to chunk and how many whole-file shards to
spread the rest over). A module published outside every named scope prefix fails
`test/shipped-gates.test.mjs` instead of silently inheriting another scope's
floors. `src/` is held at 100%; `claude-hooks/` and `bin/` carry a separate,
lower ratchet that should only ever move up.

The mutation gate additionally covers `.hooks/lib/`, which ships to nobody but
derives the pre-commit guard-pair map — a resolver arm that quietly stops
resolving there means guard tests stop running with nothing red. That scope is
derived from the directory, so a new module in it joins the gate on commit. It
carries its own ratchet (`toolingScopeBreak`), same move-up-only rule.

The mutation shards run **once a day on `main`**, not on every pull request:
they mutate the whole tree rather than a diff, so a per-PR run re-answered the
same question at ~30 runners a time. A red nightly pages through
`ci-failure-notify.yaml`. To get the verdict on a pull request before it merges
— when you have changed a mutation-gated source or the tests that kill its
mutants — add the `ci:mutation` label, or dispatch the workflow by hand.

Run the tests, lint, type-check, and formatter before pushing. The git hooks
under `.hooks/` also enforce formatting and commit conventions on commit.

## Commits

Commits **must** follow [Conventional Commits](https://www.conventionalcommits.org/):
`<type>(<scope>): <description>`. The `commit-msg` hook rejects anything else.
Types: `feat`, `fix`, `refactor`, `docs`, `test`, `ci`, `chore`, `style`,
`perf`, `build`, `revert`. Use `!` (e.g. `feat!:`) for breaking changes.

Write each subject as a **user-facing release note**: the commit subjects since
the last release are the single source of truth for the version bump and the
generated changelog. Keep internal churn out of the notes by typing it as
`test` / `ci` / `refactor` / `chore`.

**Do not hand-edit `CHANGELOG.md` or bump `package.json`'s version.** On merge to
`main`, the `auto-version` workflow derives the semver bump from the commit
subjects, publishes to npm, promotes the `## Unreleased` heading to a dated
section, and tags the release.

## Code style and tests

- **Favor precision over recall in the detection/transform layers.** A false
  positive—mangling or splicing legitimate content—is a real harm, and noisy
  flags train operators to ignore the signal. When a heuristic can't cleanly
  separate a true payload from benign input, prefer the false negative and say
  so. Validate against the actual parser/tokenizer, not an approximation; fail
  _open_ (treat as benign) on input you can't resolve.
- **Fail loudly.** Throw on unexpected input rather than swallowing it; let
  exceptions propagate unless there's a specific, necessary recovery.
- **Pair every new detector with negative tests** over a corpus of legitimate
  inputs asserting zero findings, and pin structural invariants
  (idempotence, output-is-a-subsequence, never-throws on adversarial input) with
  property/fuzz tests (`fast-check`), not just hand-picked examples.
- Don't skip or weaken existing tests. Prefer exact-equality assertions.

## Pull requests

When a feature, fix, or refactor is complete, open a PR—keep it focused, explain
what changed and how you verified it, and fill in the template. Don't include
real secrets or tokens anywhere in the PR.

## Reporting vulnerabilities

For security issues, **do not open a public issue**—see [SECURITY.md](./SECURITY.md).
