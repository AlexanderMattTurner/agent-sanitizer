# Handoff — guard-pair derivation and the eliminator-audit residue

Written at the end of a `/parallel-audit for eliminators` run. Everything below
was **measured on this tree**, not read off a comment. Where a comment in the
repo contradicts a number here, the comment is the thing that is wrong — several
already were.

Base commit for every measurement: `main` at `02e5ab8`, plus PR #281.

---

## 1. Status snapshot

| PR                         | Branch                          | State                                              |
| -------------------------- | ------------------------------- | -------------------------------------------------- |
| #278 detection layer       | `…-z04lfn-a-detection`          | **merged**                                         |
| #279 fail-open posture     | `…-z04lfn-b-failopen`           | **merged**                                         |
| #280 partition assertions  | `…-z04lfn-c-partitions`         | **merged**                                         |
| #281 red-main fix + naming | `…-z04lfn-d-guard-pairs`        | **merged**                                         |
| (this work)                | `…-z04lfn-e-derive-guard-pairs` | rebased onto `main`, carries only this file so far |

`…-e-derive-guard-pairs` was stacked on #281 (both rewrite
`test/guard-pairs.test.mjs` and `.hooks/run-guard-pairs.mjs`); #281 has merged
and the branch is rebased onto `main`, so it now stands alone.

### Incident this run is a reaction to

`test/guard-pairs.test.mjs` went red on `main` the moment #279 and #280 were
both in. #279 added `plugin/scripts/lib/fail-open.sh` + its parity test; #280
taught the guarded-data scan to see `.sh`/`.py` sources at all. #279 merged
first, so #280's branch never saw the file its own new scanner would find. Both
green on their own base, red together — a semantic merge conflict that
`RESOLVED_PATH_COUNT` (a hand-pinned number) is what caught.

#281 fixes it. **This task removes the class**: a hand-pinned count and a
hand-written map both stop existing.

---

## 2. The task: derive the guard-pair map

### 2.1 What the map is (name it correctly)

`.hooks/guard-pairs.json` is **not an SSOT**. It derives nothing. A pair says
"run this check when that file changes" — a guard over two things that must
agree. The file's own `$comment` has always said this; four sibling files
contradicted it until #281. Do not reintroduce the word.

### 2.2 Measured facts

69 pairs today. Every number below was produced by instrumenting the scanner in
`test/guard-pairs.test.mjs` (truncate the file at the first `describe(`, append
`export { analyzeModule, tracked, pairs, scanned };`, import it from a scratch
script — the technique is reproducible and how everything here was derived).

| Bucket                                                               | Count                   | Derivable?                                                                         |
| -------------------------------------------------------------------- | ----------------------- | ---------------------------------------------------------------------------------- |
| Already resolved by the scan today                                   | 50                      | **yes — pure cache, delete**                                                       |
| Module pairs that are _path-driven_ (a test spawns the file by name) | 7                       | **yes — the resolver already finds them; only the extension filter discards them** |
| pytest guards                                                        | 5                       | **yes — all use `REPO_ROOT / "…" / "…"`**                                          |
| Read through a `git ls-files` glob                                   | 1 (`fuzz-nightly.yaml`) | **yes, with glob support — decision below**                                        |
| Import-only modules                                                  | 4                       | **no — keep curated**                                                              |
| UCD generator inputs                                                 | 2                       | **no — keep curated**                                                              |

**63 of 69 become derived. 6 stay hand-written.** (Globs are in — see 2.5 — so
`fuzz-nightly.yaml` derives; before that decision it was 62/7.)

### 2.3 The 6 that stay, with the real reason

| Path                                             | Tests reaching it by import | Why it cannot be derived                                                                                                          |
| ------------------------------------------------ | --------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `src/ansi.mjs`                                   | **42**                      | deriving pairs it to a third of the suite                                                                                         |
| `src/invisible.mjs`                              | **42**                      | same                                                                                                                              |
| `src/instructions.mjs`                           | **9**                       | same                                                                                                                              |
| `.github/scripts/nightly-fuzz-issue.js`          | 1                           | import-only; a second importer would silently change its pair                                                                     |
| `scripts/data/DerivedJoiningType.json`           | —                           | generator input; only chain to a test is data → generator → generated module → importers, which lands back in the 42-test fan-out |
| `scripts/data/IndicSyllabicCategory.Virama.json` | —                           | same                                                                                                                              |

For these, "which test is the cheap guard" is a judgment, not a fact. That is
the same category as `NOT_GUARDED`, and it is fine — a 6-entry curated list with
reasons is a different animal from a 69-entry list pretending to be complete.

### 2.4 The defect behind the 7 path-driven modules

The scan runs two mechanisms: an **import graph** (`deps`) and a **path
resolver** (`refs`). `DATA_EXTENSIONS` excludes `.mjs` with this justification:

> a module that moves already fails loudly at import resolution

True of an _imported_ module. False of one a test **spawns by name**. These
seven are already found by `resolvePath` and attributed to the correct test,
then thrown away by the extension filter:

```
.github/scripts/main-health.mjs        -> main-health.test.mjs, failure-notify-roster.test.mjs
.github/scripts/npm-max-stable.mjs     -> npm-max-stable.test.mjs      (0 tests import it)
.github/scripts/set-plugin-version.mjs -> scripts/set-plugin-version.test.mjs  (0 tests import it)
claude-hooks/scan-invisible-chars.mjs  -> 4 suites
scripts/coverage.mjs                   -> shipped-gates.test.mjs
scripts/mutate.mjs                     -> shipped-gates.test.mjs
scripts/shipped-sources.mjs            -> mutation-shards.test.mjs, shipped-gates.test.mjs
```

Two of them are reached by **zero** tests through imports, so today they are
guarded only by a hand-typed line — exactly the failure mode the map exists to
prevent.

This is the identical defect #280 fixed for `.sh`/`.py`, surviving one file
extension over. Fix it the same way: split the module-extension gate into
_imported_ (excluded, with the accurate reason) and _named by path_ (derived).

### 2.5 Globs — DECIDED: teach them

Measured cost of every glob reader in the JS corpus:

| Reader                                         | Expands to          | Runtime    |
| ---------------------------------------------- | ------------------- | ---------- |
| `test/failure-notify-roster.test.mjs`          | 39 workflows        | 0.27 s     |
| `test/threat-model-layers.test.mjs`            | 55 sources          | 0.21 s     |
| `test/test-runner-partition.test.mjs`          | 129 test files      | 0.43 s     |
| `.github/scripts/script-reachability.test.mjs` | 175 `.github` files | 0.31 s     |
| `test/lint-scope.test.mjs`                     | automation tree     | **1.25 s** |

Worst realistic union (editing a `.github/` file) ≈ 2 s. Accepted. `lint-scope`
is the only one near the ~1 s-per-source budget; if it grates in practice, move
it to `NOT_GUARDED` with that as the reason rather than dropping glob support.

Note the shape: glob support adds ~400 derived edges. That is fine precisely
because nothing is hand-written — map size stops being a maintenance cost once
it is computed.

### 2.6 Deliverable

**New:** `.hooks/lib/guarded-data-scan.mjs` — the scanner extracted verbatim
from `test/guard-pairs.test.mjs` (currently lines ~26–576) and exported, so the
hook and the test share one implementation instead of the hook trusting a cache
of it.

**`.hooks/run-guard-pairs.mjs`:**

- derive at commit time (full scan measured at **0.83 s**, once per commit
  regardless of how many files are staged — cheaper than today's model in the
  multi-file case)
- union the derived map with the curated residue
- **fail loud** when a staged scannable file resolves to no tests and carries no
  excuse. Today a broken resolver silently runs nothing; that must become an
  error, not a shrug. This is the single most important behavioural change here.

**`.hooks/guard-pairs.json`:** shrinks from 69 pairs to 6, and absorbs
`NOT_GUARDED` / `NOT_MIRRORED` (moved out of the test) so the hook and the test
read one copy of the exclusions.

**`test/guard-pairs.test.mjs`:**

- import the extracted scanner
- **delete `RESOLVED_PATH_COUNT`** — it is the pin that cost us a red main, and
  once both sides are derived, comparing derived-to-derived is vacuous
- keep the named resolver probes (`join(gitRoot, …)`, module-relative,
  generator-exported, `exports`-map, self-read, dynamic-import, mirror
  extensions, root-helper). **These become the non-vacuity guard** and are now
  load-bearing at commit time, not just in CI
- re-point the "pins the pairings that actually broke main" test at the _derived_
  map instead of `pairs`

**New:** a Python-side `ast` walk (~60 lines) resolving `REPO_ROOT / "…" / "…"`
for the 5 pytest guards. Four resolve directly; `tests/secrets/test_secrets_detectors.py`
goes through a package constant (`_DETECTORS_JSON = D.DETECTORS_FILE`), the same
cross-module case the JS resolver already follows.

### 2.7 Verification

```bash
node --test test/guard-pairs.test.mjs          # 0.83 s, the derivation itself
node --test 'test/*.test.mjs'                  # 3473 passing on #281
uv run --extra dev python -m pytest tests/ -q
pnpm lint
```

Non-vacuity, and do all of these — every guard in this area has been vacuous at
least once:

1. Break the resolver (make `resolvePath` return `null`) → the probes must go
   red, and the hook must **error**, not silently run nothing.
2. Delete a curated pair → its test must stop being scheduled, and the partition
   must say so.
3. Stage a file with a fresh unguarded read → the hook must fail loud.
4. Revert the module-extension split → the 7 path-driven modules must vanish
   from the derived map and fail the partition.

### 2.8 Gotchas that will bite

- **Stryker instruments the files it mutates.** Any test asserting on the
  _syntactic form_ of a mutated file fails the dry run on a healthy tree — this
  took #279's shards red. `.hooks/lib/` is not in `.github/mutation-shards.json`
  today; if that changes, the extracted scanner must not be source-read.
- **No `.git` in the Stryker sandbox.** `test/guard-pairs.test.mjs` walks the
  tree instead of shelling to `git ls-files` for exactly this reason. Glob
  support must respect it — expand globs against the **walk**, not against
  `git ls-files`, or every mutation shard dies.
- **acorn becomes a commit-time dependency** of the hook. It already is
  transitively (the paired guard tests import it), but the hook must fail loud
  and legibly if it is missing, never fail open.
- **Pre-commit forbids depth-based repo-root discovery in Python tests** — use
  `tests/_helpers.REPO_ROOT`.
- **Do not hand-edit `CHANGELOG.md`** or bump `package.json`'s version.

---

## 3. Backlog — verified, unclaimed

### 3.1 Repo

1. **Four sync seams still unpaired.** Verified absent from the 69-entry map:
   `.github/tool-versions.sh` (version ↔ digest "bump TOGETHER", runtime check
   only); `post-merge-delta-review.sh` ↔ `remerge-diff-comment.sh` (mutual "MUST
   stay byte-identical" HTML markers); gate-script check-name ↔ workflow job
   `name:`; CLI `OPS` dispatch table ↔ Python entry points.
2. **Two dead config files.** `git grep` for `punctiliorc` and
   `mcp.json.example` outside the files themselves returns **nothing**.
3. **`config/auto-resolve-regen-rules.json` is absent.** `auto-resolve/lib.sh`
   documents that a consumer without one runs no regen pass, so absence is
   configured — but this repo declares ~10 generated artifacts. Deliberate, or a
   gap the allow-unsynced note launders? Needs a human decision, not a guard.

### 3.2 Meta

4. **Stryker dry-run vs source-shape assertions.** Confirmed class (it took #279
   red); the one instance is fixed and nothing prevents the next. Two tests read
   mutated sources today (`threat-model-layers`, `guard-pairs`) and are green
   because their assertions survive instrumentation — so a blanket "no test may
   read a mutated file" rule would be a false-positive machine, against the
   repo's own precision doctrine. **The eliminator is the real oracle:** run one
   _dry-run-only_ Stryker shard on PRs touching `test/**`. No mutants executed,
   catches the whole class.
5. **The review gate goes stale when a thread is resolved via the API.** Not a
   workflow bug — `pull_request_review_thread` is not a valid Actions `on:`
   trigger (the repo documents this in `claude-reviewer-hold-clear.yaml`), and
   `claude-review-thread-resolve.yaml` re-posts when _it_ resolves. The hole is
   an agent resolving directly: the gate stays red with nothing scheduled to
   unstick it. One line in `CLAUDE.md` — resolve by API ⇒ add
   `recheck-review-gate` — closes it. (This bit #279; the label fixed it.)
6. **Worktree teardown destroys staged work.** `git add -A`, then `git diff`
   reports nothing because the changes are _staged_, then
   `git worktree remove --force` takes them. Teardown should refuse when
   `git status --porcelain` is non-empty. Template surface (`.claude/`) → belongs
   upstream in `claude-automation-template`.
7. **Nothing stops a push that re-creates already-merged history.** The rule is
   prose in the system prompt and was violated this run from a stale local ref.
   A pre-push hook rejecting a push whose commits are all already contained in
   `origin/main` is precise and cheap — no heuristics, no false positives.

---

## 4. Working agreements this run established

- **Precision over recall** in anything detector-shaped, including these
  scanners: an unresolvable path yields _no_ entry rather than a guessed one. A
  wrong pair is worse than a missing one.
- **Name drift guards honestly.** "Contract test", "SSOT contract", "pinned to
  the SSOT" for a hand-kept second copy launders the smell. Say drift guard.
- **Every guard must be shown failing before it is trusted.** Every guard in
  this area has been vacuous at least once.
- **Don't believe the comments.** Three separate load-bearing comments in this
  tree were false: the `check-failure-notifier-coverage` hook that does not
  exist (in two files), and the module-extension rationale that conflates
  imported with spawned.
