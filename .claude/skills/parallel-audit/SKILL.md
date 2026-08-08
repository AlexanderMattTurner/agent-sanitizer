---
# prettier-ignore
name: parallel-audit
description: >
  Runs a broad, multi-dimension codebase audit by fanning out parallel read-only subagents
  (one per dimension x file-area), independently confirms their findings, then groups the
  survivors into a parallelizable multi-PR fix plan and self-critiques it before delivery.
  Activate when the user asks to "find dozens of issues", "audit the codebase", "find security/
  robustness/testing/UX deficiencies", "use subagents to audit and confirm", "find bugs and missed
  opportunities", or "make a plan to fix all of these in parallel across multiple PRs". Distinct
  from peer-review (which reviews a pending diff) and security-review (single-pass, current branch):
  this audits the WHOLE codebase along several axes at once and ends in a vetted fix plan, not edits.
---

# Parallel Audit Skill

Codifies the "fan out, confirm, plan, critique" pattern for a wide audit of an existing codebase
along multiple quality axes (security, robustness, real-vs-stubbed test coverage, UX, missed
opportunities). The output is an **audit report + a multi-PR parallel fix plan + a critique of that
plan** — the skill itself ships no code changes beyond optional scaffolding the user explicitly asks
for. It exists because one agent reading a large repo serially is slow and shallow; N agents each
owning one dimension x area read deep, and an independent confirmation pass keeps the cheap-but-wrong
findings out of the plan.

**Default posture: hunt eliminators, not spot fixes.** See
[Eliminators, not spot fixes](#eliminators-not-spot-fixes) — it changes the agent prompt contract,
the ranking, and how PRs are clustered. Fall back to spot-fix reporting only when the user
explicitly asks for a list of individual bugs.

## When to use

- The user wants breadth ("dozens and dozens", "be creative", "across the whole thing") rather than a
  review of one diff.
- The codebase is large enough that serial reading would be shallow (many files / subsystems).
- The deliverable is a _plan_, not immediate edits.

## When NOT to use

- Reviewing a pending diff before a PR → `peer-review` / `code-review`.
- A single-pass security look at the current branch → `security-review`.
- Trivial / single-file questions — just read the file.
- **Overlaps `audit-and-parallelize`**, which advertises nearly the same activation surface. They are
  redundant and should be reconciled (disambiguated in both `description` blocks, or folded into one)
  — a cross-skill decision out of scope here. Until then: this skill is the **eliminator-posture**
  default (hunt bug _classes_); reach for `audit-and-parallelize` only when a caller explicitly wants
  the plain "list individual issues" pass. Same-request routing is otherwise a coin-flip between the
  two, so name which posture you want.

## Eliminators, not spot fixes

An **eliminator** is a structural change that makes an entire CLASS of bug impossible by
construction. "This line has an off-by-one" is a spot fix; "offsets are untyped so any of the 40
call sites can confuse a code-point index with a UTF-16 index" is the class. Report a spot fix only
when it is the visible symptom of a class you can name.

Hand each agent this catalog — it is what turns "look for bugs" into "look for the shape that keeps
producing bugs":

- **N parallel lists that must be hand-synced** → one derived source + a round-trip contract test.
  (Detector tables, ignore lists, export maps, layer rosters, version pins, doc counts.)
- **A hand-rolled approximation of a real parser** → use the real parser. Check whether it is
  _already a dependency_ — the half-adopted case (real parser for one branch, regex for the other)
  is common and worse than either.
- **An untyped value whose meaning is positional convention** → a branded/carrier type. Kills whole
  offset, coordinate-frame, and "already-sanitized vs raw" families at once.
- **A policy decided at N call sites** (fail-open/fail-closed, retry, escaping, error rendering) →
  one chokepoint the callers cannot bypass.
- **An invariant re-established only on the branch that needed it** → one `applyMutation`-style
  helper every mutating path goes through.
- **An implicit ordering contract stated in a comment** → a declared pipeline that enforces it.
  Comments that say "keep it in this order" are eliminator bait; grep for them.
- **A gate checked in one direction only** (rejects stale entries, never notices a missing one) →
  a partition assertion: `REQUIRED ∪ EXEMPT == the live surface`.
- **A quota/budget applied per-unit to something indivisible** → make the budget unit the cluster.

Per-finding contract for eliminator mode (replaces the plain finding shape in step 2):

`TITLE` · `FILE:LINE` · `CLASS ELIMINATED` (the category, plus how many current/latent instances you
can point at) · `SEVERITY` (rank by REACHABILITY in normal use, not scariness) · `EVIDENCE` (1-5
verbatim lines) · `WHY IT'S A DEFECT` (specific input → wrong outcome) · `ELIMINATOR` (the new shape
of the code, concretely) · `BLAST RADIUS` (files touched, S/M/L) · `TEST THAT WOULD CATCH THE CLASS`
(an invariant, not a symptom).

Ask for **counts**, not adjectives: "17 of 62 `.sh` files lack `set -u`, counted via `grep -L`" is
actionable; "several scripts are inconsistent" is not.

## Workflow

### 1. Map the territory (main session, fast)

Before spawning anything, get a lay of the land so agent scopes are _disjoint_: directory tree,
file-type counts, the key subsystems. Skim any `CLAUDE.md` / `CONTRIBUTING.md` / `SECURITY.md` —
their stated invariants ("fail closed", "post-condition not exit code", "host code runs on BSD too")
become the _lenses_ you hand each agent. An audit that knows the project's own doctrine finds
violations of it; a generic audit re-discovers lint.

### 2. Fan out — one agent per (dimension x area), all in ONE message

Pick axes from the request (typical: **security**, **robustness/error-handling**, **e2e-test
realness**, **UX/DX**, **supply-chain**, **config-SSOT/CI**). Give each agent a **non-overlapping
file list** so they don't collide or duplicate. Launch them **concurrently** (multiple Agent calls in
a single response). Use `general-purpose` (full read tools); they are **read-only on the repo — no
edits to files under audit**. They MAY execute code to verify a finding (run existing modules,
`node -e`, a throwaway `/tmp` script — see the run-the-code bullet below); "read-only" bars mutating
the tree, not running it.

Each agent prompt MUST demand, per finding, the eliminator contract from
[Eliminators, not spot fixes](#eliminators-not-spot-fixes). (In plain spot-fix mode, the reduced
shape is `TITLE` · `FILE:LINE` · `SEVERITY` · `EVIDENCE` · `WHY IT'S A DEFECT` · `SUGGESTED FIX`.)

And MUST instruct:

- **Ground every finding in real lines you read — do NOT speculate.** Skip anything you can't quote.
- **Run the code where you can — execute, but stay read-only on the tree.** An agent that runs the
  repro and pastes real output is worth five that reason from a read. Write repro scripts to a
  scratch dir outside the repo (e.g. `/tmp`); never edit a file under audit. Findings verified by
  execution survive the confirmation pass almost always; findings reasoned from a read are where the
  drops come from.
- **Hand each agent the project's own doctrine** (`CLAUDE.md`, `THREAT-MODEL.md`, `.claude/rules/*`)
  and ask "where does the code break its own stated rules?" A repo's written invariants are the
  richest eliminator seam — a comment saying "these must stay in sync" or "keep it in this order"
  is an unenforced contract, i.e. a class waiting to happen.
- **Self-flag non-findings**: if you checked something and it's actually correct, say so explicitly.
  (This is the honesty signal that tells you which agents to trust.)
- Rank by severity; aim for a target count (e.g. 6-12) so they prioritize over dumping noise.
  Prefer 6 excellent eliminators to 15 mediocre ones, and say so in the prompt.

Scope hygiene: **never delegate edits to `.claude/` or `.devcontainer/`** (sub-agent write guards
block them silently) — but read-only _audit_ of those dirs is fine. Keep load-bearing edits in the
main session later.

### 3. Survive the rate limit — resume, don't restart

A big fan-out often trips a transient server rate limit; an agent returns `0 tokens` after having
already done real reading. **Resume it with `SendMessage` to its `agentId`** ("continue where you
left off and emit your final findings") — this reuses its accumulated context instead of paying for
the reads again. Only fully restart an agent that died before doing any work (≈≤3 tool calls).

### 4. Confirm — independently, the high-severity items at least

The user asked to _confirm_ findings; do not rubber-stamp. For every **high/critical** finding (and a
sample of the rest), **open the cited file at the cited lines yourself** and check the claim holds.
Watch for: off-by-a-few line numbers, a comment that already addresses the concern, a guard one
function up that the agent missed, severity inflation. Drop or downgrade anything that doesn't survive
your own read. Record "confirmed by independent read" per kept finding. An agent that honestly
self-flagged its own non-findings (step 2) has earned lighter scrutiny than one that didn't.

**Prefer executing to re-reading.** Where the claim is about behaviour, build the repro and run it —
that is the difference between "confirmed" and "plausible". Keep a finding you could not execute in
a separate **plausible, not confirmed** bucket and say so in the delivered plan; do not let it claim
a PR slot until someone builds the repro. When a repro is cheap, build it during the audit rather
than deferring: two of this pattern's best findings only became credible once run.

Watch your own repro harness, not just the code: a repro that throws can be _your_ calling error
(a required accumulator parameter you omitted), not a defect. Re-read the signature before
reporting a crash as a finding, and correct yourself plainly if you already did.

Harness note: `Bash` rejects a command string containing a literal control character (e.g. a raw
ESC byte) — `InputValidationError`. That is the Claude Code input validator, not the code under
audit. Write the repro to a scratch file outside the repo (e.g. `/tmp`) with a heredoc and build the
byte in-language (`String.fromCodePoint(0x1b)`), rather than concluding the case is untestable.

For _very_ large audits, this confirmation pass can itself be a second fan-out of `code-reviewer`
agents, each adversarially trying to **refute** one finding — keep only those that survive.

### 5. Dedupe and cluster into parallel-safe PRs

Merge duplicates across agents (the same bug often surfaces from two lenses). Then group survivors
into PRs by the **disjoint-file-area** rule: two PRs can land in parallel only if they touch
**non-overlapping files** — that is the real constraint, not theme. A natural grouping:
one PR per subsystem (firewall, monitor, redaction, lifecycle, …), each bundling that subsystem's
findings. Note cross-PR ordering only where a real dependency exists (e.g. an SSOT change others build
on). For each PR: scope, the findings it closes, the **test that would have caught the class**
(per the project's testing doctrine — assert the invariant, not today's symptom), and a rough size.

In eliminator mode the disjoint-file rule bites harder, because eliminators are refactors and a
refactor's blast radius is wider than a spot fix's. Two eliminators in the _same file_ are
sequential even when their findings are unrelated — and the bigger one should land second, on top of
the small self-contained one, so the small fix is not held hostage. Before publishing the plan,
build the file→PR map and check for a file claimed twice; the natural "one PR per subsystem"
grouping does NOT guarantee it once a rewrite is in the mix.

**Cover every confirmed finding.** Build the finding→PR map explicitly and check for orphans: a
subsystem whose findings never got a PR slot is the easiest thing to lose between the audit and the
plan. If the count drifts past the number the user asked for, say so and add the PR rather than
silently dropping confirmed work.

### 6. Critique the plan, then deliver

Before handing over the plan, attack it: Are any "parallel" PRs actually file-conflicting? Is a
"high" severity really reachable, or gated behind an opt-in flag (lower it)? Does any fix need a
design decision (flag it **in the delivered plan** with a recommended default — never stop mid-audit
to ask)? Are there findings with no good test? Is the PR count realistic or should some merge?
Deliver the plan **with** this critique attached — the user asked to see it. The plan delivery is
the ONE moment to batch every open question; concentrate them there.

### 7. Executing the plan (when asked)

When the user says to proceed from plan to fixes, the whole PR list is in scope — work through
**every** PR without checkpointing. Never ask "should I move on to the next PR?"; the answer is
always yes. Any question you have belongs in the batch delivered with the plan (step 6), before the
first PR starts. A design choice that surfaces only mid-implementation gets a sensible default and a
`## Decisions made` entry in that PR's description (what came up, the default chosen, what would
change under the alternative) — logged for async review, not asked. Maintain a checklist of the PR
queue and tick each off as it opens, so progress is supervisable at a glance.

## Lessons baked in

- **Give each agent the project's own rules to check against.** A repo's `CLAUDE.md` usually states
  rules it tries to follow (e.g. "fail safe when something breaks", "this script also runs on Macs").
  Hand those rules to each agent and ask "where does the code break its own rules?" — that finds far
  more than a generic "look for bugs" pass.
- **Ask each agent to also say what it checked and found fine.** An agent that only ever reports
  problems might be inventing them; one that says "I looked at X and it's correct" is being honest.
  That tells you which agents to double-check.
- **If an agent runs out of quota mid-way, continue it — don't start it over.** Send it a follow-up
  message so it picks up from where it stopped; restarting makes it re-read everything from scratch.
- **Two pieces of work can run at the same time only if they touch different files.** True for the
  agents (give each its own files so they don't overlap) and for the fix PRs (so they don't clash when
  merging). Grouping by area usually does this for you.
- **Rank a problem by how easy it is to actually trigger, not how scary it sounds.** A "critical" bug
  that only happens when someone turns on a dangerous off-by-default option is really a minor one.
  Check the problem is reachable in normal use before calling it severe.
- **Ask "could a real parser do this?" as a standing question.** Hand-rolled scanners for HTML, CSS,
  ANSI, URLs, YAML, or a commit grammar are a reliable eliminator seam. Check the dependency list
  first: the repo often already ships the parser and uses it in _one_ place, which makes the
  half-adopted path the buggy one — and makes the fix cheap to argue for.
- **The best evidence is a pasted terminal transcript.** "One uppercase letter turns this detector
  off, here is the before/after table" ends the argument; a paragraph of reasoning invites one.
- **A doc-stated invariant with no enforcement is a finding in itself.** "These three must stay in
  sync", "keep this layer before that one", "documented so the omission is a choice" — each names a
  contract that only a test can actually hold. Grep the tree for that phrasing early.
- **Check open PRs before planning.** A fix may already be in flight; overlapping a sibling branch
  wastes the work and creates a conflict the disjoint-file rule was supposed to prevent.
- **Don't stop the queue to ask.** Mid-run design choices get a sensible default plus a
  `## Decisions made` entry. The one moment for questions is the plan delivery.

## Examples

**User says:** "Find dozens of security, robustness, testing, and UX issues. Use subagents and confirm
their findings. Then plan parallel PRs to fix them, and critique the plan."

1. Map the repo; pull the invariants out of `CLAUDE.md`.
2. Launch 8 read-only `general-purpose` agents in one message — firewall, redaction, monitor,
   lifecycle, e2e-realness, UX, supply-chain, config/CI — each with a disjoint file list and the
   structured-finding contract.
3. Six trip a rate limit mid-read; resume each via `SendMessage` to its `agentId`.
4. As findings arrive, open the cited lines and confirm the high-severity ones by hand; drop the two
   that a guard upstream already handles.
5. Cluster ~70 survivors into one PR per subsystem (non-overlapping files), each with the invariant
   test that would catch the class.
6. Critique: two PRs both touch `ip-validation.bash` → merge them; one "critical" is behind
   `--dangerously-skip-firewall` → downgrade. Deliver plan + critique.

**User says:** "…but look for ELIMINATORS, fixing entire classes of bugs, not spot fixes."

Same workflow, three changes:

1. Swap the finding contract for the eliminator one and paste the genre catalog into every agent
   prompt. Without the catalog, agents return spot fixes with the word "class" pasted on top.
2. Confirm by **executing**, not re-reading. Worked examples from a real run: one uppercase letter
   (`left:-9999PX` vs `px`) disabled a hidden-element detector; a nested `<p>` made the splicer
   delete visible text; padding a token with 12 zero-width spaces suppressed a homoglyph fold and
   the _next_ layer then erased the padding, delivering the un-normalized homoglyph downstream.
   None of those are believable as prose; all are decisive as a transcript.
3. Cluster with the wider blast radius in mind. Here, one file (`src/html.mjs`) hosted two
   eliminators — a small CSS-canonicalization fix and a full parser rewrite — so they became
   sequential, small first. Scope-lock each agent explicitly ("you own the CSS detectors; a sibling
   owns the tree walker in the same file") or they will collide.
