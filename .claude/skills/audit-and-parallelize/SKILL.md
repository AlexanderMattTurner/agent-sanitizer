---
# prettier-ignore
name: audit-and-parallelize
description: >
  Runs a broad "find as many issues as you can" audit by fanning out read-only subagents over
  disjoint surfaces, VERIFIES every finding against the real code before trusting it, then turns
  the survivors into a set of small, file-disjoint parallel PRs. Activate when the user asks to
  "audit this", "find security/robustness/UX issues", "find dozens of problems", "do a deep review
  and fix everything", or any broad hunt-and-fix request that should fan out across the codebase
  and land as multiple PRs. Distinct from peer-review (which reviews a pending diff): this audits
  an entire codebase from scratch and plans the fixes.
---

# Audit & Parallelize Skill

Codifies the discipline for an open-ended "find lots of issues and fix them" request. The failure
mode it exists to prevent: **subagents over-report.** A fan-out of explorer agents will confidently
return "critical" security findings that evaporate the moment you read the cited code. Planning
fixes off unverified findings wastes effort, manufactures noise, and — in a detection/security
codebase — risks "fixing" correct, hardened code into something worse.

The non-negotiable rule: **every finding is false until the code proves it true.**

## Workflow

### 0. Plan the partition before spawning anything (`explore-plan` gate)

The surfaces you hand the agents are load-bearing: a gap means a whole area goes unaudited, a
double-claim wastes two agents on the same files, and either defect multiplies across the fan-out.
Run the `explore-plan` loop first — explore the tree (`git ls-files`, open PRs, the project's own
invariants), write the partition and doctrine lenses down, self-critique it as a hostile reviewer,
and fix what that finds. For a repo large enough to need more than ~3 agents, have a read-only
`Plan` agent attack the partition too: it catches unowned dirs, generated bundles an agent would
burn its context reading, and surfaces several times the median size.

### 1. Fan out over disjoint surfaces

Launch 2–4 **read-only** subagents (`Explore`, or `general-purpose` for deeper traces) in a single
message so they run concurrently. Partition by surface so they don't overlap — e.g.:

- core logic / algorithms
- integration, I/O, CLI, language bridges
- tests, CI, packaging, docs

Give each agent the same explicit shape for findings: `file:line`, one-line defect, a **concrete
failure input/scenario**, severity, and true-bug-vs-improvement. Ask for a specific count
("aim for 15+") to push breadth, knowing you will discard most of it.

### 2. Verify before trusting — the core step

Re-read the cited code for **every** high/critical finding. Default each to _false_ and look for the
guard, the anchored regex, the catch-all branch, the existing test that already covers it. Cheap
verifications first (does the regex actually match the claimed bypass? is the field already
type-checked upstream? is there already an e2e test for this path?).

Record each as **CONFIRMED** (with the proof) or **REJECTED** (with why). Expect to reject the
majority, including most of the scariest ones. If verification deflates the audit, **that deflation
is the headline result** — report it honestly instead of padding the plan to hit a number.

### 3. Tier and prune

Rank survivors by confidence × severity. Drop precision-risky "recall" additions: a detector tweak
that adds a rare catch at the cost of false positives on legitimate input is usually net-negative —
prefer the false negative and say so.

### 4. Plan file-disjoint parallel PRs

Group confirmed fixes into small, single-concern PRs that touch **non-overlapping files**, so they
can be developed and merged in parallel without conflicts. Watch for shared, workflow-managed files
(changelogs, lockfiles) that must not be hand-edited. Each PR: its own branch off the latest default
branch, Conventional Commits, and a **proving test added before the fix**.

### 5. Critique the plan, then present

Before handing it over, attack your own plan: Is any "fix" actually changing intentional design?
Does any finding contradict a documented tradeoff? Are the PRs genuinely independent? Is the volume
honest? Surface these as a self-critique section rather than letting the reviewer find them. This
presentation is the ONE moment to batch every open question (design calls, scope judgments) —
concentrate them here, before implementation starts.

### 6. Execute without checkpointing

When the request includes fixing (or the user says to proceed), the whole confirmed-PR list is in
scope — land **every** PR without stopping to ask "should I continue / move on to the next one?"
The answer is always yes. A design choice that surfaces only mid-implementation gets a sensible
default and a `## Decisions made` entry in that PR's description (what came up, the default chosen,
what would change under the alternative) — logged for async review, not asked. Maintain a checklist
of the PR queue and tick each off as it opens, so progress is supervisable at a glance.

## Examples

**Input:** "Find dozens of security and robustness issues in this library, confirm them with
subagents, then make parallel PRs to fix them."

**Output:** Three `Explore` agents fan out over core / integration / tests-CI-docs and return ~60
findings. Verification rejects nearly every "critical" one (e.g. a claimed "U+009D escape survives"
is disproven by the catch-all branch in the splitter; a "secret-exposure" path is already guarded by
an upstream candidate check). ~5 real, mostly-minor issues survive (a doc file missing from the
package tarball, a single-Node CI matrix, an O(n²) buffer assembly). These become five file-disjoint
PRs, each with a proving test, plus a self-critique noting which "fixes" touch intentional design.

**Input:** "Audit the parser and fix what you find."

**Output:** One `Explore` pass (narrow surface → one agent) returns 12 findings; verification
confirms 2 (an unbounded recursion on nested input; an off-by-one on EOF) and rejects 10. Two PRs
land the two fixes with regression tests; the report states plainly that the other 10 were false
positives and why.

## Anti-patterns

- **Fanning out before the partition is reviewed.** The reads an agent wastes on someone else's
  surface — or the area nobody was given — are unrecoverable. Plan it, critique it, then spawn.
- **Trusting a subagent's "CRITICAL" label.** It is a hypothesis, not a result. Read the code.
- **Padding to a number.** If only five issues are real, plan five. The over-report is the finding.
- **One giant PR.** Disjoint PRs parallelize and review cleanly; a mega-PR serializes everything.
- **Checkpointing between PRs.** Pausing after each PR to ask "move on to the next?" stalls the run
  for hours of wall-clock waiting on a yes. Questions belong batched at plan delivery; after that,
  run the queue to completion.
- **Recall over precision in detectors.** A noisy new check that flags legitimate input trains
  operators to ignore the signal. When a heuristic can't cleanly separate payload from benign input,
  prefer the false negative.
