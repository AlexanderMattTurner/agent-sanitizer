// Turn the review agent's structured findings (review.json) into ONE GitHub PR
// review with inline, line-anchored comments plus a summary body — Greptile
// style — for `gh api` to POST.
//
// Each finding names a (path, line, side). A comment on a line that is not part
// of the diff makes the whole reviews API call 422, so this parses the
// (sanitized) diff to learn which (path, line) positions are actually
// commentable on each side and MOVES any unanchorable finding into the summary
// body instead of dropping it or poisoning the request. Line numbers survive
// Layer-1 sanitization (it edits within lines, never adds/removes them), so the
// sanitized diff is a faithful anchor source.
//
// Contract with the caller: prints `PAYLOAD` on stdout when it wrote a payload
// to post, or `SKIP` when there is nothing to post (missing/invalid review.json,
// or no findings and no summary). Diagnostics go to stderr.
import { readFileSync, writeFileSync } from "node:fs";
import { sanitize } from "agent-sanitizer";
import { readRunCost, formatDollars, plansLine } from "./lib-review-cost.mjs";

// The review text is MODEL output derived from the (untrusted) PR diff, so run
// every string bound for a posted GitHub comment through the same Layer-1
// sanitizer the diff went through on the way in — stripping invisible/format
// (Cf) characters and ANSI escapes so a hidden payload the model echoed from the
// diff cannot ride into the posted review. Layer 1 leaves visible bytes (code,
// markdown, emoji) untouched, so it never corrupts a legitimate suggestion.
async function scrub(text) {
  if (typeof text !== "string" || !text) return text;
  const { cleaned } = await sanitize(text, { html: false });
  return cleaned;
}

const dir = process.env.PR_INPUT_DIR;
if (!dir) throw new Error("PR_INPUT_DIR required");
const commitId = process.env.HEAD_SHA || "";

const payloadPath = `${dir}/review-payload.json`;
const summaryPath = `${dir}/review-summary.txt`;

function skip(msg) {
  process.stdout.write("SKIP\n");
  process.stderr.write(`::warning::${msg}\n`);
  process.exit(0);
}

// A compact cost footnote: the review's API-equivalent cost, plus (via
// plansLine) how many PRs/week that rate sustains on a Max 20x plan — the
// budget-relative signal a single percentage used to carry, in the form a reader
// actually reasons about. Emits a hidden `review-cost` marker so the Haiku
// thread-resolver can read this cost back and fold it into the running total.
function costFooter() {
  const { cost, model } = readRunCost();
  if (typeof cost !== "number" || !Number.isFinite(cost) || cost < 0) return "";
  const modelLabel = model ? ` (${model})` : "";
  const marker = `<!-- review-cost usd=${cost} -->`;
  const costLine = `<sub>📊 Review cost: **$${formatDollars(cost)}**${modelLabel}.</sub>`;
  return [marker, costLine, plansLine(cost)].filter(Boolean).join("\n");
}

let review;
try {
  review = JSON.parse(readFileSync(`${dir}/review.json`, "utf8"));
} catch (err) {
  skip(`no valid review.json from the reviewer (${err.message})`);
}

const findings = Array.isArray(review.findings) ? review.findings : [];
const summary = typeof review.summary === "string" ? review.summary.trim() : "";

// Every review posts as a COMMENT: the review event carries no merge consequence
// at all. What holds a merge is the review-findings STATUS gate
// (review-findings-gate.sh), which is red exactly while an unresolved reviewer
// thread carries a gating-severity finding — so the reviewer's whole lever over
// the merge is the inline threads it opens, never an APPROVE/REQUEST_CHANGES
// verdict. (review.json's `verdict` field is advisory prose the reviewer folds
// into its own summary; nothing here acts on it.)
const event = "COMMENT";

// Commentable (path, line) positions per side, parsed from the unified diff.
// Context lines are commentable on both sides; added lines on RIGHT, removed on
// LEFT.
const rightOk = new Set();
const leftOk = new Set();
// The first commentable RIGHT-side line per path, and the first overall — the
// synthetic-anchor ladder for a gating finding whose own anchor is not in the
// diff (nearest: its own file's first changed line; else the diff's first).
const firstRightByPath = new Map();
let firstRightOverall = null;
let path = null;
let oldLine = 0;
let newLine = 0;
for (const raw of readFileSync(`${dir}/diff.txt`, "utf8").split("\n")) {
  if (raw.startsWith("--- ")) continue;
  if (raw.startsWith("+++ ")) {
    const target = raw.slice(4);
    const m = target.match(/^b\/(.*)$/);
    path = m ? m[1] : target;
    continue;
  }
  if (raw.startsWith("@@")) {
    const m = raw.match(/@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (m) {
      oldLine = Number.parseInt(m[1], 10);
      newLine = Number.parseInt(m[2], 10);
    }
    continue;
  }
  if (path === null) continue;
  const kind = raw[0];
  if (kind === "+") {
    rightOk.add(`${path}\t${newLine}`);
    if (!firstRightByPath.has(path)) firstRightByPath.set(path, newLine);
    if (!firstRightOverall) firstRightOverall = { path, line: newLine };
    newLine += 1;
  } else if (kind === "-") {
    leftOk.add(`${path}\t${oldLine}`);
    oldLine += 1;
  } else if (kind === " ") {
    rightOk.add(`${path}\t${newLine}`);
    leftOk.add(`${path}\t${oldLine}`);
    if (!firstRightByPath.has(path)) firstRightByPath.set(path, newLine);
    if (!firstRightOverall) firstRightOverall = { path, line: newLine };
    oldLine += 1;
    newLine += 1;
  }
}

// The severity model's SSOT, shared with review-findings-gate.sh: this file
// renders each finding's icon from `icons` and stamps the hidden marker below,
// and the gate re-derives which severities gate the merge from `gating` in the
// same file — so the writer of the signal and its reader cannot drift apart.
const SEVERITY_CONFIG = JSON.parse(
  readFileSync(new URL("../../config/review-severities.json", import.meta.url)),
);
const ICON = SEVERITY_CONFIG.icons;
const icon = (sev) => ICON[sev] || "•";
// Severities that HOLD the merge. Excluding `nit` is what keeps 🔵 nits
// advisory: they post as review comments the author reads without the merge
// waiting on them.
const GATING_SEVERITIES = new Set(SEVERITY_CONFIG.gating);
// Normalized before ANY severity lookup: the severity now decides whether a
// finding gates the merge, so a cased or padded "Blocking" from the model must
// not miss GATING_SEVERITIES and spill a blocking finding into the body, where
// the gate cannot see it.
const normSeverity = (s) =>
  typeof s === "string" ? s.trim().toLowerCase() : "";

// The machine-readable severity, stamped hidden on every inline finding: the
// merge gate reads this marker off an unresolved thread's ROOT comment to decide
// whether that thread gates the merge (the leading icon is only its pre-marker
// fallback). Only a KNOWN severity is stamped — an unknown one would teach the
// gate a severity the config does not carry, and it renders as the "•" fallback
// above precisely because it is not part of the model. `scrub` runs with
// `{ html: false }`, so Layer 2 never splices this comment back out.
const severityMarker = (sev) =>
  ICON[sev] ? `\n\n<!-- severity: ${sev} -->` : "";

// A `suggestion` renders as a GitHub suggested-change block the author can apply
// with one click. Suggestions can only target the new file (RIGHT side), so a
// finding carrying one is forced RIGHT. A fence longer than any run of backticks
// in the suggestion keeps code containing ``` from breaking out of the block.
function suggestionBlock(text) {
  const longest = Math.max(
    0,
    ...(text.match(/`+/g) || []).map((run) => run.length),
  );
  const fence = "`".repeat(Math.max(3, longest + 1));
  return `\n\n${fence}suggestion\n${text}\n${fence}`;
}

const commentableRight = (p, l) => l !== null && rightOk.has(`${p}\t${l}`);

const comments = [];
const spill = [];
for (const f of findings) {
  const detail = [f.title, f.body].filter(Boolean).join(" — ").trim();
  if (!detail) continue;
  const sev = normSeverity(f.severity);
  const line = Number.isInteger(f.line) ? f.line : null;
  const hasSuggestion =
    typeof f.suggestion === "string" && f.suggestion.length > 0;
  const side = hasSuggestion || f.side !== "LEFT" ? "RIGHT" : "LEFT";
  const ok = side === "LEFT" ? leftOk : rightOk;

  if (f.path && line && ok.has(`${f.path}\t${line}`)) {
    const comment = {
      path: f.path,
      line,
      side,
      body: `${icon(sev)} ${detail}`,
    };
    // Multi-line suggestion/anchor: keep it only when the whole RIGHT-side range
    // is in the diff, else GitHub 422s the review.
    const start = Number.isInteger(f.start_line) ? f.start_line : null;
    if (
      start &&
      start < line &&
      side === "RIGHT" &&
      commentableRight(f.path, start)
    ) {
      comment.start_line = start;
      comment.start_side = "RIGHT";
    }
    if (hasSuggestion && side === "RIGHT")
      comment.body += suggestionBlock(f.suggestion);
    // After the suggestion block, so the marker is its own trailing line and
    // never lands inside the fence — the gate matches it as a WHOLE line.
    comment.body += severityMarker(sev);
    comments.push(comment);
  } else {
    const where = f.path
      ? `\`${f.path}${line ? `:${line}` : ""}\``
      : "(general)";
    // A GATING finding that cannot anchor must still open a thread: the status
    // gate reads only threads, so spilling it into the review body would let it
    // ride through unresolvable — the one way this reviewer could silently lose
    // its hold on a merge. Anchor it synthetically instead — the first changed
    // line of its own file, else the diff's first changed line — and say so in
    // the body, so the author reads it as PR-wide rather than about that line.
    // No suggestion rides a synthetic anchor (it would edit a line the finding
    // is not about). Only nits (advisory either way) still spill.
    const synthetic =
      GATING_SEVERITIES.has(sev) &&
      (f.path && firstRightByPath.has(f.path)
        ? { path: f.path, line: firstRightByPath.get(f.path) }
        : firstRightOverall);
    if (synthetic) {
      comments.push({
        path: synthetic.path,
        line: synthetic.line,
        side: "RIGHT",
        body:
          `${icon(sev)} ${detail}\n\n` +
          `<sub>PR-wide finding at ${where}: it names no line in this diff, ` +
          `so it is anchored here to open a resolvable thread.</sub>` +
          severityMarker(sev),
      });
    } else {
      spill.push(`- ${icon(sev)} ${where}: ${detail}`);
    }
  }
}

// Sanitize the model-authored strings before they reach the payload: each inline
// comment body (which already carries its suggestion block) and the composite
// summary/spill body.
for (const c of comments) c.body = await scrub(c.body);

const bodyParts = [];
if (summary) bodyParts.push(summary);
if (spill.length > 0)
  bodyParts.push(`#### Additional notes\n${spill.join("\n")}`);
const body = (await scrub(bodyParts.join("\n\n"))).trim();

// A review with nothing to say is noise, so skip it. The status gate does not
// count a skipped run as a review, so a PR whose reviewer produced nothing
// stays red rather than silently passing unreviewed.
if (comments.length === 0 && !body)
  skip("reviewer produced no findings and no summary");

const footer = costFooter();
const postedBody =
  [body, footer].filter(Boolean).join("\n\n---\n") || "Automated review.";

const payload = {
  event,
  body: postedBody,
  comments,
};
if (commitId) payload.commit_id = commitId;

writeFileSync(payloadPath, JSON.stringify(payload));
writeFileSync(summaryPath, postedBody);
process.stdout.write("PAYLOAD\n");
process.stderr.write(
  `inline comments: ${comments.length}; spilled to summary: ${spill.length}\n`,
);
