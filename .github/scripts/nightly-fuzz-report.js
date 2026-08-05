// @ts-check
"use strict";

const fs = require("fs");

const LOG_FILE = "fuzz-output.log";
// Keep the report body bounded. The budget is spent on the FAILING TAP blocks
// (which carry fast-check's counterexample + seed), never on the run's tail:
// `pnpm test` ends with a 2000-test summary and a coverage table, so a raw tail
// quotes neither the failure nor the seed — the exact reason #211 was unactionable.
const MAX_FAILURE_BLOCKS = 5;
const MAX_QUOTE_CHARS = 6000;
// Fallback only, for a run that died before emitting any TAP.
const MAX_TAIL_LINES = 80;

const NOT_OK = /^(\s*)not ok \d+ - /;
// fast-check prints both of these together, and only on a property failure. Both
// are required: a plain `not ok` from an ordinary red suite must not be dressed
// up as a newly-explored input.
const FASTCHECK_MARKERS = [
  /^\s*Property failed after \d+ test/m,
  /^\s*\{\s*seed:\s*-?\d+/m,
];

/**
 * Every failing TAP test as `not ok …` plus its indented YAML diagnostic (the
 * `error:` and stack). A block ends at the first non-blank line indented no
 * deeper than its `not ok`.
 *
 * @param {string} log
 * @returns {string[]}
 */
function failureBlocks(log) {
  const lines = log.split("\n");
  const blocks = [];
  for (let i = 0; i < lines.length; i++) {
    const match = NOT_OK.exec(lines[i]);
    if (!match) continue;
    const indent = match[1].length;
    const block = [lines[i]];
    let end = i + 1;
    for (; end < lines.length; end++) {
      const line = lines[end];
      const isBlank = line.trim() === "";
      if (!isBlank && line.length - line.trimStart().length <= indent) break;
      block.push(line);
    }
    blocks.push(block.join("\n").trimEnd());
    i = end - 1;
  }
  return blocks;
}

/**
 * Fit the failing blocks into the body budget, reporting what was dropped —
 * a silent cap reads as "that was all of it".
 *
 * @param {string[]} blocks
 * @returns {{ quote: string, omitted: number }}
 */
function quoteFailures(blocks) {
  const kept = [];
  let chars = 0;
  for (const block of blocks) {
    if (kept.length >= MAX_FAILURE_BLOCKS) break;
    // Skip past an outsized block rather than stopping: one failure that dumps a
    // whole script into its diagnostic must not starve the four after it. Each
    // block carries its `not ok N`, so the gap is visible.
    if (chars + block.length > MAX_QUOTE_CHARS) continue;
    kept.push(block);
    chars += block.length + 2;
  }
  // Every failure was outsized: a truncated one still beats quoting nothing.
  if (kept.length === 0 && blocks.length > 0) {
    kept.push(`${blocks[0].slice(0, MAX_QUOTE_CHARS)}\n… (truncated)`);
  }
  return { quote: kept.join("\n\n"), omitted: blocks.length - kept.length };
}

/**
 * Wrap `text` in a fence long enough to survive it. Test output legitimately
 * contains fences (the markdownlint rule's fixtures are markdown), and a
 * three-backtick fence around one closes early — burying the failure it exists
 * to show.
 *
 * @param {string} text
 * @returns {string[]} the fenced lines
 */
function fence(text) {
  const longest = (text.match(/`+/g) || []).reduce(
    (max, run) => Math.max(max, run.length),
    0,
  );
  const bar = "`".repeat(Math.max(3, longest + 1));
  return [bar, text, bar];
}

/**
 * Build the human-readable report for a failed nightly run.
 *
 * @param {string} log - the teed `pnpm test` output
 * @param {string} runUrl
 * @returns {{ title: string, body: string }}
 */
function report(log, runUrl) {
  const isCounterexample = FASTCHECK_MARKERS.every((marker) =>
    marker.test(log),
  );
  const lede = isCounterexample
    ? [
        "The nightly unseeded fuzz run (`fuzz-nightly.yaml`) hit a failing input.",
        "",
        "Unlike PR CI, this run lets fast-check pick its own random seed, so it " +
          "explores inputs the fixed-seed PR runs never try. A failure here means " +
          '"go look" — reproduce locally by re-running the failing suite with the ' +
          "seed fast-check prints below.",
      ]
    : [
        "The nightly unseeded fuzz run (`fuzz-nightly.yaml`) failed, but its output " +
          "carries **no fast-check counterexample** (no `Property failed after …` / " +
          "`{ seed: … }`). So this is not a newly-explored input: it is an ordinary " +
          "failing suite, most likely already red on `main`.",
        "",
        "Check `main`'s status and the open PRs first — a fix may already be in flight.",
      ];

  const blocks = failureBlocks(log);
  const { quote, omitted } = quoteFailures(blocks);
  const quoted = quote
    ? fence(quote)
    : [
        "No TAP `not ok` line was found — the run likely died before reporting. " +
          "Tail of the output:",
        "",
        ...fence(
          log.split("\n").slice(-MAX_TAIL_LINES).join("\n").trimEnd() ||
            "(no test output was captured)",
        ),
      ];

  const body = [
    ...lede,
    "",
    `- Run: ${runUrl}`,
    "",
    ...quoted,
    ...(omitted > 0
      ? ["", `_${omitted} further failing test(s) omitted; see the run log._`]
      : []),
  ].join("\n");

  return {
    title: isCounterexample
      ? "Nightly fuzz found a failing input"
      : "Nightly fuzz run failed (no counterexample — check `main`)",
    body,
  };
}

// ntfy rejects a message body over 4096 BYTES outright, so the report — whose
// own budget is 6000 characters of quoted TAP — has to be cut for the push.
// Bytes, not characters: the body carries em dashes and curly quotes, and a
// failing test name can carry anything the suite put in it.
const MAX_NOTIFICATION_BYTES = 4000;
const TRUNCATION_NOTE = "\n… (truncated — full report in the run log)";

/**
 * The report body, cut to something ntfy will accept. Truncation is announced
 * rather than silent: a body that merely stops reads as the whole failure.
 *
 * @param {string} body
 * @returns {string}
 */
function forNotification(body) {
  if (Buffer.byteLength(body, "utf8") <= MAX_NOTIFICATION_BYTES) return body;
  const budget = MAX_NOTIFICATION_BYTES - Buffer.byteLength(TRUNCATION_NOTE);
  // Decoding a buffer cut mid-character yields U+FFFD, which re-encodes WIDER
  // than the bytes it replaced. Cut with the string decoder's own boundary
  // handling instead: slice to the budget, drop any trailing replacement char.
  const cut = Buffer.from(body, "utf8")
    .subarray(0, budget)
    .toString("utf8")
    .replace(/\uFFFD+$/u, "");
  return cut + TRUNCATION_NOTE;
}

/**
 * Push the nightly fuzz verdict to ntfy. Called by fuzz-nightly.yaml via
 * actions/github-script only on failure; it does not deliver the notification
 * itself, it hands `title`/`message` to the notify-ntfy step as outputs.
 *
 * Delivery is a phone push rather than a tracking issue: nobody watches the
 * nightly Actions tab, and an auto-filed issue only moved the ignoring to the
 * issue tracker. The full report stays in the run log, one tap away.
 *
 * @param {object} params
 * @param {object} params.context - GitHub Actions run context
 * @param {{ setOutput(name: string, value: string): void, notice(msg: string): void }} params.core
 */
module.exports = async ({ context, core }) => {
  const { owner, repo } = context.repo;
  const runUrl = `${context.serverUrl}/${owner}/${repo}/actions/runs/${context.runId}`;

  let log = "";
  try {
    log = fs.readFileSync(LOG_FILE, "utf8");
  } catch {
    log = "";
  }
  const { title, body } = report(log, runUrl);

  core.setOutput("title", title);
  core.setOutput("message", forNotification(body));
  core.setOutput("run_url", runUrl);
  core.notice(title);
};

module.exports.report = report;
module.exports.forNotification = forNotification;
