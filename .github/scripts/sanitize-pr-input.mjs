// Filter untrusted PR text through the agent-sanitizer before it reaches
// the review agent. Reads UTF-8 on stdin, writes the sanitized text on stdout,
// and writes a human-readable report of everything it neutralized on stderr
// (empty when the input was clean).
//
// Layer 1 only (`html: false`): strips payload-capable invisible/format (Cf)
// characters and ANSI/SGR escapes and normalizes lone UTF-16 surrogates — the
// injection vectors — while leaving the visible bytes untouched, so the diff
// stays byte-faithful and reviewable. Running the HTML layer would splice out
// legitimate HTML/markdown in the changed files and corrupt the review, so the
// exfil-URL scan runs via `exfilScan` instead: Layer 3's non-destructive
// detection, which reports suspicious URLs in `warnings` without removing
// them. The warning prose is the sanitizer's own (src/warnings.mjs) — this
// script no longer carries a copy.
//
// Usage: node sanitize-pr-input.mjs < raw.txt > cleaned.txt 2> report.txt
// This script runs against the PUBLISHED package, pinned by
// install-sanitizer.sh — not against src/ in this repo. So it may only use API
// that version already ships: `describeExfil` is re-exported from
// `agent-sanitizer/output` on this branch but not in the pin, and importing it
// here fails the whole script at module load. Hence the reasons are still
// assembled locally, and `notes` is defaulted below.
import { sanitize } from "agent-sanitizer";

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const input = Buffer.concat(chunks).toString("utf8");

const { cleaned, found, warnings } = await sanitize(input, {
  html: false,
  exfilScan: true,
});

// `notes` defaults to []: the severity split is not in the pinned version, so
// the field is absent there and spreading it would throw. It starts carrying
// findings the moment install-sanitizer.sh's pin catches up.
const {
  cleaned,
  found,
  warnings,
  notes = [],
} = await sanitize(input, {
  html: false,
});

const exfilReasons = [
  ...new Set(
    (detectExfil(input) || []).map(
      (threat) =>
        `${threat.isImage ? "image" : "link"} to ${threat.target}: ${threat.reason}`,
    ),
  ),
];

process.stdout.write(cleaned);

// A reviewer's report, not a model's banner, so both severity tiers are printed
// — the warnings first, because that ordering is the only thing that survives a
// skim.
const report = [...warnings, ...notes];
if (found.length > 0)
  report.unshift(`Neutralized categories: ${found.join(", ")}`);
if (exfilReasons.length > 0)
  report.push(`Exfil-shaped URLs detected: ${exfilReasons.join("; ")}`);
if (report.length > 0) process.stderr.write(report.join("\n") + "\n");
