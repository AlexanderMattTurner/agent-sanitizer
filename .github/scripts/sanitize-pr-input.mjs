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
// install-sanitizer.sh — not against src/ in this repo, except inside this repo
// itself, where the installer points the pin at the working tree. So it may
// only use API the pinned version already ships: subpath imports such as
// `agent-sanitizer/html` fail the whole script at module load when the pin
// predates them, which is why the exfil scan goes through the `sanitize()`
// facade and `notes` is defaulted below.
import { sanitize } from "agent-sanitizer";

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const input = Buffer.concat(chunks).toString("utf8");

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
  exfilScan: true,
});

process.stdout.write(cleaned);

// A reviewer's report, not a model's banner, so both severity tiers are printed
// — the warnings first, because that ordering is the only thing that survives a
// skim.
//
// "flagged", not "neutralized": `found` mixes destructive layers (Layer 1
// strips the bytes) with the detective one (Layer 3 reports exfil-shaped URLs
// and leaves them in place). Claiming every category was neutralized tells the
// review agent bytes were removed when a benign-but-exfil-shaped URL merely
// tripped the scan, and its prompt reads neutralized content as a supply-chain
// signal. One accurate label for both kinds keeps this script from having to
// know which layer produced which category.
const report = [...warnings, ...notes];
if (found.length > 0) report.unshift(`Categories flagged: ${found.join(", ")}`);
if (report.length > 0) process.stderr.write(report.join("\n") + "\n");
