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
// exfil-URL scan is run separately and NON-destructively: suspicious URLs are
// reported, never removed.
//
// Usage: node sanitize-pr-input.mjs < raw.txt > cleaned.txt 2> report.txt
import { sanitize } from "agent-sanitizer";
import { detectExfil } from "agent-sanitizer/html";
// The library's own sentence for a Layer-3 finding, so this report and the
// pipeline's cannot describe the same URL in two different ways.
import { describeExfil } from "agent-sanitizer/output";

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const input = Buffer.concat(chunks).toString("utf8");

const { cleaned, found, warnings, notes } = await sanitize(input, {
  html: false,
});
const threats = detectExfil(input);

process.stdout.write(cleaned);

// A reviewer's report, not a model's banner, so both severity tiers are printed
// — the warnings first, because that ordering is the only thing that survives a
// skim.
const report = [...warnings, ...notes];
if (found.length > 0)
  report.unshift(`Neutralized categories: ${found.join(", ")}`);
if (threats) report.push(describeExfil(threats));
if (report.length > 0) process.stderr.write(report.join("\n") + "\n");
