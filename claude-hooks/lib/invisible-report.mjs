/**
 * The operator-facing report for hidden-Unicode findings in instruction files.
 *
 * Its own module because two hooks render it — the SessionStart scan of the
 * files that load at launch, and the InstructionsLoaded scan of every file
 * loaded after that — and a second copy would drift in exactly the way that
 * matters: the framing that keeps a decoded payload from reading as an
 * instruction (see decodeRun's `untrusted data` prefix) is part of the report,
 * not decoration on it.
 */

/**
 * @param {Array<{
 *   file: string,
 *   findings: Array<{ line: number | null, charCount: number, method: string, decoded: string }>,
 * }>} allFindings
 * @returns {string}
 */
export function formatReport(allFindings) {
  const BAR = "━".repeat(52);
  const lines = [
    "",
    `━━━ INVISIBLE CHARACTER INJECTION DETECTED ${BAR.slice(0, 11)}`,
    "",
    "Invisible Unicode in instruction files can hijack the model’s behavior",
    "(skill invocation, tool use, instruction override). This commonly",
    "happens when copy-pasting content from the internet.",
    "",
    "These files are loaded directly as context, bypassing PostToolUse",
    "sanitization, so the invisible characters reach the model raw.",
    "",
  ];

  for (const { file, findings } of allFindings) {
    lines.push(`  ${file}:`);
    for (const finding of findings) {
      // `line` is null for the whole-file scattered-chars finding, which is
      // not tied to any single line.
      const where =
        finding.line === null ? "Whole file" : `Line ${finding.line}`;
      lines.push(
        `    ${where}: ${finding.charCount} invisible chars (${finding.method})`,
      );
      lines.push(`    Decodes to: ${JSON.stringify(finding.decoded)}`);
    }
    lines.push("");
  }

  lines.push(BAR);
  return lines.join("\n");
}
