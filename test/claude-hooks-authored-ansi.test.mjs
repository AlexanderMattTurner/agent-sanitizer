/**
 * What the write path does with ESCAPES the model authored — the half of Layer
 * 3 that decides between rewriting a field and leaving it alone.
 *
 * The layer strips a field the moment it carries a complete sequence that can
 * reposition, erase or open a control string. It does NOT strip display-only
 * colour: SGR restyles visible text and can do nothing else, so removing it only
 * costs the model the colourized fixture, TUI golden file or prompt string it
 * meant to write. Both halves are asserted here, together with the two ways SGR
 * stops being styling (a conceal parameter; a run of sequences with nothing
 * between them) — and with the false-positive twin of each, since the cost of a
 * wrong strip is content the model does not get back.
 *
 * The reconstitution case is the one that is not about the carve-out: removing
 * invisible characters can COMPLETE a sequence that was incomplete when the
 * terminal stage ran, so the field is carried to a fixed point rather than
 * through one round of each protection.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  AUTHORED_FIELDS,
  sanitizeAuthoredContent,
} from "../claude-hooks/lib/authored-content.mjs";
import { SGR_RUN_THRESHOLD } from "../src/layer1.mjs";
import { LONG_RUN_THRESHOLD } from "../src/invisible.mjs";
import { inputFor, readField } from "./helpers/authored-fields.mjs";
import { cp } from "./test-helpers.mjs";

const ESC = cp(0x1b);
const CSI = cp(0x9b);
const ZWSP = cp(0x200b);

const COLOURED = `${ESC}[32mgreen${ESC}[0m plain`;

/** Every (tool, field spec) pair the live field map declares. */
const COVERED = Object.entries(AUTHORED_FIELDS).flatMap(([tool, specs]) =>
  specs.map((spec) => /** @type {[string, string]} */ ([tool, spec])),
);

/**
 * The sanitized value of `content` in the field `spec` of `tool`, or null when
 * the layer left the input alone.
 * @param {string} tool
 * @param {string} spec
 * @param {string} content
 * @returns {string | null}
 */
function sanitized(tool, spec, content) {
  const result = sanitizeAuthoredContent(tool, inputFor(spec, content));
  if (result === null) return null;
  return /** @type {string} */ (readField(spec, result.updatedInput));
}

test("the field map is non-empty, so the cases below are not vacuous", () => {
  assert.ok(COVERED.length > 0, "AUTHORED_FIELDS declares no field");
});

test("display-only colour survives every covered field byte for byte", () => {
  for (const [tool, spec] of COVERED)
    assert.equal(
      sanitized(tool, spec, COLOURED),
      null,
      `${tool}.${spec} rewrote a colour sequence`,
    );
});

test("colour in the C1 encoding survives too", () => {
  assert.equal(sanitized("Write", "content", `${CSI}31mred${CSI}0m`), null);
});

test("a sequence that is not display-only strips the whole field, colour included", () => {
  for (const [tool, spec] of COVERED)
    assert.equal(
      sanitized(tool, spec, `${ESC}[32mgreen${ESC}[2Jgone`),
      "greengone",
      `${tool}.${spec} kept a sequence that erases the screen`,
    );
});

test("an OSC string is stripped even though the colour beside it is kept elsewhere", () => {
  assert.equal(
    sanitized("Bash", "command", `echo ${ESC}]0;title${ESC}\\hi`),
    "echo hi",
  );
});

test("a conceal parameter is not styling, so the field is stripped", () => {
  assert.equal(
    sanitized("Write", "content", `visible${ESC}[8mhidden${ESC}[28m`),
    "visiblehidden",
  );
});

test("a 256-colour index of 8 is styling, and is kept", () => {
  assert.equal(sanitized("Write", "content", `${ESC}[38;5;8mgrey`), null);
});

test("a run of sequences with nothing between them is a channel, and is stripped", () => {
  const run = `${ESC}[31m`.repeat(SGR_RUN_THRESHOLD);
  assert.equal(sanitized("Write", "content", `${run}text`), "text");
});

test("zero-width separators do not turn a run back into styling", () => {
  // One ZWSP between each pair is the shape that slips BOTH gates: too few
  // zero-widths for the invisible layer to call payload-capable, and enough to
  // break a run counted on strict byte adjacency. The gaps render nothing, so
  // the run is still a run — the separators themselves stay, being too few to
  // strip on their own.
  const run = Array.from({ length: SGR_RUN_THRESHOLD }, () => `${ESC}[31m`);
  assert.equal(
    sanitized("Write", "content", `${run.join(ZWSP)}text`),
    `${ZWSP.repeat(SGR_RUN_THRESHOLD - 1)}text`,
  );
});

test("the same count of sequences around visible text is styling, and is kept", () => {
  const styled = `${ESC}[31mx`.repeat(SGR_RUN_THRESHOLD * 2);
  assert.equal(sanitized("Write", "content", styled), null);
});

test("a sequence the invisible strip completes is stripped, not written through", () => {
  // `ESC[` ZWSP `2J` is an orphan introducer while the ZWSP sits inside it: the
  // terminal stage removes nothing. The long run makes the field payload-capable,
  // so the invisible strip runs and reconstitutes `ESC[2J` — which a single round
  // of {terminal, invisible} would then persist into the file.
  const hidden = `${ESC}[${ZWSP}2J`;
  const content = `keep${hidden}${ZWSP.repeat(LONG_RUN_THRESHOLD + 2)}tail`;
  const result = sanitizeAuthoredContent("Write", { content });
  assert.ok(result, "the payload-capable field was left alone");
  assert.equal(result.updatedInput.content, "keeptail");
});

test("AGENT_SANITIZER_TERMINAL_DISABLED=1 keeps a sequence the carve-out would strip", () => {
  process.env.AGENT_SANITIZER_TERMINAL_DISABLED = "1";
  try {
    assert.equal(sanitized("Write", "content", `${ESC}[2Jgone`), null);
    assert.equal(sanitized("Write", "content", `${ESC}[8mhidden`), null);
  } finally {
    delete process.env.AGENT_SANITIZER_TERMINAL_DISABLED;
  }
  // The knob is read per call, so the next call strips again — otherwise this
  // suite would go green on a layer that had stopped running entirely.
  assert.equal(sanitized("Write", "content", `${ESC}[2Jgone`), "gone");
});

test("AGENT_SANITIZER_INVISIBLE_DISABLED=1 leaves the terminal decision intact", () => {
  process.env.AGENT_SANITIZER_INVISIBLE_DISABLED = "1";
  try {
    assert.equal(sanitized("Write", "content", COLOURED), null);
    assert.equal(sanitized("Write", "content", `${ESC}[2Jgone`), "gone");
    const stego = ZWSP.repeat(LONG_RUN_THRESHOLD + 2);
    assert.equal(sanitized("Write", "content", `a${stego}b`), null);
  } finally {
    delete process.env.AGENT_SANITIZER_INVISIBLE_DISABLED;
  }
});

test("a preserved field is reported nowhere: no rewrite, no action", () => {
  assert.equal(sanitizeAuthoredContent("Write", { content: COLOURED }), null);
  const stripped = sanitizeAuthoredContent("Write", {
    content: `${ESC}[2Jgone`,
  });
  assert.ok(stripped);
  assert.deepEqual(stripped.changed, ["content (terminal-control sequences)"]);
});
