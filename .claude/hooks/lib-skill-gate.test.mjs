import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { createSkillGate, markerPath } from "./lib-skill-gate.mjs";

const SKILL = "writing-tests";

/** A gate over the Bash tool, writing its markers under a private directory. */
function gate(dir) {
  process.env.CLAUDE_SKILL_GATE_DIR = dir;
  return createSkillGate({
    skill: SKILL,
    triggered: (payload) => payload?.tool_name === "Bash",
    reason: (toolName) => `${toolName} needs ${SKILL}`,
  });
}

const invocation = (session) => ({
  session_id: session,
  tool_name: "Skill",
  tool_input: { skill: SKILL },
});
const gatedCall = (session) => ({ session_id: session, tool_name: "Bash" });

test("a gated call is denied until the skill is invoked, then allowed", () => {
  const judge = gate(mkdtempSync(join(tmpdir(), "gate-")));
  assert.equal(judge(gatedCall("s1")), "Bash needs writing-tests");
  assert.equal(judge(invocation("s1")), null);
  assert.equal(judge(gatedCall("s1")), null);
});

test("one session's invocation does not satisfy another's gate", () => {
  const judge = gate(mkdtempSync(join(tmpdir(), "gate-")));
  judge(invocation("s1"));
  assert.equal(judge(gatedCall("s2")), "Bash needs writing-tests");
});

test("a plugin-qualified spelling counts, a similar name does not", () => {
  const judge = gate(mkdtempSync(join(tmpdir(), "gate-")));
  judge({
    session_id: "s1",
    tool_name: "Skill",
    tool_input: { skill: `some-plugin:${SKILL}` },
  });
  assert.equal(judge(gatedCall("s1")), null);

  judge({
    session_id: "s2",
    tool_name: "Skill",
    tool_input: { skill: `${SKILL}-notes` },
  });
  assert.equal(judge(gatedCall("s2")), "Bash needs writing-tests");
});

test("an untriggered tool passes without the skill", () => {
  const judge = gate(mkdtempSync(join(tmpdir(), "gate-")));
  assert.equal(judge({ session_id: "s1", tool_name: "Read" }), null);
});

test("an unusable session id passes rather than wedging with no remedy", () => {
  const judge = gate(mkdtempSync(join(tmpdir(), "gate-")));
  // No session key means the marker cannot be located, so a denial here could
  // never be satisfied by invoking the skill.
  assert.equal(judge({ tool_name: "Bash" }), null);
  assert.equal(judge({ session_id: "a/b", tool_name: "Bash" }), null);
});

test("the marker records the skill, so one gate's latch is not another's", () => {
  const dir = mkdtempSync(join(tmpdir(), "gate-"));
  const judge = gate(dir);
  judge(invocation("s1"));
  const path = markerPath("s1", SKILL);
  assert.equal(path, join(dir, `s1.${SKILL}.marker`));
  assert.equal(readFileSync(path, "utf8"), SKILL);
});

test("a path-unsafe name yields no marker path at all", () => {
  for (const [session, skill] of [
    ["a/b", SKILL],
    ["..", SKILL],
    ["s1", "../escape"],
  ]) {
    assert.equal(markerPath(session, skill), null, `${session} ${skill}`);
  }
});

test("the default marker directory is namespaced by uid", () => {
  // A shared $TMPDIR lets another account own an un-namespaced `skill-gate`
  // directory first; its 0700 mode then makes every marker write EACCES, which
  // denies every gated action for the session with no reachable remedy.
  delete process.env.CLAUDE_SKILL_GATE_DIR;
  const dir = join(markerPath("s1", SKILL), "..");
  assert.equal(dir.endsWith(`skill-gate-${process.getuid()}`), true, dir);
});
