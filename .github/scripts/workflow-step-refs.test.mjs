// Structural guard over composite actions and workflows: every `steps.<id>`
// reference must name a step that exists in the same file.
//
// Regression: template sync #169 wired claude-run's execution-log gate to
// `steps.resolve_log.outputs.execution_file` — a step id this repo's six-rung
// credential ladder never had. A missing step id is not an error in GitHub
// Actions; the expression renders to the empty string. So the gate ran with an
// empty EXECUTION_FILE and failed EVERY gated Claude run with "produced no
// execution log", including runs where a rung had just driven Claude to
// completion. Nothing else in CI catches this: the YAML is valid, and the
// failure reads as a credential outage rather than a typo.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const REPO_ROOT = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();

// `id:` is either its own line or the first key of a `- ` step entry.
const STEP_ID = /^\s*(?:-\s+)?id:\s*["']?([A-Za-z0-9_-]+)["']?\s*$/;
const STEP_REF = /steps\.([A-Za-z0-9_-]+)\./g;

/** The step ids `text` defines, and the ids its expressions reference. */
function stepIds(text) {
  const defined = new Set();
  for (const line of text.split("\n")) {
    const match = STEP_ID.exec(line);
    if (match) defined.add(match[1]);
  }
  const referenced = new Set();
  for (const [, id] of text.matchAll(STEP_REF)) referenced.add(id);
  return { defined, referenced };
}

/** Referenced ids with no matching `id:` in the same file, sorted. */
function danglingRefs(text) {
  const { defined, referenced } = stepIds(text);
  return [...referenced].filter((id) => !defined.has(id)).sort();
}

/**
 * Every workflow and composite action. Ids are collected per FILE, not per job —
 * a deliberate over-approximation: it can miss a cross-job dangling reference,
 * but it never flags a valid one. Precision over recall.
 */
function actionFiles() {
  const workflows = readdirSync(join(REPO_ROOT, ".github/workflows"))
    .filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"))
    .map((f) => `.github/workflows/${f}`);
  const actions = readdirSync(join(REPO_ROOT, ".github/actions"), {
    withFileTypes: true,
  })
    .filter((e) => e.isDirectory())
    .map((e) => `.github/actions/${e.name}/action.yaml`);
  return [...workflows, ...actions].sort();
}

test("no workflow or composite action references a step id it never defines", () => {
  const offenders = [];
  for (const path of actionFiles()) {
    const dangling = danglingRefs(readFileSync(join(REPO_ROOT, path), "utf8"));
    if (dangling.length > 0) offenders.push(`${path}: ${dangling.join(", ")}`);
  }
  assert.deepEqual(offenders, []);
});

test("the guard reads real files, not an empty set", () => {
  const files = actionFiles();
  assert.ok(
    files.length > 5,
    `only ${files.length} workflow/action files found`,
  );
  assert.ok(files.includes(".github/actions/claude-run/action.yaml"));
});

test("the guard catches the #169 shape: a gate wired to a nonexistent step", () => {
  const path = join(REPO_ROOT, ".github/actions/claude-run/action.yaml");
  const source = readFileSync(path, "utf8");
  const { defined, referenced } = stepIds(source);
  assert.ok(
    defined.size > 5,
    `only ${defined.size} step ids parsed — parser drifted`,
  );
  assert.ok(
    referenced.size > 5,
    `only ${referenced.size} step references parsed — parser drifted`,
  );

  // The #169 shape, reproduced: repoint one expression at a step id that is not
  // in the file. Deliberately a name no step will ever use — `resolve_log` is a
  // real step now, so reusing it would make this assertion pass vacuously.
  const broken = source.replace(
    "steps.a1.outputs.execution_file",
    "steps.no_such_rung.outputs.execution_file",
  );
  assert.notEqual(broken, source, "the fixture edit did not apply");
  assert.deepEqual(danglingRefs(broken), ["no_such_rung"]);
});
