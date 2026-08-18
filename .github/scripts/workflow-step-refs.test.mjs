// Structural guard over composite actions and workflows. Two invariants, both
// covering failure modes GitHub Actions declines to treat as errors:
//
//   1. every `steps.<id>` reference must name a step that exists in the file;
//   2. every `with:` key on a `uses: ./.github/actions/<name>` step must be a
//      declared input of that action.
//
// Regression: template sync #169 wired claude-run's execution-log gate to
// `steps.resolve_log.outputs.execution_file` — a step id this repo's six-rung
// credential ladder never had. A missing step id is not an error in GitHub
// Actions; the expression renders to the empty string. So the gate ran with an
// empty EXECUTION_FILE and failed EVERY gated Claude run with "produced no
// execution log", including runs where a rung had just driven Claude to
// completion. Nothing else in CI catches this: the YAML is valid, and the
// failure reads as a credential outage rather than a typo.
//
// Regression for invariant 2: claude.yaml and pr-meta.yaml passed claude-run's
// six fallback credentials as `fallback_oauth_token[_2..6]` while the action
// declares `oauth_token_fallback[_2..6]`. An undeclared composite input is a
// WARNING, not an error — the value is dropped, `inputs.oauth_token_fallback`
// renders empty, every rung gate is false, and the six-rung ladder silently
// collapses to one. Five provisioned tokens sat unused through every rate-limit
// outage, and nothing in CI could see it.
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

// ---------------------------------------------------------------------------
// Invariant 2: `with:` keys on a local composite-action step must be declared
// inputs of that action.
// ---------------------------------------------------------------------------

const USES_LOCAL =
  /^(\s*)(-\s+)?uses:\s*\.\/(\.github\/actions\/[A-Za-z0-9._-]+)\s*(?:#.*)?$/;

/** Indent width of `line`, or null when it holds no YAML content. */
function contentIndent(line) {
  const trimmed = line.trim();
  if (trimmed === "" || trimmed.startsWith("#")) return null;
  return line.length - line.trimStart().length;
}

/**
 * The mapping keys directly under a block whose opening `key:` sits at
 * `parentIndent`, scanning from `start`. Keys are read at exactly the block's
 * own indent, so a nested map or a `|`/`>-` scalar body — always deeper — can
 * never be mistaken for one.
 */
function blockKeys(lines, start, parentIndent) {
  const keys = [];
  let blockIndent = null;
  for (let i = start; i < lines.length; i += 1) {
    const indent = contentIndent(lines[i]);
    if (indent === null) continue;
    if (indent <= parentIndent) break;
    if (blockIndent === null) blockIndent = indent;
    if (indent !== blockIndent) continue;
    const match = /^([A-Za-z0-9_.-]+):/.exec(lines[i].trim());
    if (match) keys.push(match[1]);
  }
  return keys;
}

/** Top-level `inputs:` keys declared by an action.yaml. */
function actionInputs(text) {
  const lines = text.split("\n");
  const at = lines.findIndex((line) => /^inputs:\s*$/.test(line));
  if (at === -1) return [];
  return blockKeys(lines, at + 1, 0);
}

/**
 * Every `uses: ./.github/actions/<name>` step in `text`, with the `with:` keys
 * it passes. A `- uses:` opens the step, so the step's key indent is the dash's
 * column plus two; a sibling step sits shallower and ends the scan.
 */
function localActionCalls(text) {
  const lines = text.split("\n");
  const calls = [];
  for (let i = 0; i < lines.length; i += 1) {
    const uses = USES_LOCAL.exec(lines[i]);
    if (!uses) continue;
    const keyIndent = uses[1].length + (uses[2] ? uses[2].length : 0);
    const call = { action: uses[3], line: i + 1, withKeys: [] };
    calls.push(call);
    for (let j = i + 1; j < lines.length; j += 1) {
      const indent = contentIndent(lines[j]);
      if (indent === null) continue;
      if (indent < keyIndent) break;
      if (indent !== keyIndent || !/^with:\s*$/.test(lines[j].trim())) continue;
      call.withKeys = blockKeys(lines, j + 1, keyIndent);
      break;
    }
  }
  return calls;
}

/** Every local-action call site in `files`, tagged with its file. */
function allCalls(files) {
  return files.flatMap((path) =>
    localActionCalls(readFileSync(join(REPO_ROOT, path), "utf8")).map(
      (call) => ({ ...call, path }),
    ),
  );
}

/** Cached `inputs:` set for `.github/actions/<name>`. */
const inputsOf = new Map();
function declaredInputs(action) {
  if (!inputsOf.has(action)) {
    const text = readFileSync(join(REPO_ROOT, action, "action.yaml"), "utf8");
    inputsOf.set(action, new Set(actionInputs(text)));
  }
  return inputsOf.get(action);
}

test("every `with:` key on a local composite-action step is a declared input", () => {
  const offenders = [];
  for (const call of allCalls(actionFiles())) {
    const declared = declaredInputs(call.action);
    const bad = call.withKeys.filter((key) => !declared.has(key));
    if (bad.length > 0) {
      offenders.push(`${call.path}:${call.line} -> ${call.action}: ${bad}`);
    }
  }
  assert.deepEqual(offenders, []);
});

test("the call-site sweep is non-empty and names the actions it reached", () => {
  const calls = allCalls(actionFiles());
  assert.ok(calls.length > 10, `only ${calls.length} local-action call sites`);

  // A sweep that quietly stopped seeing a call site reports the same empty
  // offender list as a clean repo, so pin which actions are reached. Only the
  // invoked ones appear — the merge-conflict resolver itself now lives in
  // AlexanderMattTurner/agent-resolve-merge-conflicts and calls claude-run from
  // its own tree, so this repo's action files hold none of that call.
  const called = [...new Set(calls.map((call) => call.action))].sort();
  assert.deepEqual(called, [
    ".github/actions/claude-run",
    ".github/actions/notify-ntfy",
    ".github/actions/report-job-result",
    ".github/actions/setup-base-env",
  ]);

  // Every action.yaml must yield inputs, so a parser that silently returned []
  // (and made the subset check trivially true) cannot pass.
  for (const dir of new Set(calls.map((call) => call.action))) {
    assert.ok(
      declaredInputs(dir).size > 0,
      `no inputs parsed from ${dir}/action.yaml`,
    );
  }

  // claude-run is where the regression landed: pin that its keys really parse.
  const ladderCalls = calls.filter((call) =>
    call.action.endsWith("/claude-run"),
  );
  assert.ok(
    ladderCalls.length >= 5,
    `only ${ladderCalls.length} claude-run calls`,
  );
  for (const call of ladderCalls) {
    assert.ok(
      call.withKeys.includes("oauth_token_fallback_2"),
      `${call.path}:${call.line} does not pass oauth_token_fallback_2`,
    );
  }
});

test("claude-run declares one input per rung of the credential-ladder SSOT", () => {
  const ladder = readFileSync(
    join(REPO_ROOT, ".github/scripts/lib/claude-oauth-ladder.bash"),
    "utf8",
  );
  const rungs = [
    ...ladder.matchAll(/^\s{2}(CLAUDE_CODE_OAUTH_TOKEN\w*)$/gm),
  ].map((match) => match[1].replace(/^CLAUDE_CODE_/, "").toLowerCase());
  assert.ok(rungs.length > 1, "no ladder rungs parsed out of the SSOT");

  const inputs = actionInputs(
    readFileSync(
      join(REPO_ROOT, ".github/actions/claude-run/action.yaml"),
      "utf8",
    ),
  );
  // `outputs:`/`runs:` sit at the same indent as `inputs:` and the folded
  // descriptions hold `key:`-looking prose — neither may leak into the keys.
  assert.ok(!inputs.includes("runs"), "parser ran past the inputs block");
  assert.ok(!inputs.includes("description"), "parser descended into a value");
  assert.ok(inputs.includes("gate_context"), "the last input was not parsed");

  const missing = rungs.filter((rung) => !inputs.includes(rung));
  assert.deepEqual(missing, [], "ladder rungs with no claude-run input");
});

test("the guard catches an undeclared `with:` key", () => {
  const source = readFileSync(
    join(REPO_ROOT, ".github/workflows/claude.yaml"),
    "utf8",
  );
  // The exact regression: the ladder key spelled in the caller's word order.
  const broken = source.replace(
    "oauth_token_fallback:",
    "fallback_oauth_token:",
  );
  assert.notEqual(broken, source, "the fixture edit did not apply");
  const call = localActionCalls(broken).find((c) =>
    c.action.endsWith("/claude-run"),
  );
  assert.ok(call, "no claude-run call site parsed from the fixture");
  const declared = declaredInputs(".github/actions/claude-run");
  assert.deepEqual(
    call.withKeys.filter((key) => !declared.has(key)),
    ["fallback_oauth_token"],
  );
});
