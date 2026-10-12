#!/usr/bin/env node
// Re-derive this repo's generated files from the rules in
// config/auto-resolve-regen-rules.json.
//
// PROBLEM CLASS — a merge conflict in a file nobody wrote by hand. A generated
// artifact or a lockfile has no correct hand resolution: whatever a human or a
// model writes into the conflicted region is a guess at what the generator would
// have produced. The answer is always to merge the SOURCES and re-run the
// generator, so the resolver routes these paths away from the model entirely.
//
// Two modes:
//   --owned            print every path the rules generate, one per line. This is
//                      the ownership oracle auto-resolve/prepare.sh partitions on.
//   --rederived-only   with --owned, print only the paths of rules flagged
//                      `reviewOmit`, which asserts a required check re-derives
//                      them and fails on any difference. Two readers hide
//                      exactly these from a reviewer: strip-generated-diff.mjs
//                      here, and the resolver's own remerge-diff-report.py,
//                      which runs `--owned --rederived-only` against this file
//                      from the pinned agent-resolve-merge-conflicts checkout.
//                      A generated path with no such check (a lockfile) is
//                      deliberately NOT listed, so both reviewers read it.
//   (no flag)          run every rule whose sources changed, re-deriving its outputs.
//   --changed <paths>  restrict the run to rules matching these changed paths.
//   --root=<dir>       act on the tree at <dir> instead of this script's own repo.
//
// A run also STAGES each rule's outputs that are still unmerged once the rule
// succeeds. A generated file git could not merge (plugin/dist is binary) keeps
// its three index stages after the generator rewrites the working copy, and the
// resolver reads "still unmerged" as "did not regenerate cleanly".
//
// Node stdlib only, and invoked as `node .github/scripts/resolve-generated.mjs`
// rather than through a package script: a repo may have no package.json at all,
// and mid-merge the one it does have can itself carry conflict markers, which
// would make a package-manager entrypoint die parsing its own manifest.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// The tree the rules act on. `--root` aims this script at a checkout that is not
// its own repository: prepare.sh retries with the trusted-base copy of this
// script when the PR's own copy is conflicted, and that copy lives in a bare
// base worktree with no node_modules. Without it the retry regenerates the BASE
// tree, not the merge. The RULES always come from the script's own repository,
// so a tree under merge cannot declare its own.
const SELF_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const rootArg = process.argv.slice(2).find((a) => a.startsWith("--root="));
const REPO_ROOT = rootArg
  ? resolve(rootArg.slice("--root=".length))
  : SELF_ROOT;
const CONFIG_PATH = join(SELF_ROOT, "config", "auto-resolve-regen-rules.json");

const die = (msg) => {
  process.stderr.write(`resolve-generated: ${msg}\n`);
  process.exit(1);
};

// A repo that declares no rules is the common case, not an error: it simply has
// no generated files the resolver must special-case, so every conflict flows to
// the normal path. An absent config file means the same thing as an empty one.
//
// A config that EXISTS but cannot be read is the opposite, and must not degrade
// into the same answer. An ownership oracle that reports "nothing is owned" when
// it breaks misroutes exactly the paths it exists to route — a generated file
// would reach the model, which would hand-edit an artifact. So parse errors and
// malformed rules exit non-zero.
function loadRules() {
  if (!existsSync(CONFIG_PATH)) return [];

  let parsed;
  try {
    parsed = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
  } catch (err) {
    die(`${CONFIG_PATH} is not valid JSON: ${err.message}`);
  }

  const rules = parsed.rules;
  if (rules === undefined) return [];
  if (!Array.isArray(rules)) die(`${CONFIG_PATH}: "rules" must be an array`);

  rules.forEach((rule, i) => {
    const at = `${CONFIG_PATH}: rules[${i}]`;
    const hasCommand = Array.isArray(rule.command) && rule.command.length > 0;
    const hasGenerator =
      typeof rule.generator === "string" && rule.generator.length > 0;
    if (hasCommand === hasGenerator) {
      die(
        `${at} must set exactly one of "command" (argv array) or "generator" (path)`,
      );
    }
    if (hasGenerator && !existsSync(join(REPO_ROOT, rule.generator))) {
      die(`${at} names generator "${rule.generator}", which does not exist`);
    }
    const owns = rule.owns ?? [];
    if (!Array.isArray(owns)) die(`${at}: "owns" must be an array`);
    if (owns.length === 0 && !rule.ownsPrefix) {
      die(`${at} generates nothing: set "owns" and/or "ownsPrefix"`);
    }
    if (rule.ownsPrefix !== undefined) {
      if (
        typeof rule.ownsPrefix !== "string" ||
        !rule.ownsPrefix.endsWith("/")
      ) {
        die(`${at}: "ownsPrefix" must be a string ending in "/"`);
      }
    }
    if (rule.reviewOmit !== undefined && typeof rule.reviewOmit !== "boolean")
      die(`${at}: "reviewOmit" must be a boolean`);
    // A check that regenerates its outputs and diffs them says nothing about an
    // EXTRA file in the subtree, while the reader acting on the flag stops
    // reading the WHOLE directory.
    if (rule.reviewOmit === true && rule.ownsPrefix !== undefined)
      die(
        `${at}: "reviewOmit" cannot cover an "ownsPrefix" — list the paths in "owns"`,
      );
    if (rule.sourcesPattern !== undefined) {
      try {
        RegExp(rule.sourcesPattern);
      } catch (err) {
        die(`${at}: "sourcesPattern" is not a valid regex: ${err.message}`);
      }
    }
  });

  return rules;
}

// A trailing-slash prefix means the whole subtree is generated. That covers an
// output directory whose exact filenames the rule cannot enumerate ahead of time,
// and paths that exist on only one side of a merge.
const ownedPaths = (rules) => {
  const out = [];
  for (const rule of rules) {
    out.push(...(rule.owns ?? []));
    if (rule.ownsPrefix) out.push(rule.ownsPrefix);
  }
  return [...new Set(out)];
};

/** The paths a rule vouches for with `reviewOmit`. Narrower than {@link
 * ownedPaths} on purpose: being generated says a path has a generator, while
 * this says a required check re-derives it and reds on a difference, which is
 * the only thing that makes hiding it from a reviewer safe. This repo runs no
 * pre-commit regeneration hook, so no rule kind earns the claim by default. */
const reviewOmitPaths = (rules) =>
  ownedPaths(rules.filter((r) => r.reviewOmit));

const ruleMatches = (rule, changed) => {
  if (changed === null) return true;
  const sources = rule.sources ?? [];
  if (sources.some((s) => changed.has(s))) return true;
  if (!rule.sourcesPattern) return false;
  const re = new RegExp(rule.sourcesPattern);
  return [...changed].some((p) => re.test(p));
};

// A rule's command runs build backends the PR author wrote — `uv lock` invokes
// PEP 517 hooks, and nothing suppresses those the way --ignore-scripts suppresses
// npm's. So it runs with the job's credentials stripped from the environment.
//
// The two patterns below are the load-bearing half. GIT_CONFIG_VALUE_0 carries
// the push token as a base64 Authorization header, so leaving it set hands the
// credential to arbitrary build code. The GITHUB_* runner channels are worse than
// a leak: appending BASH_ENV=/tmp/x.sh to $GITHUB_ENV makes the NEXT step of the
// same job source attacker-controlled shell before its first line.
const SECRETISH = /TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL/i;
const GIT_CONFIG_INJECTION = /^GIT_CONFIG_(?:COUNT|KEY_\d+|VALUE_\d+)$/;
const RUNNER_CHANNEL = /^GITHUB_(?:ENV|PATH|OUTPUT|STATE)$/;

function scrubbedEnv() {
  // Null-prototype: the keys here are environment variable names, which are
  // attacker-influenceable, and a plain object would route a variable named
  // `__proto__` through the prototype chain instead of storing it.
  const out = Object.create(null);
  for (const [k, v] of Object.entries(process.env)) {
    if (
      SECRETISH.test(k) ||
      GIT_CONFIG_INJECTION.test(k) ||
      RUNNER_CHANNEL.test(k)
    )
      continue;
    out[k] = v;
  }
  return out;
}

function runRule(rule) {
  const argv = rule.command ?? [
    ...(rule.interpreter ?? ["node"]),
    rule.generator,
  ];
  const [cmd, ...args] = argv;
  process.stderr.write(`resolve-generated: running ${argv.join(" ")}\n`);
  const res = spawnSync(cmd, args, {
    cwd: REPO_ROOT,
    env: scrubbedEnv(),
    stdio: ["ignore", "inherit", "inherit"],
  });
  if (res.error)
    die(`${argv.join(" ")} could not be run: ${res.error.message}`);
  if (res.status !== 0) die(`${argv.join(" ")} exited ${res.status}`);
}

// Whether `text` holds an opened-and-closed conflict block: a line that is
// `<<<<<<<`, then a line that is exactly `=======`, then a line that is `>>>>>>>`,
// in that order (a diff3 `|||||||` base section sits between the first two and
// needs no handling of its own). A single separator is ordinary content — a
// banner, a setext heading, an embedded multiline string — and refusing it would
// leave a correctly regenerated output unmerged, the failure this script exists
// to remove. One linear pass over the lines, with no backtracking regex.
const OPEN_MARKER = /^<{7}(?: |$)/;
const CLOSE_MARKER = /^>{7}(?: |$)/;

function hasConflictBlock(text) {
  let stage = 0;
  for (const line of text.split(/\r?\n/)) {
    if (stage === 0 && OPEN_MARKER.test(line)) stage = 1;
    else if (stage === 1 && line === "=======") stage = 2;
    else if (stage === 2 && CLOSE_MARKER.test(line)) return true;
  }
  return false;
}

/** Stage the still-unmerged outputs of `rule`, so the resolver sees them as
 * resolved. Only unmerged paths: staging anything else would put an edit
 * outside the conflicted set into the merge commit. Refuses a file that still
 * carries a conflict block, since staging it would commit the markers.
 *
 * Every git call here runs with {@link scrubbedEnv}: the generator is PR-authored
 * and can leave a clean filter or fsmonitor command in `.git/config`, which
 * `git add` then executes with whatever environment it was handed. */
function stageUnmergedOutputs(rule) {
  const pathspecs = [
    ...(rule.owns ?? []),
    ...(rule.ownsPrefix ? [rule.ownsPrefix] : []),
  ];
  if (pathspecs.length === 0) return;
  // A root that is not a git checkout has no index, so nothing can be unmerged.
  const inRepo = spawnSync("git", ["rev-parse", "--is-inside-work-tree"], {
    cwd: REPO_ROOT,
    env: scrubbedEnv(),
    stdio: "ignore",
  });
  if (inRepo.error) die(`git could not be run: ${inRepo.error.message}`);
  if (inRepo.status !== 0) return;
  const ls = spawnSync("git", ["ls-files", "-u", "-z", "--", ...pathspecs], {
    cwd: REPO_ROOT,
    env: scrubbedEnv(),
    encoding: "utf8",
  });
  if (ls.error || ls.status !== 0)
    die(`git ls-files -u failed: ${ls.error?.message ?? ls.stderr}`);
  // `<mode> <sha> <stage>\t<path>` once per stage, so a path repeats.
  const unmerged = [
    ...new Set(
      ls.stdout
        .split("\0")
        .filter(Boolean)
        .map((entry) => entry.slice(entry.indexOf("\t") + 1)),
    ),
  ];
  for (const path of unmerged) {
    const file = join(REPO_ROOT, path);
    if (existsSync(file) && hasConflictBlock(readFileSync(file, "latin1")))
      die(`${path} still carries conflict markers after regeneration`);
  }
  if (unmerged.length === 0) return;
  // --all records a deleted output as the resolution instead of failing the pathspec.
  const add = spawnSync("git", ["add", "--all", "--", ...unmerged], {
    cwd: REPO_ROOT,
    env: scrubbedEnv(),
    encoding: "utf8",
  });
  if (add.error || add.status !== 0)
    die(`git add failed: ${add.error?.message ?? add.stderr}`);
  process.stderr.write(`resolve-generated: staged ${unmerged.join(" ")}\n`);
}

function main(argv) {
  const rules = loadRules();

  // Guard the modifier, because the fallthrough is not inert: a mistyped or
  // lone --rederived-only would drop into the run path below and rewrite every
  // generated file in the tree.
  if (argv.includes("--rederived-only") && !argv.includes("--owned"))
    die("--rederived-only is a modifier of --owned, not a mode of its own");

  if (argv.includes("--owned")) {
    const paths = argv.includes("--rederived-only")
      ? reviewOmitPaths(rules)
      : ownedPaths(rules);
    for (const p of paths) process.stdout.write(`${p}\n`);
    return;
  }

  if (rules.length === 0) {
    process.stderr.write(
      "resolve-generated: no regen rules declared in config/auto-resolve-regen-rules.json — " +
        "skipping the deterministic derived-file pre-pass.\n",
    );
    return;
  }

  const i = argv.indexOf("--changed");
  const changed =
    i === -1
      ? null
      : new Set(argv.slice(i + 1).filter((a) => !a.startsWith("--")));

  const selected = rules.filter((r) => ruleMatches(r, changed));
  if (selected.length === 0) {
    process.stderr.write(
      "resolve-generated: no rule matched the changed paths.\n",
    );
    return;
  }
  // Per rule rather than once at the end: a later rule's crash (its sources
  // still conflicted) must not strand the outputs an earlier rule did derive.
  for (const rule of selected) {
    runRule(rule);
    stageUnmergedOutputs(rule);
  }
}

main(process.argv.slice(2));
