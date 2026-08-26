/**
 * Contract test for `config/auto-resolve-regen-rules.json`, the auto-resolver's
 * OWNERSHIP ORACLE.
 *
 * The config's own comment states the invariant: a rule that claims a path it
 * cannot regenerate is worse than no rule, because `auto-resolve/prepare.sh`
 * routes that path away from the model on the strength of the claim. Nothing
 * enforced it. `loadRules()` in resolve-generated.mjs validates shape — exactly
 * one of `command`/`generator`, a `generator` that exists, a non-empty
 * `owns`/`ownsPrefix` — and never checks that an `owns` or `sources` path is
 * real. `.github/scripts/resolve-generated.test.mjs` is the schema's test and
 * runs entirely against synthesized temp repos, so it never reads this file.
 *
 * The gap is silent by construction: rename `src/joining-type.mjs` and the rule
 * keeps claiming the old path. The oracle reports ownership of a file that does
 * not exist, the real conflict routes to the model to hand-edit, and every check
 * stays green — a misroute in the one place the pipeline is documented to fail
 * closed.
 *
 * So every claim in the committed config is checked against the committed tree.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

import { repoRoot } from "./helpers/repo-root.mjs";

// A plain literal, not `join("config", …)`: guard-pairs resolves a string it
// can read, so spelling the path whole is what puts this file into the scan
// and forces the pairing below to exist rather than be remembered.
const CONFIG = "config/auto-resolve-regen-rules.json";

const config = JSON.parse(readFileSync(join(repoRoot, CONFIG), "utf8"));
const rules = config.rules ?? [];

/** Every tracked path, so a claim is checked against the INDEX, not the disk —
 * a build artifact left lying around must not satisfy an `owns` entry. */
const tracked = new Set(
  execFileSync("git", ["ls-files", "-z"], { cwd: repoRoot, encoding: "utf8" })
    .split("\0")
    .filter(Boolean),
);

const trackedUnder = (prefix) =>
  [...tracked].filter((path) => path.startsWith(prefix));

describe("auto-resolve regen rules describe the repo as it is", () => {
  it("declares rules at all", () => {
    // Non-vacuity: an emptied `rules` array would satisfy every per-rule
    // assertion below by iterating zero times, which is the shape of the bug
    // this file exists to catch (an absent config and an empty one are the same
    // answer to the oracle).
    assert.ok(rules.length > 0, `${CONFIG} declares no rules`);
  });

  it("names a generator that is tracked", () => {
    for (const rule of rules) {
      if (!rule.generator) continue;
      assert.ok(
        tracked.has(rule.generator),
        `${CONFIG}: generator ${rule.generator} is not a tracked file`,
      );
    }
  });

  it("sets exactly one of command and generator", () => {
    for (const rule of rules) {
      const hasCommand = Array.isArray(rule.command) && rule.command.length > 0;
      assert.notEqual(
        hasCommand,
        Boolean(rule.generator),
        `${CONFIG}: ${JSON.stringify(rule.owns)} must set exactly one of command/generator`,
      );
    }
  });

  it("owns only tracked paths", () => {
    for (const rule of rules)
      for (const owned of rule.owns ?? [])
        assert.ok(
          tracked.has(owned),
          `${CONFIG}: owns ${owned}, which is not a tracked file — the oracle ` +
            "would claim it and prepare.sh would route a conflict away from the model",
        );
  });

  it("owns a prefix that covers at least one tracked file", () => {
    for (const rule of rules) {
      if (!rule.ownsPrefix) continue;
      assert.ok(
        rule.ownsPrefix.endsWith("/"),
        `${CONFIG}: ownsPrefix ${rule.ownsPrefix} must end in "/"`,
      );
      assert.ok(
        trackedUnder(rule.ownsPrefix).length > 0,
        `${CONFIG}: ownsPrefix ${rule.ownsPrefix} covers no tracked file`,
      );
    }
  });

  it("lists sources that are tracked", () => {
    for (const rule of rules)
      for (const source of rule.sources ?? [])
        assert.ok(
          tracked.has(source),
          `${CONFIG}: sources ${source} is not a tracked file — the rule would ` +
            "never fire for the change it is meant to react to",
        );
  });

  it("uses a sourcesPattern that matches at least one tracked path", () => {
    for (const rule of rules) {
      if (!rule.sourcesPattern) continue;
      const re = new RegExp(rule.sourcesPattern);
      assert.ok(
        [...tracked].some((path) => re.test(path)),
        `${CONFIG}: sourcesPattern ${rule.sourcesPattern} matches nothing tracked`,
      );
    }
  });

  it("watches every tracked input the redactor artifacts are built from", () => {
    // The wheel and the zipapp are built from `python/` — its package sources,
    // its `pyproject.toml`, and the `README.md` that `readme`/`include` put in
    // the wheel. Enumerating extensions here missed the JSON detector SSOTs
    // once; this asserts the rule covers the SUBTREE, so the next input needs no
    // edit at all.
    const rule = rules.find((candidate) =>
      (candidate.owns ?? []).includes("plugin/dist/redactor/daemon.pyz"),
    );
    assert.ok(rule, `${CONFIG}: no rule generates the redactor zipapp`);
    const inputs = [...tracked].filter((path) => path.startsWith("python/"));
    // The rule would pass vacuously against an empty tree.
    assert.ok(inputs.length > 5, inputs.length);
    const re = new RegExp(rule.sourcesPattern);
    for (const path of inputs)
      assert.ok(
        re.test(path),
        `${CONFIG}: ${path} is a redactor-artifact input that ${rule.sourcesPattern} does not match`,
      );
  });

  it("declares something for every rule to generate", () => {
    for (const rule of rules)
      assert.ok(
        (rule.owns ?? []).length > 0 || rule.ownsPrefix,
        `${CONFIG}: a rule generates nothing`,
      );
  });

  it("never claims a git-ignored path", () => {
    // The failure this catches is the tempting one: declaring a build artifact
    // that cannot carry a conflict because git never sees it. `owns` above
    // already requires tracked-ness, so this pins the REASON in the config's
    // own `notOwned` block — an entry moved from notOwned into rules without
    // being committed first fails here with the explanation.
    const notOwned = Object.keys(config.notOwned ?? {}).filter(
      (key) => key !== "comment",
    );
    assert.ok(notOwned.length > 0, "notOwned lost its documented exclusions");
    for (const path of notOwned)
      assert.ok(
        !rules.some(
          (rule) =>
            (rule.owns ?? []).includes(path) || rule.ownsPrefix === path,
        ),
        `${CONFIG}: ${path} is both excluded in notOwned and claimed by a rule`,
      );
  });
});
