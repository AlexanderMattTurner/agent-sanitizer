/**
 * Meta-invariant: every file this package SHIPS is inside both quality gates.
 *
 * The coverage floor and the mutation matrix were both scoped to `src/` while
 * 14 of the 25 `exports` subpaths — the whole Claude-hook layer — plus the
 * published `sanitize-cli` bin lived outside it. `pnpm test` reported "100%"
 * over a file set that excluded them, so a new early return in
 * `claude-hooks/lib/hook-io.mjs`, or an entire new untested
 * `claude-hooks/lib/*.mjs`, was green by construction.
 *
 * `scripts/shipped-sources.mjs` derives the checked set from the manifest
 * (`files` + `exports` + `bin`) and both gates consume it. This test is the
 * thing that keeps them consuming it: publish a module without putting it in
 * BOTH gates and CI goes red here.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { expandShards } from "../.github/scripts/expand-shards.mjs";
import {
  assertRatcheted,
  RATCHET_SLACK,
  SCOPES,
  srcRoots,
} from "../scripts/coverage.mjs";
import { mutateSpec } from "../scripts/mutate.mjs";
import {
  hookScope,
  mutatedSources,
  shippedSources,
  srcScope,
  TOOLING_SCOPE,
  toolingSources,
} from "../scripts/shipped-sources.mjs";

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();

const shipped = shippedSources(repoRoot);
const mutated = mutatedSources(repoRoot);
const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));

/** Every `.mjs` the manifest names, read straight off `package.json` rather
 * than through the module under test — an independent second opinion, so a bug
 * in `shippedSources` cannot make this file agree with itself. */
function manifestMjs() {
  const targets = [];
  for (const subpath of Object.values(pkg.exports))
    targets.push(
      ...(typeof subpath === "string" ? [subpath] : Object.values(subpath)),
    );
  targets.push(...Object.values(pkg.bin));
  return [
    ...new Set(
      targets
        .map((t) => t.replace(/^\.\//, ""))
        .filter((t) => t.endsWith(".mjs")),
    ),
  ].sort();
}

// drift-guard-ok: a second copy on purpose, not a drift guard — the point is
// to make LOWERING a gate cost a second, deliberate edit (CLAUDE.md's
// SSOT-contract rule), not to detect divergence.
/**
 * The agreed coverage floors, copied from `scripts/coverage.mjs`.
 *
 * This is a second copy on purpose. A floor
 * asserted only as `> 0` can be quietly dropped to 1 in a PR that is really
 * about something else, which is precisely the silent weakening this whole
 * change argues against. Raising a floor is equally deliberate: edit both.
 *
 * This pins the floor DOWNWARD only. The upward half — a floor left so far
 * behind the measurement that whole modules could go untested with CI green,
 * which is exactly what happened while `functions` sat at 72% against a measured
 * 90% — is enforced at run time by `assertRatcheted` in scripts/coverage.mjs,
 * because only the coverage run knows the measurement.
 */
const SRC_FLOORS = {
  lines: 100,
  branches: 100,
  functions: 100,
  statements: 100,
};
const HOOK_FLOORS = { lines: 93, branches: 88, functions: 87, statements: 93 };

/** The hook layer's mutation ratchet, same contract as the coverage floors. */
const HOOK_SCOPE_BREAK = 30;

/**
 * The `.hooks/lib` tooling's mutation ratchet.
 *
 * 1 is a LIVENESS bar, not a quality one: the scope has never been measured (it
 * joins the gate in the same change that adds this), and the aggregator refuses
 * a scope that scored no mutants, so a threshold of 1 still fails a matrix that
 * stopped mutating it. Raise this and `toolingScopeBreak` together once the
 * first CI run reports the real score.
 */
const TOOLING_SCOPE_BREAK = 1;

/** Parse "src/a.mjs:1-50,src/b.mjs" into [{file, ranged}, ...]. */
const parseMutate = (mutate) =>
  mutate.split(",").map((entry) => {
    const [file, range] = entry.split(":");
    return { file, ranged: range !== undefined };
  });

describe("shipped sources", () => {
  it("is a non-empty set containing the known entry points of every area", () => {
    // Non-vacuity: an empty or src-only list would make every assertion below
    // pass while measuring nothing. Name one file per shipped area.
    assert.ok(
      shipped.length >= 25,
      `expected the shipped set to cover the whole package, got ${shipped.length} files`,
    );
    for (const known of [
      "src/index.mjs",
      "src/html.mjs",
      "claude-hooks/plugin-hooks.mjs",
      "claude-hooks/lib/hook-io.mjs",
      "claude-hooks/lib/redactor-client.mjs",
      "bin/sanitize-cli.mjs",
    ])
      assert.ok(
        shipped.includes(known),
        `${known} missing from shippedSources`,
      );
  });

  it("contains every .mjs named by package.json exports/files/bin", () => {
    for (const file of manifestMjs())
      assert.ok(
        shipped.includes(file),
        `${file} is published but not in the shipped set`,
      );
  });

  it("throws on a published file `files` does not pack, and on a glob it cannot expand", () => {
    // Non-vacuity for the two fail-loud branches: silently dropping either case
    // removes files from BOTH gates, which is the failure this module exists to
    // prevent. Driven over synthetic manifests in a scratch tree so the cases
    // are real inputs to the real resolver, not source-text assertions.
    const scratch = mkdtempSync(join(tmpdir(), "shipped-sources-"));
    try {
      mkdirSync(join(scratch, "lib"));
      writeFileSync(join(scratch, "lib", "a.mjs"), "");

      const manifest = (pkg) => {
        writeFileSync(join(scratch, "package.json"), JSON.stringify(pkg));
        return () => shippedSources(scratch);
      };

      assert.deepEqual(manifest({ files: ["lib/*.mjs"] })(), ["lib/a.mjs"]);
      assert.throws(
        manifest({ files: ["lib/*.mjs"], bin: { x: "./lib/b.mjs" } }),
        /does not pack/,
      );
      assert.throws(manifest({ files: ["lib/**/*.mjs"] }), /unsupported glob/);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });

  it("throws on a shipped file that falls in no gated scope", () => {
    // `hookScope` names its prefixes so an unclaimed path is refused rather
    // than swept under the hook layer's floors and mutation ratchet. At this
    // head every shipped file is claimed, so only a synthetic manifest can
    // reach the branch — without this the guard could be deleted green.
    const scratch = mkdtempSync(join(tmpdir(), "shipped-scope-"));
    try {
      mkdirSync(join(scratch, "lib"));
      writeFileSync(join(scratch, "lib", "a.mjs"), "");
      writeFileSync(
        join(scratch, "package.json"),
        JSON.stringify({ files: ["lib/*.mjs"] }),
      );
      // The offending path must be NAMED: an error that only says "some file"
      // leaves the reader diffing the shipped set by hand.
      assert.throws(() => hookScope(scratch), /in no gated scope: lib\/a\.mjs/);

      mkdirSync(join(scratch, "bin"));
      writeFileSync(join(scratch, "bin", "cli.mjs"), "");
      writeFileSync(
        join(scratch, "package.json"),
        JSON.stringify({ files: ["bin/*.mjs"] }),
      );
      assert.deepEqual(hookScope(scratch), ["bin/cli.mjs"]);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });
});

describe("coverage gate covers the shipped set", () => {
  it("partitions every shipped file into exactly one scope", () => {
    const perScope = SCOPES.map((scope) => scope.files(repoRoot));
    for (const files of perScope) assert.ok(files.length > 0);
    const union = perScope.flat();
    assert.equal(
      new Set(union).size,
      union.length,
      "coverage scopes must not overlap (a file would be gated twice)",
    );
    assert.deepEqual(
      [...union].sort(),
      shipped,
      "coverage scopes must together cover exactly the shipped set",
    );
  });

  it("pins both scopes' floors at their agreed values", () => {
    // Scopes are matched by the file set they RESOLVE to, not by which helper
    // they were built from, so inlining an equivalent predicate keeps working
    // while genuinely dropping src/ from its own 100% floor still fails.
    const covering = (expected) => {
      const wanted = JSON.stringify(expected(repoRoot));
      return SCOPES.find(
        (scope) => JSON.stringify(scope.files(repoRoot)) === wanted,
      );
    };

    for (const [scopeName, resolves, floors] of [
      ["src/", srcScope, SRC_FLOORS],
      ["the hook layer", hookScope, HOOK_FLOORS],
    ]) {
      const scope = covering(resolves);
      assert.ok(scope, `no coverage scope resolves to the ${scopeName} files`);
      // Per-metric first, so a metric DELETED from `thresholds` (which a
      // `> 0` loop over the live object cannot notice — it simply iterates one
      // fewer entry) fails with the metric named…
      for (const [metric, floor] of Object.entries(floors))
        assert.equal(
          scope.thresholds[metric],
          floor,
          `${scopeName} ${metric} floor changed; see the FLOORS note above`,
        );
      // …then whole-object, so an extra metric cannot sneak in unpinned.
      assert.deepEqual(scope.thresholds, floors);
    }
  });

  it("fails a floor that has fallen too far behind its measurement", () => {
    // The ratchet's upward half. Pinned like the floors themselves: widening
    // the slack retires the check as surely as lowering a floor does, so it
    // costs a second deliberate edit.
    assert.equal(RATCHET_SLACK, 6);

    const scope = { name: "probe", thresholds: { lines: 90, functions: 70 } };
    // Exactly at the limit is still fine; one hundredth past it is not — the
    // boundary is where an off-by-one would hide.
    assert.doesNotThrow(() =>
      assertRatcheted(scope, { lines: 96, functions: 76 }),
    );
    assert.throws(
      () => assertRatcheted(scope, { lines: 96, functions: 76.01 }),
      /stopped ratcheting[\s\S]*functions: measured 76\.01%, floor 70%/,
    );
    // Metrics the summary reports but no floor names (c8 emits `branchesTrue`)
    // must not be compared against a floor that does not exist.
    assert.doesNotThrow(() =>
      assertRatcheted(scope, { lines: 90, functions: 70, branchesTrue: 100 }),
    );
    // A floor whose metric the report does not carry gates nothing, so it fails
    // rather than being skipped — the fail-open this whole script exists to close.
    assert.throws(
      () => assertRatcheted(scope, { lines: 100 }),
      /has a functions floor, but the coverage summary reports no functions/,
    );
    // The message has to name BOTH files, or the fix is a scavenger hunt.
    assert.throws(
      () => assertRatcheted(scope, { lines: 100, functions: 70 }),
      (error) => {
        assert.match(error.message, /scripts\/coverage\.mjs/);
        assert.match(error.message, /test\/shipped-gates\.test\.mjs/);
        return true;
      },
    );
  });

  it("walks a --src root for every directory the shipped set lives in", () => {
    // c8 only DISCOVERS a zero-execution file underneath a `--src` root; one
    // outside every root is absent from the report, and c8 then skips the
    // threshold check rather than scoring it 0% (verified against c8 11: an
    // include with no matching walked file exits 0 under --check-coverage).
    // A shipped file in a new top-level directory would still be in a coverage
    // scope and in the shard matrix, so every other assertion here stays green
    // — this is the one that notices.
    // Fixed inputs first, so a hardcoded return (the bug) or an empty one fails
    // here rather than agreeing with whatever the live shipped set happens to be.
    assert.deepEqual(srcRoots(["a/x.mjs", "a/y.mjs", "b/c/z.mjs"]), ["a", "b"]);
    assert.deepEqual(srcRoots([]), []);

    const roots = srcRoots(shipped);
    assert.ok(roots.length > 0);
    for (const file of shipped)
      assert.ok(
        roots.includes(file.split("/")[0]),
        `${file} has no --src root, so c8 would never walk it`,
      );
  });

  it("routes `pnpm test` through the derived-include wrapper", () => {
    // The floors only apply if this is the command CI runs; a plain `c8 node
    // --test` would silently fall back to c8's defaults and gate nothing.
    for (const script of ["test", "coverage"])
      assert.equal(pkg.scripts[script], "node scripts/coverage.mjs");
    assert.equal(pkg.scripts["test:mutation"], "node scripts/mutate.mjs");
  });
});

describe("mutation gate covers the mutated set", () => {
  const shards = expandShards(repoRoot);
  const entries = shards.flatMap((shard) => parseMutate(shard.mutate));

  it("puts every mutated file in the shard matrix, whole files exactly once", () => {
    assert.deepEqual(
      [...new Set(entries.map((e) => e.file))].sort(),
      mutated,
      "the expanded shard matrix must cover exactly the mutated set — expand-shards.mjs derives it, so a mismatch is a bug in that derivation, not a missing config entry",
    );

    // A split file is deliberately spread over several line-ranged shards (the
    // ranges are proven to tile in mutation-shards.test.mjs). A whole-file entry
    // appearing twice would double-mutate it and skew the aggregate score.
    const wholeFileCounts = new Map();
    for (const { file, ranged } of entries) {
      if (ranged) continue;
      wholeFileCounts.set(file, (wholeFileCounts.get(file) ?? 0) + 1);
    }
    for (const [file, count] of wholeFileCounts)
      assert.equal(count, 1, `${file} appears in ${count} whole-file shards`);
  });

  it("passes the whole mutated set to an unsharded run", () => {
    assert.deepEqual(mutateSpec(repoRoot).split(","), mutated);
  });

  it("mutates the .hooks/lib tooling, derived from the directory", () => {
    // The tooling half is not in the manifest, so nothing else in this file
    // would notice it vanishing from the gate. Both halves are asserted
    // non-empty: an empty `toolingSources` would make the equality above hold
    // against a shard matrix that had also dropped it.
    const tooling = toolingSources(repoRoot);
    assert.ok(
      tooling.includes(`${TOOLING_SCOPE}guarded-data-scan.mjs`),
      `expected the guard-pair scanner in the tooling scope, got ${tooling.join(", ") || "nothing"}`,
    );
    for (const file of tooling)
      assert.ok(
        mutated.includes(file),
        `${file} is in the tooling scope but not in the mutated set`,
      );
    // Disjoint by construction; an overlap would double-count in the aggregate,
    // whose scopes partition on the same two prefixes.
    assert.deepEqual(
      shipped.filter((file) => file.startsWith(TOOLING_SCOPE)),
      [],
    );
  });

  it("keeps `mutate` out of stryker.conf.json so it cannot go stale", () => {
    // The config used to pin `src/*.mjs`; that hardcoded list is what excluded
    // the hook layer for the life of the gate. Both entry points now pass
    // --mutate explicitly (scripts/mutate.mjs and run-mutation-shard.sh), and a
    // re-added key would silently win back for anything that forgets to.
    const conf = JSON.parse(
      readFileSync(join(repoRoot, "stryker.conf.json"), "utf8"),
    );
    assert.equal(conf.mutate, undefined);
  });

  it("gates the hook and tooling scopes on their own explicit, non-zero break thresholds", () => {
    const shardConf = JSON.parse(
      readFileSync(join(repoRoot, ".github", "mutation-shards.json"), "utf8"),
    );
    const strykerConf = JSON.parse(
      readFileSync(join(repoRoot, "stryker.conf.json"), "utf8"),
    );
    assert.ok(
      shardConf.hookScopeBreak >= HOOK_SCOPE_BREAK,
      `hookScopeBreak is a ratchet: it may rise above ${HOOK_SCOPE_BREAK} (raise HOOK_SCOPE_BREAK with it) but never fall, got ${shardConf.hookScopeBreak}`,
    );
    assert.ok(
      shardConf.toolingScopeBreak >= TOOLING_SCOPE_BREAK,
      `toolingScopeBreak is a ratchet: it may rise above ${TOOLING_SCOPE_BREAK} (raise TOOLING_SCOPE_BREAK with it) but never fall, got ${shardConf.toolingScopeBreak}`,
    );
    // src/ keeps its own long-standing floor; the hook ratchet must never be
    // used as an excuse to lower it.
    assert.ok(strykerConf.thresholds.break >= 83);
  });
});
