/**
 * Contract test for the sharded mutation-testing matrix.
 *
 * `.github/mutation-shards.json` declares which files to mutate: big files under
 * `split` are chunked into `splitEvery`-line slices, the rest are hand-balanced
 * whole-file `groups`. `.github/scripts/expand-shards.mjs` turns that into the
 * concrete matrix at CI time from each file's real length. The sharded workflow
 * enumerates files explicitly — so a newly shipped file, or a hole in a split
 * file's slices, would be mutated by nobody and the gate would silently fail
 * open over uncovered code.
 *
 * This guards both holes against the EXPANDED matrix (what CI actually runs):
 * every mutated `.mjs` is covered exactly once, and each split file's slices
 * tile [1, EOF) with no gap or overlap, ending open. The mutated set comes from
 * `scripts/shipped-sources.mjs` — the package manifest for the shipped half and
 * the `.hooks/lib/` directory for the tooling half — not from a `readdir` of
 * `src/`; reading only `src/` is what let the whole `claude-hooks/` layer sit
 * outside the gate while this test stayed green.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  expandShards,
  EOF_SENTINEL,
} from "../.github/scripts/expand-shards.mjs";
import { mutatedSources } from "../scripts/shipped-sources.mjs";

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();

const config = JSON.parse(
  readFileSync(join(repoRoot, ".github", "mutation-shards.json"), "utf8"),
);
const shards = expandShards(repoRoot);

/** Parse "src/a.mjs:1-50,src/b.mjs" into [{file, start?, end?}, ...]. */
const parseMutate = (mutate) =>
  mutate.split(",").map((entry) => {
    const [file, range] = entry.split(":");
    if (!range) return { file };
    const [start, end] = range.split("-").map(Number);
    return { file, start, end };
  });

describe("mutation shard matrix", () => {
  it("expands to a non-empty matrix of {id, mutate} shards with unique ids", () => {
    assert.ok(shards.length > 0, "expander produced no shards");
    for (const shard of shards) {
      assert.equal(typeof shard.id, "string");
      assert.equal(typeof shard.mutate, "string");
    }
    const ids = shards.map((s) => s.id);
    assert.equal(
      new Set(ids).size,
      ids.length,
      "shard ids must be unique (they key the per-shard incremental cache and artifact name)",
    );
  });

  it("covers exactly the .mjs files the gate mutates", () => {
    const onDisk = mutatedSources(repoRoot);

    const inShards = [
      ...new Set(
        shards.flatMap((s) => parseMutate(s.mutate).map((e) => e.file)),
      ),
    ].sort();

    assert.deepEqual(
      inShards,
      onDisk,
      "shard file set must equal the mutated .mjs set (add a `split` entry or `group` when a published file or a .hooks/lib module is added/removed)",
    );
  });

  it("tiles every split file's slices with no gap or overlap, ending open", () => {
    assert.ok(config.split?.length > 0, "expected at least one split file");
    const splitFiles = new Set(config.split.map((s) => s.file));

    const byFile = new Map();
    for (const shard of shards) {
      for (const entry of parseMutate(shard.mutate)) {
        if (entry.start === undefined) continue;
        if (!byFile.has(entry.file)) byFile.set(entry.file, []);
        byFile.get(entry.file).push(entry);
      }
    }

    assert.deepEqual(
      [...byFile.keys()].sort(),
      [...splitFiles].sort(),
      "line-range slices must appear for exactly the declared split files",
    );

    for (const [file, ranges] of byFile) {
      ranges.sort((a, b) => a.start - b.start);
      assert.equal(ranges[0].start, 1, `${file}: first slice must start at 1`);
      for (let i = 1; i < ranges.length; i++) {
        assert.equal(
          ranges[i].start,
          ranges[i - 1].end + 1,
          `${file}: slice ${i} must start one line after the previous slice ends (no gap/overlap)`,
        );
      }
      assert.ok(
        ranges.at(-1).end >= EOF_SENTINEL,
        `${file}: last slice must end open (>= ${EOF_SENTINEL}) so the tail is always mutated`,
      );

      // No slice may start past the file's real end: that shard would mutate
      // zero lines and cover nothing while this test stays green. The expander
      // derives slice count from the live length, so this holds by construction
      // — pin it so a regression in the expander is caught.
      const lineCount = readFileSync(join(repoRoot, file), "utf8").split(
        "\n",
      ).length;
      for (const range of ranges) {
        assert.ok(
          range.start <= lineCount,
          `${file}: slice start ${range.start} is past the file's real line count (${lineCount})`,
        );
      }
    }
  });

  it("caps every split slice at splitEvery lines (last slice excepted, it ends open)", () => {
    const { splitEvery } = config;
    for (const shard of shards) {
      for (const entry of parseMutate(shard.mutate)) {
        if (entry.start === undefined || entry.end >= EOF_SENTINEL) continue;
        assert.equal(
          entry.end - entry.start + 1,
          splitEvery,
          `${shard.id}: interior slice must be exactly ${splitEvery} lines`,
        );
      }
    }
  });
});
