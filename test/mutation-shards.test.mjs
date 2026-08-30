/**
 * Contract test for the sharded mutation-testing matrix.
 *
 * `.github/mutation-shards.json` declares which big files to chunk into
 * `splitEvery`-line slices and how many whole-file shards to spread the rest
 * over; `.github/scripts/expand-shards.mjs` derives the membership from
 * `scripts/shipped-sources.mjs` and the ranges from each file's real length.
 * The sharded workflow enumerates files explicitly — so a newly shipped file,
 * or a hole in a split file's slices, would be mutated by nobody and the gate
 * would silently fail open over uncovered code.
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
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  expandShards,
  EOF_SENTINEL,
} from "../.github/scripts/expand-shards.mjs";
import { mutatedSources, shippedSources } from "../scripts/shipped-sources.mjs";

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();

const config = JSON.parse(
  readFileSync(join(repoRoot, ".github", "mutation-shards.json"), "utf8"),
);
const shards = expandShards(repoRoot);

/**
 * A throwaway repo the expander can be driven over end to end.
 *
 * `src/*.mjs` is what the scratch manifest packs and `.hooks/lib` is read
 * straight off disk, so `mutatedSources` resolves for real — the derivation
 * under test is the live one, not a stand-in.
 *
 * @param {{split?: {id: string, file: string, splitEvery?: unknown}[],
 *   groupCount?: number, splitEvery?: number,
 *   src?: Record<string, number>, tooling?: Record<string, number>,
 *   packs?: string[]}} spec file names mapped to their line counts
 * @returns {string} the scratch repo root
 */
function scratchRepo({
  split = [],
  groupCount = 2,
  splitEvery = 300,
  src = {},
  tooling = {},
  packs = ["src/*.mjs"],
}) {
  const root = mkdtempSync(join(tmpdir(), "mutation-shards-"));
  mkdirSync(join(root, ".github"));
  mkdirSync(join(root, "src"));
  mkdirSync(join(root, ".hooks", "lib"), { recursive: true });
  const write = (dir, files) => {
    for (const [name, lines] of Object.entries(files))
      writeFileSync(join(root, dir, name), "const x = 1;\n".repeat(lines));
  };
  write("src", src);
  write(join(".hooks", "lib"), tooling);
  writeFileSync(join(root, "package.json"), JSON.stringify({ files: packs }));
  writeFileSync(
    join(root, ".github", "mutation-shards.json"),
    JSON.stringify({ splitEvery, split, groupCount }),
  );
  return root;
}

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

  it("puts a newly mutated file in a shard with no config edit", () => {
    // The whole point of deriving membership: adding a module used to mean
    // hand-typing it into `groups`, and forgetting to left it mutated by
    // nobody while every other check stayed green.
    const root = scratchRepo({ src: { "a.mjs": 5, "b.mjs": 5 } });
    try {
      const configPath = join(root, ".github", "mutation-shards.json");
      const before = readFileSync(configPath, "utf8");
      assert.deepEqual(
        expandShards(root)
          .flatMap((s) => parseMutate(s.mutate))
          .map((e) => e.file)
          .sort(),
        ["src/a.mjs", "src/b.mjs"],
      );

      writeFileSync(join(root, "src", "c.mjs"), "const x = 1;\n");
      const files = expandShards(root)
        .flatMap((s) => parseMutate(s.mutate))
        .map((e) => e.file);
      assert.deepEqual(files.sort(), ["src/a.mjs", "src/b.mjs", "src/c.mjs"]);
      assert.equal(
        files.filter((f) => f === "src/c.mjs").length,
        1,
        "the new file must land in exactly one shard",
      );
      assert.equal(readFileSync(configPath, "utf8"), before);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("balances the group shards by line count, not file count", () => {
    // The heavy file is LAST in path order on purpose: assigning in path order
    // hands it to a shard that already holds a small file, so one runner does
    // ~900 lines plus change while the other does 3. Longest-first is what
    // isolates it. A shard's runtime tracks the mutants in it, not the paths.
    const root = scratchRepo({
      groupCount: 2,
      src: { "a1.mjs": 3, "a2.mjs": 3, "zbig.mjs": 900 },
    });
    try {
      const groups = expandShards(root).map((s) => s.mutate);
      assert.deepEqual(groups, ["src/zbig.mjs", "src/a1.mjs,src/a2.mjs"]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("refuses a split entry the mutated set does not contain", () => {
    // A rename that updates the file but not the split entry: the stale shard
    // mutates an unscored path while the real file falls into the groups.
    const root = scratchRepo({
      packs: ["src/a.mjs"],
      src: { "a.mjs": 5, "unpacked.mjs": 5 },
      split: [{ id: "stale", file: "src/unpacked.mjs" }],
    });
    try {
      assert.throws(
        () => expandShards(root),
        /splits src\/unpacked\.mjs, which the mutated set does not contain/,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("refuses a groupCount that would leave a shard mutating nothing", () => {
    const root = scratchRepo({
      groupCount: 3,
      src: { "a.mjs": 5, "b.mjs": 5 },
    });
    try {
      assert.throws(
        () => expandShards(root),
        /groupCount is 3 but only 2 mutated file\(s\) remain/,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("refuses a groupCount that is not a positive integer", () => {
    // The config is rewritten rather than passed through `scratchRepo`, so the
    // MISSING-key case really is missing: a helper default would silently
    // supply the very value under test.
    for (const groupCount of [0, -1, 2.5, "7", null, undefined]) {
      const root = scratchRepo({ src: { "a.mjs": 5, "b.mjs": 5 } });
      try {
        writeFileSync(
          join(root, ".github", "mutation-shards.json"),
          JSON.stringify({ splitEvery: 300, split: [], groupCount }),
        );
        assert.throws(
          () => expandShards(root),
          /groupCount must be a positive integer/,
          `groupCount ${JSON.stringify(groupCount)} must be refused`,
        );
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    }
  });

  it("caps every split slice at its entry's splitEvery (last slice excepted, it ends open)", () => {
    const widthOf = new Map(
      config.split.map((entry) => [
        entry.file,
        entry.splitEvery ?? config.splitEvery,
      ]),
    );
    let checked = 0;
    for (const shard of shards) {
      for (const entry of parseMutate(shard.mutate)) {
        if (entry.start === undefined || entry.end >= EOF_SENTINEL) continue;
        const width = widthOf.get(entry.file);
        assert.equal(
          entry.end - entry.start + 1,
          width,
          `${shard.id}: interior slice must be exactly ${width} lines`,
        );
        checked++;
      }
    }
    // Every split file could be short enough to be one open-ended slice, in
    // which case the loop above asserts nothing at all.
    assert.ok(checked > 0, "no interior slice was measured");
  });

  it("narrows only the entry that overrides splitEvery", () => {
    const root = scratchRepo({
      splitEvery: 300,
      src: { "wide.mjs": 600, "narrow.mjs": 600, "grouped.mjs": 5 },
      split: [
        { id: "wide", file: "src/wide.mjs" },
        { id: "narrow", file: "src/narrow.mjs", splitEvery: 200 },
      ],
      groupCount: 1,
    });
    try {
      const ranges = Object.fromEntries(
        expandShards(root).map((s) => [s.id, s.mutate]),
      );
      // Both files are 600 written lines, so `split("\n")` counts 601 and each
      // gets one extra slice past the last full-width boundary.
      assert.deepEqual(
        Object.entries(ranges).filter(([id]) => !id.startsWith("group-")),
        [
          ["wide-1", "src/wide.mjs:1-300"],
          ["wide-2", "src/wide.mjs:301-600"],
          ["wide-3", `src/wide.mjs:601-${EOF_SENTINEL}`],
          ["narrow-1", "src/narrow.mjs:1-200"],
          ["narrow-2", "src/narrow.mjs:201-400"],
          ["narrow-3", "src/narrow.mjs:401-600"],
          ["narrow-4", `src/narrow.mjs:601-${EOF_SENTINEL}`],
        ],
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("refuses a per-entry splitEvery that is not a positive integer", () => {
    // `null` is absent from this list on purpose: `??` treats it as "not set"
    // and falls back to the global width, which is a valid expansion.
    for (const splitEvery of [0, -1, 2.5, "7"]) {
      const root = scratchRepo({
        src: { "a.mjs": 5, "b.mjs": 5, "c.mjs": 5 },
        split: [{ id: "bad", file: "src/a.mjs", splitEvery }],
      });
      try {
        assert.throws(
          () => expandShards(root),
          /split entry bad has splitEvery .*, which is not a positive integer/,
          `per-entry splitEvery ${JSON.stringify(splitEvery)} must be refused`,
        );
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    }
  });
});

describe("the dry-run oracle's scope", () => {
  // The oracle instruments whatever this CLI prints. Printing the SHIPPED
  // subset is what let it pass on exactly the commits where a shard was about
  // to die: the matrix mutates the `.hooks/lib/` tooling too, and a dry-run
  // failure there is invisible to an oracle that never instrumented it.
  it("prints everything the shards mutate, tooling included", () => {
    const printed = execFileSync(
      process.execPath,
      [join(repoRoot, "scripts", "shipped-sources.mjs")],
      { encoding: "utf8" },
    )
      .trim()
      .split("\n");
    assert.deepEqual(printed, mutatedSources(repoRoot));
    // Without this the assertion above holds just as well while the two sets
    // are equal, which is the state it exists to rule out.
    assert.ok(
      mutatedSources(repoRoot).length > shippedSources(repoRoot).length,
      "the tooling half of the mutated set is empty — this proves nothing",
    );
  });
});
