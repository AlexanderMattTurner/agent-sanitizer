#!/usr/bin/env node
/**
 * Wall-clock cost of the three BLOCKING hook paths, by document shape and size.
 *
 * `test/hook-latency.test.mjs` gates these same entry points in calibration
 * units, which is what makes it survive a loaded CI runner — but a ratio cannot
 * tell you whether a 256 KB paste costs 4 ms or 400 ms on a laptop, and it
 * cannot be differenced across two revisions. This prints the milliseconds, so a
 * change can be quoted before and after with the same method.
 *
 * The shapes mirror the suite's. Sizes span the range the hooks actually see: a
 * few KB of ordinary prose, a large paste, and a multi-megabyte log — the last
 * one is where a super-linear path stops being a slow hook and becomes a hang.
 *
 * Usage:
 *   node scripts/bench-hooks.mjs                     # 4 KB, 256 KB, 8 MB
 *   node scripts/bench-hooks.mjs --sizes 4096,262144 # explicit sizes, in bytes
 *   node scripts/bench-hooks.mjs --runs 1            # timed calls per cell
 *   node scripts/bench-hooks.mjs --json              # one JSON row per line
 */
import { classifyPrompt } from "../src/prompt.mjs";
import { scanText } from "../src/instructions.mjs";
import { sanitizeText } from "../src/output.mjs";

const cp = (n) => String.fromCodePoint(n);
const grow = (unit, n) => unit.repeat(Math.ceil(n / unit.length)).slice(0, n);

/** @type {Record<string, (n: number) => string>} */
export const SHAPES = {
  "ascii-prose": (n) =>
    grow("The quick brown fox jumps over the lazy dog. ", n),
  "cjk-prose": (n) => grow("速い茶色の狐が怠惰な犬を飛び越える。", n),
  "emoji-prose": (n) => grow("🙂 ok 🚀 go 🎉 ", n),
  "html-prose": (n) =>
    grow(
      "<p>The quick brown fox <b>jumps</b> over the <i>lazy</i> dog.</p>\n",
      n,
    ),
  "joiner-dense": (n) => grow("می" + cp(0x200c) + "خواهم ", n),
  "vs-dense": (n) => grow("漢" + cp(0xe0100), n),
  "emoji-zwj": (n) => grow("\u{1F3F3}️‍\u{1F308}", n),
  "payload-run": (n) => grow(cp(0x200b), n),
  "payload-scattered": (n) => grow("a" + cp(0x00ad), n),
};

/** The blocking entry points, called the way their hooks call them. */
export const ENTRIES = {
  scanText: (text) => scanText(text),
  classifyPrompt: (text) => classifyPrompt(text),
  sanitizeText: (text) => sanitizeText(text, { html: true, exfilScan: true }),
};

const DEFAULT_SIZES = [4 * 1024, 256 * 1024, 8 * 1024 * 1024];
const DEFAULT_RUNS = 4;

/** The fastest of `runs` timed calls after a warm-up, in ms. The minimum rather
 * than the median: it is the measurement least polluted by whatever else the
 * machine was doing, which is what a before/after comparison wants.
 * @param {() => unknown | Promise<unknown>} fn @param {number} runs */
async function fastest(fn, runs) {
  await fn();
  let best = Infinity;
  for (let i = 0; i < runs; i++) {
    const started = performance.now();
    await fn();
    best = Math.min(best, performance.now() - started);
  }
  return best;
}

/**
 * Every (size, shape, entry) cell, in milliseconds — or `null` with the thrown
 * error's name when a cell does not survive. A throw IS the measurement for that
 * cell (today an 8 MB run of zero-widths overflows V8's RegExp stack inside
 * `scanText`), and a harness that died on the first one would report nothing
 * about the other twenty-six.
 *
 * `onRow` is handed each cell the moment it is measured. An 8 MB sweep over the
 * pre-optimization sources runs for tens of minutes, and a harness that only
 * printed at the end loses every completed cell to the timeout that stops it.
 *
 * @param {number[]} sizes @param {number} runs
 * @param {(row: {size: number, entry: string, shape: string, ms: number | null, error?: string}) => void} onRow
 */
export async function benchmark(sizes, runs, onRow = () => {}) {
  /** @type {Array<{ size: number, entry: string, shape: string, ms: number | null, error?: string }>} */
  const rows = [];
  for (const size of sizes)
    for (const [shape, generate] of Object.entries(SHAPES)) {
      const text = generate(size);
      for (const [entry, run] of Object.entries(ENTRIES)) {
        const row = await fastest(() => run(text), runs).then(
          (ms) => ({ size, entry, shape, ms }),
          (err) => ({
            size,
            entry,
            shape,
            ms: null,
            error: /** @type {Error} */ (err).constructor.name,
          }),
        );
        onRow(row);
        rows.push(row);
      }
    }
  return rows;
}

const args = process.argv.slice(2);
const sizesArg = args.indexOf("--sizes");
const sizes =
  sizesArg === -1
    ? DEFAULT_SIZES
    : args[sizesArg + 1].split(",").map((n) => Number(n));
const runsArg = args.indexOf("--runs");
const runs = runsArg === -1 ? DEFAULT_RUNS : Number(args[runsArg + 1]);
const asJson = args.includes("--json");
const rows = await benchmark(sizes, runs, (row) => {
  if (asJson) console.log(JSON.stringify(row));
});

if (!asJson) {
  const label = (n) => (n >= 1 << 20 ? `${n >> 20} MB` : `${n >> 10} KB`);
  for (const size of sizes) {
    console.log(`\n${label(size)}`);
    console.log(
      `  ${"shape".padEnd(18)}${Object.keys(ENTRIES)
        .map((e) => e.padStart(16))
        .join("")}`,
    );
    for (const shape of Object.keys(SHAPES))
      console.log(
        `  ${shape.padEnd(18)}${Object.keys(ENTRIES)
          .map(
            (entry) =>
              /** @type {{ ms: number | null }} */ (
                rows.find(
                  (r) =>
                    r.size === size && r.entry === entry && r.shape === shape,
                )
              ).ms
                ?.toFixed(1)
                .padStart(16) ?? "throws".padStart(16),
          )
          .join("")}`,
      );
  }
}
