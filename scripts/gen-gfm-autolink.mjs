#!/usr/bin/env node
/**
 * Generate `src/vendor/gfm-autolink-literal.mjs`: GFM autolink literals for
 * micromark, i.e. `micromark-extension-gfm-autolink-literal@2.1.0`'s
 * `lib/syntax.js` (MIT, (c) 2020 Titus Wormer; licence in LICENSE-THIRD-PARTY)
 * with ONE function changed by `scripts/patches/*.patch`. Nothing is committed
 * but the patch: `pnpm install` runs this through `prepare` and `npm pack`/
 * `publish` through `prepack`, like scripts/gen-unicode.mjs, and the output is
 * git-ignored.
 *
 * WHY A PATCH AT ALL. `previousUnbalanced` decides whether an autolink literal
 * may start at this position, and upstream answers it by walking back over
 * every event the document has produced so far. It memoizes only the "no"
 * answer, so one unclosed `[` — a JSON array is the everyday shape, since its
 * `]` is the last byte — makes the answer "yes" for the rest of the document
 * and costs one full walk per word character. 172 KB of prose behind a single
 * `[` took 20.2s to parse; the same text takes 0.17s patched. Layer 3 reads its
 * URLs off this parse, so the cost lands on every `detectExfil` call.
 *
 * WHAT THE PATCH CHANGES. One function. `previousUnbalanced` now also records
 * where the walk stopped, and a later walk resumes from that index rather than
 * re-reading the run before it. The record is used only while `events[index]`
 * still holds the same token, so a resolver that splices events invalidates it
 * and the walk falls back to reading everything.
 *
 * WHY NOT A PNPM PATCH. A `pnpm` patch fixes this repository's own installs and
 * the plugin bundle built from them, and reaches no consumer of the published
 * npm package. A generated module under `src/` ships in the tarball. The
 * upstream package is therefore a pinned devDependency: this script needs its
 * source at pack time, and the published package does not depend on it.
 *
 * WHY A SHA-256 PIN. The patch targets exactly 2.1.0's `lib/syntax.js`. A bump
 * that changes the file must fail here, loudly, instead of applying a stale
 * hunk to code it was not written against.
 *
 * WHEN TO DELETE IT. When a published release of the upstream package carries
 * an equivalent fix: drop this script, the patch, the devDependency, the
 * `gfm.mjs` assembly, and go back to `remark-gfm`.
 * `test/gfm-autolink-parity.test.mjs` pins the behaviour either way.
 *
 * Run from the repo root: `node scripts/gen-gfm-autolink.mjs`.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { applyPatch as applyUnifiedDiff, parsePatch } from "diff";

import { writeGenerated } from "./lib/write-generated.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));

export const UPSTREAM_PACKAGE = "micromark-extension-gfm-autolink-literal";
export const UPSTREAM_VERSION = "2.1.0";
/** SHA-256 of the 2.1.0 `lib/syntax.js` the patch was derived from. */
export const UPSTREAM_SHA256 =
  "2b45c68982c1f80daf125b709faba88803b131a0d710b0374dd309495a74efeb";
export const PATCH_PATH = join(
  __dirname,
  "patches",
  `${UPSTREAM_PACKAGE}@${UPSTREAM_VERSION}.patch`,
);
export const OUTPUT_PATH = join(
  __dirname,
  "..",
  "src",
  "vendor",
  "gfm-autolink-literal.mjs",
);

/** The installed upstream `lib/syntax.js`; the package's `exports` hides it, so
 * resolve its entry point and walk to the sibling. */
export function readUpstream() {
  const entry = createRequire(import.meta.url).resolve(UPSTREAM_PACKAGE);
  return readFileSync(join(dirname(entry), "lib", "syntax.js"), "utf8");
}

/**
 * Apply a unified diff of one file with jsdiff, without fuzz. The input is
 * pinned by hash, so jsdiff's offset search can only land the hunks where the
 * patch names them or not at all; either way a patch that fails to apply
 * throws instead of returning upstream's slow code.
 *
 * @param {string} source
 * @param {string} patch
 * @returns {string}
 */
export function applyPatch(source, patch) {
  const files = parsePatch(patch);
  if (files.length !== 1 || files[0].hunks.length === 0)
    throw new Error("patch: expected hunks for exactly one file");
  const patched = applyUnifiedDiff(source, files[0]);
  if (patched === false) throw new Error("patch: a hunk does not apply");
  return patched;
}

/**
 * The generated module's source: the pinned upstream file with the patch
 * applied, under a banner.
 *
 * @param {string} [upstream] the upstream source (default: the installed one)
 * @param {string} [patch] the unified diff (default: the committed patch)
 * @returns {string}
 */
export function renderGfmAutolink(
  upstream = readUpstream(),
  patch = readFileSync(PATCH_PATH, "utf8"),
) {
  const actual = createHash("sha256").update(upstream).digest("hex");
  if (actual !== UPSTREAM_SHA256)
    throw new Error(
      `${UPSTREAM_PACKAGE}'s lib/syntax.js hashes to ${actual}, not the ` +
        `${UPSTREAM_SHA256} of @${UPSTREAM_VERSION} that ` +
        `scripts/patches/${UPSTREAM_PACKAGE}@${UPSTREAM_VERSION}.patch targets. ` +
        "Re-derive the patch against the installed version, then update the " +
        "pinned version, hash and patch name together.",
    );
  // Upstream ships `syntax.js` without a final newline. Add it here so the
  // output is already what the repo's end-of-file fixer would make of it, and the
  // on-disk bytes cannot diverge from a fresh render once a hook has touched them.
  return `/**
 * GENERATED by scripts/gen-gfm-autolink.mjs at install, pack and build time;
 * git-ignored, never committed — DO NOT EDIT.
 *
 * \`${UPSTREAM_PACKAGE}@${UPSTREAM_VERSION}\`'s \`lib/syntax.js\` (MIT, (c) 2020
 * Titus Wormer; licence in LICENSE-THIRD-PARTY) with the one-function
 * \`previousUnbalanced\` performance fix from
 * \`scripts/patches/${UPSTREAM_PACKAGE}@${UPSTREAM_VERSION}.patch\`. The
 * generator's header says why it is patched and when to delete it.
 */
${applyPatch(upstream, patch).replace(/\n?$/, "\n")}`;
}

function main() {
  writeGenerated(OUTPUT_PATH, renderGfmAutolink());
  console.log(`wrote ${OUTPUT_PATH}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
