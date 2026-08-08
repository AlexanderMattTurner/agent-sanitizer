/**
 * Shared test helpers.
 */
import { occurrences } from "../src/view-map.mjs";

/**
 * The bytes a needle splice may NOT touch: every index of the ORIGINAL `text`
 * not covered by an occurrence of any needle, in order. A set-union oracle,
 * independent of the collect-sort-splice `spliceOrdered` performs — it is the
 * exact expected residue of a deletion when no two needles' matches overlap,
 * and a lower bound on what must survive when they do (an overlapping match is
 * dropped, never applied at a shifted offset). Shared so the splice and Layer-5
 * suites cannot drift into two subtly different oracles.
 * @param {string} text
 * @param {string[]} needles
 * @returns {string}
 */
export function keptOutsideNeedles(text, needles) {
  const covered = new Array(text.length).fill(false);
  for (const needle of needles)
    for (const index of occurrences(text, needle))
      for (let i = index; i < index + needle.length; i++) covered[i] = true;
  let out = "";
  for (let i = 0; i < text.length; i++) if (!covered[i]) out += text[i];
  return out;
}

/**
 * fast-check run options. A fixed seed is replayed when FC_REPRODUCIBLE=1, which
 * the seed-pinned CI jobs set (mutation.yaml pins it; the PR/push test run is
 * meant to as well) so a green run stays green and any failure is reproducible
 * from the logged seed. Only the nightly unseeded fuzz job (fuzz-nightly.yaml)
 * leaves the flag unset — there fast-check randomizes and keeps surfacing new
 * counterexamples across a broader slice of the input space.
 * @param {import("fast-check").Parameters} [overrides]
 */
export function fcRunOptions(overrides = {}) {
  const reproducible = process.env.FC_REPRODUCIBLE === "1";
  return {
    verbose: false,
    ...(reproducible ? { seed: 0x5eed1234 } : {}),
    ...overrides,
  };
}

/** String.fromCodePoint shorthand used throughout the Unicode tests. */
export const cp = (codePoint) => String.fromCodePoint(codePoint);
