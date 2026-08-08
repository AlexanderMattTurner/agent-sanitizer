# Vendored Unicode Character Database slices

Pinned inputs for `scripts/gen-joining-type.mjs` → `src/joining-type.mjs`.
Extracted from [`ucd-full`](https://www.npmjs.com/package/ucd-full)**@17.0.0**
(Unicode 17.0.0, matching Node 22's bundled ICU):

- `DerivedJoiningType.json` — verbatim `extracted/DerivedJoiningType.json`
  (every code point's `Joining_Type`).
- `IndicSyllabicCategory.Virama.json` — the `syllabicCategory === "Virama"`
  entries of `IndicSyllabicCategory.json` (the joiner trigger).
- `IndicSyllabicCategory.Consonant.json` — the `syllabicCategory === "Consonant"`
  entries of the same file. Intersected with `\p{Script=…}` (which the engine
  does expose) over the Brahmic scripts the joiner carve-out covers, these give
  `BRAHMIC_CONSONANT_RANGES` — the bases a virama may sit on.

To refresh for a new Unicode version: `pnpm add -D ucd-full@<v>`, re-extract these
three files, bump `UNICODE_VERSION` in the generator, run `pnpm gen:joining-type`,
then drop the dev dependency again. `test/joining-type.test.mjs` fails if the
committed module drifts from these slices.
