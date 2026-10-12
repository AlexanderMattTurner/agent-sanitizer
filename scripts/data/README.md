# Vendored Unicode Character Database slices

Every Unicode property the sanitizer's behaviour depends on is read from these
files, never from the running Node's `\p{…}` (whose answer moves with its ICU:
Node 22.22 is Unicode 16, Node 22.23 is Unicode 17). All of them are cut from
ONE Unicode version, `UNICODE_VERSION` in `scripts/lib/ucd.mjs` (**17.0.0**), by
`scripts/extract-ucd-slices.mjs` from the official text files at
<https://www.unicode.org/Public/17.0.0/ucd/>. The extractor refuses a file whose
header names another version. `test/unicode-property-pin.test.mjs` fails on a
live property escape in `src/`, `claude-hooks/` or a `scripts/gen-*.mjs`.

Each JSON slice keeps the `{ range: [start, end?], <field>: value }` entry shape
and only the values a generator reads:

| Slice                                  | Source file                                                                           | Kept                                                                     | Read by                                                           |
| -------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------- |
| `DerivedJoiningType.json`              | `extracted/DerivedJoiningType.txt`                                                    | every `Joining_Type`                                                     | `gen-joining-type.mjs` → `src/joining-type.mjs`                   |
| `IndicSyllabicCategory.Virama.json`    | `IndicSyllabicCategory.txt`                                                           | `Virama` (the joiner trigger)                                            | `gen-joining-type.mjs`                                            |
| `IndicSyllabicCategory.Consonant.json` | `IndicSyllabicCategory.txt`                                                           | `Consonant` (the bases a virama may sit on)                              | `gen-joining-type.mjs`                                            |
| `Scripts.Pinned.json`                  | `Scripts.txt`                                                                         | the scripts owning a virama, plus Braille and Hangul                     | `gen-joining-type.mjs`, `gen-unicode-properties.mjs`              |
| `DerivedGeneralCategory.Cf.json`       | `extracted/DerivedGeneralCategory.txt`                                                | `Cf`                                                                     | `gen-invisible-charset.mjs` → `src/cf-charset.mjs` + Python JSON  |
| `PropList.Pinned.json`                 | `PropList.txt`                                                                        | `Unified_Ideograph`, `Variation_Selector`                                | `gen-unicode-properties.mjs`, `gen-standardized-variants.mjs`     |
| `emoji-data.Pinned.json`               | `emoji/emoji-data.txt`                                                                | `Emoji`, `Emoji_Presentation`, `Emoji_Modifier`, `Extended_Pictographic` | `gen-unicode-properties.mjs` → `src/unicode-properties.mjs`       |
| `emoji-zwj-sequences.Rgi.json`         | `emoji/emoji-zwj-sequences.txt` (from <https://www.unicode.org/Public/17.0.0/emoji/>) | every `RGI_Emoji_ZWJ_Sequence`, as code points                           | `gen-unicode-properties.mjs`                                      |
| `StandardizedVariants.txt`             | `StandardizedVariants.txt`                                                            | verbatim                                                                 | `gen-standardized-variants.mjs` → `src/standardized-variants.mjs` |

Do not cut these from the `ucd-full` npm package: `ucd-full@17.0.0` ships
Unicode **16** data (its PropList lacks CJK Extension J, U+323B0–U+33479, and
its Extended_Pictographic is Unicode 16's 3537 code points where Unicode 17 has
2848). `test/unicode-properties.test.mjs` compares every pinned table with the
live escape on a Node whose Unicode is the pin, which is how that surfaced.

To refresh for a new Unicode version: download the nine files above into one
directory (`emoji-zwj-sequences.txt` comes from the version's `emoji/`
directory, not `ucd/`), bump `UNICODE_VERSION` in `scripts/lib/ucd.mjs`, run
`node scripts/extract-ucd-slices.mjs <dir>`, `pnpm format`, then every generator
(`pnpm gen:unicode-properties`, `pnpm gen:joining-type`,
`node scripts/gen-invisible-charset.mjs`,
`node scripts/gen-standardized-variants.mjs`). The contract tests fail if any
committed module drifts from these slices.
