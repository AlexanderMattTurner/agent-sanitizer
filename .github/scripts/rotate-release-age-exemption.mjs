// Rotate pnpm-workspace.yaml's own-package `minimumReleaseAgeExclude` entry to
// the committed engine pin.
//
// The workspace deliberately exempts the pinned agent-sanitizer release from
// the 3-day third-party minimumReleaseAge window (it is built and published
// from this repository), and tests/test_minimum_release_age.py fails any
// exclude entry package.json no longer pins — so the entry must move with the
// `sanitizer-engine` alias. Renovate moves the alias but knows nothing about
// the workspace entry; plugin-dist-autofix.yaml runs this on every bump PR so
// the rotation lands in the same regeneration commit and the contract test
// stays green.
//
// String surgery on the one anchored list-item line rather than a YAML
// round-trip, so the file's comments survive. Exactly one entry must exist:
// zero means the exemption the rotation maintains is gone, more than one means
// a stale entry outlived its pin — both are states the contract test rejects,
// so fail loud here rather than guess.
//
// argv: [workspace-file] [pin] — production passes neither; the overrides let
// the test suite drive a scratch file with a chosen version.
import { readFileSync, writeFileSync } from "node:fs";
import { enginePin } from "../../plugin/scripts/build-plugin.mjs";

const [file = "pnpm-workspace.yaml", pinOverride] = process.argv.slice(2);
const pin = pinOverride ?? enginePin();

const text = readFileSync(file, "utf8");
const entries = [
  ...text.matchAll(/^(?<indent>[ \t]+)- agent-sanitizer@(?<version>\S+)$/gmu),
];
if (entries.length !== 1) {
  console.error(
    `${file}: expected exactly one "- agent-sanitizer@<version>" minimumReleaseAgeExclude entry, found ${entries.length}`,
  );
  process.exit(1);
}
const [entry] = entries;
// The named groups keep the pattern readable; the indexed reads are what the
// type system knows are strings.
const version = entry[2];
if (version === pin) {
  console.log(`exemption already names agent-sanitizer@${pin}`);
} else {
  writeFileSync(
    file,
    text.slice(0, entry.index) +
      `${entry[1]}- agent-sanitizer@${pin}` +
      text.slice(entry.index + entry[0].length),
  );
  console.log(
    `rotated minimumReleaseAgeExclude: agent-sanitizer@${version} -> agent-sanitizer@${pin}`,
  );
}
