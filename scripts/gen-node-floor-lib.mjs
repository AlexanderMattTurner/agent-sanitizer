#!/usr/bin/env node
/**
 * Emit `plugin/scripts/lib/node-floor.sh` from `package.json`'s `engines.node`.
 *
 * The floor is declared once, for npm, in `engines.node`. The plugin launcher
 * needs the same number at runtime — an unsupported runtime kills the bundle
 * before it can answer, and without the floor that is indistinguishable from a
 * corrupt install — and it runs inside an installed plugin, where this
 * `package.json` is not on disk. So the number is RENDERED into a shell lib that
 * ships with the plugin rather than re-typed there.
 *
 * A build-time emitter, deliberately standalone (the same split as
 * `gen-fail-open-lib.mjs`): nothing a hook imports at runtime should carry a
 * shell template.
 *
 * `plugin/scripts/build-plugin.mjs` writes the file (`pnpm build:plugin`); it is
 * git-ignored and baked onto the `plugin-dist` branch with the rest of the
 * plugin's build output. `node scripts/gen-node-floor-lib.mjs` prints the bytes.
 */
import { readFileSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
export const OUTPUT_PATH = join("plugin", "scripts", "lib", "node-floor.sh");

/**
 * The major version a `engines.node` range requires.
 *
 * Only the `>=N` spelling is accepted, and anything else throws rather than
 * being approximated: a range this parser guessed at would put a WRONG floor in
 * an operator-facing diagnosis, which is worse than the build failing here.
 * @param {unknown} declared
 * @returns {number}
 */
export function parseNodeMajorFloor(declared) {
  const match = /^>=\s*(\d+)(?:\.\d+)*$/.exec(String(declared ?? ""));
  if (!match)
    throw new Error(
      `package.json engines.node is ${JSON.stringify(declared)}, which this ` +
        `generator cannot render as a single major-version floor. Either write ` +
        `it as ">=N", or teach ${OUTPUT_PATH}'s consumer the richer range.`,
    );
  return Number(match[1]);
}

/**
 * The major version this package's own `engines.node` requires.
 * @returns {number}
 */
export function nodeMajorFloor() {
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  return parseNodeMajorFloor(pkg.engines?.node);
}

/**
 * The bytes of `plugin/scripts/lib/node-floor.sh`: the floor plus the two
 * helpers the launcher diagnoses with.
 * @returns {string}
 */
export function nodeFloorShellLib() {
  const floor = nodeMajorFloor();
  return `# shellcheck shell=bash
# GENERATED from engines.node in package.json by scripts/gen-node-floor-lib.mjs
# — do not edit by hand. Rebuild with:
#
#   pnpm build:plugin
#
# The plugin launcher runs inside an INSTALLED plugin, where package.json is not
# on disk, so it cannot read the floor at runtime. Rather than re-type the
# number there (where it would drift the day engines.node moves),
# scripts/safe-launch.sh sources this. plugin/test/node-floor-parity.test.mjs
# asserts the shell comparison agrees with the declared range.
#
# Sourced, never executed — hence no shebang and no +x bit.
AGENT_SANITIZER_NODE_MAJOR_FLOOR=${floor}

# The major version \`$1\` (a node binary) reports, or nothing when it cannot be
# asked or answered something unrecognizable. Empty means UNKNOWN, and every
# caller treats unknown as "do not claim a version fault" — a wrong version
# diagnosis sends an operator to reinstall a runtime that was fine.
agent_sanitizer_node_major() {
  local reported major
  reported="$("$1" --version 2>/dev/null)" || return 0
  # \`v22.14.0\` -> \`22\`; anything without that shape yields nothing.
  case "$reported" in
  v[0-9]*)
    major="\${reported#v}"
    major="\${major%%.*}"
    case "$major" in
    *[!0-9]*) return 0 ;;
    *) ;;
    esac
    printf '%s' "$major"
    ;;
  *) ;;
  esac
}

# Returns 0 when \`$1\` (a node binary) is at or above the floor, or when its
# version could not be determined; 1 only when it is DEFINITELY too old.
agent_sanitizer_node_meets_floor() {
  local major
  major="$(agent_sanitizer_node_major "$1")"
  [[ -z "$major" ]] && return 0
  ((major >= AGENT_SANITIZER_NODE_MAJOR_FLOOR))
}
`;
}

if (
  process.argv[1] &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
)
  process.stdout.write(nodeFloorShellLib());
