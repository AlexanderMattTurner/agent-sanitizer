#!/usr/bin/env node
/**
 * Emit `plugin/scripts/lib/fail-open.sh` from the JS source of truth.
 *
 * A build-time emitter, deliberately not part of `claude-hooks/lib/hook-io.mjs`:
 * that module is imported by every hook at runtime, and a shell template string
 * is not hook I/O. The closed set still lives there — this only renders it.
 *
 * Usage: `pnpm gen:fail-open-lib` (writes the file), or `node
 * scripts/gen-fail-open-lib.mjs --stdout` to inspect the bytes.
 */
import { realpathSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  FAIL_CLOSED_VALUES,
  FAIL_OPEN_ENV,
} from "../claude-hooks/lib/hook-io.mjs";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
export const OUTPUT_PATH = join("plugin", "scripts", "lib", "fail-open.sh");

/**
 * The committed bytes of `plugin/scripts/lib/fail-open.sh`: a shell function
 * deciding the posture exactly as `failOpenEnabled()` does, rendered from
 * `FAIL_CLOSED_VALUES` so the shell and JS spellings cannot drift.
 *
 * Emitted already Prettier-clean (two-space indent, trailing newline) because a
 * generator whose output a formatter then rewrites makes the round-trip test
 * fail on a freshly regenerated file.
 * @returns {string}
 */
export function failOpenShellLib() {
  return `# shellcheck shell=bash
# GENERATED from FAIL_CLOSED_VALUES in claude-hooks/lib/hook-io.mjs by
# scripts/gen-fail-open-lib.mjs — do not edit by hand. Regenerate with:
#
#   pnpm gen:fail-open-lib
#
# The posture knob (${FAIL_OPEN_ENV}) has to be read by shell shims that
# cannot import the JS. Rather than restate the closed set in each of them, they
# source this one function. plugin/test/fail-open-parity.test.mjs asserts these
# bytes are what the generator still produces, and tests/test_safe_launch.py
# asserts every remaining hand-written implementation agrees with it.
#
# Returns 0 to fail OPEN (the default: the guarded action runs, loudly), 1 to
# fail CLOSED (block/ask/suppress). Sourced, never executed — hence no shebang
# and no +x bit (the repo's shebang/executable pre-commit hook pairs the two).
agent_sanitizer_fail_open() {
  case "\${${FAIL_OPEN_ENV}:-}" in
  ${FAIL_CLOSED_VALUES.join(" | ")}) return 1 ;;
  *) return 0 ;;
  esac
}
`;
}

// Importable without side effects: the parity test reads `failOpenShellLib()`
// and must not rewrite the committed file just by importing this module.
if (
  process.argv[1] &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  if (process.argv.includes("--stdout"))
    process.stdout.write(failOpenShellLib());
  else writeFileSync(join(ROOT, OUTPUT_PATH), failOpenShellLib());
}
