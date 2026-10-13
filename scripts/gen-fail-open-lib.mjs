#!/usr/bin/env node
/**
 * Emit `plugin/scripts/lib/fail-open.sh` from the JS source of truth.
 *
 * A build-time emitter, deliberately not part of `claude-hooks/lib/hook-io.mjs`:
 * that module is imported by every hook at runtime, and a shell template string
 * is not hook I/O. The closed set still lives there — this only renders it.
 *
 * `plugin/scripts/build-plugin.mjs` writes the file (`pnpm build:plugin`); it is
 * git-ignored and baked onto the `plugin-dist` branch with the rest of the
 * plugin's build output. `node scripts/gen-fail-open-lib.mjs` prints the bytes.
 */
import { realpathSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  FAIL_CLOSED_VALUES,
  FAIL_OPEN_ENV,
} from "../claude-hooks/lib/hook-io.mjs";

export const OUTPUT_PATH = join("plugin", "scripts", "lib", "fail-open.sh");

/**
 * The bytes of `plugin/scripts/lib/fail-open.sh`: a shell function deciding
 * the posture exactly as `failOpenEnabled()` does, rendered from
 * `FAIL_CLOSED_VALUES` so the shell and JS spellings come from one source.
 * @returns {string}
 */
export function failOpenShellLib() {
  return `# shellcheck shell=bash
# GENERATED from FAIL_CLOSED_VALUES in claude-hooks/lib/hook-io.mjs by
# scripts/gen-fail-open-lib.mjs — do not edit by hand. Rebuild with:
#
#   pnpm build:plugin
#
# The posture knob (${FAIL_OPEN_ENV}) has to be read by shell shims that
# cannot import the JS. Rather than restate the closed set in each of them, they
# source this one function. plugin/test/fail-open-parity.test.mjs asserts it
# decides exactly as failOpenEnabled() does, and tests/test_safe_launch.py
# asserts every remaining hand-written implementation agrees with it.
#
# Returns 0 to fail OPEN (the default: the guarded action runs, loudly), 1 to
# fail CLOSED (block/ask/suppress). Sourced, never executed — hence no shebang
# and no +x bit.
agent_sanitizer_fail_open() {
  case "\${${FAIL_OPEN_ENV}:-}" in
  ${FAIL_CLOSED_VALUES.join(" | ")}) return 1 ;;
  *) return 0 ;;
  esac
}
`;
}

if (
  process.argv[1] &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
)
  process.stdout.write(failOpenShellLib());
