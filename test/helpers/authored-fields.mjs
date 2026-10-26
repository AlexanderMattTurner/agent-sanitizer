/**
 * Addressing the fields `AUTHORED_FIELDS` declares, so a suite drives the LIVE
 * field map instead of a second hand-kept copy of it: a `key[].sub` spec
 * addresses `sub` on every element of the array at `key`, and both directions
 * (build an input, read the value back) have to agree about that shape.
 */

import { parseFieldSpec } from "../../src/file-write-tools.mjs";

/**
 * A tool_input carrying `value` in the field `spec` addresses.
 * @param {string} spec
 * @param {string} value
 * @returns {Record<string, unknown>}
 */
export function inputFor(spec, value) {
  const parsed = parseFieldSpec(spec);
  if ("key" in parsed) return { [parsed.key]: value };
  return { [parsed.arr]: [{ [parsed.sub]: value }] };
}

/**
 * The field `spec` addresses, read back out of a tool_input.
 * @param {string} spec
 * @param {any} input
 * @returns {unknown}
 */
export function readField(spec, input) {
  const parsed = parseFieldSpec(spec);
  if ("key" in parsed) return input[parsed.key];
  return input[parsed.arr][0][parsed.sub];
}
