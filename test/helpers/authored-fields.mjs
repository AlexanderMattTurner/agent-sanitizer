/**
 * Addressing the fields `AUTHORED_FIELDS` declares, so a suite drives the LIVE
 * field map instead of a second hand-kept copy of it: a `key[].sub` spec
 * addresses `sub` on every element of the array at `key`, and both directions
 * (build an input, read the value back) have to agree about that shape.
 */

const NESTED_SPEC = /^(?<arr>\w+)\[\]\.(?<sub>\w+)$/u;

/**
 * A tool_input carrying `value` in the field `spec` addresses.
 * @param {string} spec
 * @param {string} value
 * @returns {Record<string, unknown>}
 */
export function inputFor(spec, value) {
  const nested = NESTED_SPEC.exec(spec);
  if (!nested) return { [spec]: value };
  return { [nested.groups.arr]: [{ [nested.groups.sub]: value }] };
}

/**
 * The field `spec` addresses, read back out of a tool_input.
 * @param {string} spec
 * @param {any} input
 * @returns {unknown}
 */
export function readField(spec, input) {
  const nested = NESTED_SPEC.exec(spec);
  if (!nested) return input[spec];
  return input[nested.groups.arr][0][nested.groups.sub];
}
