/**
 * The redactor daemon's wire protocol, on the Node side: the one codec every
 * party that speaks it here (the client, and the stand-in daemons the tests
 * serve) derives from.
 *
 * The protocol itself is python/agent_sanitizer/secrets/data/redactor-protocol.json,
 * which the Python daemon reads too: the frame cap and the exact shape of every
 * request and response. A frame is a 4-byte big-endian body length, then that
 * many bytes of UTF-8 JSON, in both directions.
 */
import PROTOCOL from "../../python/agent_sanitizer/secrets/data/redactor-protocol.json" with { type: "json" };

export { PROTOCOL };

// Refuse absurd frames rather than buffer unbounded, in either direction.
export const FRAME_CAP = PROTOCOL.frame_cap;

const HEADER_BYTES = 4;

/** @typedef {Record<string, string>} Shape protocol field name -> field type */

/**
 * Whether `value` is of protocol field type `kind` (see the protocol file's
 * description). An unknown type throws: it is a defect in the protocol file,
 * never a verdict on the value.
 * @param {unknown} value
 * @param {string} kind
 * @returns {boolean}
 */
function hasType(value, kind) {
  switch (kind) {
    case "string":
      return typeof value === "string";
    case "boolean":
      return typeof value === "boolean";
    case "index":
      return Number.isSafeInteger(value) && /** @type {number} */ (value) >= 0;
    case "string-list":
      return Array.isArray(value) && value.every((v) => typeof v === "string");
    case "string-map":
      return (
        isPlainObject(value) &&
        Object.values(value).every((v) => typeof v === "string")
      );
    case "pair-list":
      return (
        Array.isArray(value) && value.every((v) => conforms(v, PROTOCOL.pair))
      );
    default:
      throw new Error(`unknown protocol field type ${JSON.stringify(kind)}`);
  }
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
export function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Whether `value` is an object with exactly `shape`'s fields, each of its
 * declared protocol type.
 * @param {unknown} value
 * @param {Shape} shape
 * @returns {boolean}
 */
export function conforms(value, shape) {
  if (!isPlainObject(value)) return false;
  const names = Object.keys(shape);
  return (
    Object.keys(value).length === names.length &&
    names.every(
      (name) => Object.hasOwn(value, name) && hasType(value[name], shape[name]),
    )
  );
}

/**
 * One frame carrying `value`. Throws (with no errno, so the client does not
 * mistake it for a dead daemon) when the body exceeds the frame cap, which the
 * peer would refuse unread.
 * @param {unknown} value
 * @returns {Buffer}
 */
export function encodeFrame(value) {
  const body = Buffer.from(JSON.stringify(value), "utf8");
  if (body.length > FRAME_CAP) {
    throw new Error(
      `redactor frame of ${body.length} bytes exceeds the ${FRAME_CAP}-byte frame cap`,
    );
  }
  const header = Buffer.allocUnsafe(HEADER_BYTES);
  header.writeUInt32BE(body.length, 0);
  return Buffer.concat([header, body]);
}

/**
 * Reassembles one frame from the chunks a stream delivers. Holds a running
 * byte total so the backlog is concatenated at most twice (header, then the
 * whole frame) rather than on every chunk, which would be quadratic.
 */
export class FrameReader {
  /** @type {Buffer[]} */
  #chunks = [];
  #received = 0;
  /** @type {number | null} */
  #expected = null;

  /**
   * Feed one chunk. Returns `{ value }` once the whole frame has arrived and
   * undefined before then; throws on a header over the frame cap or a body
   * that is not JSON.
   * @param {Buffer} chunk
   * @returns {{ value: unknown } | undefined}
   */
  push(chunk) {
    this.#chunks.push(chunk);
    this.#received += chunk.length;
    if (this.#expected === null) {
      if (this.#received < HEADER_BYTES) return undefined;
      this.#expected = this.#joined().readUInt32BE(0);
      if (this.#expected > FRAME_CAP) {
        throw new Error(
          `redactor frame header claims ${this.#expected} bytes, over the ${FRAME_CAP}-byte frame cap`,
        );
      }
    }
    const end = HEADER_BYTES + this.#expected;
    if (this.#received < end) return undefined;
    return {
      value: JSON.parse(
        this.#joined().subarray(HEADER_BYTES, end).toString("utf8"),
      ),
    };
  }

  /** The bytes buffered so far, copying only when more than one chunk is held. */
  #joined() {
    return this.#chunks.length === 1
      ? this.#chunks[0]
      : Buffer.concat(this.#chunks, this.#received);
  }
}
