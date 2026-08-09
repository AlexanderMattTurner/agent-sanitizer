/**
 * Shared test helpers.
 */
import { createServer } from "node:net";
import fc from "fast-check";

import { occurrences } from "../src/view-map.mjs";

/**
 * A SUBSTITUTING stub redactor daemon over the real socket protocol (4-byte BE
 * length prefix + JSON): it redacts exactly `secret` wherever it appears and
 * reports nothing to redact (null) otherwise, so redaction is observable
 * per-text instead of a fixed canned reply. Lives here because the hook suites
 * that need one all need the identical wire handling; the per-suite copies
 * predate this helper.
 * @param {string} socketPath
 * @param {{ secret: string, mark: string }} substitution
 * @returns {Promise<import("node:net").Server>}
 */
export function startStubRedactorDaemon(socketPath, { secret, mark }) {
  const server = createServer((sock) => {
    // Thousands of short-lived connections run through this in a fuzz suite;
    // without a handler a socket 'error' is re-thrown and takes down the test
    // runner with an unattributable stack.
    sock.on("error", () => {});
    const chunks = [];
    sock.on("data", (chunk) => {
      chunks.push(chunk);
      const buf = Buffer.concat(chunks);
      if (buf.length < 4) return;
      const expected = buf.readUInt32BE(0);
      if (buf.length < 4 + expected) return;
      const request = JSON.parse(
        buf.subarray(4, 4 + expected).toString("utf8"),
      );
      const reply = request.text.includes(secret)
        ? { text: request.text.replaceAll(secret, mark), found: ["StubSecret"] }
        : null;
      const body = Buffer.from(JSON.stringify(reply), "utf8");
      const header = Buffer.allocUnsafe(4);
      header.writeUInt32BE(body.length, 0);
      sock.end(Buffer.concat([header, body]));
    });
  });
  return new Promise((resolve) =>
    server.listen(socketPath, () => resolve(server)),
  );
}

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
 * the seed-pinned CI jobs set (mutation.yaml and node-tests.yaml both pin it)
 * so a green run stays green and any failure is reproducible
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

/**
 * Any single code point except the surrogate range, astral included, so
 * `fromCodePoint` never throws (fast-check v4 dropped `fc.fullUnicode`). Lone
 * surrogates are injected separately via `loneSurrogate` as raw UTF-16 units.
 * One canonical copy so the property suites can't drift onto subtly different
 * input distributions.
 */
export const unicodeChar = fc
  .integer({ min: 0, max: 0x10ffff })
  .filter((code) => code < 0xd800 || code > 0xdfff)
  .map((code) => String.fromCodePoint(code));

/** A lone UTF-16 surrogate code unit (D800–DFFF), the ill-formed-string half
 * of the fuzz alphabet `unicodeChar` deliberately excludes. */
export const loneSurrogate = fc
  .integer({ min: 0xd800, max: 0xdfff })
  .map((code) => String.fromCharCode(code));
