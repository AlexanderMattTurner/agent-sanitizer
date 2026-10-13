/**
 * sanitize-output's post-sanitization key-collision recovery.
 *
 * Two raw field names can sanitize to the same name (`label` and a `label`
 * carrying a zero-width space Layer 1 strips). Overwriting one would hand back
 * an object with fewer keys than the raw response, which the harness rejects —
 * showing the RAW, unvetted output (fail OPEN). The recovery withholds the
 * colliding values only: siblings keep their sanitized data, the field count is
 * preserved, and the warning names where the collision sat.
 *
 * Every fixture avoids the Layer-4 secret-hint vocabulary (`token`, `key`,
 * `secret`, …) and every control character apart from the zero-width space
 * (and, for the many-field case, word joiner) that forces the collision, so no
 * live redactor daemon is needed.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  assertLinear,
  describeGrowth,
  geometricSizes,
  growth,
  timed,
} from "./helpers/cpu-timing.mjs";
import {
  sanitizeValue,
  collisionWarning,
  COLLISION_WITHHELD_MESSAGE,
} from "../claude-hooks/sanitize-output.mjs";

// Built from a code point so no raw invisible byte sits in this source (this
// file is itself scanned by the repo's own guards).
const ZW = String.fromCharCode(0x200b);

/** Run the walk and hand back the value plus the accumulated warnings. */
async function walk(value) {
  /** @type {string[]} */
  const warnings = [];
  const result = await sanitizeValue(value, "mcp__evil__list", warnings);
  return { ...result, warnings };
}

/** A second invisible character Layer 1 strips from a key, beside `ZW`. */
const WJ = String.fromCharCode(0x2060);

/**
 * `{k: "0"}` plus `n` more raw keys that all sanitize to `k`. Each spells its
 * index in binary over two stripped characters at one fixed width, so every
 * key is the same length at every `n`: one zero-width space repeated `i` times
 * would grow the INPUT quadratically in `n`, and a cost gate over it would read
 * quadratic for a linear walk.
 * @param {number} n
 */
function collidingFields(n) {
  const width = 12;
  assert.ok(n < 2 ** width, `${n} fields do not fit ${width} bits`);
  /** @type {Record<string, string>} */
  const fields = { k: "0" };
  for (let i = 1; i <= n; i++) {
    let key = "k";
    for (let bit = 0; bit < width; bit++) key += (i >> bit) & 1 ? WJ : ZW;
    fields[key] = String(i);
  }
  return fields;
}

/** The collision warnings only — Layer 1 also warns about the stripped key. */
const collisions = (warnings) =>
  warnings.filter((warning) => warning.includes("collapsed to the name"));

describe("sanitize-output: key-collision recovery", () => {
  it("withholds only the colliding values, leaving siblings intact", async () => {
    const { value, modified, warnings } = await walk({
      a: { label: "legit-value", [`label${ZW}`]: "planted-value" },
      b: { keep: "untouched", nested: ["one", "two"] },
    });

    // The sibling subtree is byte-identical.
    assert.deepEqual(value.b, { keep: "untouched", nested: ["one", "two"] });
    // Both colliding values are withheld — the hook cannot tell the legitimate
    // field from the planted one, and insertion order is the attacker's.
    assert.equal(value.a.label, COLLISION_WITHHELD_MESSAGE);
    assert.equal(
      value.a["label [withheld duplicate 2]"],
      COLLISION_WITHHELD_MESSAGE,
    );
    assert.equal(JSON.stringify(value).includes("planted-value"), false);
    assert.equal(JSON.stringify(value).includes("legit-value"), false);
    // Field count preserved: a shape REDUCTION is what makes the harness fall
    // back to the raw output.
    assert.equal(Object.keys(value.a).length, 2);
    assert.equal(modified, true);
    assert.deepEqual(collisions(warnings), [collisionWarning("label", "a")]);
  });

  it("names the top level when the collision is not nested", async () => {
    const { warnings } = await walk({ id: "x", [`id${ZW}`]: "y" });
    assert.deepEqual(collisions(warnings), [collisionWarning("id", "")]);
    assert.match(collisions(warnings)[0], /at the top level/);
  });

  it("withholds a colliding value's whole subtree, leaving no leaf behind", async () => {
    const { value } = await walk({
      cfg: { deep: { leaf: "some text", flag: true, count: 7 } },
      [`cfg${ZW}`]: "planted",
    });
    // The WHOLE value goes, not a leaf-wise walk of it: a shape-preserving
    // suppressor rewrites only string leaves, so `flag`/`count` would survive
    // while the warning claimed the field was withheld.
    assert.equal(value.cfg, COLLISION_WITHHELD_MESSAGE);
    assert.equal(
      value["cfg [withheld duplicate 2]"],
      COLLISION_WITHHELD_MESSAGE,
    );
    assert.equal(JSON.stringify(value).includes("some text"), false);
  });

  it("withholds colliding NON-string values too", async () => {
    // The misattribution this guard exists to prevent does not care about the
    // value's type: an attacker-chosen number under a legitimate field name is
    // exactly the substitution being refused.
    const { value, warnings } = await walk({
      n: 1,
      [`n${ZW}`]: 999,
      ok: true,
      [`ok${ZW}`]: null,
    });
    assert.equal(value.n, COLLISION_WITHHELD_MESSAGE);
    assert.equal(value["n [withheld duplicate 2]"], COLLISION_WITHHELD_MESSAGE);
    assert.equal(value.ok, COLLISION_WITHHELD_MESSAGE);
    assert.equal(
      value["ok [withheld duplicate 2]"],
      COLLISION_WITHHELD_MESSAGE,
    );
    assert.equal(JSON.stringify(value).includes("999"), false);
    assert.equal(collisions(warnings).length, 2);
  });

  it("collapses N raw keys into N slots with one warning", async () => {
    // Correctness for the memo the cost gate below times: every field still
    // lands in its own slot, and the warning is per name, not per field.
    const { value, warnings } = await walk(collidingFields(400));
    assert.equal(Object.keys(value).length, 401);
    assert.equal(new Set(Object.values(value)).size, 1);
    assert.equal(collisions(warnings).length, 1);
  });

  timed("does not rescan from the first slot on each collision", async (t) => {
    // Non-vacuity for the memo: N fields collapsing to one name is an
    // attacker-composable input, and an O(N^2) probe is a stall onto the
    // raw-output fail-open. Restarting the probe at 2 on every collision read
    // exponent 1.85 here, the memoized probe 1.05.
    const curve = await growth(
      (n, attempt) => collidingFields(n - attempt),
      (fields) => walk(fields),
      geometricSizes(200, 1600),
    );
    t.diagnostic(describeGrowth(curve));
    assertLinear("the collision walk", curve);
  });

  it("handles three raw keys collapsing to one name, warning once", async () => {
    const { value, warnings } = await walk({
      k: "1",
      [`k${ZW}`]: "2",
      [`k${ZW}${ZW}`]: "3",
    });
    assert.deepEqual(Object.keys(value), [
      "k",
      "k [withheld duplicate 2]",
      "k [withheld duplicate 3]",
    ]);
    assert.equal(collisions(warnings).length, 1);
    for (const key of Object.keys(value))
      assert.equal(value[key], COLLISION_WITHHELD_MESSAGE);
  });

  it("does not clobber a raw key that already looks like a withheld slot", async () => {
    const { value } = await walk({
      k: "1",
      "k [withheld duplicate 2]": "pre-existing",
      [`k${ZW}`]: "2",
    });
    // The pre-existing field keeps its own sanitized value; the collision takes
    // the next free slot instead of overwriting it.
    assert.equal(value["k [withheld duplicate 2]"], "pre-existing");
    assert.equal(value["k [withheld duplicate 3]"], COLLISION_WITHHELD_MESSAGE);
    assert.equal(Object.keys(value).length, 3);
  });

  it("leaves a collision-free object byte-identical and unflagged", async () => {
    const input = {
      stdout: "all good\n",
      stderr: "",
      nested: { list: [1, "two", null, false] },
    };
    const { value, modified, warnings } = await walk(input);
    assert.deepEqual(value, input);
    assert.equal(modified, false);
    assert.deepEqual(warnings, []);
  });

  it("never lets a generated duplicate name overwrite a later raw field", async () => {
    // `a` and `a<ZW>` collapse to `a`; the first free generated name is
    // `a [withheld duplicate 2]`, which a LATER raw field already carries. The
    // generated name must step past it so that unrelated value survives.
    const { value, warnings } = await walk({
      a: "one",
      [`a${ZW}`]: "two",
      "a [withheld duplicate 2]": "raw-survivor",
    });
    // Exact entries, in order: neither colliding value survives anywhere.
    assert.deepEqual(Object.entries(value), [
      ["a", COLLISION_WITHHELD_MESSAGE],
      ["a [withheld duplicate 3]", COLLISION_WITHHELD_MESSAGE],
      ["a [withheld duplicate 2]", "raw-survivor"],
    ]);
    assert.deepEqual(collisions(warnings), [collisionWarning("a", "")]);
  });
});
