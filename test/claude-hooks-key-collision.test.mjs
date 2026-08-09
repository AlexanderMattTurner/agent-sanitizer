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
 * `secret`, …) and every control character apart from the one zero-width space
 * that forces the collision, so no live redactor daemon is needed.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
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

  it("withholds a colliding value's whole subtree, shape preserved", async () => {
    const { value } = await walk({
      cfg: { deep: { leaf: "some text", flag: true } },
      [`cfg${ZW}`]: "planted",
    });
    assert.deepEqual(value.cfg, {
      deep: { leaf: COLLISION_WITHHELD_MESSAGE, flag: true },
    });
    assert.equal(
      value["cfg [withheld duplicate 2]"],
      COLLISION_WITHHELD_MESSAGE,
    );
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
});
