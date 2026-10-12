// drift-guard-ok: a tool-generated artifact kept for a hard constraint (the
// bundle must not carry css-tree's 400 KB mdn-data load), guarded by exactly
// this committed == regenerate(css-tree) freshness check.
/**
 * `src/css-syntax-data.mjs` must equal what `scripts/gen-css-syntax.mjs`
 * derives from the INSTALLED css-tree right now. The lexer that decides which
 * inline-style declarations a browser drops reads these grammars; a css-tree
 * bump that changes one without a regenerate would leave the cascade judging
 * declarations against stale grammar.
 *
 * Regenerate with `node scripts/gen-css-syntax.mjs`.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { deriveCssSyntax } from "../scripts/gen-css-syntax.mjs";
import { CSS_SYNTAX } from "../src/css-syntax-data.mjs";

describe("css-syntax-data SSOT", () => {
  it("the committed grammar tables equal the installed css-tree's", () => {
    const derived = deriveCssSyntax();
    // Non-vacuity: an emptied derivation would compare equal to an emptied
    // module and prove nothing.
    assert.ok(Object.keys(derived.properties).length > 500);
    assert.ok(Object.hasOwn(derived.properties, "display"));
    assert.deepEqual(
      {
        types: { ...CSS_SYNTAX.types },
        properties: { ...CSS_SYNTAX.properties },
      },
      { types: { ...derived.types }, properties: { ...derived.properties } },
    );
  });
});
