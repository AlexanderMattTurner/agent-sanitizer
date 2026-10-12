// drift-guard-ok: a tool-generated artifact kept for a hard constraint (the
// bundle must not carry css-tree's 400 KB mdn-data load), guarded by exactly
// this committed == regenerate(css-tree, src/html.mjs) freshness check.
/**
 * `src/css-syntax-data.mjs` must equal what `scripts/gen-css-syntax.mjs`
 * derives from the INSTALLED css-tree and the CURRENT src/html.mjs. The lexer
 * that decides which inline-style declarations a browser drops reads these
 * grammars; a css-tree bump, or a detector reading a new property, without a
 * regenerate would leave the cascade judging declarations against stale or
 * missing grammar.
 *
 * Regenerate with `node scripts/gen-css-syntax.mjs`.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

// @ts-ignore -- css-tree ships no bundled types.
import { Lexer } from "css-tree/lexer";
// @ts-ignore -- see above.
import generate from "css-tree/generator";
import { deriveCssSyntax } from "../scripts/gen-css-syntax.mjs";
import { CSS_SYNTAX } from "../src/css-syntax-data.mjs";

describe("css-syntax-data SSOT", () => {
  it("the committed grammar tables equal the derivation", () => {
    const derived = deriveCssSyntax();
    // Non-vacuity: an emptied derivation would compare equal to an emptied
    // module and prove nothing.
    for (const property of ["display", "font", "all", "padding-block-end"])
      assert.ok(Object.hasOwn(derived.properties, property), property);
    assert.deepEqual(
      {
        types: { ...CSS_SYNTAX.types },
        properties: { ...CSS_SYNTAX.properties },
      },
      { types: { ...derived.types }, properties: { ...derived.properties } },
    );
  });

  it("keeps only the properties a reader names, closed over references", () => {
    // `-moz-opacity` is kept as the basename the lexer falls back to; a
    // non-property literal is not kept at all.
    const derived = deriveCssSyntax('nodeOf("-moz-opacity"); "bogus" "none"');
    assert.deepEqual(Object.keys(derived.properties), ["opacity"]);
    assert.deepEqual(Object.keys(derived.types), ["opacity-value"]);
    // Every `<type>`/`<'property'>` the kept grammars reference resolves.
    const lexer = new Lexer({ generic: true, ...CSS_SYNTAX }, { generate });
    assert.equal(lexer.validate(), null);
  });
});
