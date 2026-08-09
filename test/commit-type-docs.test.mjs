/**
 * SSOT guard: three docs hand-enumerate the Conventional Commit types that
 * `config/javascript/commitlint.config.js` actually enforces (today by
 * extending `@commitlint/config-conventional`). Each of those lists has already
 * drifted once — all three omitted `revert` — so this asserts set equality
 * between that config's resolved `type-enum` and every doc's enumeration,
 * resolving the `extends` chain rather than reading the preset directly: a
 * local `rules` override must move the docs too. The extraction is
 * asserted non-empty per doc, so a rephrased sentence that dodges the regex
 * fails loudly instead of passing vacuously.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// Resolved from the config the repo actually ENFORCES, not from the preset it
// happens to extend today: a `rules: { "type-enum": [...] }` override added to
// commitlint.config.js would otherwise leave this guard checking the docs
// against a list nobody enforces. The `extends` chain is walked the way
// commitlint walks it — depth-first, a config's own `rules` winning over the
// presets it extends.
const CONFIG_URL = new URL(
  "../config/javascript/commitlint.config.js",
  import.meta.url,
);

/**
 * @param {{extends?: string|string[], rules?: Record<string, unknown>}} config
 * @param {URL|null} baseUrl  the config's own location, for relative `extends`
 * @returns {Promise<Record<string, unknown>>}
 */
async function resolveRules(config, baseUrl) {
  const rules = {};
  for (const preset of [config.extends ?? []].flat()) {
    if (!preset.startsWith(".")) {
      // A bare package preset resolves through node; a relative `extends`
      // inside one would need that package's own path, which this guard does
      // not model — such a preset throws below rather than silently dropping
      // the rules it contributes.
      Object.assign(
        rules,
        await resolveRules((await import(preset)).default, null),
      );
      continue;
    }
    if (!baseUrl)
      throw new Error(
        `cannot resolve relative extends "${preset}" reached through a package preset`,
      );
    const url = new URL(preset, baseUrl);
    Object.assign(
      rules,
      await resolveRules((await import(url.href)).default, url),
    );
  }
  return Object.assign(rules, config.rules ?? {});
}

const enforcedRules = await resolveRules(
  (await import(CONFIG_URL.href)).default,
  CONFIG_URL,
);
const typeEnum = enforcedRules["type-enum"];
const [, , enforcedTypes] = typeEnum ?? [];

/**
 * Each doc's enumeration, located by the sentence that introduces it (not by
 * grepping for individual type names, which would match unrelated prose) and
 * parsed as either backticked or bare comma-separated tokens.
 */
const DOCS = [
  {
    file: "CONTRIBUTING.md",
    // "Types: `feat`, `fix`, ... `revert`." — backticked, wraps across lines.
    sentence: /Types: (`[a-z]+`(?:,\s*`[a-z]+`)*)\./u,
    token: /`([a-z]+)`/gu,
  },
  {
    file: "CLAUDE.md",
    // "Types: feat, fix, ... revert." — bare comma-separated tokens.
    sentence: /Types: ([a-z]+(?:, [a-z]+)*)\./u,
    token: /([a-z]+)/gu,
  },
  {
    file: ".claude/skills/conventional-commits/SKILL.md",
    // "- Allowed types: `feat`, `fix`, ..." — backticked, single line.
    sentence: /Allowed types: (`[a-z]+`(?:,\s*`[a-z]+`)*)/u,
    token: /`([a-z]+)`/gu,
  },
];

describe("commit-type documentation matches the commitlint config", () => {
  it("a type-enum was actually resolved from the enforcing config", () => {
    // Non-vacuity: without this, a config whose extends chain stopped
    // contributing `type-enum` would leave `enforcedTypes` undefined and every
    // doc comparison below would fail for an unrelated reason (or, with a
    // permissive default, pass against nothing).
    assert.ok(
      Array.isArray(typeEnum),
      `no type-enum resolved from ${CONFIG_URL.pathname}; resolved rules: ${JSON.stringify(Object.keys(enforcedRules))}`,
    );
    assert.ok(Array.isArray(enforcedTypes), "type-enum has no value list");
    assert.ok(enforcedTypes.length > 0, "resolved type-enum is empty");
  });

  it("a local rules override would win over the extended preset", async () => {
    // The whole reason this guard reads the repo's config instead of the
    // preset: proven here rather than assumed, so the resolution cannot
    // silently degrade into "the preset's rules, always".
    const rules = await resolveRules(
      {
        extends: ["@commitlint/config-conventional"],
        rules: { "type-enum": [2, "always", ["only-this"]] },
      },
      null,
    );
    assert.deepEqual(rules["type-enum"], [2, "always", ["only-this"]]);
    // Positive marker: the preset really was loaded and merged under it.
    assert.ok(Object.keys(rules).length > 1);
  });

  for (const { file, sentence, token } of DOCS) {
    it(`${file} enumerates exactly the enforced types`, () => {
      const text = readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
      const match = text.match(sentence);
      assert.ok(
        match,
        `${file}: no type-enumeration sentence found — if the wording changed, update this test's sentence regex in the same commit`,
      );
      const documented = [...match[1].matchAll(token)].map((m) => m[1]);
      assert.ok(documented.length > 0, `${file}: extracted no type tokens`);
      assert.deepEqual(
        [...documented].sort(),
        [...enforcedTypes].sort(),
        `${file}: documented commit types differ from the type-enum config/javascript/commitlint.config.js enforces`,
      );
    });
  }
});
