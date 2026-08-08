/**
 * Publishing gate for the Claude Code plugin: the two manifests users actually
 * install through — the repo-root `.claude-plugin/marketplace.json` and the
 * plugin's own `.claude-plugin/plugin.json` — stay schema-valid, mutually
 * consistent, and consistent with the install commands the READMEs advertise.
 *
 * Nothing else in CI reads these files: they are not imported, not bundled, and
 * not exercised by the hook tests, so a typo'd key or a renamed plugin ships
 * straight to every installer. The field lists below are the documented schemas
 * (code.claude.com/docs/en/plugins-reference and .../plugin-marketplaces); an
 * unrecognized key is a warning to Claude Code but an error here, which is what
 * `claude plugin validate --strict` would do without needing the CLI in CI.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { failOpenEnabled } from "../../claude-hooks/lib/hook-io.mjs";

const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const MARKETPLACE_PATH = join(ROOT, ".claude-plugin", "marketplace.json");
const MANIFEST_PATH = join(ROOT, "plugin", ".claude-plugin", "plugin.json");

const readJson = (path) => JSON.parse(readFileSync(path, "utf-8"));
const marketplace = readJson(MARKETPLACE_PATH);
const manifest = readJson(MANIFEST_PATH);

/** Documented top-level keys of marketplace.json. */
const MARKETPLACE_KEYS = new Set([
  "$schema",
  "name",
  "owner",
  "plugins",
  "description",
  "version",
  "metadata",
  "allowCrossMarketplaceDependenciesOn",
  "renames",
]);

/** Documented keys of plugin.json. */
const MANIFEST_KEYS = new Set([
  "$schema",
  "name",
  "displayName",
  "version",
  "description",
  "author",
  "homepage",
  "repository",
  "license",
  "keywords",
  "metadata",
  "defaultEnabled",
  "skills",
  "commands",
  "agents",
  "workflows",
  "hooks",
  "mcpServers",
  "outputStyles",
  "lspServers",
  "experimental",
  "dependencies",
]);

/** A marketplace entry may carry any plugin.json key plus these. */
const ENTRY_KEYS = new Set([
  ...MANIFEST_KEYS,
  "source",
  "category",
  "tags",
  "strict",
  "relevance",
]);

const KEBAB = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const SEMVER = /^[0-9]+\.[0-9]+\.[0-9]+$/;

// ─── marketplace.json ────────────────────────────────────────────────────────

test("marketplace.json carries the required fields and only documented keys", () => {
  assert.match(marketplace.name, KEBAB);
  assert.equal(typeof marketplace.owner?.name, "string");
  assert.ok(Array.isArray(marketplace.plugins));
  assert.ok(marketplace.plugins.length > 0);

  const unknown = Object.keys(marketplace).filter(
    (k) => !MARKETPLACE_KEYS.has(k),
  );
  assert.deepEqual(
    unknown,
    [],
    `unrecognized marketplace.json keys: ${unknown}`,
  );
});

test("every marketplace entry resolves to a real plugin inside the repo", () => {
  const seen = new Set();
  for (const entry of marketplace.plugins) {
    assert.match(entry.name, KEBAB);
    assert.ok(!seen.has(entry.name), `duplicate plugin entry: ${entry.name}`);
    seen.add(entry.name);

    const unknown = Object.keys(entry).filter((k) => !ENTRY_KEYS.has(k));
    assert.deepEqual(
      unknown,
      [],
      `unrecognized keys on entry ${entry.name}: ${unknown}`,
    );

    // Only relative in-repo sources are used here; a string source that stopped
    // being one means the distribution model changed and this test's
    // path-traversal and manifest checks below silently stop applying.
    assert.equal(typeof entry.source, "string");
    assert.ok(
      entry.source.startsWith("./"),
      `${entry.name}: source not relative`,
    );
    assert.ok(!isAbsolute(entry.source));
    assert.ok(
      !normalize(entry.source).startsWith(".."),
      `${entry.name}: source escapes the marketplace root`,
    );

    const dir = join(ROOT, entry.source);
    assert.ok(
      statSync(dir).isDirectory(),
      `${entry.name}: ${dir} is not a directory`,
    );
    assert.ok(
      existsSync(join(dir, ".claude-plugin", "plugin.json")),
      `${entry.name}: no plugin.json under ${entry.source}`,
    );

    // The docs are explicit that plugin.json's version wins silently over the
    // entry's, so a version here would be a value nobody can observe — and a
    // trap the moment the two drift.
    assert.equal(
      entry.version,
      undefined,
      `${entry.name}: pin the version in plugin.json, not the marketplace entry`,
    );
  }
});

// ─── plugin.json ─────────────────────────────────────────────────────────────

test("plugin.json carries the required fields and only documented keys", () => {
  assert.match(manifest.name, KEBAB);
  const unknown = Object.keys(manifest).filter((k) => !MANIFEST_KEYS.has(k));
  assert.deepEqual(unknown, [], `unrecognized plugin.json keys: ${unknown}`);
});

test("plugin.json declares the version Claude Code updates users on", () => {
  // Setting `version` PINS the plugin: users keep the cached copy until this
  // string changes, so every release must stamp it (version-bump.sh does, via
  // set-plugin-version.mjs). A non-semver value would be pinned just as hard.
  assert.match(manifest.version, SEMVER);
});

test("plugin.json and the marketplace entry name the same plugin", () => {
  const entry = marketplace.plugins.find((p) => p.source === "./plugin");
  assert.ok(entry, "no marketplace entry sources ./plugin");
  assert.equal(entry.name, manifest.name);
});

test("plugin.json licence matches the package it ships", () => {
  const pkg = readJson(join(ROOT, "package.json"));
  assert.equal(manifest.license, pkg.license);
});

test("the hooks Claude Code loads are where it looks for them", () => {
  // No `hooks` field: the plugin relies on the default `hooks/hooks.json`
  // discovery, so the file must be there. A manifest that grows a custom path
  // has to point at something that exists.
  const declared = manifest.hooks ?? "./hooks/hooks.json";
  assert.equal(
    typeof declared,
    "string",
    "custom hooks config is no longer a path",
  );
  const path = join(ROOT, "plugin", declared);
  assert.ok(existsSync(path), `hooks config missing: ${declared}`);
  assert.ok(Object.keys(readJson(path).hooks).length > 0);
});

test("neither description advertises a posture the hooks do not take", () => {
  // The default posture is fail-OPEN (a hook that cannot run warns and passes
  // the action through). Both descriptions are pre-install surfaces — the
  // marketplace entry is what `/plugin marketplace` lists, the manifest is what
  // the picker shows — and both claimed fail-closed for several releases after
  // the default flipped.
  assert.equal(
    failOpenEnabled({}),
    true,
    "default posture changed — revisit both descriptions",
  );
  const entry = marketplace.plugins.find((p) => p.source === "./plugin");
  for (const text of [manifest.description, entry.description])
    assert.doesNotMatch(text, /fails?[- ]closed/i);
});

// ─── the install commands the docs advertise ─────────────────────────────────

test("both READMEs advertise the marketplace and plugin these manifests define", () => {
  const entry = marketplace.plugins.find((p) => p.source === "./plugin");
  const install = `/plugin install ${entry.name}@${marketplace.name}`;
  // `/plugin marketplace add <owner>/<repo>` is a GitHub shorthand, so it has to
  // name the repo this marketplace is actually served from. A fork or a rename
  // leaves it pointing at the upstream, and every reader installs someone else's
  // plugin.
  const { url } = readJson(join(ROOT, "package.json")).repository;
  const slug = /github\.com\/(?<slug>[^/]+\/[^/.]+)/.exec(url)?.groups.slug;
  assert.ok(slug, `could not read an owner/repo slug from ${url}`);
  const add = `/plugin marketplace add ${slug}`;
  // Auto-update is off by default for a third-party marketplace, so both READMEs
  // also advertise the manual refresh. Same rename hazard as the install pair.
  const refresh = `/plugin marketplace update ${marketplace.name}`;
  const update = `/plugin update ${entry.name}@${marketplace.name}`;
  for (const doc of ["README.md", join("plugin", "README.md")]) {
    const text = readFileSync(join(ROOT, doc), "utf-8");
    for (const command of [install, add, refresh, update])
      assert.ok(text.includes(command), `${doc} is missing: ${command}`);
  }
  // The managed-settings snippet re-states both rename-sensitive values as JSON,
  // out of reach of the command checks above: the repo, and the object key —
  // which is the marketplace name `/plugin update ...@<name>` resolves against.
  const pluginReadme = readFileSync(join(ROOT, "plugin", "README.md"), "utf-8");
  assert.ok(
    pluginReadme.includes(`"repo": "${slug}"`),
    `plugin/README.md's extraKnownMarketplaces entry does not name ${slug}`,
  );
  assert.ok(
    pluginReadme.includes(`"${marketplace.name}": {`),
    `plugin/README.md's extraKnownMarketplaces entry is not keyed ${marketplace.name}`,
  );
  assert.equal(manifest.repository, `https://github.com/${slug}`);
  assert.equal(manifest.homepage, `https://github.com/${slug}#readme`);
});
