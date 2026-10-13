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
import { failOpenEnabled, HookEvent } from "../../claude-hooks/lib/hook-io.mjs";
import * as hookIo from "../../claude-hooks/lib/hook-io.mjs";
import * as envConfig from "../../claude-hooks/lib/env-config.mjs";

const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const MARKETPLACE_PATH = join(ROOT, ".claude-plugin", "marketplace.json");
const MANIFEST_PATH = join(ROOT, "plugin", ".claude-plugin", "plugin.json");

const readJson = (path) => JSON.parse(readFileSync(path, "utf-8"));
const marketplace = readJson(MARKETPLACE_PATH);
const manifest = readJson(MANIFEST_PATH);

/** `owner/repo` this package is published from, per package.json. */
const REPO_SLUG = (() => {
  const { url } = readJson(join(ROOT, "package.json")).repository;
  const slug = /github\.com\/(?<slug>[^/]+\/[^/.]+)/.exec(url)?.groups?.slug;
  assert.ok(slug, `could not read an owner/repo slug from ${url}`);
  return slug;
})();

/** The marketplace entry that installs plugin/, where plugin.json lives. */
const pluginEntry = () => {
  const entry = marketplace.plugins.find((p) => p.source?.path === "plugin");
  assert.ok(entry, "no marketplace entry installs the plugin/ directory");
  return entry;
};

/**
 * Every operator-facing knob the hook modules name, read from the modules
 * themselves. A hand-pasted list pins today's count and stays green for the
 * next knob added, which is how one reached a release undocumented. A
 * `_`-prefixed name is internal plumbing (plugin/README.md) and never belongs
 * on the pre-install surface, so only the bare prefix counts.
 */
const PUBLIC_KNOBS = [hookIo, envConfig]
  .flatMap((module) => Object.entries(module))
  .filter(([name]) => name.endsWith("_ENV"))
  .map(([, value]) => value)
  .filter(
    (value) =>
      typeof value === "string" && value.startsWith("AGENT_SANITIZER_"),
  );

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

test("every marketplace entry installs this repo's plugin from the plugin-dist branch", () => {
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

    // The plugin's build output lives only on plugin-dist (the release bakes
    // it there), so a relative `./plugin` source would install a tree with no
    // bundle, and a URL naming another repo would install someone else's code.
    // No `sha`: pinning one would freeze every install at a single release.
    assert.deepEqual(entry.source, {
      source: "git-subdir",
      url: `https://github.com/${REPO_SLUG}.git`,
      path: entry.source.path,
      ref: "plugin-dist",
    });
    const { path } = entry.source;
    assert.equal(typeof path, "string");
    assert.ok(!isAbsolute(path), `${entry.name}: path is absolute`);
    assert.ok(
      !normalize(path).startsWith(".."),
      `${entry.name}: path escapes the repo root`,
    );

    // plugin-dist's tree is a release tag's with the build output laid over
    // it, so the plugin's sources are at the same path here.
    const dir = join(ROOT, path);
    assert.ok(
      statSync(dir).isDirectory(),
      `${entry.name}: ${dir} is not a directory`,
    );
    assert.ok(
      existsSync(join(dir, ".claude-plugin", "plugin.json")),
      `${entry.name}: no plugin.json under ${path}`,
    );

    // The docs are explicit that plugin.json's version wins silently over the
    // entry's, so a version here would be a value nobody can observe — and a
    // trap the moment the two drift. `description` resolves the same way, and
    // it drifted for real: the entry's copy still advertised a posture the
    // hooks had stopped taking, several releases after the manifest's was
    // corrected. Neither field is restated here; plugin.json is the source.
    for (const field of ["version", "description"])
      assert.equal(
        entry[field],
        undefined,
        `${entry.name}: set ${field} in plugin.json, not the marketplace entry`,
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
  assert.equal(pluginEntry().name, manifest.name);
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

test("the description does not advertise a posture the hooks do not take", () => {
  // The description is the pre-install surface — what the picker and
  // `/plugin marketplace` show — so it is the one place a reader decides what
  // this plugin does before any of it runs. The default posture is fail-OPEN:
  // a hook that cannot run warns and passes the action through.
  assert.equal(
    failOpenEnabled({}),
    true,
    "default posture changed — revisit the description",
  );
  assert.doesNotMatch(manifest.description, /fails?[- ]closed/i);
});

test("the description names each hook's event and every public knob", () => {
  // A description that lists capabilities without saying which event they run
  // on, or that omits a knob, is the drift this test exists to catch: the
  // picker is the only surface an operator reads before installing, and both
  // halves went stale before (a posture claim that had flipped, and a layer
  // that shipped opt-in with the description still implying it was always on).
  for (const event of Object.values(HookEvent))
    assert.match(manifest.description, new RegExp(event, "u"));
  assert.ok(
    PUBLIC_KNOBS.length,
    "read no knob names from the hook modules — every case below would pass over nothing",
  );
  for (const knob of PUBLIC_KNOBS)
    assert.ok(
      manifest.description.includes(knob),
      `description does not mention ${knob}`,
    );
});

// ─── the install commands the docs advertise ─────────────────────────────────

test("both READMEs advertise the marketplace and plugin these manifests define", () => {
  const entry = pluginEntry();
  const install = `/plugin install ${entry.name}@${marketplace.name}`;
  // `/plugin marketplace add <owner>/<repo>` is a GitHub shorthand, so it has to
  // name the repo this marketplace is actually served from. A fork or a rename
  // leaves it pointing at the upstream, and every reader installs someone else's
  // plugin.
  const add = `/plugin marketplace add ${REPO_SLUG}`;
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
    pluginReadme.includes(`"repo": "${REPO_SLUG}"`),
    `plugin/README.md's extraKnownMarketplaces entry does not name ${REPO_SLUG}`,
  );
  assert.ok(
    pluginReadme.includes(`"${marketplace.name}": {`),
    `plugin/README.md's extraKnownMarketplaces entry is not keyed ${marketplace.name}`,
  );
  assert.equal(manifest.repository, `https://github.com/${REPO_SLUG}`);
  assert.equal(manifest.homepage, `https://github.com/${REPO_SLUG}#readme`);
});

// ─── this repo's own sessions ────────────────────────────────────────────────

test("the project settings install and auto-update this marketplace's plugin", () => {
  // `.claude/settings.json` is what makes a session in this repo run the
  // SHIPPED hooks: trusting the folder prompts the install, and from then on
  // Claude Code background-refreshes the marketplace clone and picks up each
  // release's `version` bump. Every identifier here is a name from the two
  // manifests, so a rename that missed this file leaves the entry pointing at a
  // marketplace nobody publishes — which fails silently, as a plugin that never
  // installs rather than an error.
  const settings = readJson(join(ROOT, ".claude", "settings.json"));
  const known = settings.extraKnownMarketplaces?.[marketplace.name];
  assert.deepEqual(known?.source, { source: "github", repo: REPO_SLUG });
  // Without this the marketplace clone is refreshed only when someone runs
  // `/plugin marketplace update` by hand, and sessions here silently keep
  // running whatever release was current the day they first trusted the folder.
  assert.equal(known?.autoUpdate, true);
  const entry = pluginEntry();
  assert.equal(
    settings.enabledPlugins?.[`${entry.name}@${marketplace.name}`],
    true,
  );
});
