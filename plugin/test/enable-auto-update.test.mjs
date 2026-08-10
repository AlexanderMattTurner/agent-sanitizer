/**
 * `plugin/scripts/enable-auto-update.mjs` edits Claude Code's own marketplace
 * registry, so every case here runs the real script against a temp registry:
 * what it writes, and — more importantly — the states it must refuse to write
 * through rather than corrupting a file it does not own.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  MARKETPLACE,
  knownMarketplacesPath,
} from "../scripts/enable-auto-update.mjs";

const ROOT = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf-8",
}).trim();
const SCRIPT = join(ROOT, "plugin", "scripts", "enable-auto-update.mjs");
const readJson = (path) => JSON.parse(readFileSync(path, "utf-8"));

/** A registry Claude Code could plausibly have written, plus a bystander entry. */
function registry(entry) {
  const dir = mkdtempSync(join(tmpdir(), "agent-sanitizer-registry-"));
  const path = join(dir, "known_marketplaces.json");
  const config = {
    "claude-plugins-official": {
      source: { source: "github", repo: "anthropics/claude-plugins-official" },
      installLocation: join(dir, "marketplaces", "official"),
      lastUpdated: "2026-01-01T00:00:00.000Z",
      autoUpdate: true,
    },
    ...(entry ? { [MARKETPLACE]: entry } : {}),
  };
  writeFileSync(path, JSON.stringify(config, null, 2), "utf-8");
  return { dir, path };
}

const ENTRY = {
  source: { source: "github", repo: "AlexanderMattTurner/agent-sanitizer" },
  installLocation: "/tmp/marketplaces/agent-sanitizer",
  lastUpdated: "2026-02-02T00:00:00.000Z",
};

/** Runs the script against registry dir `dir`; returns its stdout. */
function run(dir, args = [], script = SCRIPT) {
  const result = execFileSync(process.execPath, [script, ...args], {
    env: { ...process.env, CLAUDE_CODE_PLUGIN_CACHE_DIR: dir },
    encoding: "utf-8",
    // Non-zero is an expected outcome for half these cases, not a test failure.
    stdio: ["ignore", "pipe", "pipe"],
  });
  return result;
}

function runExpectingFailure(dir, args = [], script = SCRIPT) {
  try {
    run(dir, args, script);
  } catch (error) {
    return error;
  }
  return assert.fail("script exited 0 where it should have refused");
}

test("the hardcoded marketplace name matches the manifest Claude Code keys by", () => {
  // The manifest lives at the repo root, outside the installed plugin, so the
  // script cannot read it at runtime — this pair is the only thing keeping the
  // constant honest through a marketplace rename.
  const manifest = readJson(join(ROOT, ".claude-plugin", "marketplace.json"));
  assert.equal(MARKETPLACE, manifest.name);
});

test("the `/plugin marketplace add` line in its errors names this repo", () => {
  const { url } = readJson(join(ROOT, "package.json")).repository;
  const slug = /github\.com\/(?<slug>[^/]+\/[^/.]+)/.exec(url)?.groups.slug;
  assert.ok(slug, `could not read an owner/repo slug from ${url}`);
  const source = readFileSync(SCRIPT, "utf-8");
  const advertised = [
    ...source.matchAll(/\/plugin marketplace add (?<slug>[\w.-]+\/[\w.-]+)/g),
  ].map((m) => m.groups.slug);
  assert.ok(advertised.length, "script no longer tells the user how to add it");
  for (const named of advertised) assert.equal(named, slug);
});

test("enabling writes autoUpdate through and leaves other entries alone", () => {
  const { dir, path } = registry(ENTRY);
  const stdout = run(dir);
  const after = readJson(path);
  assert.deepEqual(after[MARKETPLACE], { ...ENTRY, autoUpdate: true });
  assert.equal(after["claude-plugins-official"].autoUpdate, true);
  assert.match(stdout, /auto-update enabled/);
});

test("--disable writes false rather than dropping the key", () => {
  const { dir, path } = registry({ ...ENTRY, autoUpdate: true });
  run(dir, ["--disable"]);
  assert.equal(readJson(path)[MARKETPLACE].autoUpdate, false);
});

test("an already-enabled registry is left byte-identical", () => {
  const { dir, path } = registry({ ...ENTRY, autoUpdate: true });
  const before = readFileSync(path, "utf-8");
  const stdout = run(dir);
  assert.equal(readFileSync(path, "utf-8"), before);
  assert.match(stdout, /already enabled/);
});

test("a missing registry refuses instead of creating one", () => {
  const dir = mkdtempSync(join(tmpdir(), "agent-sanitizer-empty-"));
  const { status, stderr } = runExpectingFailure(dir);
  assert.equal(status, 1);
  assert.match(stderr, /no marketplace registry/);
  assert.match(stderr, /plugin marketplace add/);
});

test("an unregistered marketplace refuses instead of inventing an entry", () => {
  const { dir, path } = registry(null);
  const before = readFileSync(path, "utf-8");
  const { status, stderr } = runExpectingFailure(dir);
  assert.equal(status, 1);
  assert.match(stderr, /is not registered/);
  // The bystander entry is named, so the user can see what Claude Code did register.
  assert.match(stderr, /claude-plugins-official/);
  assert.equal(readFileSync(path, "utf-8"), before);
});

test("an entry shape it does not recognize refuses instead of rewriting it", () => {
  const { dir, path } = registry({ installLocation: "/tmp/x" });
  const before = readFileSync(path, "utf-8");
  const { status, stderr } = runExpectingFailure(dir);
  assert.equal(status, 1);
  assert.match(stderr, /not the shape this script knows how to edit/);
  assert.equal(readFileSync(path, "utf-8"), before);
});

test("a non-boolean autoUpdate refuses instead of overwriting it", () => {
  const { dir, path } = registry({ ...ENTRY, autoUpdate: "yes" });
  const before = readFileSync(path, "utf-8");
  const { status, stderr } = runExpectingFailure(dir);
  assert.equal(status, 1);
  assert.match(stderr, /not a boolean/);
  assert.equal(readFileSync(path, "utf-8"), before);
});

test(
  "a write the OS refuses names the routes that do work, not a stack trace",
  // Claude Code's Bash sandbox denies writes under the plugin cache, which is
  // how this arrives in the wild; a read-only directory is the portable stand-in.
  { skip: process.getuid?.() === 0 && "root writes through mode bits" },
  () => {
    const { dir, path } = registry(ENTRY);
    const before = readFileSync(path, "utf-8");
    chmodSync(dir, 0o555);
    try {
      const { status, stderr } = runExpectingFailure(dir);
      assert.equal(status, 1);
      assert.match(
        stderr,
        /cannot write .*known_marketplaces\.json \(EACCES\)/,
      );
      assert.match(stderr, /\/plugin -> Marketplaces/);
      // An uncaught errno exits 1 too — the absence of a trace is the fix.
      assert.doesNotMatch(stderr, /\n\s+at /);
      assert.equal(readFileSync(path, "utf-8"), before);
      assert.equal(existsSync(`${path}.agent-sanitizer.tmp`), false);
    } finally {
      chmodSync(dir, 0o755);
    }
  },
);

test(
  "a refused cleanup is reported, not thrown over the message",
  // Staging exists because a run can be interrupted, so a leftover temp file is
  // a state the next run meets. Rewriting that file needs no directory
  // permission, so the write succeeds and the RENAME is what gets refused —
  // then the unlink is refused too, on the same missing directory permission.
  { skip: process.getuid?.() === 0 && "root writes through mode bits" },
  () => {
    const { dir, path } = registry(ENTRY);
    const temp = `${path}.agent-sanitizer.tmp`;
    writeFileSync(temp, "{half-written", "utf-8");
    chmodSync(dir, 0o555);
    try {
      const { stderr } = runExpectingFailure(dir);
      assert.match(stderr, /cannot write .* \(EACCES\)/);
      assert.doesNotMatch(stderr, /\n\s+at /);
      assert.ok(
        stderr.includes(`The staged copy at ${temp} could not be cleaned up`),
        `leftover temp file not reported in:\n${stderr}`,
      );
    } finally {
      chmodSync(dir, 0o755);
    }
  },
);

for (const args of [[], ["--disable"]])
  test(
    `a refused ${args.join(" ") || "enable"} hands back a runnable command line`,
    // The agent running the skill cannot get past this refusal by any route the
    // sandbox allows, so the message's job is to be pasteable by the human.
    { skip: process.getuid?.() === 0 && "root writes through mode bits" },
    () => {
      // An install path with a space in it is ordinary on macOS and Windows; an
      // unquoted command line there pastes as two arguments and fails.
      const scriptDir = mkdtempSync(join(tmpdir(), "agent sanitizer path-"));
      const copied = join(scriptDir, "enable-auto-update.mjs");
      copyFileSync(SCRIPT, copied);
      // Each direction has to already be the opposite, or the script exits 0
      // before it ever reaches a write.
      const { dir } = registry({ ...ENTRY, autoUpdate: args.length > 0 });
      chmodSync(dir, 0o555);
      try {
        const { stderr } = runExpectingFailure(dir, args, copied);
        const line = `\n  node '${copied}'${args.map((a) => ` ${a}`).join("")}\n`;
        assert.ok(stderr.includes(line), `no rerun line in:\n${stderr}`);
      } finally {
        chmodSync(dir, 0o755);
      }
    },
  );

test("a corrupt registry propagates rather than being rewritten over", () => {
  const dir = mkdtempSync(join(tmpdir(), "agent-sanitizer-corrupt-"));
  writeFileSync(join(dir, "known_marketplaces.json"), "{not json", "utf-8");
  const { status, stderr } = runExpectingFailure(dir);
  assert.notEqual(status, 0);
  assert.match(stderr, /JSON/);
});

test("an unrecognized flag refuses rather than silently enabling", () => {
  const { dir } = registry(ENTRY);
  const { status, stderr } = runExpectingFailure(dir, ["--disble"]);
  assert.equal(status, 1);
  assert.match(stderr, /unrecognized argument/);
});

test("it still runs from an install path containing a space", () => {
  // Marketplace installs live under a generated, versioned directory, and a home
  // directory with a space in it is ordinary on macOS and Windows. A main-module
  // check that mis-compares there would exit 0 having done nothing — the one
  // failure this script must not have.
  const dir = mkdtempSync(join(tmpdir(), "agent sanitizer path-"));
  const copied = join(dir, "enable-auto-update.mjs");
  copyFileSync(SCRIPT, copied);
  const { dir: registryDir, path } = registry(ENTRY);
  const stdout = run(registryDir, [], copied);
  assert.match(stdout, /auto-update enabled/);
  assert.equal(readJson(path)[MARKETPLACE].autoUpdate, true);
});

test("the registry path follows Claude Code's own overrides", () => {
  const cache = join("/tmp", "cache");
  assert.equal(
    knownMarketplacesPath({ CLAUDE_CODE_PLUGIN_CACHE_DIR: cache }),
    join(cache, "known_marketplaces.json"),
  );
  assert.equal(
    knownMarketplacesPath({ CLAUDE_CONFIG_DIR: "/tmp/cfg" }),
    join("/tmp/cfg", "plugins", "known_marketplaces.json"),
  );
  // Cowork keeps a separate plugin root; the wrong one would write a file that
  // Claude Code never reads, and the toggle would look applied but do nothing.
  assert.equal(
    knownMarketplacesPath({
      CLAUDE_CONFIG_DIR: "/tmp/cfg",
      CLAUDE_CODE_USE_COWORK_PLUGINS: "1",
    }),
    join("/tmp/cfg", "cowork_plugins", "known_marketplaces.json"),
  );
});

test("both READMEs advertise the skill under the name it is invoked by", () => {
  // Claude Code namespaces a plugin skill as /<plugin name>:<skill name>, so the
  // command in the docs is a function of two manifests and a directory name —
  // rename any one of them and the docs advertise a command that does not exist.
  const plugin = readJson(
    join(ROOT, "plugin", ".claude-plugin", "plugin.json"),
  );
  const command = `/${plugin.name}:enable-auto-update`;
  for (const doc of ["README.md", join("plugin", "README.md")]) {
    const text = readFileSync(join(ROOT, doc), "utf-8");
    assert.ok(text.includes(command), `${doc} is missing: ${command}`);
  }
  assert.ok(
    existsSync(
      join(ROOT, "plugin", "skills", "enable-auto-update", "SKILL.md"),
    ),
    `no skill directory backs ${command}`,
  );
});

test("the skill points at the script that exists", () => {
  const skill = readFileSync(
    join(ROOT, "plugin", "skills", "enable-auto-update", "SKILL.md"),
    "utf-8",
  );
  const invocation = /node "\$\{CLAUDE_PLUGIN_ROOT\}\/(?<rel>[^"]+)"/.exec(
    skill,
  )?.groups.rel;
  assert.ok(
    invocation,
    "SKILL.md no longer runs a script from the plugin root",
  );
  assert.ok(
    existsSync(join(ROOT, "plugin", invocation)),
    `SKILL.md runs plugin/${invocation}, which does not exist`,
  );
});
