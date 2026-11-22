// install-sanitizer.sh, local-checkout path.
//
// Regression: npm packs a `file:` dependency by running that package's own
// `prepare`/`prepack`, and does so even under --ignore-scripts (npm 10.9). This
// repo's `prepare` is `pnpm build:types`, and the three claude-* review
// workflows install neither pnpm nor the typescript devDependency — so the
// install step died with `pnpm: not found` and took every review job with it
// before it read a single diff. The fixture's lifecycle scripts below exit
// non-zero, so this test fails exactly the way CI did if the staging that
// strips them is removed.
import { strict as assert } from "node:assert";
import { execFile, execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const SCRIPT = join(
  dirname(fileURLToPath(import.meta.url)),
  "install-sanitizer.sh",
);

/**
 * A miniature of this repo as the script sees it: named `agent-sanitizer` (so
 * the local-checkout branch is taken), dependency-free (so the install needs no
 * registry), carrying a `files` allowlist and lifecycle scripts that fail.
 */
function makeCheckout({ manifestExtra = {}, rootModules = {} } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "install-sanitizer-"));
  const manifest = {
    name: "agent-sanitizer",
    version: "0.0.0",
    type: "module",
    main: "src/index.mjs",
    scripts: {
      prepare: "exit 17",
      prepack: "exit 17",
    },
    files: ["src/*.mjs", "src/vendor/*.mjs"],
    ...manifestExtra,
  };
  // The root node_modules a frozen `pnpm install` leaves behind: one installed
  // version per dependency, which is what the lockfile pins.
  for (const [name, version] of Object.entries(rootModules)) {
    mkdirSync(join(dir, "node_modules", name), { recursive: true });
    writeFileSync(
      join(dir, "node_modules", name, "package.json"),
      JSON.stringify({ name, version }),
    );
  }
  writeFileSync(
    join(dir, "package.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  mkdirSync(join(dir, "src"));
  writeFileSync(
    join(dir, "src", "index.mjs"),
    'export { TABLE } from "./table.mjs";\nexport const sanitize = () => {};\n',
  );
  // A generated, git-ignored module, as src/cf-charset.mjs and friends are:
  // `git archive HEAD` omits it, so the install has to generate and stage it.
  writeFileSync(
    join(dir, ".gitignore"),
    "node_modules/\nsrc/table.mjs\nsrc/vendor/patched.mjs\n",
  );
  mkdirSync(join(dir, "scripts"));
  writeFileSync(
    join(dir, "scripts", "gen-unicode.mjs"),
    `import { writeFileSync } from "node:fs";
writeFileSync(new URL("../src/table.mjs", import.meta.url), "export const TABLE = 1;\\n");
`,
  );
  // The second generator, whose output sits one directory down as
  // src/vendor/gfm-autolink-literal.mjs does: the pathspec has to reach it.
  writeFileSync(
    join(dir, "scripts", "gen-gfm-autolink.mjs"),
    `import { mkdirSync, writeFileSync } from "node:fs";
mkdirSync(new URL("../src/vendor", import.meta.url), { recursive: true });
writeFileSync(new URL("../src/vendor/patched.mjs", import.meta.url), "export const PATCHED = 1;\\n");
`,
  );
  // Outside `files`: proves the install still ships the PUBLISHED tree rather
  // than the whole checkout, which is what staging-then-packing preserves.
  writeFileSync(join(dir, "unpublished.txt"), "not in files\n");
  mkdirSync(join(dir, ".github", "scripts"), { recursive: true });

  // `git archive HEAD` stages the committed tree, so the fixture needs a commit.
  const git = (...args) =>
    execFileSync("git", ["-C", dir, ...args], { encoding: "utf8" });
  git("init", "--quiet");
  git("config", "user.email", "test@example.com");
  git("config", "user.name", "test");
  git("add", "--all");
  git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture");
  return dir;
}

test("installs the local checkout without running its lifecycle scripts", () => {
  const dir = makeCheckout();
  const res = spawnSync("bash", [SCRIPT], { cwd: dir, encoding: "utf8" });
  const installed = join(
    dir,
    ".github",
    "scripts",
    "node_modules",
    "agent-sanitizer",
  );
  const ok = res.status === 0;
  const hasEntry = existsSync(join(installed, "src", "index.mjs"));
  const hasUnpublished = existsSync(join(installed, "unpublished.txt"));
  const hasGenerated = existsSync(join(installed, "src", "table.mjs"));
  const hasVendorGenerated = existsSync(
    join(installed, "src", "vendor", "patched.mjs"),
  );
  rmSync(dir, { recursive: true, force: true });

  assert.equal(ok, true, `install failed:\n${res.stdout}\n${res.stderr}`);
  assert.equal(
    hasEntry,
    true,
    "the local checkout's entry point was not installed",
  );
  assert.equal(
    hasGenerated,
    true,
    "the git-ignored generated module was not staged into the install",
  );
  assert.equal(
    hasVendorGenerated,
    true,
    "the git-ignored generated module under src/vendor/ was not staged",
  );
  assert.equal(
    hasUnpublished,
    false,
    "installed a file outside `files` — the install no longer mirrors the published package",
  );
});

/**
 * A local npm registry. `packages` maps name -> version -> tarball path, or
 * null for a version the packument lists but whose tarball 404s: the state
 * registry.npmjs.org was in for minutes after agent-control-plane-core 0.15.9
 * was published. The last version listed is `latest`.
 */
async function startRegistry(packages) {
  const server = createServer((req, res) => {
    const base = `http://127.0.0.1:${server.address().port}`;
    const name = decodeURIComponent(req.url.slice(1));
    if (packages[name]) {
      const versions = Object.keys(packages[name]);
      const packument = {
        name,
        "dist-tags": { latest: versions.at(-1) },
        versions: Object.fromEntries(
          versions.map((version) => {
            const tgz = packages[name][version];
            const bytes = tgz ? readFileSync(tgz) : Buffer.from(version);
            const digest = createHash("sha512").update(bytes).digest("base64");
            const tarball = `${base}/-/${name}-${version}.tgz`;
            const dist = { tarball, integrity: `sha512-${digest}` };
            return [version, { name, version, dist }];
          }),
        ),
      };
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(packument));
      return;
    }
    const tarball = req.url.match(/^\/-\/(.+)-(\d+\.\d+\.\d+)\.tgz$/);
    const tgz = tarball && packages[tarball[1]]?.[tarball[2]];
    if (tgz) {
      res.writeHead(200, { "content-type": "application/octet-stream" });
      res.end(readFileSync(tgz));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  return server;
}

/** `npm pack` a dependency-free package, returning the tarball path. */
function packFixture(root, name, version) {
  const src = join(root, `${name}-${version}`);
  mkdirSync(src);
  writeFileSync(join(src, "package.json"), JSON.stringify({ name, version }));
  execFileSync("npm", ["pack", "--silent", "--pack-destination", root], {
    cwd: src,
  });
  return join(root, `${name}-${version}.tgz`);
}

test("installs the lockfile's dependency versions, not the registry's newest", async () => {
  const work = mkdtempSync(join(tmpdir(), "install-sanitizer-registry-"));
  const server = await startRegistry({
    "fake-core": {
      "0.12.0": packFixture(work, "fake-core", "0.12.0"),
      "0.15.9": null,
    },
    "fake-dep": {
      "1.0.0": packFixture(work, "fake-dep", "1.0.0"),
      "1.1.0": null,
    },
  });
  const dir = makeCheckout({
    manifestExtra: {
      dependencies: { "fake-dep": "^1.0.0" },
      peerDependencies: { "fake-core": ">=0.11.2 <1.0.0" },
    },
    rootModules: { "fake-core": "0.12.0", "fake-dep": "1.0.0" },
  });
  const registry = `http://127.0.0.1:${server.address().port}/`;
  let result;
  try {
    result = await promisify(execFile)("bash", [SCRIPT], {
      cwd: dir,
      encoding: "utf8",
      env: {
        ...process.env,
        npm_config_registry: registry,
        npm_config_cache: join(work, "cache"),
        NO_PROXY: "127.0.0.1",
        no_proxy: "127.0.0.1",
      },
    }).catch((error) => error);
  } finally {
    server.close();
  }
  const modules = join(dir, ".github", "scripts", "node_modules");
  const versionOf = (name) =>
    existsSync(join(modules, name, "package.json"))
      ? JSON.parse(readFileSync(join(modules, name, "package.json"), "utf8"))
          .version
      : undefined;
  const installed = [versionOf("fake-core"), versionOf("fake-dep")];
  rmSync(dir, { recursive: true, force: true });
  rmSync(work, { recursive: true, force: true });

  assert.equal(
    result.code ?? 0,
    0,
    `install failed:\n${result.stdout}\n${result.stderr}`,
  );
  assert.deepEqual(installed, ["0.12.0", "1.0.0"]);
});
