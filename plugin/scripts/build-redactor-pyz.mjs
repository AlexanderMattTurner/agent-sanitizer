/**
 * Build the Python half of the plugin: a self-contained, platform-
 * independent zipapp at plugin/dist/redactor/daemon.pyz carrying the redaction
 * engine built from this tree's `python/`, plus its third-party dependencies.
 *
 * The .pyz is the guaranteed floor, so Layer 4 works with no network and no
 * provisioning; the venv `provision-redactor.sh` builds is a startup-latency
 * optimization the launcher prefers when present. Both install the SAME engine
 * wheel this script writes, so the fast path and the floor are one build.
 *
 * NETWORK: this build resolves the third-party tree from PyPI, so it is NOT
 * part of the network-free `prepare` build. node-tests runs it (`pnpm
 * build:redactor`) before the plugin suites, which assert the built artifact's
 * properties (pure-Python, runnable); the release bake runs it and ships the
 * output on the plugin-dist branch.
 *
 * Determinism: third-party packages come from the fully resolved, hash-pinned
 * plugin/requirements.txt, so no transitive release can change these bytes, and
 * the engine comes from the working tree, which git already content-addresses.
 * `--no-binary :all:` installs every
 * package from its sdist (the pure-Python source files are copied verbatim, so
 * the tree does not vary by build platform); compiled speedups (PyYAML's _yaml,
 * charset_normalizer's mypyc) are stripped — both packages fall back to pure
 * Python — and asserted absent; installer-varying metadata (RECORD, INSTALLER,
 * WHEEL, direct_url) is dropped, keeping only METADATA per dist-info; the zip is
 * written with sorted entries, fixed 1980-01-01 timestamps, fixed permissions,
 * and no compression (deflate output varies with the host zlib).
 */
import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  rmSync,
  existsSync,
  mkdirSync,
  readFileSync,
  copyFileSync,
  cpSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  REQUIREMENTS_LOCK_PATH,
  lockedEngineVersion,
} from "./build-plugin.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Built artifact path; the release bake ships it on plugin-dist. */
export const PYZ_PATH = join(ROOT, "plugin", "dist", "redactor", "daemon.pyz");

/**
 * The engine wheel, shipped beside the zipapp.
 *
 * It ships because the plugin is distributed as `plugin/` alone — a user's
 * machine has no `python/` tree — and `provision-redactor.sh` needs the same
 * engine the zipapp carries. One artifact consumed by both is what keeps the
 * provisioned venv and the shipped floor from being two versions.
 */
export const WHEEL_PATH = join(
  ROOT,
  "plugin",
  "dist",
  "redactor",
  "agent_sanitizer-0.0.0-py3-none-any.whl",
);

/**
 * Build the engine wheel from `python/` into its shipped path and return it.
 *
 * `SOURCE_DATE_EPOCH` is pinned for the same reason the zip below is written
 * with fixed timestamps: a wheel whose bytes move with the clock would make the
 * shipped artifact differ from every rebuild.
 * @returns {string}
 */
export function buildEngineWheel() {
  // The charset JSON is git-ignored, generated at install time, and hatch's
  // `artifacts` skips a missing file without complaint: a wheel built before
  // `pnpm install` (or `node scripts/gen-unicode.mjs`) would ship without it and
  // fail closed at import in the daemon.
  const charset = join(
    ROOT,
    "python",
    "agent_sanitizer",
    "data",
    "invisible-charset.json",
  );
  if (!existsSync(charset))
    throw new Error(
      `${charset} is missing, so the wheel would ship without it. It is ` +
        "generated, not committed: run `pnpm install` or `node scripts/gen-unicode.mjs`.",
    );
  // `python/` is staged without `_bundled/` first. pyproject force-includes the
  // git-ignored `_bundled/sanitize-cli.mjs` WHEN IT EXISTS, so building straight
  // off the checkout would let the builder's local state decide the bytes of a
  // shipped artifact — and a 1.7 MB Node bridge no consumer of this wheel
  // reaches (the daemon is pure Python) would ride into every rebuild's diff.
  const stage = mkdtempSync(join(tmpdir(), "agent-sanitizer-py-"));
  // Built into a scratch dir and copied in: `uv build --out-dir` drops a
  // `.gitignore` of `*` beside its output, which in a COMMITTED directory would
  // silently keep the wheel out of the commit that ships it.
  const out = mkdtempSync(join(tmpdir(), "agent-sanitizer-wheel-"));
  try {
    const source = join(stage, "python");
    cpSync(join(ROOT, "python"), source, {
      recursive: true,
      filter: (from) => basename(from) !== "_bundled",
    });
    if (existsSync(join(source, "agent_sanitizer", "_bundled")))
      throw new Error(
        "the _bundled/ exclusion did not take, so the wheel's bytes would " +
          "depend on whether this machine has run scripts/bundle-python-cli.mjs",
      );
    run("uv", ["build", "--wheel", "--out-dir", out, source], {
      SOURCE_DATE_EPOCH: "315532800",
    });
    const built = join(out, basename(WHEEL_PATH));
    if (!existsSync(built))
      throw new Error(
        `uv build did not produce ${basename(WHEEL_PATH)}. The version in ` +
          "python/pyproject.toml must stay the 0.0.0 sentinel (the release " +
          "workflow injects the real one at publish time).",
      );
    mkdirSync(dirname(WHEEL_PATH), { recursive: true });
    copyFileSync(built, WHEEL_PATH);
    return WHEEL_PATH;
  } finally {
    rmSync(out, { recursive: true, force: true });
    rmSync(stage, { recursive: true, force: true });
  }
}

/**
 * The zipapp's `__main__.py`, exported so a test can run the real stub. The
 * engine reads data files through Path(__file__), which cannot be opened inside
 * a zip, so the stub self-extracts to a cache keyed on the archive digest (stale
 * trees are inert) under `$CLAUDE_PLUGIN_DATA/redactor-pyz` when writable, else
 * a uid-named temp-dir directory. Both names are predictable, so every directory
 * it imports from must pass `trusted_dir`.
 */
export const PYZ_MAIN = String.raw`import hashlib, os, shutil, stat, sys, tempfile, zipfile

archive = os.path.dirname(os.path.abspath(__file__))


def trusted_dir(path):
    """Exit unless only this uid can write PATH: a real directory (lstat, so a
    symlink is refused rather than followed), owned by this uid, with no
    group/other write bit. This refusal is what blocks another local user
    pre-creating the predictable cache directory and planting modules that
    this process would then import and run as us."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise SystemExit(
            f"agent-sanitizer redactor: refusing {path}: not a real directory"
        )
    if st.st_uid != os.getuid():
        raise SystemExit(
            f"agent-sanitizer redactor: refusing {path}: owned by uid "
            f"{st.st_uid}, not {os.getuid()}"
        )
    if st.st_mode & 0o022:
        raise SystemExit(
            f"agent-sanitizer redactor: refusing {path}: writable by group or "
            f"other (mode {stat.S_IMODE(st.st_mode):o})"
        )


with open(archive, "rb") as fh:
    digest = hashlib.sha256(fh.read()).hexdigest()[:16]

candidates = [
    os.path.join(tempfile.gettempdir(), f"agent-sanitizer-pyz-{os.getuid()}")
]
plugin_data = os.environ.get("CLAUDE_PLUGIN_DATA")
if plugin_data:
    candidates.insert(0, os.path.join(plugin_data, "redactor-pyz"))
# The per-install directory is preferred, but a host that cannot write it (the
# same read-only plugin data that leaves no venv) still has a usable temp
# cache. Only a base that cannot be created or written is skipped: a base that
# exists and fails trusted_dir below is an attack signal and stays fatal.
for base in candidates:
    try:
        os.makedirs(base, mode=0o700, exist_ok=True)
    except OSError:
        if base is candidates[-1]:
            raise
        continue
    if os.access(base, os.W_OK) or base is candidates[-1]:
        break
trusted_dir(base)
tree = os.path.join(base, digest)

if not os.path.lexists(tree):
    # Extracted privately and renamed into place, so the digest path only ever
    # names a complete tree.
    scratch = tempfile.mkdtemp(dir=base)
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(scratch)
    try:
        os.rename(scratch, tree)
    except OSError:
        if not os.path.isdir(tree):
            raise
        # A concurrent spawn won the race; its tree is identical by digest.
        shutil.rmtree(scratch)
trusted_dir(tree)

sys.path.insert(0, tree)
from agent_sanitizer.secrets.daemon import main

sys.exit(main())
`;

/** Zip-writing helper, run under python3 (stdlib only; PYZ_* env carries args). */
const WRITE_PYZ = `
import os, sys, zipfile

target = os.environ["PYZ_TARGET_DIR"]
out = os.environ["PYZ_OUT"]
MAIN = os.environ["PYZ_MAIN"]

entries = []
for base, dirs, files in os.walk(target):
    dirs[:] = sorted(d for d in dirs if d != "__pycache__")
    for name in sorted(files):
        path = os.path.join(base, name)
        rel = os.path.relpath(path, target).replace(os.sep, "/")
        if rel.endswith((".pyc", ".pyo", ".so", ".pyd")):
            continue
        if "/bin/" in "/" + rel or rel.startswith("bin/"):
            continue
        if ".dist-info/" in rel and not rel.endswith("/METADATA"):
            continue
        entries.append((rel, path))

entries.sort()
with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
    info = zipfile.ZipInfo("__main__.py", date_time=(1980, 1, 1, 0, 0, 0))
    info.external_attr = 0o644 << 16
    zf.writestr(info, MAIN)
    for rel, path in entries:
        info = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16
        with open(path, "rb") as fh:
            zf.writestr(info, fh.read())

with open(out, "rb") as fh:
    body = fh.read()
with open(out, "wb") as fh:
    fh.write(b"#!/usr/bin/env python3\\n" + body)
print(f"wrote {out} ({len(body)} bytes zipped, {len(entries)} files)")
`;

/**
 * Run a command, throwing on failure with its output attached.
 * @param {string} cmd
 * @param {string[]} args
 * @param {Record<string, string>} [env]
 */
function run(cmd, args, env = {}) {
  const res = spawnSync(cmd, args, {
    encoding: "utf8",
    env: { ...process.env, ...env },
    maxBuffer: 64 * 1024 * 1024,
  });
  if (res.status !== 0)
    throw new Error(
      `${cmd} ${args.join(" ")} failed (${res.status}):\n${res.stdout}\n${res.stderr}`,
    );
  return res.stdout;
}

export function buildRedactorPyz() {
  // The lock covers the daemon's THIRD-PARTY dependencies only; `agent_sanitizer`
  // is installed from `python/` in this same tree, which is what makes the zipapp
  // and the JS bundle beside it the same commit rather than two versions that
  // happen to agree. A published pin here could never name an unreleased HEAD,
  // so the two would drift by construction.
  const locked = lockedEngineVersion(
    readFileSync(REQUIREMENTS_LOCK_PATH, "utf-8"),
  );
  if (locked !== null)
    throw new Error(
      `${REQUIREMENTS_LOCK_PATH} pins agent-sanitizer==${locked}. The zipapp ` +
        "installs the engine from python/ in this tree, so the lock must carry " +
        "third-party dependencies only. Re-lock with `node " +
        "plugin/scripts/build-plugin.mjs && node plugin/scripts/lock-redactor-deps.mjs`.",
    );
  const work = mkdtempSync(join(tmpdir(), "agent-sanitizer-pyz-"));
  try {
    const target = join(work, "site");
    // uv is a hard requirement, not a preference: the engine wheel below is
    // built with `uv build`, and lock-redactor-deps.mjs compiles the lock this
    // reads with `uv pip compile`. A pip fallback for the install alone would
    // never be reached.
    if (spawnSync("uv", ["--version"]).status !== 0)
      throw new Error(
        "uv is required to build the redactor zipapp (https://docs.astral.sh/uv/). " +
          "It builds the engine wheel and installs the hash-pinned lock.",
      );
    const engineSource = buildEngineWheel();
    // `--require-hashes` is explicit rather than left to be inferred from the
    // lock carrying hashes: an unhashed line slipping in must fail the build,
    // not quietly disable hash checking for the whole file.
    run("uv", [
      "pip",
      "install",
      "--quiet",
      "--target",
      target,
      "--no-binary",
      ":all:",
      "--no-compile-bytecode",
      "--require-hashes",
      "-r",
      REQUIREMENTS_LOCK_PATH,
    ]);
    // Second pass, and `--no-deps`: the tree's own dependencies were just
    // installed from the hashed lock, and a local path carries no hash, so
    // resolving it here would turn hash checking off for the whole install.
    // No `--no-binary` either: that flag exists to refuse PyPI's prebuilt
    // wheels, and this one is the pure-Python artifact this build just made.
    run("uv", [
      "pip",
      "install",
      "--quiet",
      "--target",
      target,
      "--no-compile-bytecode",
      "--no-deps",
      engineSource,
    ]);
    mkdirSync(dirname(PYZ_PATH), { recursive: true });
    const out = run("python3", ["-c", WRITE_PYZ], {
      PYZ_TARGET_DIR: target,
      PYZ_OUT: PYZ_PATH,
      PYZ_MAIN,
    });
    process.stderr.write(out);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

// `--if-missing` is the pre-push `pnpm build`: it makes a fresh checkout
// testable without paying the PyPI build on every push. It never rebuilds a
// stale pair, so node-tests and the release bake call the plain build.
const BUILT = [PYZ_PATH, WHEEL_PATH].every((path) => existsSync(path));
if (BUILT && process.argv.includes("--if-missing")) {
  process.stderr.write("redactor already built, skipping (--if-missing)\n");
} else if (
  import.meta.url === new URL(`file://${process.argv[1]}`).href ||
  process.argv[1]?.endsWith("build-redactor-pyz.mjs")
) {
  buildRedactorPyz();
}
