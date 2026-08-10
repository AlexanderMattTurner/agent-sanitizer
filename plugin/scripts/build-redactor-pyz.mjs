/**
 * Build the committed Python half of the plugin: a self-contained, platform-
 * independent zipapp at plugin/dist/redactor/daemon.pyz carrying the redaction
 * engine built from this tree's `python/`, plus its third-party dependencies.
 *
 * The .pyz is the guaranteed floor, so Layer 4 works with no network and no
 * provisioning; the venv `provision-redactor.sh` builds is a startup-latency
 * optimization the launcher prefers when present. Both install the SAME engine
 * wheel this script writes, so the fast path and the floor are one build.
 *
 * NETWORK: this build resolves the third-party tree from PyPI, so it is NOT part
 * of the network-free reproducibility rebuild in the default test suite. The
 * live-engine CI job rebuilds and byte-compares it; the default suite asserts
 * the committed artifact's properties (tracked, pure-Python, runnable).
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
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  REQUIREMENTS_LOCK_PATH,
  lockedEngineVersion,
} from "./build-plugin.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Committed artifact path. */
export const PYZ_PATH = join(ROOT, "plugin", "dist", "redactor", "daemon.pyz");

/**
 * The engine wheel, committed beside the zipapp.
 *
 * It ships because the plugin is distributed as `plugin/` alone — a user's
 * machine has no `python/` tree — and `provision-redactor.sh` needs the same
 * engine the zipapp carries. One artifact consumed by both is what keeps the
 * provisioned venv and the committed floor from being two versions.
 */
export const WHEEL_PATH = join(
  ROOT,
  "plugin",
  "dist",
  "redactor",
  "agent_sanitizer-0.0.0-py3-none-any.whl",
);

/**
 * Build the engine wheel from `python/` into its committed path and return it.
 *
 * `SOURCE_DATE_EPOCH` is pinned for the same reason the zip below is written
 * with fixed timestamps: a wheel whose bytes move with the clock would make the
 * committed artifact differ from every rebuild.
 * @returns {string}
 */
export function buildEngineWheel() {
  // Built into a scratch dir and copied in: `uv build --out-dir` drops a
  // `.gitignore` of `*` beside its output, which in a COMMITTED directory would
  // silently keep the wheel out of the commit that ships it.
  const out = mkdtempSync(join(tmpdir(), "agent-sanitizer-wheel-"));
  try {
    run("uv", ["build", "--wheel", "--out-dir", out, join(ROOT, "python")], {
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
  }
}

/** Zip-writing helper, run under python3 (stdlib only; PYZ_* env carries args). */
const WRITE_PYZ = `
import os, sys, zipfile

target = os.environ["PYZ_TARGET_DIR"]
out = os.environ["PYZ_OUT"]

# The engine reads data files through Path(__file__) (e.g.
# agent_sanitizer/data/invisible-charset.json), which cannot be opened inside
# a zip — the Python twin of the css-tree runtime-require defect on the JS
# side. So the entry self-extracts to a content-addressed per-user cache and
# imports from there: the COMMITTED artifact stays one deterministic file,
# and any Path-based file access works at runtime. The cache key is the
# archive digest, so a plugin update extracts fresh and stale trees are inert.
MAIN = """\\
import hashlib, os, shutil, sys, tempfile, zipfile

archive = os.path.dirname(os.path.abspath(__file__))

with open(archive, "rb") as fh:
    digest = hashlib.sha256(fh.read()).hexdigest()[:16]

base = os.path.join(
    tempfile.gettempdir(), f"agent-sanitizer-pyz-{os.getuid()}"
)
os.makedirs(base, mode=0o700, exist_ok=True)
tree = os.path.join(base, digest)

if not os.path.isdir(tree):
    scratch = tempfile.mkdtemp(dir=base)
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(scratch)
    try:
        os.rename(scratch, tree)
    except OSError:
        # A concurrent spawn won the race; its tree is identical by digest.
        shutil.rmtree(scratch, ignore_errors=True)

sys.path.insert(0, tree)
from agent_sanitizer.secrets.daemon import main

sys.exit(main())
"""

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
    // uv when available (CI installs it; much faster sdist builds), pip
    // otherwise. Both get the same determinism-bearing flags. `--require-hashes`
    // is explicit rather than left to be inferred from the lock carrying
    // hashes: an unhashed line slipping in must fail the build, not quietly
    // disable hash checking for the whole file.
    const uv = spawnSync("uv", ["--version"]).status === 0;
    const engineSource = buildEngineWheel();
    if (uv) {
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
    } else {
      run("python3", [
        "-m",
        "pip",
        "install",
        "--quiet",
        "--target",
        target,
        "--no-binary",
        ":all:",
        "--no-compile",
        "--require-hashes",
        "-r",
        REQUIREMENTS_LOCK_PATH,
      ]);
      run("python3", [
        "-m",
        "pip",
        "install",
        "--quiet",
        "--target",
        target,
        "--no-compile",
        "--no-deps",
        engineSource,
      ]);
    }
    mkdirSync(dirname(PYZ_PATH), { recursive: true });
    const out = run("python3", ["-c", WRITE_PYZ], {
      PYZ_TARGET_DIR: target,
      PYZ_OUT: PYZ_PATH,
    });
    process.stderr.write(out);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

if (existsSync(PYZ_PATH) && process.argv.includes("--if-missing")) {
  process.stderr.write("daemon.pyz already present, skipping (--if-missing)\n");
} else if (
  import.meta.url === new URL(`file://${process.argv[1]}`).href ||
  process.argv[1]?.endsWith("build-redactor-pyz.mjs")
) {
  buildRedactorPyz();
}
