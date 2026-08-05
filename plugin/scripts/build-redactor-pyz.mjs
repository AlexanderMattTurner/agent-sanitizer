/**
 * Build the committed Python half of the plugin: a self-contained, platform-
 * independent zipapp at plugin/dist/redactor/daemon.pyz carrying the pinned
 * agent-sanitizer[secrets] redaction engine.
 *
 * Without this the Python side had the cold-start hole the JS bundle closes:
 * provision-redactor.sh installs from PyPI at SessionStart, so until that
 * finishes (or forever, without network) sanitize-output failed closed on every
 * tool call. The committed .pyz is the guaranteed floor; the provisioned venv
 * remains a startup-latency optimization the launcher prefers when present.
 *
 * NETWORK: this build installs from PyPI, so it is NOT part of the network-free
 * reproducibility rebuild in the default test suite. The live-engine CI job
 * rebuilds and byte-compares it; the default suite asserts the committed
 * artifact's properties (tracked, pure-Python, runnable) without rebuilding.
 *
 * Determinism: the install comes from the fully resolved, hash-pinned
 * plugin/requirements.txt, so no transitive release can change these bytes —
 * pinning only the engine left certifi/charset-normalizer/idna/pyyaml/requests/
 * urllib3 to be re-resolved on every build, and each of their releases silently
 * invalidated the committed artifact. `--no-binary :all:` installs every
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
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  REQUIREMENTS_LOCK_PATH,
  enginePin,
  lockedEngineVersion,
} from "./build-plugin.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Committed artifact path. */
export const PYZ_PATH = join(ROOT, "plugin", "dist", "redactor", "daemon.pyz");

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
  const version = enginePin();
  // The lock is what actually gets installed, so a lock that pins some other
  // engine would silently ship a zipapp disagreeing with the JS bundle beside
  // it. Refuse rather than build the mismatch.
  const locked = lockedEngineVersion(
    readFileSync(REQUIREMENTS_LOCK_PATH, "utf-8"),
  );
  if (locked !== version)
    throw new Error(
      `${REQUIREMENTS_LOCK_PATH} pins agent-sanitizer==${locked}, but the ` +
        `sanitizer-engine alias in package.json pins ${version}. Re-lock with ` +
        "`node plugin/scripts/build-plugin.mjs && node plugin/scripts/lock-redactor-deps.mjs`.",
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
