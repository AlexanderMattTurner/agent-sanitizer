/**
 * Compile plugin/requirements.in into plugin/requirements.txt: the fully
 * resolved, hash-pinned dependency tree of the redaction engine.
 *
 * WHY A LOCK. The zipapp build used to install the bare
 * `agent-sanitizer[secrets]==X.Y.Z` spec, so pip re-resolved the TRANSITIVE
 * tree at build time. Only the engine was pinned; certifi, charset-normalizer,
 * idna, pyyaml, requests and urllib3 floated. Every release of any of them
 * changed the committed daemon.pyz's bytes with no diff anywhere in this repo —
 * the byte-compare in the live-engine job went red on a PR that touched nothing
 * related, and the only fix was a one-line regeneration that bought a few days.
 * With every version and artifact hash pinned here, the rebuild is reproducible
 * until someone deliberately re-locks.
 *
 * NETWORK: this resolves against PyPI, so it is NOT part of the offline
 * reproducibility rebuild. Run it when the engine pin moves (requirements.in
 * changed) or when you deliberately want newer transitives; both are reviewable
 * as a diff of the lock.
 *
 * Determinism: `--universal` resolves one tree valid on every platform, so the
 * lock does not depend on the machine that compiled it; `--python-version`
 * pins the resolution floor; `--custom-compile-command` keeps the header
 * stable no matter how the script was invoked.
 */
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import {
  REQUIREMENTS_IN_PATH,
  REQUIREMENTS_LOCK_PATH,
  enginePin,
  lockedEngineVersion,
} from "./build-plugin.mjs";

/**
 * Resolution floor. The engine's own `requires-python` is >=3.10; resolving at
 * the floor keeps the lock installable on every Python the plugin supports. A
 * bump in the engine's floor surfaces here as a loud resolver error, not as a
 * lock that silently excludes older interpreters.
 */
const PYTHON_VERSION = "3.10";

/** Reproduced verbatim in the lock header, so re-running is copy-pasteable. */
const COMPILE_COMMAND = "node plugin/scripts/lock-redactor-deps.mjs";

export function lockRedactorDeps() {
  if (spawnSync("uv", ["--version"]).status !== 0)
    throw new Error(
      "uv is required to compile the redactor lock (https://docs.astral.sh/uv/). " +
        "pip-tools is not a substitute: the lock's universal resolution and hash " +
        "set must match what the build installs with.",
    );

  const res = spawnSync(
    "uv",
    [
      "pip",
      "compile",
      REQUIREMENTS_IN_PATH,
      "--generate-hashes",
      // Mirrors the build's install flags, so the resolver considers exactly
      // the artifacts the build will accept.
      "--no-binary",
      ":all:",
      "--universal",
      "--python-version",
      PYTHON_VERSION,
      "--custom-compile-command",
      COMPILE_COMMAND,
      "--output-file",
      REQUIREMENTS_LOCK_PATH,
    ],
    { encoding: "utf8" },
  );
  if (res.status !== 0)
    throw new Error(
      `uv pip compile failed (${res.status}):\n${res.stdout}\n${res.stderr}`,
    );

  // uv echoes the input path as given, which is absolute here; rewrite it to the
  // repo-relative spelling so the lock does not carry the compiling machine's
  // directory layout. Normalise before validating, so a failed check never
  // leaves a machine-specific file behind.
  const text = readFileSync(REQUIREMENTS_LOCK_PATH, "utf-8").replaceAll(
    REQUIREMENTS_IN_PATH,
    "plugin/requirements.in",
  );
  writeFileSync(REQUIREMENTS_LOCK_PATH, text);

  // The lock is only useful if it pins the engine this plugin is built against.
  // A resolver that quietly picked a different version (a stale requirements.in,
  // a hand-edited --output-file) must fail loudly, not ship a mismatched floor.
  const version = enginePin();
  const locked = lockedEngineVersion(text);
  if (locked !== version)
    throw new Error(
      `${REQUIREMENTS_LOCK_PATH} pins agent-sanitizer==${locked}, but the ` +
        `sanitizer-engine alias in package.json pins ${version}. Regenerate ` +
        `requirements.in with \`node plugin/scripts/build-plugin.mjs\` first.`,
    );
  process.stderr.write(
    `wrote ${REQUIREMENTS_LOCK_PATH} (agent-sanitizer==${version})\n`,
  );
}

/**
 * True when the committed lock does not pin the engine package.json pins — the
 * only condition under which re-locking is MANDATORY (the build refuses a
 * mismatch). Everything else about the lock is deliberately frozen.
 * @returns {boolean}
 */
export function lockIsStale() {
  return (
    lockedEngineVersion(readFileSync(REQUIREMENTS_LOCK_PATH, "utf-8")) !==
    enginePin()
  );
}

if (process.argv[1] === import.meta.filename) {
  // `--if-stale` is what CI runs. An unconditional re-lock there would re-resolve
  // the transitive tree on every artifact-regenerating PR, reintroducing exactly
  // the floating-dependency drift this lock exists to stop. Refreshing
  // transitives stays a deliberate, reviewable act: run this with no flag.
  if (process.argv.includes("--if-stale") && !lockIsStale())
    process.stderr.write(
      `${REQUIREMENTS_LOCK_PATH} already pins agent-sanitizer==${enginePin()}, skipping (--if-stale)\n`,
    );
  else lockRedactorDeps();
}
