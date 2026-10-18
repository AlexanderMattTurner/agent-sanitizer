/**
 * The host override for the cold-start hookgate marker.
 *
 * The hooks wait out an in-flight `session-setup` by polling a marker file whose
 * path they DERIVE from `CLAUDE_PROJECT_DIR`. A host whose own setup script
 * already writes a marker — under its own naming convention — otherwise has two
 * choices, both bad: adopt this package's stem and digest verbatim (pinning
 * itself to our path forever), or run a second wait loop against a path nothing
 * writes. `configureHookgateMarker` is the third option, and this file pins its
 * two properties:
 *
 *   - LOAD-BEARING WHEN SUPPLIED. Every consumer that resolves through
 *     `hookgateMarkerPath()` — the module-scope wait in lib/control-plane.mjs,
 *     the lazy reload in scan-invisible-chars — sees the host's path, and the
 *     trust check that guards the wait accepts a real file there.
 *   - LOUD, NOT FATAL, WHEN LATE. control-plane.mjs resolves the marker at module
 *     scope, so a configure call that lands after that import cannot steer the
 *     wait it was meant to steer. That is reported on stderr and not thrown: a
 *     throw at a bundle entry's top level kills the hook before it writes a
 *     response, and a hook that emits nothing is read as non-blocking — a
 *     fail-OPEN, which is a far worse outcome than a mis-timed override.
 *
 * hook-io is imported ALONE here, and nothing resolves a marker before the first
 * test: importing a hook module would run control-plane's module-scope
 * resolution first, and the before-anything-resolved case could then never be
 * observed at all.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "acorn";

const {
  configureHookgateMarker,
  hookgateMarkerPath,
  isPrivateDir,
  markerIsTrusted,
} = await import("../claude-hooks/lib/hook-io.mjs");

const dir = mkdtempSync(join(tmpdir(), "sanitizer-marker-"));
const HOST_MARKER = join(dir, "host-hookgate-inflight");

/** Run `fn` with stderr captured, returning what it wrote. */
function captureStderr(fn) {
  /** @type {string[]} */
  const written = [];
  const original = process.stderr.write;
  // @ts-expect-error -- narrower than the overloaded write signature; the
  // callers here only ever pass a string chunk.
  process.stderr.write = (chunk) => {
    written.push(String(chunk));
    return true;
  };
  try {
    fn();
  } finally {
    process.stderr.write = original;
  }
  return written.join("");
}

describe("configureHookgateMarker", () => {
  it("replaces the derived path for every consumer", () => {
    const warning = captureStderr(() => configureHookgateMarker(HOST_MARKER));
    // Nothing has resolved a marker yet, so this call is in time and silent.
    assert.equal(warning, "");
    assert.equal(hookgateMarkerPath(), HOST_MARKER);
    // Explicit arguments lose to the override too: a host that named its marker
    // is naming it for every consumer, not just the env-derived ones.
    assert.equal(
      hookgateMarkerPath("/work/proj", "/run/user/1000"),
      HOST_MARKER,
    );
  });

  it("hands the wait a marker the trust check accepts", () => {
    writeFileSync(HOST_MARKER, `${process.pid}\n`);
    // markerIsTrusted is what gates the cold-start poll; resolving to a path it
    // rejects would leave the wait permanently unarmed.
    assert.equal(markerIsTrusted(hookgateMarkerPath()), true);
  });

  it("restores the derivation when passed null", () => {
    captureStderr(() => configureHookgateMarker(null));
    const derived = hookgateMarkerPath("/work/proj", "");
    assert.ok(derived?.startsWith("/tmp/agent-sanitizer-hookgate-inflight-"));
    assert.equal(hookgateMarkerPath("", ""), null);
  });

  it("warns rather than throws when it lands after a resolution", () => {
    const warning = captureStderr(() => configureHookgateMarker(HOST_MARKER));
    assert.match(warning, /configureHookgateMarker called after/u);
    // The late call still governs every LATER resolution — the warning names
    // what it could not reach, it does not discard the override.
    assert.equal(hookgateMarkerPath(), HOST_MARKER);
  });
});

/**
 * Every hook module under claude-hooks/, as [relative path, parsed program].
 * Parsed with acorn rather than grepped: a mention in a comment or a string is
 * not a reference, and a call split across lines is still one.
 * @returns {Array<[string, import("acorn").Program]>}
 */
function hookPrograms() {
  const root = fileURLToPath(new URL("../claude-hooks/", import.meta.url));
  return readdirSync(root, { recursive: true })
    .map(String)
    .filter((rel) => rel.endsWith(".mjs"))
    .sort()
    .map((rel) => [
      rel,
      parse(readFileSync(join(root, rel), "utf8"), {
        ecmaVersion: "latest",
        sourceType: "module",
      }),
    ]);
}

/**
 * Identifier and non-computed property names referenced in `program`, counted.
 * @param {import("acorn").Program} program
 * @returns {Map<string, number>}
 */
function identifierCounts(program) {
  /** @type {Map<string, number>} */
  const counts = new Map();
  // Every child node, generically: acorn-walk's base visitor skips the
  // Identifier children of import specifiers, which is where a bare
  // `import { userInfo }` lives.
  const visit = (/** @type {any} */ node) => {
    if (node === null || typeof node !== "object") return;
    if (node.type === "Identifier")
      counts.set(node.name, (counts.get(node.name) ?? 0) + 1);
    for (const child of Array.isArray(node) ? node : Object.values(node))
      visit(child);
  };
  visit(program);
  return counts;
}

/**
 * Property names `program` reads as `x.name` (non-computed member access) —
 * what a stat's owner or mode looks like, as distinct from an options key
 * (`{ mode: 0o700 }`) or a local named `uid`.
 * @param {import("acorn").Program} program
 * @returns {Set<string>}
 */
function memberReads(program) {
  /** @type {Set<string>} */
  const names = new Set();
  const visit = (/** @type {any} */ node) => {
    if (node === null || typeof node !== "object") return;
    if (node.type === "MemberExpression" && !node.computed)
      names.add(node.property.name);
    for (const child of Array.isArray(node) ? node : Object.values(node))
      visit(child);
  };
  visit(program);
  return names;
}

describe("ownership checks read the kernel uid, never the passwd database", () => {
  it("survive a uid that has no passwd entry", async () => {
    // A container started as `--user 54321` has a uid and no passwd row, and
    // os.userInfo() throws ENOENT there. Model exactly that: every ownership
    // check must still answer, because a throw out of one crashes its hook.
    const os = await import("node:os");
    const { syncBuiltinESMExports } = await import("node:module");
    const real = os.default.userInfo;
    os.default.userInfo = () => {
      throw Object.assign(new Error("uv_os_get_passwd returned ENOENT"), {
        code: "ENOENT",
      });
    };
    syncBuiltinESMExports();
    try {
      const own = join(dir, "own-marker");
      writeFileSync(own, "");
      assert.equal(markerIsTrusted(own), true);
      const { classifySocket } =
        await import("../claude-hooks/lib/redactor-client.mjs");
      assert.equal(classifySocket(join(dir, "no-socket")), "absent");
      const { ownedByCurrentUser } =
        await import("../claude-hooks/lib/hook-io.mjs");
      assert.equal(ownedByCurrentUser({ uid: -12345 }), false);
    } finally {
      os.default.userInfo = real;
      syncBuiltinESMExports();
    }
  });

  it("route every ownership and mode test through the hook-io predicates", () => {
    const programs = hookPrograms();
    assert.ok(programs.length > 5, "no hook modules parsed");
    const offenders = programs
      .filter(([, program]) => identifierCounts(program).has("userInfo"))
      .map(([rel]) => rel);
    assert.deepEqual(offenders, [], "os.userInfo() throws for an unmapped uid");
    // A stat's owner and mode bits are read in hook-io alone, so a new store
    // cannot hand-roll a weaker trust test beside the shared one.
    const ownHome = join("lib", "hook-io.mjs");
    const readers = programs.flatMap(([rel, program]) => {
      const read = memberReads(program);
      return ["uid", "mode", "getuid"]
        .filter((name) => read.has(name))
        .map((name) => `${rel}: .${name}`);
    });
    assert.deepEqual(
      readers.filter((entry) => !entry.startsWith(`${ownHome}:`)),
      [],
    );
    // Positive markers: hook-io is where they live, and the predicates are
    // what the stores call — so dropping the checks cannot pass vacuously.
    // More than one reference = the import plus at least one use.
    assert.deepEqual(readers, [
      `${ownHome}: .uid`,
      `${ownHome}: .mode`,
      `${ownHome}: .getuid`,
    ]);
    const users = programs
      .filter(([rel, program]) => {
        const counts = identifierCounts(program);
        return (
          rel !== ownHome &&
          [
            "ownedByCurrentUser",
            "isPrivateDir",
            "privateDirAt",
            "currentUid",
          ].some((name) => (counts.get(name) ?? 0) > 1)
        );
      })
      .map(([rel]) => rel);
    assert.deepEqual(users, [
      join("lib", "invisible-alert.mjs"),
      join("lib", "redactor-client.mjs"),
      join("lib", "reveal.mjs"),
    ]);
  });
});

describe("isPrivateDir is the one private-directory trust test", () => {
  const SELF = 1000;
  /**
   * A stat shape the test process could not create for real (another uid's
   * directory, a root-owned one).
   * @param {{ dir?: boolean, uid?: number, mode: number }} shape
   */
  const stat = ({ dir = true, uid = SELF, mode }) => ({
    isDirectory: () => dir,
    uid,
    mode: (dir ? 0o040000 : 0o100000) | mode,
  });
  /** [case, stat shape, opts, trusted] */
  const CASES = [
    ["own 0700", { mode: 0o700 }, {}, true],
    ["own 0755 (read is not the property)", { mode: 0o755 }, {}, true],
    ["own, group-writable", { mode: 0o770 }, {}, false],
    ["own, world-writable", { mode: 0o707 }, {}, false],
    ["own, sticky world-writable", { mode: 0o1777 }, {}, false],
    ["another uid's 0700", { uid: 4242, mode: 0o700 }, {}, false],
    ["root's 0755, root not allowed", { uid: 0, mode: 0o755 }, {}, false],
    [
      "root's 0755, root allowed",
      { uid: 0, mode: 0o755 },
      { rootMayOwn: true },
      true,
    ],
    [
      "root's 0777, root allowed",
      { uid: 0, mode: 0o777 },
      { rootMayOwn: true },
      false,
    ],
    ["a file, not a dir", { dir: false, mode: 0o600 }, {}, false],
    [
      "no uid model, root-owned",
      { uid: 0, mode: 0o700 },
      { uid: null, rootMayOwn: true },
      false,
    ],
  ];
  for (const [label, shape, opts, trusted] of CASES)
    it(`${label}: ${trusted ? "trusted" : "refused"}`, () => {
      assert.equal(isPrivateDir(stat(shape), { uid: SELF, ...opts }), trusted);
    });

  it("judges a real symlink to a private dir as the link, not the target", () => {
    const target = join(dir, "private-target");
    const link = join(dir, "private-link");
    mkdirSync(target, { mode: 0o700 });
    symlinkSync(target, link);
    assert.equal(isPrivateDir(lstatSync(target)), true);
    assert.equal(isPrivateDir(lstatSync(link)), false);
  });
});

after(() => rmSync(dir, { recursive: true, force: true }));
