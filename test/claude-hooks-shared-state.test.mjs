/**
 * The cross-instance seam on hook-io: `hookIoSharedState` / `adoptHookIoSharedState`.
 *
 * A host that ships its own hook-io module beside the packaged hooks runs TWO
 * instances of this file's state in one process. Each keeps its own copy of all
 * four host-visible slots — the lazy registry, the CLI-entry latch, the
 * missing-package remedy and the hookgate marker path — so a slot set on one is
 * invisible to the readers on the other. Every one of those splits fails
 * SILENTLY, which is why each has a test here: an unregistered specifier makes
 * the gate fail closed on every call, a lost claim makes an inlined CLI eat the
 * entry's stdin, a lost remedy names a command the host does not have, and a
 * lost marker path makes the cold-start wait poll a file nobody writes. The seam
 * lets the second instance adopt the first's state object instead.
 *
 * Two module instances are produced here the same way a bundler produces them:
 * by importing the module under two distinct specifiers, which gives two
 * separate module records. The first test asserts they really are separate —
 * without it every assertion below could pass on one shared instance and prove
 * nothing.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

const MODULE = "../claude-hooks/lib/hook-io.mjs";

let instances = 0;

/**
 * A pair of independent hook-io module instances, as a bundler's duplication
 * produces them.
 * @returns {Promise<[any, any]>}
 */
async function twoInstances() {
  const tag = ++instances;
  return Promise.all([
    import(`${MODULE}?instance=${tag}a`),
    import(`${MODULE}?instance=${tag}b`),
  ]);
}

const ALPHA = { alpha: 1 };
const BETA = { beta: 2 };

/** The argv[1] URL isMain compares against, so a claim is what flips it. */
const entryUrl = pathToFileURL(process.argv[1]).href;

const HOST_REMEDY = "run ./setup.sh in the project root and retry.";
const HOST_MARKER = "/run/host-hookgate-inflight";

/** What hookgateMarkerPath DERIVES for ("/proj", "/run") when no host path is set
 * -- the answer an omitted `hookgateMarker` slot must not displace. */
const DERIVED_MARKER = (
  await import("../claude-hooks/lib/hook-io.mjs?derived")
).hookgateMarkerPath("/proj", "/run");

describe("hook-io instances are separate without the seam", () => {
  it("neither registrations nor a CLI claim cross instances", async () => {
    const [host, packaged] = await twoInstances();
    host.registerLazyModules({ "pkg/one": ALPHA });
    host.claimCliEntry();
    assert.equal(packaged.registeredLazyModule("pkg/one"), undefined);
    assert.deepEqual(await packaged.lazyImport("pkg/one"), {});
    assert.equal(packaged.isMain(entryUrl), true);
  });
});

describe("adoptHookIoSharedState", () => {
  it("gives one registerLazyModules call reach over both instances", async () => {
    const [host, packaged] = await twoInstances();
    packaged.adoptHookIoSharedState(host.hookIoSharedState());
    host.registerLazyModules({ "pkg/one": ALPHA });
    assert.equal(packaged.registeredLazyModule("pkg/one"), ALPHA);
    assert.equal(await packaged.lazyImport("pkg/one"), ALPHA);
    // And back the other way: after the adopt there is one registry, not a copy
    // taken at adopt time, so a packaged registration reaches the host binders.
    packaged.registerLazyModules({ "pkg/two": BETA });
    assert.equal(host.registeredLazyModule("pkg/two"), BETA);
  });

  it("gives one claimCliEntry call reach over both instances", async () => {
    const [host, packaged] = await twoInstances();
    packaged.adoptHookIoSharedState(host.hookIoSharedState());
    assert.equal(packaged.isMain(entryUrl), true);
    host.claimCliEntry();
    assert.equal(packaged.isMain(entryUrl), false);
    assert.equal(host.isMain(entryUrl), false);
  });

  it("carries the adopting instance's own registrations and claim over", async () => {
    const [host, packaged] = await twoInstances();
    packaged.registerLazyModules({ "pkg/two": BETA });
    packaged.claimCliEntry();
    packaged.adoptHookIoSharedState(host.hookIoSharedState());
    assert.equal(host.registeredLazyModule("pkg/two"), BETA);
    assert.equal(host.isMain(entryUrl), false);
  });

  it("keeps a claim already made on the adopted state", async () => {
    // The mirror of the case above, and the one that pins `if (claimed) set true`
    // against a plain `state.x = shared.x`: the plain form erases a claim the
    // adopted root already holds. An entry that claims and then adopts would
    // silently lose the claim, and per isMain's own note the inlined hook's CLI
    // then fires alongside the entry's and eats its stdin — a fail-open.
    const [host, packaged] = await twoInstances();
    host.claimCliEntry();
    packaged.adoptHookIoSharedState(host.hookIoSharedState());
    assert.equal(host.isMain(entryUrl), false);
    assert.equal(packaged.isMain(entryUrl), false);
  });

  it("carries the host remedy and marker path to the other instance", async () => {
    // The two slots beyond the registry and the latch. Split, they fail the same
    // silent way: the packaged control-plane waits on a marker path nobody
    // writes, and a fail-closed reason names `pnpm install` in a host whose one
    // install entry point is its own setup script.
    const [host, packaged] = await twoInstances();
    packaged.adoptHookIoSharedState(host.hookIoSharedState());
    host.configureMissingPackageRemedy(HOST_REMEDY);
    host.configureHookgateMarker(HOST_MARKER);
    assert.match(
      packaged.missingPackageMessage("pkg"),
      new RegExp(HOST_REMEDY),
    );
    assert.equal(packaged.hookgateMarkerPath("/proj"), HOST_MARKER);
  });

  it("keeps a remedy and a marker set before the adopt", async () => {
    const [host, packaged] = await twoInstances();
    packaged.configureMissingPackageRemedy(HOST_REMEDY);
    packaged.configureHookgateMarker(HOST_MARKER);
    packaged.adoptHookIoSharedState(host.hookIoSharedState());
    assert.match(host.missingPackageMessage("pkg"), new RegExp(HOST_REMEDY));
    assert.equal(host.hookgateMarkerPath("/proj"), HOST_MARKER);
  });

  it("keeps the adopted state's own remedy and marker when both hold one", async () => {
    // The adopted root is the host's choice, so its value wins over whatever the
    // adopting instance had. Without that arm the carry-over above overwrites the
    // root and the host's own configuration is silently replaced by the packaged
    // instance's.
    const [host, packaged] = await twoInstances();
    host.configureMissingPackageRemedy(HOST_REMEDY);
    host.configureHookgateMarker(HOST_MARKER);
    packaged.configureMissingPackageRemedy("some other remedy.");
    packaged.configureHookgateMarker("/run/other-marker");
    packaged.adoptHookIoSharedState(host.hookIoSharedState());
    assert.match(
      packaged.missingPackageMessage("pkg"),
      new RegExp(HOST_REMEDY),
    );
    assert.equal(packaged.hookgateMarkerPath("/proj"), HOST_MARKER);
  });

  it("keeps the adopted state's own entry for a specifier both hold", async () => {
    const [host, packaged] = await twoInstances();
    host.registerLazyModules({ "pkg/one": ALPHA });
    packaged.registerLazyModules({ "pkg/one": BETA });
    packaged.adoptHookIoSharedState(host.hookIoSharedState());
    assert.equal(packaged.registeredLazyModule("pkg/one"), ALPHA);
  });

  it("fills slots a host root object omits", async () => {
    // A host builds this object itself, so one written against an earlier version
    // of the package lacks the slots added since. Every reader tests `!== null`,
    // which an absent slot satisfies -- so unfilled, hookgateMarkerPath answers
    // `undefined` instead of deriving a path, and the cold-start wait then treats
    // setup as alive forever.
    const [, packaged] = await twoInstances();
    const legacyRoot = /** @type {any} */ ({
      lazyModules: Object.create(null),
      cliEntryClaimed: false,
    });
    packaged.adoptHookIoSharedState(legacyRoot);
    assert.equal(packaged.hookgateMarkerPath("/proj", "/run"), DERIVED_MARKER);
    assert.ok(
      packaged
        .missingPackageMessage("pkg")
        .endsWith(packaged.DEFAULT_MISSING_PACKAGE_REMEDY),
    );
  });

  it("fills a root that omits lazyModules, which would otherwise throw", async () => {
    // The loudest of the omissions. Pre-fill, the carry-over loop indexes
    // `state.lazyModules[specifier]` on an undefined — a TypeError at a bundle
    // entry's top level, which kills the hook before it writes a response.
    const [, packaged] = await twoInstances();
    packaged.registerLazyModules({ "pkg/one": ALPHA });
    const bareRoot = /** @type {any} */ ({});
    packaged.adoptHookIoSharedState(bareRoot);
    assert.equal(packaged.registeredLazyModule("pkg/one"), ALPHA);
  });

  it("carries a remedy and marker onto a root that omits those slots", async () => {
    // What makes the fill load-bearing for these two: the carry-over arms test
    // `state.x === null`, which is FALSE for an absent slot, so without the fill
    // the adopting instance's own configured values are dropped on the floor
    // rather than moved onto the root.
    const [, packaged] = await twoInstances();
    packaged.configureMissingPackageRemedy(HOST_REMEDY);
    packaged.configureHookgateMarker(HOST_MARKER);
    const legacyRoot = /** @type {any} */ ({
      lazyModules: Object.create(null),
      cliEntryClaimed: false,
    });
    packaged.adoptHookIoSharedState(legacyRoot);
    assert.equal(legacyRoot.hookgateMarker, HOST_MARKER);
    assert.equal(legacyRoot.missingPackageRemedy, HOST_REMEDY);
  });

  it("is a no-op on the instance's own state", async () => {
    const [host] = await twoInstances();
    host.registerLazyModules({ "pkg/one": ALPHA });
    host.adoptHookIoSharedState(host.hookIoSharedState());
    assert.equal(host.registeredLazyModule("pkg/one"), ALPHA);
  });
});
