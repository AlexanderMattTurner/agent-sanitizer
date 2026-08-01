/**
 * The cross-instance seam on hook-io: `hookIoSharedState` / `adoptHookIoSharedState`.
 *
 * A host that bundles its own copy of these helpers beside the packaged hooks
 * runs TWO instances of this module in one process. Each keeps its own lazy
 * registry and its own CLI-entry latch, so a specifier registered on one is
 * invisible to the binders on the other — inside a bundle those binders then
 * dial a loader with no node_modules and the gate fails closed on every call.
 * The seam lets the second instance adopt the first's state object instead.
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

  it("keeps the adopted state's own entry for a specifier both hold", async () => {
    const [host, packaged] = await twoInstances();
    host.registerLazyModules({ "pkg/one": ALPHA });
    packaged.registerLazyModules({ "pkg/one": BETA });
    packaged.adoptHookIoSharedState(host.hookIoSharedState());
    assert.equal(packaged.registeredLazyModule("pkg/one"), ALPHA);
  });

  it("is a no-op on the instance's own state", async () => {
    const [host] = await twoInstances();
    host.registerLazyModules({ "pkg/one": ALPHA });
    host.adoptHookIoSharedState(host.hookIoSharedState());
    assert.equal(host.registeredLazyModule("pkg/one"), ALPHA);
  });
});
