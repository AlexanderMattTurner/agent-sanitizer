/**
 * Drives the two clocks `claude-hooks/lib/hook-timing.mjs` reads by default, so a
 * test of a timer exercises the PRODUCTION default path (`Date.now`, and
 * `process.cpuUsage` through `processCpuMs`) with exact deltas instead of
 * sleeping or spinning for a real interval and asserting a lower or upper bound
 * on what the machine happened to do. The default parameters are resolved at
 * call time, so stubbing the globals reaches them; the stubs are restored when
 * the test ends.
 *
 * A callback that "blocks" calls {@link DrivenClock.wait} (wall clock only, as a
 * hook parked on a socket) or {@link DrivenClock.compute} (wall and CPU, as a
 * `spawnSync`-style annotator that burns processor time in this process).
 */

/**
 * @typedef {object} DrivenClock
 * @property {(ms: number) => void} wait  advance wall clock only
 * @property {(ms: number) => void} compute  advance wall clock and CPU alike
 */

/**
 * @param {import("node:test").TestContext} t
 * @returns {DrivenClock}
 */
export function driveClocks(t) {
  let wallMs = 1_000_000;
  let cpuMs = 0;
  t.mock.method(Date, "now", () => wallMs);
  t.mock.method(process, "cpuUsage", () => ({
    user: cpuMs * 1000,
    system: 0,
  }));
  return {
    wait: (ms) => {
      wallMs += ms;
    },
    compute: (ms) => {
      wallMs += ms;
      cpuMs += ms;
    },
  };
}
