/**
 * The shared hook-timing report: one threshold, one message, one merge rule.
 *
 * A hook that gets slow is invisible from the inside — it reads as "the agent is
 * slow" — so the only thing that surfaces it is this in-band notice. These cases
 * pin what the notice says, that it never displaces a hook's real verdict
 * context, and that a healthy run says NOTHING (a performance line on every call
 * would be exactly the alert fatigue the sanitizer's warnings already fight).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  chargeHostExtension,
  chargeHostExtensionSync,
  excludeProvisioning,
  formatBytes,
  reportSlowHook,
  sanitizerVersion,
  slowHookNotice,
  startHookTimer,
  withSlowHookNotice,
  writeSlowHookNotice,
  SLOW_HOOK_THRESHOLD_MS,
} from "../claude-hooks/lib/hook-timing.mjs";
import { runJudgeCli } from "../claude-hooks/lib/control-plane.mjs";
import { awaitLazyDependency } from "../claude-hooks/lib/hook-io.mjs";
import { redactViaDaemon } from "../claude-hooks/lib/redactor-client.mjs";

/** A clock that advances by exactly the deltas it is given. */
function fakeClock(...deltas) {
  let t = 1_000_000;
  const steps = [0, ...deltas];
  return () => {
    t += /** @type {number} */ (steps.shift() ?? 0);
    return t;
  };
}

describe("startHookTimer", () => {
  it("reports the elapsed milliseconds, and can be read more than once", () => {
    const timer = startHookTimer(fakeClock(250, 400));
    assert.equal(timer.wallMs(), 250);
    assert.equal(timer.wallMs(), 650);
  });

  it("reports CPU separately from wall-clock", () => {
    // The split the notice is built on: a run that waited 7.2s while computing
    // 0.3s of it is a busy machine, not a slow sanitizer.
    const timer = startHookTimer(fakeClock(7200), fakeClock(300));
    assert.equal(timer.wallMs(), 7200);
    assert.equal(timer.cpuMs(), 300);
  });

  it("measures real CPU through the default clock", () => {
    // Non-vacuity for the production path: the injected-clock cases above
    // would all pass if process.cpuUsage() were never wired in at all.
    const timer = startHookTimer();
    let sink = 0;
    for (let i = 0; i < 5_000_000; i++) sink += i % 7;
    assert.ok(sink > 0);
    assert.ok(timer.cpuMs() > 0, "a busy loop must show up as CPU");
  });

  it("charges a hook that WAITS no CPU it did not spend", async () => {
    // The false positive this whole split closes: a hook parked on a loaded
    // scheduler or a slow socket burns wall-clock and no processor time.
    const timer = startHookTimer();
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.ok(timer.wallMs() >= 45, `wall was ${timer.wallMs()}`);
    assert.ok(timer.cpuMs() < 40, `sleeping cost ${timer.cpuMs()}ms of CPU`);
  });
});

describe("provisioning is not the hook's cost", () => {
  // The false positive this closes: on a cold container the dependency wait and
  // the first redactor spawn run INSIDE a hook invocation and take seconds. A
  // notice charging those to the hook would fire on the first call of every
  // session, name the wrong culprit, and teach the reader to ignore it.

  it("subtracts a provisioning window that runs inside the timer", async () => {
    let t = 0;
    const clock = () => t;
    const timer = startHookTimer(clock);
    t += 50; // real hook work
    await excludeProvisioning(async () => {
      t += 30_000; // a dependency install we merely waited out
    }, clock);
    t += 20; // more real work
    assert.equal(timer.wallMs(), 70);
    assert.equal(slowHookNotice("h", timer.wallMs()), null);
  });

  it("subtracts the CPU a provisioning step spent, not just its wait", async () => {
    // awaitLazyDependency imports the engine INSIDE a provisioning window, and
    // that import is real in-process work — charged, it would hand the first
    // call of every session a CPU figure it never spent.
    let t = 0;
    let cpu = 0;
    const clock = () => t;
    const cpuClock = () => cpu;
    const timer = startHookTimer(clock, cpuClock);
    t += 50;
    cpu += 40; // real hook work
    await excludeProvisioning(
      async () => {
        t += 3_000;
        cpu += 900; // importing the engine
      },
      clock,
      cpuClock,
    );
    assert.equal(timer.wallMs(), 50);
    assert.equal(timer.cpuMs(), 40);
  });

  it("charges provisioning that FAILED, so a failed wait is not reported as slow", async () => {
    let t = 0;
    const clock = () => t;
    const timer = startHookTimer(clock);
    await assert.rejects(
      excludeProvisioning(async () => {
        t += 5_000;
        throw new Error("install died");
      }, clock),
      /install died/u,
    );
    assert.equal(timer.wallMs(), 0);
  });

  it("never lets one run's provisioning pay down a later run's real cost", async () => {
    let t = 0;
    let cpu = 0;
    const clock = () => t;
    const cpuClock = () => cpu;
    await excludeProvisioning(
      async () => {
        t += 30_000;
        cpu += 900;
      },
      clock,
      cpuClock,
    );
    // A LATER timer sees none of that credit: its window starts clean.
    const timer = startHookTimer(clock, cpuClock);
    t += 2_000;
    cpu += 1_500;
    assert.equal(timer.wallMs(), 2_000);
    assert.equal(timer.cpuMs(), 1_500);
    assert.match(slowHookNotice("h", timer.wallMs()), /2\.0s/u);
  });

  it("excuses the cold-start dependency wait (awaitLazyDependency)", async () => {
    let t = 0;
    const clock = () => t;
    const timer = startHookTimer(clock);
    let polls = 0;
    const loaded = await awaitLazyDependency({
      // Resolves only after the install "finishes" — three polls of waiting.
      tryImport: async () => (++polls < 4 ? null : { ok: true }),
      markerPresent: () => true,
      setupAlive: () => true,
      now: clock,
      sleep: async () => {
        t += 10_000;
      },
      intervalMs: 10_000,
    });
    assert.deepEqual(loaded, { ok: true });
    assert.equal(timer.wallMs(), 0, "30s of install wait must not be charged");
  });

  it("excuses the cold redactor-daemon spawn", async () => {
    let t = 0;
    const clock = () => t;
    const timer = startHookTimer(clock);
    const dead = Object.assign(new Error("no socket"), { code: "ENOENT" });
    let dialled = 0;
    const result = await redactViaDaemon("some text", {
      // First dial fails as if the daemon were absent; the retry succeeds.
      connect: async () => {
        if (++dialled === 1) throw dead;
        return { text: "some text", found: [] };
      },
      spawn: () => {},
      waitForSocket: async () => {
        t += 3_000; // detect-secrets import + plugin prime
        return true;
      },
      now: clock,
    });
    assert.deepEqual(result, { text: "some text", found: [] });
    assert.equal(
      timer.wallMs(),
      0,
      "the daemon cold start must not be charged",
    );
    assert.equal(
      timer.redactorMs(),
      0,
      "a cold start is provisioning, not a round trip",
    );
  });
});

describe("the redactor round trip's share of the wait", () => {
  // The daemon runs in its own long-lived process, so its cost lands in neither
  // this process's getrusage(RUSAGE_SELF) (what process.cpuUsage reads) nor
  // RUSAGE_CHILDREN (which needs a reaped child). Unmeasured, a hook whose
  // second went entirely into a redaction call reports near-zero CPU and reads
  // as a busy machine that never touched the sanitizer.

  it("charges a round trip to the redactor, and to the wall-clock the user waited", async () => {
    let t = 0;
    const clock = () => t;
    const timer = startHookTimer(clock, () => 0);
    const result = await redactViaDaemon("some text", {
      connect: async () => {
        t += 2_500;
        return { text: "some text", found: [] };
      },
      now: clock,
    });
    assert.deepEqual(result, { text: "some text", found: [] });
    assert.equal(timer.redactorMs(), 2_500);
    assert.equal(
      timer.wallMs(),
      2_500,
      "a slow redaction is a per-call cost the user waits for, so it stays in wall",
    );
  });

  it("charges a round trip that FAILED", async () => {
    // A dial that stalled to its deadline is the most expensive one there is;
    // dropping it would hand the whole wait to the busy-machine reading.
    let t = 0;
    const clock = () => t;
    const timer = startHookTimer(clock, () => 0);
    await assert.rejects(
      redactViaDaemon("some text", {
        connect: async () => {
          t += 20_000;
          throw new Error("redactor response timeout");
        },
        now: clock,
      }),
      /redactor response timeout/u,
    );
    assert.equal(timer.redactorMs(), 20_000);
  });

  it("charges BOTH dials when a dead socket forces a respawn and retry", async () => {
    let t = 0;
    const clock = () => t;
    const timer = startHookTimer(clock, () => 0);
    const dead = Object.assign(new Error("no socket"), { code: "ENOENT" });
    let dialled = 0;
    await redactViaDaemon("some text", {
      connect: async () => {
        t += 400;
        if (++dialled === 1) throw dead;
        return { text: "some text", found: [] };
      },
      spawn: () => {},
      waitForSocket: async () => {
        t += 3_000; // provisioning: the cold detect-secrets import
        return true;
      },
      now: clock,
    });
    assert.equal(timer.redactorMs(), 800, "both dials, and not the cold start");
  });

  it("never lets one run's round trip land on a later run's timer", async () => {
    let t = 0;
    const clock = () => t;
    await redactViaDaemon("some text", {
      connect: async () => {
        t += 5_000;
        return { text: "some text", found: [] };
      },
      now: clock,
    });
    const timer = startHookTimer(clock, () => 0);
    t += 40;
    assert.equal(timer.redactorMs(), 0);
  });
});

describe("slowHookNotice", () => {
  it("says nothing at or under the budget", () => {
    assert.equal(slowHookNotice("sanitize-output", 0), null);
    assert.equal(
      slowHookNotice("sanitize-output", SLOW_HOOK_THRESHOLD_MS),
      null,
    );
  });

  it("names the hook, the timing and where to report it", () => {
    const notice = slowHookNotice(
      "scan-invisible-chars",
      SLOW_HOOK_THRESHOLD_MS + 29_000,
    );
    assert.match(notice, /scan-invisible-chars/);
    assert.match(notice, /30\.0s/);
    assert.match(notice, /1\.0s budget/);
    assert.match(notice, /github\.com\/.*\/issues/);
  });

  it("names the CPU share, and blames the sanitizer for only that", () => {
    // The measured case this wording exists for: 7.2s of wall against 0.3s of
    // work, on a box running three other jobs. The old line asserted the whole
    // 7.2s was the sanitizer's and that every call repeated it — both false.
    const notice = slowHookNotice("sanitize-output", 7_200, undefined, {
      cpuMs: 300,
    });
    assert.match(notice, /took 7\.2s/);
    assert.match(notice, /used 0\.3s of CPU/);
    assert.match(notice, /Only the CPU share is work every affected call/);
    assert.match(notice, /spent waiting/);
    assert.match(notice, /hook name and both timings/);
  });

  it("names candidates for the wait and commits to none", () => {
    // A hook blocked on a dead socket inside a HOST extension spends no CPU and
    // adds no machine load, so a clause asserting "waiting on a busy machine"
    // states a cause nothing measured — the same overreach the CPU split closed
    // one sentence earlier. Observed: 5.25s of wall, ~0 CPU, one unanswered
    // TCP connect issued by a host extension.
    const notice = slowHookNotice("sanitize-output", 5_250, undefined, {
      cpuMs: 0,
    });
    assert.match(notice, /on a busy machine or on something this hook called/);
    assert.doesNotMatch(notice, /the rest was waiting on a busy machine/);
  });

  it("puts the wait in the redactor call when that is where it went", () => {
    // The report this wording exists for: 6.9s of wall against 0.05s of CPU,
    // all of it inside a redactor round trip. Read as CPU-versus-the-rest, that
    // is indistinguishable from a loaded box that never called the sanitizer.
    const notice = slowHookNotice("sanitize-output", 6_900, undefined, {
      cpuMs: 50,
      redactorMs: 6_800,
    });
    assert.match(notice, /0\.1s was this hook's own CPU/);
    assert.match(notice, /6\.8s was inside redactor round trips/);
    assert.match(
      notice,
      /The largest share was spent inside the redactor round trip/,
    );
    // No host figure was passed, so the notice claims none and asks for three.
    assert.doesNotMatch(notice, /inside host extensions/);
    assert.match(notice, /hook name and all three timings/);
  });

  it("names the round trip as a WINDOW, never as the culprit inside it", () => {
    // The round trip is wall-clock from this side, so it holds the daemon's
    // scan AND whatever descheduling a contended host imposed on either end.
    // Naming the daemon from that number would re-commit, one bucket over, the
    // overreach the CPU split exists to retract — so the verdict offers both
    // and picks neither. Separating them needs telemetry from inside the
    // daemon, which the wire protocol (whose response may be a bare null) has
    // nowhere to carry.
    const notice = slowHookNotice("sanitize-output", 6_900, undefined, {
      cpuMs: 50,
      redactorMs: 6_800,
    });
    assert.match(notice, /the daemon's scan, the host it shares, or both/);
    assert.doesNotMatch(notice, /the sanitizer owns/);
  });

  it("blames this hook when the hook is what computed", () => {
    const notice = slowHookNotice("scan-invisible-chars", 4_000, undefined, {
      cpuMs: 3_800,
      redactorMs: 100,
    });
    assert.match(notice, /The largest share is this hook computing/);
    assert.doesNotMatch(notice, /inside the redactor round trip/);
  });

  it("blames neither when the time went somewhere it can see neither of", () => {
    // Same 7.2s-against-0.3s host contention as above, now with the redactor
    // call ruled OUT by measurement rather than left as an unfalsified
    // candidate — the one thing this side CAN settle.
    const notice = slowHookNotice("sanitize-output", 7_200, undefined, {
      cpuMs: 300,
      redactorMs: 120,
    });
    assert.match(
      notice,
      /The largest share is neither the redactor nor this hook computing/,
    );
    assert.match(notice, /a host extension this caller does not measure/);
  });

  it("names the host extension when the wait went into a composer's callback", () => {
    // The report this window exists for: a composer's best-effort audit POST to
    // an unreachable sink waited out its 1.0s connect bound on EVERY tool call,
    // and the notice could attribute none of it — a reader was sent to the
    // sanitizer for a wait its own extension spent.
    const notice = slowHookNotice("sanitize-output", 1_150, undefined, {
      cpuMs: 100,
      redactorMs: 0,
      hostMs: 1_000,
    });
    assert.match(notice, /1\.0s was inside host extensions/);
    assert.match(
      notice,
      /The largest share was spent inside a host extension this hook called/,
    );
    assert.doesNotMatch(notice, /blocked on a loaded machine/);
  });

  it("counts a nested charge once, not once per bracket", async () => {
    // The package brackets `postText` and `audit` itself AND publishes the
    // charger, so a composer charging its own work inside one of those callbacks
    // would double-count: a 60ms callback reported as 120ms of host time, which
    // can exceed the run's own wall-clock and flip the largest-share verdict.
    const timer = startHookTimer();
    await chargeHostExtension(() =>
      chargeHostExtension(
        () => new Promise((resolve) => setTimeout(resolve, 60)),
      ),
    );
    assert.ok(
      timer.hostMs() >= 50 && timer.hostMs() < 120,
      `one interval, charged once (${timer.hostMs()}ms)`,
    );
  });

  it("charges a SYNCHRONOUS callback's wait and keeps its CPU off the hook", () => {
    // `redactNote` must answer synchronously, so the async charger cannot wrap it.
    // Its CPU lands in this process, so an uncharged sync callback is worse than
    // an unmeasured one: the wait vanishes AND the sanitizer is billed for it.
    const timer = startHookTimer();
    const before = timer.cpuMs();
    const value = chargeHostExtensionSync(() => {
      const until = Date.now() + 60;
      while (Date.now() < until) {
        /* a callback that computes, as a spawnSync-based annotator does */
      }
      return "note";
    });
    assert.equal(value, "note");
    assert.ok(timer.hostMs() >= 50, `charged (${timer.hostMs()}ms)`);
    // The hook's own CPU figure must not grow by the callback's compute: it is
    // the composer's cost, and charging it twice would name the sanitizer.
    assert.ok(
      timer.cpuMs() - before < 40,
      `the callback's CPU stays off the hook (${timer.cpuMs() - before}ms)`,
    );
  });

  it("tells a measured-empty host window apart from an unmeasured one", () => {
    // A caller that runs the charger and saw no callback passes 0, and the zero is
    // a finding: it rules the window OUT. A caller that cannot measure omits the
    // number, and the notice must not invent a zero for it.
    const measured = slowHookNotice("sanitize-output", 4_000, undefined, {
      cpuMs: 3_800,
      redactorMs: 100,
      hostMs: 0,
    });
    assert.match(measured, /0\.0s was inside host extensions/);
    assert.match(measured, /The largest share is this hook computing/);
    const unmeasured = slowHookNotice(
      "scan-invisible-chars",
      4_000,
      undefined,
      {
        cpuMs: 3_800,
        redactorMs: 100,
      },
    );
    assert.doesNotMatch(unmeasured, /inside host extensions/);
    assert.match(unmeasured, /hook name and all three timings/);
  });

  it("admits it cannot attribute the wait when no CPU figure is given", () => {
    // The shell port's case. Silence about the split beats a claim nothing
    // measured — see plugin/scripts/lib/hook-timing.sh.
    const notice = slowHookNotice("safe-launch PreToolUse", 7_200);
    assert.match(notice, /Wall-clock alone cannot separate/);
    assert.doesNotMatch(notice, /CPU share/);
    assert.match(notice, /hook name and timing\./);
  });

  it("claims no per-call cost it has not measured, in either form", () => {
    // Non-vacuity for the two cases above: the retracted sentence is gone from
    // BOTH forms, not merely reworded in the one the shell does not emit.
    for (const context of [undefined, { cpuMs: 300 }])
      assert.doesNotMatch(
        slowHookNotice("h", 7_200, undefined, context),
        /this delay is the sanitizer's/,
      );
  });

  it("honors an explicit threshold", () => {
    assert.equal(slowHookNotice("x", 50, 100), null);
    assert.match(slowHookNotice("x", 300, 100), /0\.3s/);
  });

  it("omits the context clause when no context is given", () => {
    const notice = slowHookNotice("h", SLOW_HOOK_THRESHOLD_MS + 500);
    assert.doesNotMatch(notice, /payload/);
    assert.doesNotMatch(notice, /tool /);
  });

  it("omits the context clause when context carries neither field", () => {
    const notice = slowHookNotice(
      "h",
      SLOW_HOOK_THRESHOLD_MS + 500,
      undefined,
      {},
    );
    assert.doesNotMatch(notice, /payload/);
  });

  it("names the payload size and triggering tool when both are known", () => {
    const notice = slowHookNotice(
      "sanitize-output",
      SLOW_HOOK_THRESHOLD_MS + 3_400,
      undefined,
      { payloadBytes: 1_363_149, tool: "TaskOutput" },
    );
    assert.match(notice, /a 1\.3 MB payload/);
    assert.match(notice, /tool TaskOutput/);
  });

  it("names only the field that is known", () => {
    const bytesOnly = slowHookNotice(
      "h",
      SLOW_HOOK_THRESHOLD_MS + 500,
      undefined,
      { payloadBytes: 2048 },
    );
    assert.match(bytesOnly, /a 2\.0 KB payload/);
    assert.doesNotMatch(bytesOnly, /tool /);

    const toolOnly = slowHookNotice(
      "h",
      SLOW_HOOK_THRESHOLD_MS + 500,
      undefined,
      { tool: "Bash" },
    );
    assert.match(toolOnly, /tool Bash/);
    assert.doesNotMatch(toolOnly, /payload/);
  });
});

describe("the version an issue report is asked to carry", () => {
  it("names this build, so the report does not have to be chased for it", () => {
    // A timing means nothing without the build it was measured on: the report
    // that prompted this arrived as "1.1s of hook CPU" with no version, and
    // pinning it down took a round trip.
    assert.match(
      slowHookNotice("sanitize-output", 1_100, undefined, {
        cpuMs: 1_100,
        redactorMs: 0,
        hostMs: 0,
      }),
      new RegExp(`with agent-sanitizer ${sanitizerVersion()}, the hook name`),
    );
  });

  /**
   * Stage one artifact layout: a copy of the module under `moduleDir`, plus a
   * manifest per entry of `manifests`, and report the version it resolves.
   *
   * A copy rather than a stub, so what answers is the shipped resolver reading
   * a real tree — the layouts are exactly the offsets each artifact ships at.
   * @param {string} moduleDir  the module's directory, relative to the root
   * @param {Record<string, unknown>} manifests  root-relative path to contents
   * @returns {Promise<string | null>}
   */
  async function versionUnderLayout(moduleDir, manifests) {
    const root = mkdtempSync(path.join(tmpdir(), "hook-timing-layout-"));
    for (const [file, contents] of Object.entries(manifests)) {
      mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
      writeFileSync(path.join(root, file), JSON.stringify(contents));
    }
    const target = path.join(root, moduleDir, "hook-timing.mjs");
    mkdirSync(path.dirname(target), { recursive: true });
    copyFileSync(
      path.join(
        path.dirname(fileURLToPath(import.meta.url)),
        "..",
        "claude-hooks",
        "lib",
        "hook-timing.mjs",
      ),
      target,
    );
    const staged = await import(pathToFileURL(target).href);
    return staged.sanitizerVersion();
  }

  const PLUGIN_MANIFEST = ".claude-plugin/plugin.json";

  it("reads the manifest each shipped artifact puts beside it", async () => {
    // npm ships this module at claude-hooks/lib/ beside the package.json whose
    // version is injected at publish; the plugin ships the bundle at
    // plugin/dist/hooks/ beside its own manifest.
    assert.equal(
      await versionUnderLayout("claude-hooks/lib", {
        "package.json": { name: "agent-sanitizer", version: "3.1.4" },
      }),
      "3.1.4",
    );
    assert.equal(
      await versionUnderLayout("plugin/dist/hooks", {
        [`plugin/${PLUGIN_MANIFEST}`]: { version: "5.6.7" },
      }),
      "5.6.7",
    );
  });

  it("prefers a checkout's plugin manifest over package.json's placeholder", async () => {
    // In a source tree package.json still holds the frozen placeholder npm
    // overwrites at publish — a real past release, so reporting it would be
    // indistinguishable from an install of that version.
    assert.equal(
      await versionUnderLayout("claude-hooks/lib", {
        "package.json": { name: "agent-sanitizer", version: "1.0.1" },
        [`plugin/${PLUGIN_MANIFEST}`]: { version: "2.2.2" },
      }),
      "2.2.2",
    );
  });

  it("reads the fixed offsets only, never an ancestor's manifest", async () => {
    // A copy sitting somewhere other than the offsets the artifacts ship at —
    // vendored, relocated — has no manifest of its own, and the nearest one up
    // the tree describes a DIFFERENT install of this package. Reporting 9.9.9
    // from there sends the maintainer to the wrong tree, which is the whole
    // failure the version exists to prevent.
    assert.equal(
      await versionUnderLayout("nested/claude-hooks/lib", {
        "package.json": { name: "agent-sanitizer", version: "9.9.9" },
      }),
      null,
    );
  });

  it("asks for the version rather than guessing one when it knows none", () => {
    // A compiled hook binary resolves no manifest. Printing a placeholder
    // version there would route every report to the wrong tree.
    const unknown = slowHookNotice(
      "sanitize-output",
      1_100,
      undefined,
      undefined,
      null,
    );
    assert.match(unknown, /with your agent-sanitizer version, the hook name/);
    assert.doesNotMatch(unknown, /agent-sanitizer [0-9]/);
  });
});

describe("formatBytes", () => {
  it("tiers bytes, KB and MB", () => {
    assert.equal(formatBytes(512), "512 B");
    assert.equal(formatBytes(2048), "2.0 KB");
    assert.equal(formatBytes(1_363_149), "1.3 MB");
  });
});

describe("writeSlowHookNotice with context", () => {
  it("carries the context into the stderr-written notice", () => {
    const errs = [];
    const notice = writeSlowHookNotice(
      "h",
      SLOW_HOOK_THRESHOLD_MS + 500,
      (chunk) => errs.push(chunk),
      { payloadBytes: 100, tool: "Bash" },
    );
    assert.match(notice, /tool Bash/);
    assert.match(errs[0], /tool Bash/);
  });
});

describe("withSlowHookNotice with context", () => {
  it("folds the context into the verdict's additional_context", () => {
    const out = withSlowHookNotice(
      "h",
      SLOW_HOOK_THRESHOLD_MS + 500,
      { decision: "allow" },
      () => {},
      { payloadBytes: 1_363_149, tool: "TaskOutput" },
    );
    assert.match(out.additional_context, /a 1\.3 MB payload/);
    assert.match(out.additional_context, /tool TaskOutput/);
  });
});

describe("withSlowHookNotice", () => {
  it("returns the verdict untouched, and writes nothing, under budget", () => {
    const errs = [];
    const verdict = { decision: "allow" };
    const out = withSlowHookNotice("h", 10, verdict, (chunk) =>
      errs.push(chunk),
    );
    assert.equal(out, verdict);
    assert.deepEqual(errs, []);
  });

  it("attaches the notice to a verdict that carries no context", () => {
    const out = withSlowHookNotice(
      "h",
      SLOW_HOOK_THRESHOLD_MS + 500,
      { decision: "allow" },
      () => {},
    );
    assert.equal(out.decision, "allow");
    assert.match(out.additional_context, /PERFORMANCE/);
  });

  it("APPENDS to an existing context instead of replacing it", () => {
    const out = withSlowHookNotice(
      "h",
      SLOW_HOOK_THRESHOLD_MS + 500,
      { decision: "allow", additional_context: "API keys/secrets redacted" },
      () => {},
    );
    assert.match(out.additional_context, /API keys\/secrets redacted/);
    assert.match(out.additional_context, /PERFORMANCE/);
  });

  it("also puts the timing on stderr, once", () => {
    const errs = [];
    withSlowHookNotice(
      "h",
      SLOW_HOOK_THRESHOLD_MS + 500,
      { decision: "allow" },
      (chunk) => errs.push(chunk),
    );
    assert.equal(errs.length, 1);
    assert.match(errs[0], /PERFORMANCE/);
  });
});

describe("reportSlowHook (no-verdict events)", () => {
  it("emits nothing for a run inside the budget", () => {
    const errs = [];
    const emitted = [];
    const reported = reportSlowHook(
      "scan-invisible-chars",
      5,
      "SessionStart",
      (event, fields) => emitted.push([event, fields]),
      (chunk) => errs.push(chunk),
    );
    assert.equal(reported, false);
    assert.deepEqual(errs, []);
    assert.deepEqual(emitted, []);
  });

  it("emits the envelope and the stderr line for a slow run", () => {
    const errs = [];
    const emitted = [];
    const reported = reportSlowHook(
      "scan-invisible-chars",
      SLOW_HOOK_THRESHOLD_MS + 1,
      "SessionStart",
      (event, fields) => emitted.push([event, fields]),
      (chunk) => errs.push(chunk),
    );
    assert.equal(reported, true);
    assert.equal(errs.length, 1);
    assert.equal(emitted.length, 1);
    const [event, fields] = emitted[0];
    assert.equal(event, "SessionStart");
    assert.match(fields.additionalContext, /scan-invisible-chars/);
  });

  it("carries the caller's CPU figure into both channels", () => {
    // The SessionStart scanners have no verdict to fold a notice into, so this
    // is the only route their CPU reading takes to the model.
    const errs = [];
    const emitted = [];
    reportSlowHook(
      "scan-invisible-chars",
      7_200,
      "SessionStart",
      (event, fields) => emitted.push([event, fields]),
      (chunk) => errs.push(chunk),
      { cpuMs: 700 },
    );
    assert.match(emitted[0][1].additionalContext, /used 0\.7s of CPU/);
    assert.match(errs[0], /used 0\.7s of CPU/);
  });
});

describe("runJudgeCli times every judge hook", () => {
  const event = {
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "echo hi" },
  };

  it("attaches nothing when the judge is quick", async () => {
    const written = [];
    await runJudgeCli("pretooluse-sanitize", () => ({ decision: "allow" }), {
      onError: (err) => assert.fail(String(err)),
      readInput: async () => event,
      write: (chunk) => written.push(chunk),
    });
    assert.equal(
      written.join("").includes("PERFORMANCE"),
      false,
      written.join(""),
    );
  });

  it("attaches the notice when the judge overruns the budget", async () => {
    // A real overrun rather than an injected clock: the wiring under test is
    // that runJudgeCli measures the judge AT ALL, and a stubbed clock would
    // pass even if the call were never timed.
    const written = [];
    const errs = [];
    const realErr = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk) => {
      errs.push(String(chunk));
      return true;
    };
    try {
      await runJudgeCli(
        "pretooluse-sanitize",
        async () => {
          await new Promise((resolve) =>
            setTimeout(resolve, SLOW_HOOK_THRESHOLD_MS + 100),
          );
          return { decision: "allow" };
        },
        {
          onError: (err) => assert.fail(String(err)),
          readInput: async () => event,
          write: (chunk) => written.push(chunk),
        },
      );
    } finally {
      process.stderr.write = realErr;
    }
    const stdout = written.join("");
    assert.match(stdout, /PERFORMANCE/);
    assert.match(stdout, /pretooluse-sanitize/);
    // A judge that SLEPT past the budget is the contended-host case in
    // miniature: the wall-clock is real, most of it bought no work, and the
    // notice has to say so rather than call the whole second sanitizer work.
    // Compared, not pinned to 0.0s: the same window really does load the
    // control plane, and on a cold runner that is a tenth of a second of CPU.
    const timings = stdout.match(
      /took (\d+\.\d)s .*?of which (\d+\.\d)s was this hook's own CPU, (\d+\.\d)s was inside redactor round trips/u,
    );
    assert.ok(timings, stdout);
    const [, wall, cpu, redactor] = timings;
    assert.ok(
      Number(cpu) < Number(wall),
      `a sleeping judge must report CPU (${cpu}s) below wall (${wall}s)`,
    );
    // A judge that never dialled the daemon is the case the third number
    // exonerates the redactor in: the notice can only place a wait in that call
    // when a round trip actually happened.
    assert.equal(redactor, "0.0", stdout);
    assert.match(stdout, /The largest share is none of those three/);
    assert.ok(
      errs.some((line) => line.includes("PERFORMANCE")),
      "the timing must also reach stderr",
    );
  });

  it("reports the timing of a judge that overran AND THEN THREW", async () => {
    // The run most worth naming — slow and broken — used to report nothing at
    // all, because the timer lived inside the try and only the success path
    // read it. Again a real overrun, so the test fails if the catch stops
    // measuring rather than merely stops printing.
    const errs = [];
    let onErrorCalled = false;
    const realErr = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk) => {
      errs.push(String(chunk));
      return true;
    };
    try {
      await runJudgeCli(
        "sanitize-output",
        async () => {
          await new Promise((resolve) =>
            setTimeout(resolve, SLOW_HOOK_THRESHOLD_MS + 100),
          );
          throw new Error("judge exploded");
        },
        {
          onError: () => {
            onErrorCalled = true;
          },
          readInput: async () => event,
          write: () => assert.fail("a throwing judge writes no verdict"),
        },
      );
    } finally {
      process.stderr.write = realErr;
    }
    const stderr = errs.join("");
    assert.match(stderr, /sanitize-output hook error: judge exploded/);
    assert.match(stderr, /PERFORMANCE/);
    assert.match(stderr, /sanitize-output hook took/);
    // The error path carries all four timings too: a judge that threw after
    // stalling inside a redaction call is the run whose redactor share is the
    // finding, and this stderr line is its only report.
    assert.match(
      stderr,
      /of which \d+\.\ds was this hook's own CPU, 0\.0s was inside redactor round trips and 0\.0s was inside host extensions/u,
    );
    // The posture still runs: the timing is an addition to the fault report,
    // never a replacement for it.
    assert.ok(onErrorCalled, "onError must still take the failure posture");
  });

  it("names the triggering tool in the notice, but omits payload size for an injected reader", async () => {
    // The tool name comes from adapter.parse(event), independent of which
    // stdin reader ran; the payload-size clause is keyed off readInput being
    // the real readStdinJson, so an injected test seam must not report a
    // stale size left by some earlier real call.
    const written = [];
    await runJudgeCli(
      "pretooluse-sanitize",
      async () => {
        await new Promise((resolve) =>
          setTimeout(resolve, SLOW_HOOK_THRESHOLD_MS + 100),
        );
        return { decision: "allow" };
      },
      {
        onError: (err) => assert.fail(String(err)),
        readInput: async () => event,
        write: (chunk) => written.push(chunk),
      },
    );
    const stdout = written.join("");
    assert.match(stdout, /tool Bash/);
    assert.doesNotMatch(stdout, /payload/);
  });

  it("says nothing about timing when the INPUT read is what failed", async () => {
    // Nothing was measured — the timer starts only once stdin has arrived — and
    // inventing a number for the wait that preceded it would blame this hook
    // for the harness's handover.
    const errs = [];
    const realErr = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk) => {
      errs.push(String(chunk));
      return true;
    };
    try {
      await runJudgeCli("sanitize-output", () => assert.fail("unreachable"), {
        onError: () => {},
        readInput: async () => {
          await new Promise((resolve) =>
            setTimeout(resolve, SLOW_HOOK_THRESHOLD_MS + 100),
          );
          throw new Error("stdin closed");
        },
        write: () => assert.fail("no verdict"),
      });
    } finally {
      process.stderr.write = realErr;
    }
    assert.match(errs.join(""), /stdin closed/);
    assert.equal(errs.join("").includes("PERFORMANCE"), false);
  });
});
