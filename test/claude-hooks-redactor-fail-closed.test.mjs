/**
 * The fail-closed error `redactViaDaemon` hands its caller is an operator-facing
 * message: a hook splices it into what the user reads when an output could not
 * be vetted. Its exact shape is therefore the observable, and these cases pin
 * it — one fail-closed sentence, and a timeout that names the wait the redactor
 * was actually given rather than the constant it was clamped from.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  redactViaDaemon,
  spawnDaemon,
  waitForSocket,
} from "../claude-hooks/lib/redactor-client.mjs";

/** A connect failure the client treats as "no daemon" and respawns for. */
function deadSocket() {
  return Object.assign(new Error("connect ENOENT"), { code: "ENOENT" });
}

/** Rejects with the error `redactViaDaemon` threw, failing if it resolves. */
async function failure(promise) {
  try {
    await promise;
  } catch (error) {
    return /** @type {Error} */ (error);
  }
  return assert.fail("redactViaDaemon resolved where it had to fail closed");
}

describe("the fail-closed message is wrapped exactly once", () => {
  it("wraps a malformed response from the first dial once", async () => {
    const error = await failure(
      redactViaDaemon("some text", {
        webIngress: false,
        connect: async () => ({ found: [] }),
      }),
    );
    assert.equal(
      error.message,
      "secret redaction unavailable (redactor returned a malformed plain " +
        "response (neither null nor `{text, found}`)); secret-shaped output " +
        "could not be vetted",
    );
  });

  it("wraps a malformed response from the post-respawn retry once", async () => {
    // The retry arm wraps what its own catch caught, so a response validated
    // inside it is the second way the sentence can nest inside itself.
    let dialled = 0;
    const error = await failure(
      redactViaDaemon("some text", {
        map: true,
        webIngress: false,
        connect: async () => {
          if (++dialled === 1) throw deadSocket();
          return {};
        },
        spawn: () => {},
        waitForSocket: async () => true,
      }),
    );
    assert.equal(dialled, 2);
    assert.equal(
      error.message,
      "secret redaction unavailable (redactor returned a malformed map " +
        "response (neither `{text, pairs, found}` nor `{unmappable}`)); " +
        "secret-shaped output could not be vetted",
    );
  });
});

describe("the respawn timeout names the wait that actually elapsed", () => {
  it("reports the budget-clamped wait, not the unclamped constant", async () => {
    // A caller's shared budget of 200ms clamps the cold-start wait to 200ms, so
    // an operator reading the default 8000ms would hunt a slow daemon that was
    // never given the time.
    const error = await failure(
      redactViaDaemon("some text", {
        webIngress: false,
        deadline: { remainingMs: () => 200 },
        connect: async () => {
          throw deadSocket();
        },
        spawn: () => {},
        waitForSocket: async () => false,
      }),
    );
    assert.equal(
      error.message,
      "secret redaction unavailable (redactor daemon did not start within " +
        "200ms); secret-shaped output could not be vetted",
    );
  });

  it("names the unclamped wait when the budget cannot clamp it", async () => {
    // Non-vacuity for the clamp: a budget WIDER than the constant leaves the
    // constant as the wait, so the message must name that — a fix that simply
    // printed the budget would read 999999ms here. The standalone (no budget)
    // call must land on the same wait, since nothing clamped it either.
    const timedOut = (opts) =>
      failure(
        redactViaDaemon("some text", {
          webIngress: false,
          ...opts,
          connect: async () => {
            throw deadSocket();
          },
          spawn: () => {},
          waitForSocket: async () => false,
        }),
      );
    const wide = await timedOut({ deadline: { remainingMs: () => 999_999 } });
    const standalone = await timedOut({});
    assert.equal(wide.message, standalone.message);
    const named = /did not start within (?<ms>\d+)ms/.exec(wide.message)?.groups
      .ms;
    assert.ok(named, `no wait named in: ${wide.message}`);
    assert.ok(
      Number(named) > 200 && Number(named) < 999_999,
      `the wait must be the constant, not the budget: ${wide.message}`,
    );
  });
});

describe("webIngress is a required choice, never a default", () => {
  for (const [label, opts] of [
    ["omitted options", undefined],
    ["omitted flag", { map: true }],
    ["non-boolean flag", { webIngress: "false" }],
  ])
    it(`refuses ${label} before dialing`, async () => {
      let dialled = false;
      const run = () =>
        redactViaDaemon(
          "some text",
          opts && {
            ...opts,
            connect: async () => {
              dialled = true;
              return null;
            },
          },
        );
      await assert.rejects(run, {
        name: "TypeError",
        message: /opts\.webIngress must be true .* or false/u,
      });
      assert.equal(dialled, false);
    });
});

describe("a daemon that dies on startup fails the call with its own reason", () => {
  /**
   * Drive the respawn arm with a REAL spawned process standing in for the
   * daemon, and the real socket wait, bounded by `budgetMs` — or, with
   * `endless`, by nothing at all: the wait then ends only when the daemon is
   * reported dead, which is what proves it did not wait out a budget.
   * @param {string[]} command
   * @param {number} budgetMs
   * @param {{endless?: boolean}} [opts]
   */
  async function respawnWith(command, budgetMs, { endless = false } = {}) {
    const started = Date.now();
    return failure(
      redactViaDaemon("some text", {
        webIngress: false,
        socketPath: "/nonexistent-dir/redactor.sock",
        deadline: { remainingMs: () => budgetMs - (Date.now() - started) },
        connect: async () => {
          throw deadSocket();
        },
        spawn: (socketPath) => spawnDaemon(socketPath, command),
        waitForSocket: endless
          ? (socketPath, opts) =>
              waitForSocket(socketPath, { ...opts, deadlineMs: Infinity })
          : waitForSocket,
      }),
    );
  }

  it(
    "reports a non-zero exit with its stderr tail, without waiting out the budget",
    // A hang bound, not a speed bound: a passing run returns as soon as the
    // child exits, so no load comes near it.
    { timeout: 60_000 },
    async () => {
      // The wait has no deadline here, so only the exit can end it: a wait that
      // ignored the death would never return, and the timeout above reports it.
      const error = await respawnWith(
        [
          "python3",
          "-c",
          "import sys; sys.stderr.write('refusing the cache dir\\n'); sys.exit(3)",
        ],
        6000,
        { endless: true },
      );
      assert.equal(
        error.message,
        "secret redaction unavailable (redactor daemon failed to start " +
          "(exit 3: refusing the cache dir)); secret-shaped output could not be vetted",
      );
    },
  );

  it("reports a daemon binary that does not exist", async () => {
    const error = await respawnWith(["/nonexistent/redactor-daemon"], 6000);
    assert.match(
      error.message,
      /redactor daemon failed to start \(spawn \/nonexistent\/redactor-daemon ENOENT\)/u,
    );
  });

  it("keeps waiting after a clean exit, which is a lost bind race", async () => {
    // Exit 0 is what a daemon does when another already owns the socket, so it
    // must not abandon the wait: the failure is the plain timeout.
    const error = await respawnWith(["python3", "-c", "pass"], 600);
    assert.match(error.message, /redactor daemon did not start within \d+ms/u);
  });
});
