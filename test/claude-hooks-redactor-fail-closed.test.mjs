/**
 * The fail-closed error `redactViaDaemon` hands its caller is an operator-facing
 * message: a hook splices it into what the user reads when an output could not
 * be vetted. Its exact shape is therefore the observable, and these cases pin
 * it — one fail-closed sentence, and a timeout that names the wait the redactor
 * was actually given rather than the constant it was clamped from.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { redactViaDaemon } from "../claude-hooks/lib/redactor-client.mjs";

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
      redactViaDaemon("some text", { connect: async () => ({ found: [] }) }),
    );
    assert.equal(
      error.message,
      "secret redaction unavailable (redactor returned a malformed plain " +
        "response (no string `text`)); secret-shaped output could not be vetted",
    );
  });

  it("wraps a malformed response from the post-respawn retry once", async () => {
    // The retry arm wraps what its own catch caught, so a response validated
    // inside it is the second way the sentence can nest inside itself.
    let dialled = 0;
    const error = await failure(
      redactViaDaemon("some text", {
        map: true,
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
        "response (no `unmappable` marker and no `{text, pairs}` map)); " +
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
