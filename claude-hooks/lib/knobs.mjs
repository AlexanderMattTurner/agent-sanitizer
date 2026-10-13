/**
 * THE environment knobs the hooks and the CLI read, as one table.
 *
 * Every `AGENT_SANITIZER_*` / `_AGENT_SANITIZER_*` read goes through
 * {@link readKnob}, which looks the name up here, parses the raw value with the
 * entry's own grammar, and REPORTS a value the grammar does not recognize
 * instead of silently treating it as unset. Seven hand-rolled parsers each
 * decided that alone, and each failed the same way: `SECRETS_ENABLED=true`
 * left the secret layer off, `FAIL_OPEN=FALSE` left the hooks open, and
 * `MAX_INPUT_BYTES=0.5` became a zero-byte cap — all without a word.
 *
 * A bad value is reported, never thrown: these variables are set outside the
 * session, so a throw (or a blocking verdict) would fail every tool call on a
 * config value the session cannot edit. The entry's `fallback` is what the
 * value then reads as, and `consequence` says so in the report.
 *
 * `test/claude-hooks-knobs.test.mjs` parses every hook module and the CLI and
 * asserts the knobs they read are exactly this table, and that nothing reads
 * one past {@link readKnob}.
 */

/**
 * Values of AGENT_SANITIZER_FAIL_OPEN that select the fail-closed posture.
 * Matched exactly: a case-insensitive match would need `tr`, which the launcher
 * cannot reach (it runs its no-node arm on shell builtins alone).
 *
 * THE single source of truth for the closed set. The shell shims cannot import
 * it, so `plugin/scripts/lib/fail-open.sh` is GENERATED from it at build time
 * by `scripts/gen-fail-open-lib.mjs`; plugin/test/fail-open-parity.test.mjs
 * asserts the generated lib decides as failOpenEnabled(). Everything else that spells the set
 * out by hand is an implementation that must appear in the parity table in
 * tests/test_safe_launch.py.
 */
export const FAIL_CLOSED_VALUES = Object.freeze(["0", "false"]);

/** What a parser returns for a value its grammar does not recognize. */
const INVALID = Symbol("invalid knob value");

/**
 * One knob: its grammar, the value an unrecognized input reads as, and the two
 * halves of the report naming it.
 * @template T
 * @typedef {{
 *   parse: (raw: string | undefined) => T | typeof INVALID,
 *   fallback: T,
 *   expect: string,
 *   consequence: string,
 * }} Knob
 */

/**
 * `spec`, checked against {@link Knob} so a grammar and its fallback agree in
 * type; {@link on} freezes it.
 * @template T
 * @param {Knob<T>} spec
 * @returns {Knob<T>}
 */
const knob = (spec) => spec;

/**
 * Who sets a knob, which is where it must be documented (asserted in
 * test/claude-hooks-knobs.test.mjs):
 *   - `hooks`: a Claude Code plugin operator — plugin/README.md's knob tables;
 *   - `cli`: a caller of bin/sanitize-cli.mjs — README.md;
 *   - `internal`: `_`-prefixed plumbing hooks.json and tests set — no stable
 *     interface, so documented nowhere by name.
 * @typedef {"hooks" | "cli" | "internal"} Surface
 */

/**
 * `spec`, tagged with the surface that sets it.
 * @template {Knob<any>} S
 * @param {Surface} surface
 * @param {S} spec
 * @returns {Readonly<S & { surface: Surface }>}
 */
const on = (surface, spec) => Object.freeze({ ...spec, surface });

/** Unset and empty are the same request: the default. */
const unset = (/** @type {string | undefined} */ raw) =>
  raw === undefined || raw === "";

/**
 * An on/off switch spelled `1`. Only `1` turns it on, so no typo can switch a
 * layer on or off by accident; `0` and unset are the recognized off spellings,
 * and anything else (`true`, `yes`) is reported and reads as off.
 * @param {string} consequence  what an unrecognized value leaves in place
 * @returns {Knob<boolean>}
 */
const flag = (consequence) =>
  knob({
    parse: (raw) => {
      if (raw === "1") return true;
      return unset(raw) || raw === "0" ? false : INVALID;
    },
    fallback: false,
    expect: "1 to set it, 0 or unset to leave it off",
    consequence,
  });

/**
 * `raw` as a finite positive number of milliseconds, else `fallback`. A bare
 * `Number(env) || fallback` silently accepts a NEGATIVE override (`-5 || 8000`
 * is -5), and a non-positive deadline makes a fail-closed wait return at once.
 * @param {string | undefined} raw
 * @param {number} fallback
 * @returns {number}
 */
export function positiveMsOr(raw, fallback) {
  const ms = Number(raw);
  return Number.isFinite(ms) && ms > 0 ? ms : fallback;
}

/**
 * A duration override in milliseconds.
 * @param {number} fallback
 * @returns {Knob<number>}
 */
const milliseconds = (fallback) =>
  knob({
    parse: (raw) => {
      if (unset(raw)) return fallback;
      const ms = positiveMsOr(raw, Number.NaN);
      return Number.isNaN(ms) ? INVALID : ms;
    },
    fallback,
    expect: "a positive number of milliseconds",
    consequence: `the ${fallback} ms default applies`,
  });

/**
 * Free text the consumer interprets itself — a path, or a list whose entries
 * it validates against its own vocabulary. Empty reads as unset.
 * @returns {Knob<string | undefined>}
 */
const text = () =>
  knob({
    parse: (raw) => (unset(raw) ? undefined : raw),
    fallback: undefined,
    expect: "any text",
    consequence: "it is ignored",
  });

/** Trace verbosity spellings, matched case-insensitively. */
const TRACE_LEVELS = Object.freeze({
  0: ["", "0", "off", "false"],
  1: ["1", "info", "true", "on"],
  2: ["2", "debug"],
});

/** Largest single CLI request, in UTF-8 bytes, when the knob is unset. */
const DEFAULT_MAX_INPUT_BYTES = 10 * 1024 * 1024;

/** Every knob, by variable name. */
export const KNOBS = Object.freeze({
  // Fail-open unless one of FAIL_CLOSED_VALUES; the documented open spellings
  // are recognized too, so only a genuinely foreign value is reported.
  AGENT_SANITIZER_FAIL_OPEN: on(
    "hooks",
    knob({
      parse: (raw) => {
        if (raw !== undefined && FAIL_CLOSED_VALUES.includes(raw)) return false;
        return unset(raw) || raw === "1" || raw === "true" ? true : INVALID;
      },
      fallback: true,
      expect: `${FAIL_CLOSED_VALUES.join(" or ")} to fail closed, 1/true/unset for the default`,
      consequence: "the hooks stay fail-OPEN",
    }),
  ),
  AGENT_SANITIZER_DISABLED_HOOKS: on("hooks", text()),
  AGENT_SANITIZER_SECRETS_ENABLED: on(
    "hooks",
    flag("the secret layer stays OFF"),
  ),
  AGENT_SANITIZER_FLAG_DIGEST_VALUES: on(
    "hooks",
    flag("digest-shaped values stay exempt"),
  ),
  AGENT_SANITIZER_INVISIBLE_DISABLED: on(
    "hooks",
    flag("invisible-character stripping stays ON"),
  ),
  AGENT_SANITIZER_TERMINAL_DISABLED: on(
    "hooks",
    flag("terminal-control stripping stays ON"),
  ),
  AGENT_SANITIZER_OUTPUT_DISABLED: on(
    "hooks",
    flag("authored-content sanitizing stays ON"),
  ),
  AGENT_SANITIZER_MAX_INPUT_BYTES: on(
    "cli",
    knob({
      parse: (raw) => {
        if (unset(raw)) return DEFAULT_MAX_INPUT_BYTES;
        const bytes = Number(raw);
        return Number.isInteger(bytes) && bytes >= 1 ? bytes : INVALID;
      },
      fallback: DEFAULT_MAX_INPUT_BYTES,
      expect: "a positive whole number of bytes",
      consequence: `the ${DEFAULT_MAX_INPUT_BYTES}-byte default applies`,
    }),
  ),
  _AGENT_SANITIZER_EXTRA_SECRET_VARS: on("internal", text()),
  _AGENT_SANITIZER_TRACE: on(
    "internal",
    knob({
      parse: (raw) => {
        const value = (raw ?? "").toLowerCase();
        const level = Object.entries(TRACE_LEVELS).find(([, spellings]) =>
          spellings.includes(value),
        );
        return level === undefined ? INVALID : Number(level[0]);
      },
      fallback: 0,
      expect: "off/0, info/1/on/true, or debug/2",
      consequence: "tracing stays off",
    }),
  ),
  _AGENT_SANITIZER_TRACE_FILE: on("internal", text()),
  _AGENT_SANITIZER_REDACTOR_SOCKET: on("internal", text()),
  _AGENT_SANITIZER_REDACTOR_DAEMON: on("internal", text()),
  _AGENT_SANITIZER_REDACTOR_PYZ: on("internal", text()),
  _AGENT_SANITIZER_REDACTOR_WAIT_MS: on("internal", milliseconds(8000)),
  _AGENT_SANITIZER_REDACTOR_REQUEST_MS: on("internal", milliseconds(20000)),
  _AGENT_SANITIZER_SANITIZE_BUDGET_MS: on("internal", milliseconds(120000)),
  _AGENT_SANITIZER_REVEAL_DIR: on("internal", text()),
});

/**
 * The operator knobs the plugin's shell launcher (plugin/scripts/) reads before
 * any JS runs. They share plugin/README.md's knob tables with the `hooks`
 * surface, so the tables document exactly these plus that surface; JS never
 * reads them (the partition test holds JS reads to KNOBS).
 */
export const LAUNCHER_KNOBS = Object.freeze([
  "AGENT_SANITIZER_NODE",
  "AGENT_SANITIZER_HOOK_BINARY",
  "AGENT_SANITIZER_COMPILE_CACHE",
  "AGENT_SANITIZER_REPEAT_DEGRADED_CONTEXT",
]);

/** @typedef {typeof KNOBS} Knobs */

/** `name=value` pairs already reported, so a per-leaf read reports once. */
const reported = new Set();

/**
 * Write `message` to stderr the first time it is seen in this process.
 * @param {string} message
 * @returns {void}
 */
function reportOnce(message) {
  if (reported.has(message)) return;
  reported.add(message);
  process.stderr.write(`${message}\n`);
}

/**
 * The parsed value of knob `name` in `env`. An unrecognized value is reported
 * through `report` and reads as the knob's fallback; a name missing from
 * {@link KNOBS} throws, since it is a wiring bug in this package rather than
 * operator input.
 * @template {keyof Knobs} K
 * @param {K} name
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 * @param {(message: string) => void} [report]
 * @returns {Knobs[K]["fallback"]}
 */
export function readKnob(name, env = process.env, report = reportOnce) {
  if (!Object.hasOwn(KNOBS, name))
    throw new Error(
      `unknown knob ${JSON.stringify(name)}: declare it in KNOBS ` +
        "(claude-hooks/lib/knobs.mjs) before reading it",
    );
  /** @type {Knob<any>} */
  const spec = KNOBS[name];
  const raw = env[name];
  const value = spec.parse(raw);
  if (value !== INVALID) return value;
  const shown = JSON.stringify(/** @type {string} */ (raw).slice(0, 80));
  report(
    `agent-sanitizer: ${name}=${shown} is not a recognized value ` +
      `(${spec.expect}); ${spec.consequence}.`,
  );
  return spec.fallback;
}
