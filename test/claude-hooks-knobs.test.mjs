/**
 * The environment knobs are ONE table (claude-hooks/lib/knobs.mjs), read only
 * through readKnob, and a value outside a knob's grammar is reported rather than
 * silently read as unset.
 *
 * Seven hand-rolled parsers each made that call alone, and each failed quietly:
 * `AGENT_SANITIZER_SECRETS_ENABLED=true` left the secret layer off,
 * `AGENT_SANITIZER_FAIL_OPEN=FALSE` left the hooks open, and
 * `AGENT_SANITIZER_MAX_INPUT_BYTES=0.5` became a zero-byte cap. So this file
 * pins three things:
 *
 *   - the PARTITION: the knobs the hook modules and the CLI read are exactly
 *     the table's keys, and nothing reads one past readKnob (parsed, not
 *     grepped, so a mention in prose is not a read);
 *   - each knob's GRAMMAR, including the reported values;
 *   - every public knob is DOCUMENTED, since an operator can only set a knob
 *     they can find.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "acorn";

import { KNOBS, readKnob } from "../claude-hooks/lib/knobs.mjs";
import { failOpenEnabled } from "../claude-hooks/lib/hook-io.mjs";
import { secretsEnabled } from "../claude-hooks/lib/env-config.mjs";

const repo = fileURLToPath(new URL("..", import.meta.url));
const KNOB_NAME = /^_?AGENT_SANITIZER_[A-Z0-9_]+$/u;

/** Every module that may read a knob, as [repo-relative path, source]. */
function knobReaders() {
  const hooks = readdirSync(join(repo, "claude-hooks"), { recursive: true })
    .map(String)
    .filter((rel) => rel.endsWith(".mjs"))
    .map((rel) => join("claude-hooks", rel));
  return [...hooks, join("bin", "sanitize-cli.mjs")]
    .filter((rel) => rel !== join("claude-hooks", "lib", "knobs.mjs"))
    .sort()
    .map((rel) => [rel, readFileSync(join(repo, rel), "utf8")]);
}

/**
 * Every node of `program`, generically — acorn-walk's base visitor skips some
 * Identifier children, and this question needs all of them.
 * @param {any} node
 * @param {(node: any) => void} visit
 */
function eachNode(node, visit) {
  if (node === null || typeof node !== "object") return;
  if (typeof node.type === "string") visit(node);
  for (const child of Array.isArray(node) ? node : Object.values(node))
    eachNode(child, visit);
}

/**
 * The knob reads and the bypasses in one module's source.
 * @param {string} source
 * @returns {{ reads: string[], unresolved: string[], bypasses: string[] }}
 */
function knobUse(source) {
  const program = parse(source, {
    ecmaVersion: "latest",
    sourceType: "module",
  });
  /** Module-scope string constants, so `readKnob(FAIL_OPEN_ENV)` resolves. */
  const constants = new Map();
  eachNode(program, (node) => {
    if (
      node.type === "VariableDeclarator" &&
      node.id.type === "Identifier" &&
      node.init?.type === "Literal" &&
      typeof node.init.value === "string"
    )
      constants.set(node.id.name, node.init.value);
  });
  /** @param {any} node @returns {string | undefined} */
  const nameOf = (node) =>
    node.type === "Literal" && typeof node.value === "string"
      ? node.value
      : node.type === "Identifier"
        ? constants.get(node.name)
        : undefined;
  const reads = [];
  const unresolved = [];
  const bypasses = [];
  eachNode(program, (node) => {
    if (
      node.type === "CallExpression" &&
      node.callee.type === "Identifier" &&
      node.callee.name === "readKnob"
    ) {
      const name = nameOf(node.arguments[0]);
      if (name === undefined)
        unresolved.push(source.slice(node.start, node.end));
      else reads.push(name);
    }
    // `env.AGENT_SANITIZER_X`, `env["AGENT_SANITIZER_X"]`, `env[X_ENV]`.
    if (node.type === "MemberExpression") {
      const key = node.computed ? nameOf(node.property) : node.property.name;
      if (key !== undefined && KNOB_NAME.test(key))
        bypasses.push(source.slice(node.start, node.end));
    }
  });
  return { reads, unresolved, bypasses };
}

describe("every knob read goes through the one table", () => {
  const modules = knobReaders().map(([rel, source]) => [rel, knobUse(source)]);

  it("finds the bypass shapes it polices (non-vacuous)", () => {
    const sample = knobUse(
      'const X_ENV = "AGENT_SANITIZER_FAIL_OPEN";\n' +
        "process.env.AGENT_SANITIZER_SECRETS_ENABLED;\n" +
        'env["_AGENT_SANITIZER_TRACE"];\n' +
        "env[X_ENV];\n" +
        "env[name];\n" +
        "readKnob(X_ENV);\n",
    );
    assert.deepEqual(sample.bypasses, [
      "process.env.AGENT_SANITIZER_SECRETS_ENABLED",
      'env["_AGENT_SANITIZER_TRACE"]',
      "env[X_ENV]",
    ]);
    assert.deepEqual(sample.reads, ["AGENT_SANITIZER_FAIL_OPEN"]);
  });

  it("reads no knob past readKnob", () => {
    const offenders = modules.flatMap(([rel, use]) =>
      use.bypasses.map((expr) => `${rel}: ${expr}`),
    );
    assert.deepEqual(offenders, []);
  });

  it("names every knob it reads as a literal or a module constant", () => {
    const unresolved = modules.flatMap(([rel, use]) =>
      use.unresolved.map((expr) => `${rel}: ${expr}`),
    );
    assert.deepEqual(unresolved, []);
  });

  it("reads exactly the table's knobs, in both directions", () => {
    const read = new Set(modules.flatMap(([, use]) => use.reads));
    assert.deepEqual([...read].sort(), Object.keys(KNOBS).sort());
  });
});

/**
 * readKnob with the report captured.
 * @param {keyof typeof KNOBS} name
 * @param {string | undefined} raw
 */
function readCaptured(name, raw) {
  /** @type {string[]} */
  const reports = [];
  const value = readKnob(name, { [name]: raw }, (message) =>
    reports.push(message),
  );
  return { value, reported: reports.length > 0 };
}

const MiB10 = 10 * 1024 * 1024;

describe("each knob's grammar", () => {
  /** [knob, raw, value, reported] */
  const CASES = [
    ["AGENT_SANITIZER_FAIL_OPEN", undefined, true, false],
    ["AGENT_SANITIZER_FAIL_OPEN", "", true, false],
    ["AGENT_SANITIZER_FAIL_OPEN", "1", true, false],
    ["AGENT_SANITIZER_FAIL_OPEN", "true", true, false],
    ["AGENT_SANITIZER_FAIL_OPEN", "0", false, false],
    ["AGENT_SANITIZER_FAIL_OPEN", "false", false, false],
    // Only the exact closed spellings close it — the launcher's shell arm
    // cannot case-fold — but the near miss is now said out loud.
    ["AGENT_SANITIZER_FAIL_OPEN", "FALSE", true, true],
    ["AGENT_SANITIZER_FAIL_OPEN", "off", true, true],
    ["AGENT_SANITIZER_SECRETS_ENABLED", "1", true, false],
    ["AGENT_SANITIZER_SECRETS_ENABLED", "0", false, false],
    ["AGENT_SANITIZER_SECRETS_ENABLED", undefined, false, false],
    ["AGENT_SANITIZER_SECRETS_ENABLED", "true", false, true],
    ["AGENT_SANITIZER_SECRETS_ENABLED", "yes", false, true],
    ["AGENT_SANITIZER_OUTPUT_DISABLED", "1", true, false],
    ["AGENT_SANITIZER_OUTPUT_DISABLED", "on", false, true],
    ["AGENT_SANITIZER_MAX_INPUT_BYTES", undefined, MiB10, false],
    ["AGENT_SANITIZER_MAX_INPUT_BYTES", "1024", 1024, false],
    ["AGENT_SANITIZER_MAX_INPUT_BYTES", "1e6", 1000000, false],
    ["AGENT_SANITIZER_MAX_INPUT_BYTES", "0.5", MiB10, true],
    ["AGENT_SANITIZER_MAX_INPUT_BYTES", "0", MiB10, true],
    ["AGENT_SANITIZER_MAX_INPUT_BYTES", "-5", MiB10, true],
    ["AGENT_SANITIZER_MAX_INPUT_BYTES", "lots", MiB10, true],
    ["_AGENT_SANITIZER_TRACE", undefined, 0, false],
    ["_AGENT_SANITIZER_TRACE", "DEBUG", 2, false],
    ["_AGENT_SANITIZER_TRACE", "on", 1, false],
    ["_AGENT_SANITIZER_TRACE", "verbose", 0, true],
    ["_AGENT_SANITIZER_REDACTOR_WAIT_MS", undefined, 8000, false],
    ["_AGENT_SANITIZER_REDACTOR_WAIT_MS", "300", 300, false],
    ["_AGENT_SANITIZER_REDACTOR_WAIT_MS", "-5", 8000, true],
    ["_AGENT_SANITIZER_REVEAL_DIR", "", undefined, false],
    ["_AGENT_SANITIZER_REVEAL_DIR", "/x", "/x", false],
  ];
  for (const [name, raw, value, reported] of CASES)
    it(`${name}=${JSON.stringify(raw)} reads ${JSON.stringify(value)}${reported ? ", reported" : ""}`, () => {
      assert.deepEqual(readCaptured(name, raw), { value, reported });
    });

  it("names the knob, the value and the consequence in the report", () => {
    /** @type {string[]} */
    const reports = [];
    readKnob(
      "AGENT_SANITIZER_SECRETS_ENABLED",
      { AGENT_SANITIZER_SECRETS_ENABLED: "true" },
      (message) => reports.push(message),
    );
    assert.deepEqual(reports, [
      'agent-sanitizer: AGENT_SANITIZER_SECRETS_ENABLED="true" is not a ' +
        "recognized value (1 to set it, 0 or unset to leave it off); the " +
        "secret layer stays OFF.",
    ]);
  });

  it("throws on a knob the table does not declare", () => {
    assert.throws(
      () => readKnob(/** @type {any} */ ("AGENT_SANITIZER_NOPE"), {}),
      /unknown knob "AGENT_SANITIZER_NOPE"/u,
    );
    // Not fooled by an inherited property name.
    assert.throws(() => readKnob(/** @type {any} */ ("toString"), {}));
  });

  it("reports through the public predicates once per value, on stderr", () => {
    /** @type {string[]} */
    const written = [];
    const original = process.stderr.write;
    // @ts-expect-error -- narrower than the overloaded write signature.
    process.stderr.write = (chunk) => written.push(String(chunk));
    try {
      const env = { AGENT_SANITIZER_SECRETS_ENABLED: "TRUE" };
      assert.equal(secretsEnabled(env), false);
      assert.equal(secretsEnabled(env), false);
      assert.equal(failOpenEnabled({ AGENT_SANITIZER_FAIL_OPEN: "no" }), true);
    } finally {
      process.stderr.write = original;
    }
    assert.equal(written.length, 2, written.join(""));
    assert.match(written[0], /AGENT_SANITIZER_SECRETS_ENABLED="TRUE"/u);
    assert.match(written[1], /AGENT_SANITIZER_FAIL_OPEN="no".*fail-OPEN/u);
  });
});

describe("every public knob is documented", () => {
  it("appears in the README or the plugin README", () => {
    const docs =
      readFileSync(join(repo, "README.md"), "utf8") +
      readFileSync(join(repo, "plugin", "README.md"), "utf8");
    const publicKnobs = Object.keys(KNOBS).filter((n) => !n.startsWith("_"));
    assert.ok(publicKnobs.length > 0, "no public knobs in the table");
    assert.deepEqual(
      publicKnobs.filter((name) => !docs.includes(name)),
      [],
    );
  });
});
