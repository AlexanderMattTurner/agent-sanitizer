/**
 * What a tool call DOES, for every hook that acts on a push or on a new pull
 * request or issue: the PreToolUse push gate and the skill gates.
 *
 * PROBLEM CLASS — hooks deciding "is this a push / a PR create" by matching the
 * command's TEXT. A settings.json `if` such as `Bash(git push:*)` missed
 * `git -C /repo push`, and a regex read the `; git push` inside
 * `git commit -m "docs; git push after checks"` as a second command. Every hook
 * asks this module, and this module asks the bash grammar (tree-sitter-bash,
 * through web-tree-sitter's wasm build): a `command` node is executed, while a
 * `string` argument or a `heredoc_body` is text.
 *
 * A word scan only SHORTLISTS: a command that does not hold every word of the
 * invocation as a token is never parsed, which keeps the parser's load off every
 * other tool call. A shortlisted command that cannot be judged — the parser
 * package is absent, or the parse has an ERROR node — counts as the invocation,
 * so the push gate runs its checks rather than waving the call through.
 */
import { createRequire } from "node:module";

import { lazyImport } from "./lib-hook-io.mjs";

/** git's global options that take their value as the next word. */
const GIT_VALUE_FLAGS = Object.freeze([
  "-C",
  "-c",
  "--git-dir",
  "--work-tree",
  "--namespace",
  "--config-env",
  "--attr-source",
]);

/** gh's flags that may precede the subcommand and take a value. */
const GH_VALUE_FLAGS = Object.freeze(["-R", "--repo"]);

/** `env` options that take their value as the next word. */
const ENV_VALUE_FLAGS = Object.freeze(["-u", "-C", "-S"]);

/** Suffix-matched: the same tool arrives as `mcp__github__…` or `mcp__github_remote__…`. */
const PR_MCP_TOOL_RE = /^mcp__.*create_pull_request$/;

/** A wrapper that runs the rest of its arguments as the command. */
const WRAPPERS = new Set(["env", "command", "exec"]);

/** @type {Promise<any|null>|undefined} */
let parserPromise;

/**
 * The bash parser, or null when its packages cannot load. Loaded once per
 * process, and only for a shortlisted command.
 * @returns {Promise<any|null>}
 */
function bashParser() {
  parserPromise ??= (async () => {
    const { Parser, Language } = await lazyImport("web-tree-sitter");
    if (!Parser) return null;
    let wasm;
    try {
      wasm = createRequire(import.meta.url).resolve(
        "tree-sitter-bash/tree-sitter-bash.wasm",
      );
    } catch {
      return null; // tree-sitter-bash is not installed: the caller's fallback.
    }
    await Parser.init();
    const parser = new Parser();
    parser.setLanguage(await Language.load(wasm));
    return parser;
  })();
  return parserPromise;
}

/**
 * The literal value of one word node, or null when the shell computes it (an
 * expansion or a substitution inside it).
 * @param {any} node @returns {string|null}
 */
function literal(node) {
  if (node.type === "word") return node.text;
  if (node.type === "raw_string") return node.text.slice(1, -1);
  if (node.type === "string") {
    const parts = node.namedChildren;
    if (parts.every((/** @type {any} */ p) => p.type === "string_content"))
      return parts.map((/** @type {any} */ p) => p.text).join("");
  }
  return null;
}

/**
 * Where this argv runs `program [flags] ...words`: the program's own `options`
 * and the `rest` after `words`, or null when it runs something else. Skips
 * wrappers (`env` with its options and assignments, `command`, `exec`), then the
 * program's own flags, consuming the value of each flag in `valueFlags`.
 * @param {(string|null)[]} argv @param {string} program
 * @param {readonly string[]} valueFlags @param {readonly string[]} words
 * @returns {{options: (string|null)[], rest: (string|null)[]}|null}
 */
function argvMatch(argv, program, valueFlags, words) {
  let i = 0;
  while (WRAPPERS.has(argv[i] ?? "")) {
    if (argv[i++] !== "env") continue;
    for (; argv[i]?.startsWith("-") || /^\w+=/.test(argv[i] ?? ""); i++)
      if (ENV_VALUE_FLAGS.includes(argv[i] ?? "")) i++;
  }
  const name = argv[i++];
  if (typeof name !== "string") return null;
  if (name.slice(name.lastIndexOf("/") + 1) !== program) return null;
  const optionsStart = i;
  for (; argv[i]?.startsWith("-"); i++)
    if (valueFlags.includes(argv[i] ?? "")) i++;
  if (!words.every((word, k) => argv[i + k] === word)) return null;
  return {
    options: argv.slice(optionsStart, i),
    rest: argv.slice(i + words.length),
  };
}

/**
 * The argv of a `command` node, each word's literal value or null.
 * @param {any} cmd @returns {(string|null)[]}
 */
function argvOf(cmd) {
  // The `name` field is a `command_name` node wrapping the word itself.
  const name = cmd.childForFieldName("name")?.namedChildren[0];
  const args = cmd.childrenForFieldName("argument");
  return [name, ...args].map((n) => (n ? literal(n) : null));
}

/**
 * Parse `command` when it could run `program ...words`, and hand the tree to
 * `inspect`. `unjudgeable` is the answer for a command that names the
 * invocation but cannot be parsed; `absent` for one that cannot run it at all.
 * @template T
 * @param {string} command @param {string} program @param {readonly string[]} words
 * @param {(root: any) => T} inspect @param {T} unjudgeable @param {T} absent
 * @returns {Promise<T>}
 */
async function inspectParse(
  command,
  program,
  words,
  inspect,
  unjudgeable,
  absent,
) {
  const shortlisted = [program, ...words].every((w) =>
    new RegExp(String.raw`(?<![\w-])${w}(?![\w-])`).test(command),
  );
  if (!shortlisted) return absent;
  const parser = await bashParser();
  if (parser === null) return unjudgeable;
  const tree = parser.parse(command);
  try {
    return tree.rootNode.hasError ? unjudgeable : inspect(tree.rootNode);
  } finally {
    tree.delete();
  }
}

/**
 * Does `command` run `program [flags] ...words` anywhere it executes — a list,
 * a pipeline, a subshell, a command substitution — but not inside a string or a
 * heredoc body?
 * @param {string} command @param {string} program
 * @param {readonly string[]} valueFlags @param {readonly string[]} words
 * @returns {Promise<boolean>}
 */
function runs(command, program, valueFlags, words) {
  return inspectParse(
    command,
    program,
    words,
    (root) =>
      root
        .descendantsOfType("command")
        .some(
          (/** @type {any} */ cmd) =>
            argvMatch(argvOf(cmd), program, valueFlags, words) !== null,
        ),
    true,
    false,
  );
}

/**
 * The shell text of a Bash tool call, or null for any other call.
 * @param {any} payload @returns {string|null}
 */
export function bashCommand(payload) {
  const command = payload?.tool_input?.command;
  return payload?.tool_name === "Bash" && typeof command === "string"
    ? command
    : null;
}

/**
 * Does this Bash command run `gh <group> <action>`?
 * @param {string} command @param {string} group @param {string} action
 * @returns {Promise<boolean>}
 */
export function runsGh(command, group, action) {
  return runs(command, "gh", GH_VALUE_FLAGS, [group, action]);
}

/**
 * Does this tool call push commits?
 * @param {any} payload @returns {Promise<boolean>}
 */
export async function pushesCommits(payload) {
  const command = bashCommand(payload);
  return command !== null && runs(command, "git", GIT_VALUE_FLAGS, ["push"]);
}

/**
 * Does this tool call open a pull request — `gh pr create`, or any MCP
 * `create_pull_request` tool? Out of scope: `gh api` or `curl` to the pulls
 * endpoint, a script whose body runs `gh pr create`, `bash -c "…"`, and the web
 * UI. Each is some program's argument, so matching them means matching text.
 * @param {any} payload @returns {Promise<boolean>}
 */
export async function opensPullRequest(payload) {
  if (typeof payload?.tool_name !== "string") return false;
  if (PR_MCP_TOOL_RE.test(payload.tool_name)) return true;
  const command = bashCommand(payload);
  return command !== null && runsGh(command, "pr", "create");
}

/** git options that point it at a repository some other way than `-C`. */
const GIT_LOCATION_OPTION_RE = /^--(git-dir|work-tree)(=|$)/;

/** Nodes whose body runs in its own shell, or not in sequence with what follows. */
const SCOPE_TYPES = new Set([
  "program",
  "subshell",
  "command_substitution",
  "process_substitution",
  "function_definition",
]);

/**
 * The shell a command's `cd` changes: its nearest scope node, or null inside a
 * pipeline, where each element runs in a subshell of its own.
 * @param {any} cmd @returns {any}
 */
function shellScope(cmd) {
  for (let node = cmd.parent; node; node = node.parent) {
    if (node.type === "pipeline") return null;
    if (SCOPE_TYPES.has(node.type)) return node;
  }
  return null;
}

/** `cd`'s own options, none of which takes a value. */
const CD_OPTION_RE = /^-[LPe@]+$/;

/**
 * The first `git push` this Bash call runs: `chdirs`, the directory changes in
 * force for it in order (each `cd` whose list encloses it, then its `-C`
 * options; `~` for a bare `cd`, null where the shell computes the target), and
 * `args`, what follows `push`. Null when the call runs no push it can parse.
 * @param {any} payload
 * @returns {Promise<{chdirs: (string|null)[], args: (string|null)[]}|null>}
 */
export async function gitPushInvocation(payload) {
  const command = bashCommand(payload);
  if (command === null) return null;
  return inspectParse(
    command,
    "git",
    ["push"],
    (root) => {
      const commands = root.descendantsOfType("command");
      for (const cmd of commands) {
        const match = argvMatch(argvOf(cmd), "git", GIT_VALUE_FLAGS, ["push"]);
        if (match === null) continue;
        const enclosing = new Set();
        for (let node = cmd.parent; node; node = node.parent)
          enclosing.add(node.id);
        const chdirs = commands
          .filter(
            (/** @type {any} */ c) =>
              c.startIndex < cmd.startIndex && enclosing.has(shellScope(c)?.id),
          )
          .map(argvOf)
          .filter((argv) => argv[0] === "cd")
          .map(cdTarget);
        for (let i = 0; i < match.options.length; i++) {
          const option = match.options[i] ?? "";
          if (option === "-C") chdirs.push(match.options[++i] ?? null);
          else if (GIT_LOCATION_OPTION_RE.test(option)) {
            chdirs.push(null);
            if (!option.includes("=")) i++;
          } else if (GIT_VALUE_FLAGS.includes(option)) i++;
        }
        return { chdirs, args: match.rest };
      }
      return null;
    },
    null,
    null,
  );
}

/**
 * Where a `cd` argv goes: its operand, `~` for none, null for `cd -` or a
 * computed operand.
 * @param {(string|null)[]} argv @returns {string|null}
 */
function cdTarget(argv) {
  const operands = argv
    .slice(1)
    .filter((arg) => arg === null || !CD_OPTION_RE.test(arg));
  if (operands.length === 0) return "~";
  const [target] = operands;
  return target === "-" ? null : target;
}
