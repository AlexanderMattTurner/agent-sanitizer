// template-sync-resolve.sh installs the claude CLI only when its model tier
// runs. fanout.py shells out to `claude`, which the runner image lacks; a sync
// that mergiraf settles, or that has no token, must not depend on an npm
// download, and a failed install must cost the model tier alone (exit 0, file
// reported unresolved) rather than skip the whole resolve step.
//
// The script and its lib/ run from a scratch copy beside a stub
// install-claude-cli.sh, with a stub mergiraf and a stub fanout.py, so each
// tier's choice is observed without a network or a model.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPTS = dirname(fileURLToPath(import.meta.url));

const scratched = [];
process.on("exit", () => {
  for (const dir of scratched) rmSync(dir, { recursive: true, force: true });
});

const STUB_INSTALLER = `#!/usr/bin/env bash
echo install >>"$CALLS"
exit "$INSTALL_EXIT"
`;
const STUB_MERGIRAF = `#!/usr/bin/env bash
echo merged
`;
const STUB_FANOUT = `import os
with open(os.environ["CALLS"], "a") as calls:
    calls.write("fanout\\n")
for path in os.environ["CONFLICT_LIST"].split():
    with open(path, "w") as f:
        f.write("resolved\\n")
`;

const runResolve = ({ mergiraf, token, installExit }) => {
  const root = mkdtempSync(join(tmpdir(), "template-sync-resolve-"));
  scratched.push(root);
  const scripts = join(root, "scripts");
  cpSync(join(SCRIPTS, "lib"), join(scripts, "lib"), { recursive: true });
  copyFileSync(
    join(SCRIPTS, "template-sync-resolve.sh"),
    join(scripts, "template-sync-resolve.sh"),
  );
  writeFileSync(join(scripts, "install-claude-cli.sh"), STUB_INSTALLER);
  mkdirSync(join(root, "resolver", "auto-resolve"), { recursive: true });
  writeFileSync(
    join(root, "resolver", "auto-resolve", "fanout.py"),
    STUB_FANOUT,
  );
  writeFileSync(join(root, "mergiraf"), STUB_MERGIRAF);
  chmodSync(join(root, "mergiraf"), 0o755);
  mkdirSync(join(root, "work"));
  writeFileSync(
    join(root, "work", "f.txt"),
    "<<<<<<< local\nmine\n=======\ntheirs\n>>>>>>> template\n",
  );
  const calls = join(root, "calls");
  const output = join(root, "output");
  writeFileSync(calls, "");
  const result = spawnSync(
    "bash",
    [join(scripts, "template-sync-resolve.sh")],
    {
      cwd: join(root, "work"),
      encoding: "utf8",
      env: {
        ...process.env,
        CONFLICT_FILES: "f.txt",
        PR_NUMBER: "1",
        RESOLVER_DIR: join(root, "resolver"),
        GITHUB_OUTPUT: output,
        CLAUDE_CODE_OAUTH_TOKEN: token,
        MERGIRAF_BIN: mergiraf ? join(root, "mergiraf") : "no-such-mergiraf",
        CALLS: calls,
        INSTALL_EXIT: String(installExit),
      },
    },
  );
  assert.equal(result.status, 0, result.stderr);
  const outputs = Object.fromEntries(
    readFileSync(output, "utf8")
      .split("\n")
      .filter((line) => line.includes("="))
      .map((line) => [
        line.slice(0, line.indexOf("=")),
        line.slice(line.indexOf("=") + 1),
      ]),
  );
  return {
    calls: readFileSync(calls, "utf8").split("\n").filter(Boolean),
    tiers: [outputs.deterministic, outputs.by_model, outputs.unresolved],
  };
};

for (const [name, setup, calls, tiers] of [
  [
    "mergiraf settles everything, so nothing is installed",
    { mergiraf: true, token: "tok", installExit: 0 },
    [],
    ["f.txt", "", ""],
  ],
  [
    "no token skips the model tier and its install",
    { mergiraf: false, token: "", installExit: 0 },
    [],
    ["", "", "f.txt"],
  ],
  [
    "a failed install skips fanout and leaves the file unresolved",
    { mergiraf: false, token: "tok", installExit: 1 },
    ["install"],
    ["", "", "f.txt"],
  ],
  [
    "a successful install runs fanout",
    { mergiraf: false, token: "tok", installExit: 0 },
    ["install", "fanout"],
    ["", "f.txt", ""],
  ],
])
  test(name, () => {
    assert.deepEqual(runResolve(setup), { calls, tiers });
  });
