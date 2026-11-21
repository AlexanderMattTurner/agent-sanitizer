import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

// The executed release helper lives beside version-bump.sh in .github/scripts/;
// scripts/version-bump.sh was deduplicated away, so test the single live copy.
const SCRIPT = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  ".github",
  "scripts",
  "promote-changelog.mjs",
);

const HEADER = `# Changelog

## Unreleased
`;
const TAIL = `
## [1.0.0] - 2026-01-01

### Added

- First release.
`;

/** Run promote-changelog.mjs in a throwaway dir against `changelog`, return its new contents and stdout. */
function run(changelog, env) {
  const dir = mkdtempSync(join(tmpdir(), "promote-"));
  try {
    writeFileSync(join(dir, "CHANGELOG.md"), changelog);
    const stdout = execFileSync("node", [SCRIPT], {
      cwd: dir,
      env: { ...process.env, ...env },
    });
    return {
      result: readFileSync(join(dir, "CHANGELOG.md"), "utf8"),
      stdout: String(stdout),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const RELEASE_ENV = { NEW_VERSION: "1.1.0", RELEASE_DATE: "2026-06-22" };

test("promotes the Unreleased block to a dated section, keeping surrounding content", () => {
  const { result, stdout } = run(
    `${HEADER}\n### Changed\n\n- A thing changed.\n${TAIL}`,
    {
      ...RELEASE_ENV,
      CHANGELOG_SECTION: "### Changed\n\n- A thing changed.",
    },
  );
  assert.match(stdout, /Promoted Unreleased → \[1\.1\.0\] - 2026-06-22/);
  assert.match(
    result,
    /## Unreleased\n\n## \[1\.1\.0\] - 2026-06-22\n\n### Changed\n\n- A thing changed\./,
  );
  // The prior release section survives untouched.
  assert.match(result, /## \[1\.0\.0\] - 2026-01-01/);
});

test("strips a leading version heading the model may emit despite 'body only'", () => {
  const { result } = run(`${HEADER}${TAIL}`, {
    ...RELEASE_ENV,
    CHANGELOG_SECTION: "## [1.1.0] - whatever\n\n### Fixed\n\n- Bug squashed.",
  });
  assert.match(
    result,
    /## \[1\.1\.0\] - 2026-06-22\n\n### Fixed\n\n- Bug squashed\./,
  );
  assert.doesNotMatch(result, /- whatever/);
});

const ENTRIES = "### Added\n\n- A thing.";
for (const [name, section, entries, body] of [
  ["empty", "", "", "No user-visible changes."],
  ["blank", "   \n\n", "", "No user-visible changes."],
  ["empty beside entries", "", `\n${ENTRIES}\n`, ENTRIES],
]) {
  test(`still dates the release when the drafted body is ${name}`, () => {
    const env = { ...RELEASE_ENV, CHANGELOG_SECTION: section };
    const { result } = run(`${HEADER}${entries}${TAIL}`, env);
    assert.equal(
      result,
      `${HEADER}\n## [1.1.0] - 2026-06-22\n\n${body}\n${TAIL}`,
    );
  });
}

test("leaves the file unchanged when there is no Unreleased heading", () => {
  const input = `# Changelog\n${TAIL}`;
  const { result } = run(input, {
    ...RELEASE_ENV,
    CHANGELOG_SECTION: "### Added\n\n- x",
  });
  assert.equal(result, input);
});
