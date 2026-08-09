import assert from "node:assert/strict";
import { test } from "node:test";

import {
  TEST_FILE_PATTERNS,
  editsTestFile,
  isTestFile,
} from "./gate-tests-skill.mjs";

/**
 * A path that must match, and one that must not, for each naming convention the
 * gate claims. Keyed by the pattern's own `name`, so a convention added to
 * TEST_FILE_PATTERNS without a case here fails the coverage check below.
 */
const CASES = {
  "pytest module": {
    matches: ["tests/test_thing.py", "test_thing.py"],
    misses: ["tests/pretest_thing.py", "tests/test_thing.pyc"],
  },
  "pytest module, suffix spelling": {
    matches: ["tests/thing_test.py"],
    misses: ["tests/thing_testing.py"],
  },
  "node test module": {
    matches: ["test/thing.test.mjs", ".claude/hooks/thing.test.mjs"],
    misses: ["test/thing.mjs", "test/thing.test.js"],
  },
  "pytest conftest": {
    matches: ["tests/conftest.py", "conftest.py"],
    misses: ["tests/myconftest.py"],
  },
  "test harness module": {
    matches: ["tests/_helpers.py", "python/tests/_fake_gh.py"],
    misses: ["tests/helpers.py", "src/_helpers.py"],
  },
};

test("every declared convention has a case, and every case is declared", () => {
  assert.deepEqual(
    TEST_FILE_PATTERNS.map(({ name }) => name).sort(),
    Object.keys(CASES).sort(),
  );
});

for (const [name, { matches, misses }] of Object.entries(CASES)) {
  test(`${name}: the declared paths match, the near-misses do not`, () => {
    const { re } = TEST_FILE_PATTERNS.find((p) => p.name === name);
    for (const path of matches) {
      assert.equal(re.test(path), true, `${name} should match ${path}`);
      assert.equal(isTestFile(path), true, path);
    }
    for (const path of misses) {
      assert.equal(re.test(path), false, `${name} should not match ${path}`);
    }
  });
}

test("a non-test path is not gated", () => {
  assert.equal(isTestFile("src/index.mjs"), false);
  assert.equal(isTestFile(undefined), false);
});

test("only the file-writing tools trigger the gate", () => {
  const file_path = "tests/test_thing.py";
  assert.equal(
    editsTestFile({ tool_name: "Write", tool_input: { file_path } }),
    true,
  );
  assert.equal(
    editsTestFile({ tool_name: "Edit", tool_input: { file_path } }),
    true,
  );
  // Read does not write, and NotebookEdit is deliberately out of scope.
  assert.equal(
    editsTestFile({ tool_name: "Read", tool_input: { file_path } }),
    false,
  );
  assert.equal(
    editsTestFile({ tool_name: "NotebookEdit", tool_input: { file_path } }),
    false,
  );
});
