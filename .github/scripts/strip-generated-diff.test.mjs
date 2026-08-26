// strip-generated-diff decides what the automated reviewer never sees, so the
// asymmetry is the whole test: dropping a hand-written file is an unread change,
// while keeping a generated one costs only review budget. Every case below is a
// header shape that could be misread in one of those two directions.
import assert from "node:assert/strict";
import { test } from "node:test";

import { omissionNote, stripGenerated } from "./strip-generated-diff.mjs";

/** A minimal but real two-file diff: one generated, one hand-written. */
const DIFF = [
  "diff --git a/plugin/dist/hooks/plugin-hooks.bundle.mjs b/plugin/dist/hooks/plugin-hooks.bundle.mjs",
  "index 1111111..2222222 100644",
  "--- a/plugin/dist/hooks/plugin-hooks.bundle.mjs",
  "+++ b/plugin/dist/hooks/plugin-hooks.bundle.mjs",
  "@@ -1 +1 @@",
  "-var a = 1;",
  "+var a = 2;",
  "diff --git a/src/html.mjs b/src/html.mjs",
  "index 3333333..4444444 100644",
  "--- a/src/html.mjs",
  "+++ b/src/html.mjs",
  "@@ -1 +1 @@",
  '-import * as csstree from "css-tree";',
  '+import cssParse from "css-tree/parser";',
  "",
].join("\n");

const OMIT = ["plugin/dist/hooks/plugin-hooks.bundle.mjs", "types/"];

test("drops a generated file's section and keeps the hand-written one", () => {
  const { kept, dropped } = stripGenerated(DIFF, OMIT);
  assert.deepEqual(
    dropped.map((d) => d.path),
    ["plugin/dist/hooks/plugin-hooks.bundle.mjs"],
  );
  assert.ok(kept.includes("diff --git a/src/html.mjs b/src/html.mjs"));
  assert.ok(!kept.includes("plugin-hooks.bundle.mjs"));
  // The kept section must survive intact, not merely be present: a splitter that
  // ate the first or last line of a section would still pass a substring check.
  assert.ok(kept.includes('+import cssParse from "css-tree/parser";'));
});

test("a diff with nothing generated passes through byte for byte", () => {
  const { kept, dropped } = stripGenerated(DIFF, ["types/"]);
  assert.deepEqual(dropped, []);
  assert.equal(kept, DIFF);
});

test("a directory entry hides nothing under it", () => {
  // A check that regenerates its outputs and diffs them says nothing about an
  // EXTRA file in the subtree, so a prefix cannot carry the flag's claim.
  // resolve-generated.mjs refuses such a rule and main() refuses such a list;
  // this pins the matcher itself, which is what would hide the file.
  const diff = [
    "diff --git a/types/index.d.ts b/types/index.d.ts",
    "@@ -1 +1 @@",
    "-declare const a: 1;",
    "+declare const a: 2;",
    "",
  ].join("\n");
  assert.deepEqual(stripGenerated(diff, OMIT).dropped, []);
  // ...while the exact path it names still goes.
  assert.deepEqual(
    stripGenerated(diff, ["types/index.d.ts"]).dropped.map((d) => d.path),
    ["types/index.d.ts"],
  );
});

test("a rename with only one generated side is kept", () => {
  const diff = [
    "diff --git a/src/html.mjs b/plugin/dist/hooks/plugin-hooks.bundle.mjs",
    "similarity index 100%",
    "",
  ].join("\n");
  assert.deepEqual(stripGenerated(diff, OMIT).dropped, []);
});

test("a space-bearing path AFTER an omitted file survives", () => {
  // The section split must not depend on parsing paths. When it did, this
  // header failed to start a new section, so the hand-written file was appended
  // to the omitted artifact above it and vanished from the review with it —
  // fail-CLOSED, the one outcome this script must never produce.
  const diff = [
    "diff --git a/plugin/dist/hooks/plugin-hooks.bundle.mjs b/plugin/dist/hooks/plugin-hooks.bundle.mjs",
    "@@ -1 +1 @@",
    "-var a = 1;",
    "+var a = 2;",
    "diff --git a/src/file name.mjs b/src/file name.mjs",
    "@@ -1 +1 @@",
    "-const hand = 1;",
    "+const written = 2;",
    "",
  ].join("\n");
  const { kept, dropped } = stripGenerated(diff, OMIT);
  assert.deepEqual(
    dropped.map((d) => d.path),
    ["plugin/dist/hooks/plugin-hooks.bundle.mjs"],
  );
  assert.ok(kept.includes("+const written = 2;"), kept);
  assert.ok(kept.includes("diff --git a/src/file name.mjs"), kept);
});

test("an unparsable header is kept, never dropped", () => {
  // git leaves a space-bearing path unquoted, so the header is ambiguous. Keeping
  // it costs review budget; dropping it would hide a change nobody reviewed.
  const diff = [
    'diff --git "a/plugin/dist/hooks/plugin-hooks.bundle.mjs" "b/plugin/dist/hooks/plugin-hooks.bundle.mjs"',
    "@@ -1 +1 @@",
    "-a",
    "+b",
    "",
  ].join("\n");
  assert.deepEqual(stripGenerated(diff, OMIT).dropped, []);
});

test("an empty owned list drops nothing", () => {
  assert.deepEqual(stripGenerated(DIFF, []).dropped, []);
});

test("the note names every omitted path and is empty when none were", () => {
  assert.equal(omissionNote([]), "");
  const note = omissionNote([{ path: "a/b.json", lines: 42 }]);
  assert.match(note, /1 generated file\(s\)/u);
  assert.match(note, /a\/b\.json \(42 diff lines, omitted\)/u);
  // Every line must be a comment, so the note cannot be read as diff content.
  for (const line of note.split("\n").filter(Boolean))
    assert.match(line, /^#/u);
});

test("a content line that looks like a header does not start a section", () => {
  // Section splitting is safe only because diff content lines always carry a
  // +/-/space prefix, so `^diff --git ` can never match inside a hunk. That is
  // what stops a fixture file from smuggling a hand-written change into a
  // dropped section, and it is load-bearing enough to pin: a later relaxation of
  // the anchor would break it with every other case still green.
  const diff = [
    "diff --git a/src/fixture.txt b/src/fixture.txt",
    "@@ -0,0 +1,2 @@",
    "+diff --git a/plugin/dist/hooks/plugin-hooks.bundle.mjs b/plugin/dist/hooks/plugin-hooks.bundle.mjs",
    "+payload",
    "",
  ].join("\n");
  const { kept, dropped } = stripGenerated(diff, OMIT);
  assert.deepEqual(dropped, []);
  assert.equal(kept, diff);
});
