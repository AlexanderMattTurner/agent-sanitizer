import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  // Lint only the library sources; the template's automation scripts
  // (.github, .hooks, config) carry their own conventions.
  {
    ignores: [
      "coverage/**",
      "types/**",
      "node_modules/**",
      ".github/**",
      ".claude/**",
      ".hooks/**",
      "config/**",
      "tests/**",
      // The committed plugin bundle is generated (~1.8 MB of inlined
      // dependencies); the sources it is built from are linted instead.
      "plugin/dist/**",
      // Stryker copies the project into a sandbox here during a mutation run and
      // mutates the sources in place; never lint that transient mutated copy.
      ".stryker-tmp/**",
      "reports/**",
      // `uv sync` materializes the Python env here; its vendored JS (regexploit,
      // urllib3) is not ours to lint and fails no-undef under this flat config.
      ".venv/**",
    ],
  },
  js.configs.recommended,
  {
    files: [
      "src/**/*.mjs",
      "test/**/*.mjs",
      "scripts/**/*.mjs",
      "claude-hooks/**/*.mjs",
      "plugin/scripts/**/*.mjs",
      "plugin/test/**/*.mjs",
    ],
    languageOptions: {
      // "latest" rather than a pinned year: the hook config modules are loaded
      // with import attributes (`with { type: "json" }`), which no fixed
      // ecmaVersion below 2025 parses.
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.node,
      },
    },
    rules: {
      "consistent-return": "error",
    },
  },
);
