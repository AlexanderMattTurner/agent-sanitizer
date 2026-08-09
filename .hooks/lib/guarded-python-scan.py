#!/usr/bin/env python3
"""Resolve the repo files each pytest module reads, with Python's own parser.

The JS half of the guarded-data scan (`guarded-data-scan.mjs`) cannot see these:
a pytest guard names its subject as ``REPO_ROOT / "a" / "b"``, which is a Python
expression, and the repo's rule is to validate against the real parser rather
than a hand-rolled approximation of one. So this walks ``ast`` and hands the
resolved paths back as JSON.

Stdlib only, and run under bare ``python3``: the pre-commit hook derives its map
before it knows whether this repo's virtualenv is provisioned, and a guard that
cannot run in the hook only catches drift after the commit lands.

Protocol: repo root as argv[1], ``{"tests": [...], "tracked": [...]}`` on stdin,
``{"<test path>": ["<repo path>", ...]}`` on stdout. Precision over recall — an
expression that does not resolve to a statically-known repo path contributes
nothing rather than a guess.
"""

import ast
import json
import sys
from pathlib import Path, PurePosixPath

#: The one binding this resolver seeds by name. `tests/_helpers.REPO_ROOT` is
#: assigned from a `git rev-parse` subprocess, which no static resolver can
#: follow — and it is the repo's single sanctioned way for a test to find the
#: repo root (CLAUDE.md, Testing: never walk parents by depth). Seeding it here,
#: at its definition, means every consumer picks it up through ordinary import
#: resolution instead of this file special-casing the name at each use site.
ROOT_BINDING = ("tests/_helpers.py", "REPO_ROOT")


class Scanner:
    def __init__(self, root: Path, tracked: set[str]) -> None:
        self.root = root
        self.tracked = tracked
        self.modules: dict[str, dict] = {}

    # -- module analysis ---------------------------------------------------- #

    def analyze(self, file: str) -> dict:
        """Bindings and repo paths for one module, memoized.

        Seeded before recursion so an import cycle terminates with the bindings
        resolved so far (a false negative) instead of recursing forever.
        """
        cached = self.modules.get(file)
        if cached is not None:
            return cached
        result = {
            "paths": {},
            "strings": {},
            "aliases": {},
            "imports": set(),
            "refs": set(),
        }
        self.modules[file] = result
        tree = ast.parse((self.root / file).read_text(encoding="utf-8"), filename=file)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target = self.resolve_module(alias.name, file)
                    if target:
                        result["aliases"][alias.asname or alias.name] = target
                        result["imports"].add(target)
            elif isinstance(node, ast.ImportFrom):
                target = self.resolve_module(self.absolute(node, file), file)
                if not target:
                    continue
                result["imports"].add(target)
                imported = self.analyze(target)
                for alias in node.names:
                    local = alias.asname or alias.name
                    for kind in ("paths", "strings"):
                        if alias.name in imported[kind]:
                            result[kind][local] = imported[kind][alias.name]
                    # `from .credential_names import X` in a package __init__ is
                    # also how a submodule becomes an attribute of the package,
                    # which is how a test reaches a path constant two modules
                    # deep. Follow the submodule as well as the name.
                    submodule = self.resolve_module(
                        f"{self.absolute(node, file)}.{alias.name}", file
                    )
                    if submodule:
                        result["imports"].add(submodule)
                        result["aliases"][local] = submodule

        if file == ROOT_BINDING[0]:
            result["paths"][ROOT_BINDING[1]] = ""

        # Two passes: a module may name a path before the assignment that binds
        # the constant it is built from (a helper defined below its callers).
        for _ in range(2):
            for node in ast.walk(tree):
                targets = []
                if isinstance(node, ast.Assign):
                    targets = [t for t in node.targets if isinstance(t, ast.Name)]
                elif isinstance(node, ast.AnnAssign) and isinstance(
                    node.target, ast.Name
                ):
                    targets = [node.target]
                if not targets:
                    continue
                path = self.resolve(node.value, file, result)
                text = (
                    node.value.value
                    if isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                    else None
                )
                for target in targets:
                    # The seeded root is the one binding an assignment may not
                    # overwrite: its own `REPO_ROOT = _repo_root()` resolves to
                    # nothing and would delete the seed on the first pass.
                    if (file, target.id) == ROOT_BINDING:
                        continue
                    # A rebinding writes both maps, None included: a name that
                    # stopped holding a path must stop resolving, not keep the
                    # stale entry.
                    result["paths"][target.id] = path
                    result["strings"][target.id] = text
                    if path is None:
                        del result["paths"][target.id]
                    if text is None:
                        del result["strings"][target.id]

        for node in ast.walk(tree):
            if isinstance(node, (ast.BinOp, ast.Attribute, ast.Name, ast.Call)):
                path = self.resolve(node, file, result)
                if path in self.tracked:
                    result["refs"].add(path)
        return result

    def absolute(self, node: ast.ImportFrom, importer: str) -> str:
        """The absolute dotted name of a `from … import` target.

        `from .config import X` inside `python/agent_sanitizer/secrets/__init__.py`
        means `agent_sanitizer.secrets.config`, and the package re-export is
        exactly how a test reaches a path constant defined two modules deep.
        """
        if node.level == 0:
            return node.module or ""
        # One leading dot means "this module's own directory", whether the
        # module is a package `__init__.py` or a plain module inside it; each
        # further dot goes one directory up.
        parts = list(PurePosixPath(importer).parent.parts)
        # `python/` is the distribution directory, not a package.
        if parts and parts[0] == "python":
            parts = parts[1:]
        base = parts[: len(parts) - node.level + 1]
        return ".".join([*base, *([node.module] if node.module else [])])

    def resolve_module(self, dotted: str, importer: str) -> str | None:
        """The repo file a dotted module name refers to, or None if it is not
        one of ours (stdlib, a third-party package, an installed distribution).
        """
        parts = dotted.split(".")
        candidates = []
        for prefix in ("", "python/"):
            joined = prefix + "/".join(parts)
            candidates += [f"{joined}.py", f"{joined}/__init__.py"]
        # conftest.py puts a suite's own directory on sys.path, so a single-name
        # import can mean the module sitting next to the importer.
        if len(parts) == 1:
            candidates.append(str(PurePosixPath(importer).parent / f"{parts[0]}.py"))
        for candidate in candidates:
            if candidate in self.tracked:
                return candidate
        return None

    # -- expression resolution ---------------------------------------------- #

    def resolve(self, node, file: str, scope: dict) -> str | None:
        """The repo-relative path an expression denotes, or None."""
        if isinstance(node, ast.Name):
            return scope["paths"].get(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            base = self.resolve(node.left, file, scope)
            if base is None:
                return None
            segment = self.text(node.right, scope)
            return None if segment is None else str(PurePosixPath(base) / segment)
        if isinstance(node, ast.Attribute):
            if node.attr == "parent":
                base = self.resolve(node.value, file, scope)
                return None if base is None else str(PurePosixPath(base).parent)
            alias = (
                scope["aliases"].get(node.value.id)
                if isinstance(node.value, ast.Name)
                else None
            )
            return self.analyze(alias)["paths"].get(node.attr) if alias else None
        if not isinstance(node, ast.Call):
            return None
        # `Path(__file__)` is the module itself; `.resolve()` and `str()` leave
        # it alone.
        if isinstance(node.func, ast.Name) and node.func.id in ("Path", "str"):
            arg = node.args[0] if len(node.args) == 1 else None
            if isinstance(arg, ast.Name) and arg.id == "__file__":
                return file
            return self.resolve(arg, file, scope) if arg is not None else None
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "resolve"
            and not node.args
        ):
            return self.resolve(node.func.value, file, scope)
        return None

    def text(self, node, scope: dict) -> str | None:
        """The string a path SEGMENT denotes, or None."""
        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, str) else None
        if isinstance(node, ast.Name):
            return scope["strings"].get(node.id)
        return None


def main() -> None:
    root = Path(sys.argv[1])
    request = json.load(sys.stdin)
    scanner = Scanner(root, set(request["tracked"]))
    out = {}
    for test in request["tests"]:
        # Transitive: a suite that imports `agent_sanitizer.secrets` guards the
        # JSON that package reads at import time just as surely as one that
        # spells the path itself — `test_secrets_config.py` never names
        # `redaction-floor.json`, and reading it is the whole point of the test.
        # The imported MODULES are deliberately not registered as guarded
        # sources here: pytest guards are the expensive half of the map, and
        # scheduling every secrets suite on every Python source edit is a cost
        # nobody asked for. The JS half derives module pairs; this half derives
        # data pairs.
        refs, queue, seen = set(), [test], {test}
        while queue:
            module = scanner.analyze(queue.pop())
            refs |= module["refs"]
            for imported in module["imports"]:
                if imported not in seen:
                    seen.add(imported)
                    queue.append(imported)
        if refs:
            out[test] = sorted(refs)
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
