#!/usr/bin/env python3
"""Lint: no depth-based (or hand-rolled git) repo-root derivation in test files.

Flags any expression rooted at ``Path(__file__)`` that walks upward more than
one level — a ``.parents[...]`` subscript, or two-plus chained ``.parent``
attributes — because the depth silently goes stale when a test file moves.
Tests must import ``REPO_ROOT`` from ``tests/_helpers.py`` (which asks git via
``rev-parse --show-toplevel``) instead. A single ``.parent`` (anchoring a
subprocess cwd at the file's own directory) is fine and not flagged.

Also flags an import-time subprocess call whose argv contains both
``rev-parse`` and ``--show-toplevel`` — a re-inlined copy of the
``tests/_helpers.py`` block (the copies historically also dropped its ``cwd=``
argument, a live divergence). ``tests/_helpers.py`` itself is the one allowed
home for that call and is exempt. "Import time" means the module body plus any
module-level function the body actually CALLS — the helper's own block lives in
a ``_repo_root()`` behind a ``REPO_ROOT = _repo_root()`` constant, and a copy of
that shape is still a copy. A function merely defined (a test body shelling out
to git to exercise behavior) is not followed and not flagged.

Also flags an import-time ``sys.path`` mutation — the second half of the same
bootstrap. Tests must call ``ensure_python_pkg_on_path()`` from
``tests/_helpers.py`` rather than hand-inserting ``python/``: the hand-copied
inserts drift on ordering and on whether they resolve the root via git, and one
copy left behind is how the next one gets written. ``tests/_helpers.py`` is the
one allowed home and is exempt.

Uses the real Python parser (ast), so string contents, comments, and
formatting variations can't produce false positives — in particular a
``sys.path.insert`` inside a string that a test writes out as a subprocess
program is not a mutation of THIS module's path and is not flagged.

Usage: check-test-repo-root.py <file.py> [<file.py>...]   (exit 1 on hits)
"""

import ast
import sys
from pathlib import PurePosixPath


def _is_path_file_call(node: ast.AST) -> bool:
    """True for a ``Path(__file__)`` call."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Path"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "__file__"
    )


def _rooted_at_path_file(node: ast.AST, parent_hops: int) -> bool:
    """Walk down a ``.parent``/``.parents[...]``/method-call chain; True when
    the base is ``Path(__file__)`` and the chain walks up 2+ levels."""
    if isinstance(node, ast.Subscript):
        value = node.value
        if isinstance(value, ast.Attribute) and value.attr == "parents":
            # parents[N] jumps an arbitrary depth: always a violation.
            return _base_is_path_file(value.value)
        return False
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        parent_hops += 1
        if parent_hops >= 2 and _base_is_path_file(node.value):
            return True
        return _rooted_at_path_file(node.value, parent_hops)
    return False


def _base_is_path_file(node: ast.AST) -> bool:
    """Strip interleaved no-arg method calls (``.resolve()``, ``.absolute()``)
    and ``.parent`` hops down to the chain's base; True if it is
    ``Path(__file__)``."""
    while True:
        if _is_path_file_call(node):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            node = node.func.value
        elif isinstance(node, ast.Attribute) and node.attr in ("parent", "parents"):
            node = node.value
        else:
            return False


def violations(source: str) -> list[int]:
    """Line numbers of depth-based repo-root walks in *source*."""
    return sorted(
        node.lineno
        for node in ast.walk(ast.parse(source))
        if _rooted_at_path_file(node, 0)
    )


def _calls_show_toplevel(node: ast.AST) -> bool:
    """True for a call whose argv (a list/tuple argument) contains both the
    ``rev-parse`` and ``--show-toplevel`` string constants — the exact command
    the shared helper owns. Keyed on the argv contents, not the callee name, so
    ``subprocess.run``/``check_output``/aliases all match while unrelated
    rev-parse uses (``rev-parse HEAD``) don't."""
    if not isinstance(node, ast.Call):
        return False
    return any(
        isinstance(arg, (ast.List, ast.Tuple))
        and {"rev-parse", "--show-toplevel"}
        <= {
            elt.value
            for elt in arg.elts
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
        }
        for arg in node.args
    )


def _import_time_nodes(source: str) -> list[ast.AST]:
    """Every AST node that runs at IMPORT time: statements directly in the
    module body, plus the bodies of module-level functions those statements
    actually call (transitively).

    Following the calls is what keeps the lint on the shape the helper itself
    now uses — the git call lives in ``_repo_root()`` and the module body is
    just ``REPO_ROOT = _repo_root()``. A copy of that is still a re-inlined
    copy. Functions that are merely DEFINED are not followed: a test body
    shelling out to git is exercising behavior, not duplicating the bootstrap,
    and flagging it would be a false positive.
    """
    tree = ast.parse(source)
    defs = {
        stmt.name: stmt
        for stmt in tree.body
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    roots = [
        stmt
        for stmt in tree.body
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    nodes: list[ast.AST] = []
    seen: set[str] = set()
    while roots:
        pending = []
        for root in roots:
            for node in ast.walk(root):
                nodes.append(node)
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                    continue
                called = node.func.id
                if called in defs and called not in seen:
                    seen.add(called)
                    pending.append(defs[called])
        roots = pending
    return nodes


def rev_parse_violations(source: str) -> list[int]:
    """Line numbers of import-time ``rev-parse --show-toplevel`` calls."""
    return sorted(
        node.lineno for node in _import_time_nodes(source) if _calls_show_toplevel(node)
    )


def _mutates_sys_path(node: ast.AST) -> bool:
    """True for a ``sys.path.insert(...)``/``.append(...)``/``.extend(...)`` call.

    Matched on the ``sys.path`` attribute chain, so a bare ``path.append`` on an
    unrelated object does not trip it.
    """
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr not in ("insert", "append", "extend"):
        return False
    target = node.func.value
    return (
        isinstance(target, ast.Attribute)
        and target.attr == "path"
        and isinstance(target.value, ast.Name)
        and target.value.id == "sys"
    )


def sys_path_violations(source: str) -> list[int]:
    """Line numbers of import-time ``sys.path`` mutations in *source*."""
    return sorted(
        node.lineno for node in _import_time_nodes(source) if _mutates_sys_path(node)
    )


def _is_helpers_module(path: str) -> bool:
    """True for ``tests/_helpers.py``, the one allowed home of the call."""
    parts = PurePosixPath(path.replace("\\", "/")).parts
    return parts[-2:] == ("tests", "_helpers.py")


def main() -> None:
    failed = False
    for path in sys.argv[1:]:
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        for lineno in violations(source):
            failed = True
            print(
                f"{path}:{lineno}: depth-based repo-root walk from Path(__file__) — "
                "import REPO_ROOT from tests._helpers (git rev-parse) instead",
                file=sys.stderr,
            )
        if _is_helpers_module(path):
            continue
        for lineno in rev_parse_violations(source):
            failed = True
            print(
                f"{path}:{lineno}: module-level `git rev-parse --show-toplevel` — "
                "import REPO_ROOT from tests._helpers instead of re-inlining it",
                file=sys.stderr,
            )
        for lineno in sys_path_violations(source):
            failed = True
            print(
                f"{path}:{lineno}: module-level `sys.path` mutation — call "
                "ensure_python_pkg_on_path() from tests._helpers instead",
                file=sys.stderr,
            )
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
