"""Static guard: no regex in the Python package compiles a pattern whose SIZE
scales with call-time data.

The ReDoS guard beside this file (``test_redos_static_guard.py``) asks whether a
pattern can backtrack; it cannot see how LONG a pattern is. A pattern built from
data that exists only while the code runs — a parameter, tool output, a prompt,
``os.environ`` — is as long as that data: a ~4 KB invisible-character class
spliced between every character of an env secret's value makes one long key a
~1.4 s compile on every redaction. A pattern derived only from module constants
or shipped data has a size fixed when the package is built.

The guard parses every module with :mod:`ast` and, for each call to a
``re``/``regex`` pattern function whose pattern argument is not a literal, walks
the data that argument can reach — :func:`call_time_inputs` states the rules.
A site that reaches call-time data must be listed in ``REVIEWED_CALL_TIME_SITES``
with the reason its size is bounded anyway; every other site must reach none.
Scopes are resolved from the language rules rather than :mod:`symtable`, whose
comprehension scopes differ across the supported Pythons (PEP 709 inlines them
from 3.12).
"""

import ast
import builtins
import dataclasses
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT

PACKAGE_ROOT = REPO_ROOT / "python" / "agent_sanitizer"

#: The stdlib modules whose pattern functions compile their first argument.
REGEX_MODULES = frozenset({"re", "regex"})
PATTERN_FUNCTIONS = frozenset(
    {
        "compile",
        "search",
        "match",
        "fullmatch",
        "finditer",
        "findall",
        "sub",
        "subn",
        "split",
    }
)

#: Imports a pattern may read, by dotted prefix: pure functions and constant
#: tables. Anything else imported — ``os``, ``sys``, detect-secrets' plugin
#: registry — can carry host or registry state, so reading it counts as a
#: call-time input.
ENV_FREE_IMPORTS = {
    "bisect": "pure search over a sorted sequence",
    "collections": "container types",
    "dataclasses": "class decorators",
    "functools": "pure combinators and caches",
    "itertools": "pure iteration",
    "json": "parses the shipped data files it is handed",
    "pathlib": "names the package's own data files",
    "re": "pattern functions and escaping",
    "regex": "pattern functions and escaping",
    "typing": "annotations only",
    "detect_secrets.plugins.keyword": "upstream's constant noun table, DENYLIST",
}

#: Builtins whose result depends only on their arguments, every exception
#: class, and the two module globals naming the module itself. ``open``,
#: ``input``, ``getattr``, ``globals`` and the rest stay out.
PURE_BUILTINS = frozenset(
    {
        "abs",
        "all",
        "any",
        "bool",
        "bytes",
        "chr",
        "dict",
        "enumerate",
        "filter",
        "float",
        "format",
        "frozenset",
        "hex",
        "int",
        "isinstance",
        "issubclass",
        "iter",
        "len",
        "list",
        "map",
        "max",
        "min",
        "next",
        "ord",
        "range",
        "repr",
        "reversed",
        "set",
        "sorted",
        "str",
        "sum",
        "tuple",
        "zip",
        "classmethod",
        "object",
        "property",
        "staticmethod",
        "type",
        "__file__",
        "__name__",
    }
) | frozenset(
    name
    for name, value in vars(builtins).items()
    if isinstance(value, type) and issubclass(value, BaseException)
)

#: Container methods that write their arguments into the receiver, so a value
#: passed to one flows into the container's binding.
MUTATORS = frozenset(
    {
        "add",
        "append",
        "appendleft",
        "extend",
        "extendleft",
        "insert",
        "setdefault",
        "update",
    }
)

_SCOPE_NODES = (
    ast.Module,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
    ast.ClassDef,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
)
_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)

# Data-derived sites whose pattern reads call-time data and is bounded anyway,
# keyed by (file, enclosing function, pattern argument as ``ast.unparse`` spells
# it), each with the reason its SIZE cannot scale with untrusted input.
REVIEWED_CALL_TIME_SITES = {
    (
        "secrets/engine.py",
        "_denylist_prefilter",
        "'|'.join((f'(?:{p})' for p in patterns))",
    ): (
        "The union of the active detect-secrets plugins' denylist patterns, read "
        "from the live plugin registry configure_plugins() set up. Size: the sum "
        "of those shipped and bundled detector patterns — never tool output — "
        "built once per configuration under functools.cache."
    ),
    (
        "secrets/engine.py",
        "_eligible_probe",
        "_relax_trailing_boundary(_relax_leading_boundary(pat.pattern))",
    ): (
        "One shipped or bundled detector's denylist pattern from the live plugin "
        "registry, with a boundary lookaround stripped. Size: that detector's "
        "own pattern, built once per configuration under functools.cache."
    ),
    (
        "secrets/invisible.py",
        "_invisible_char_re",
        "_invisible_class(charset)",
    ): (
        "The invisible charset a Python embedder may pass through "
        "RedactorConfig.invisible_charset (no CLI, env or daemon path sets it; "
        "the default is the shipped SSOT). Size: one range-collapsed character "
        "class over that configured charset, compiled once per distinct charset "
        "under functools.cache — never over tool output."
    ),
}


@dataclasses.dataclass(eq=False)
class Scope:
    node: ast.AST
    parent: "Scope | None"
    bindings: dict[str, list["Binding"]] = dataclasses.field(default_factory=dict)
    declared_global: set[str] = dataclasses.field(default_factory=set)
    #: Values written INTO a bound container (`xs.append(v)`, `d[k] = v`).
    written: dict[str, list[ast.AST]] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True, eq=False)
class Binding:
    """One way a name gets a value: ``kind`` says how, ``source`` is the
    expression or definition that value comes from."""

    kind: str  # assign | def | param | import | exception
    source: ast.AST | None
    alias: ast.alias | None = None
    param_owner: ast.AST | None = None


@dataclasses.dataclass(eq=False)
class Module:
    path: Path
    rel: str
    tree: ast.Module
    #: The scope each indexed `Name` load is read from.
    scope_of: dict[ast.AST, Scope] = dataclasses.field(default_factory=dict)
    scopes: dict[ast.AST, Scope] = dataclasses.field(default_factory=dict)
    #: `id(call.func)` -> the call, to find where a function is called.
    calls: dict[int, ast.Call] = dataclasses.field(default_factory=dict)

    @property
    def module_scope(self) -> Scope:
        return self.scopes[self.tree]


@dataclasses.dataclass(frozen=True)
class Site:
    rel: str
    line: int
    function: str
    pattern: str
    inputs: tuple[str, ...]


class Package:
    """Every module under ``root``, parsed and scope-indexed."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.modules = {
            path: _index(Module(path, path.relative_to(root).as_posix(), _parse(path)))
            for path in sorted(root.rglob("*.py"))
        }

    def import_target(self, module: Module, node: ast.ImportFrom) -> Path | None:
        """The package file an ``ImportFrom`` reads from, or None when external."""
        if node.level == 0:
            parts = (node.module or "").split(".")
            if parts[0] != self.root.name:
                return None
            base = self.root.joinpath(*parts[1:])
        else:
            base = module.path.parent
            for _ in range(node.level - 1):
                base = base.parent
            if node.module:
                base = base.joinpath(*node.module.split("."))
        target = _module_file(base)
        assert target, f"{module.rel}:{node.lineno}: unresolvable package import"
        return target

    def submodule(
        self, module: Module, node: ast.ImportFrom, name: str
    ) -> Module | None:
        """The package module ``from <pkg> import name`` binds, when it is one."""
        target = self.import_target(module, node)
        if target is None or target.name != "__init__.py":
            return None
        path = _module_file(target.parent / name)
        return self.modules[path] if path else None


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _module_file(base: Path) -> Path | None:
    for candidate in (base.with_suffix(".py"), base / "__init__.py"):
        if candidate.is_file():
            return candidate
    return None


def _store_names(target: ast.AST) -> Iterator[ast.Name]:
    for node in ast.walk(target):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            yield node


def _children(node: ast.AST) -> Iterator[ast.AST]:
    """Child nodes, skipping type annotations: a hint is never pattern data."""
    for field, value in ast.iter_fields(node):
        if field in {"annotation", "returns", "type_comment", "type_params"}:
            continue
        for child in value if isinstance(value, list) else [value]:
            if isinstance(child, ast.AST):
                yield child


def _span(node: ast.AST) -> tuple[tuple[int, int], tuple[int, int]]:
    return (node.lineno, node.col_offset), (node.end_lineno, node.end_col_offset)


def _contains(outer: ast.AST, inner: ast.AST) -> bool:
    if isinstance(outer, ast.Module):
        return True
    (start, end), (inner_start, inner_end) = _span(outer), _span(inner)
    return start <= inner_start and inner_end <= end


def _container_root(node: ast.AST) -> ast.AST:
    while isinstance(node, (ast.Call, ast.Attribute, ast.Subscript)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node


def _index(module: Module) -> Module:
    """Record every scope, every binding, and the scope each name is read in."""
    writes: list[tuple[ast.AST, ast.AST]] = []

    def bind(scope: Scope, name: str, binding: Binding) -> None:
        if name in scope.declared_global:
            scope = module.module_scope
        scope.bindings.setdefault(name, []).append(binding)

    def visit(node: ast.AST, scope: Scope) -> None:
        if isinstance(node, _SCOPE_NODES):
            enter(node, scope)
            return
        if isinstance(node, (ast.Nonlocal, ast.Match)):
            raise NotImplementedError(
                f"{module.rel}:{node.lineno}: {type(node).__name__}"
            )
        if isinstance(node, ast.Global):
            scope.declared_global.update(node.names)
        elif (
            isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)) and node.value
        ):
            for target in (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            ):
                for name in _store_names(target):
                    bind(scope, name.id, Binding("assign", node.value))
                if isinstance(target, (ast.Subscript, ast.Attribute)):
                    writes.append((target, node.value))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            for name in _store_names(node.target):
                bind(scope, name.id, Binding("assign", node.iter))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                for name in (
                    _store_names(item.optional_vars) if item.optional_vars else ()
                ):
                    bind(scope, name.id, Binding("assign", item.context_expr))
        elif isinstance(node, ast.NamedExpr):
            # An assignment expression in a comprehension binds outside it.
            outer = scope
            while isinstance(outer.node, _COMPREHENSIONS):
                outer = outer.parent
            bind(outer, node.target.id, Binding("assign", node.value))
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bind(scope, node.name, Binding("exception", None))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                bind(scope, name, Binding("import", node, alias=alias))
        elif isinstance(node, ast.Call):
            module.calls[id(node.func)] = node
            # `by_flags.setdefault(k, []).append(v)`: a mutator call anywhere
            # in a chain writes its arguments into the chain's root container.
            link: ast.AST = node
            while isinstance(link, (ast.Call, ast.Attribute, ast.Subscript)):
                if isinstance(link, ast.Call):
                    if (
                        isinstance(link.func, ast.Attribute)
                        and link.func.attr in MUTATORS
                    ):
                        writes.extend((link, a) for a in link.args)
                        writes.extend((link, k.value) for k in link.keywords)
                    link = link.func
                else:
                    link = link.value
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            module.scope_of[node] = scope
        for child in _children(node):
            visit(child, scope)

    def enter(node: ast.AST, outer: Scope) -> None:
        scope = Scope(node, outer)
        module.scopes[node] = scope
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bind(outer, node.name, Binding("def", node))
            for decorator in node.decorator_list:
                visit(decorator, outer)
        if isinstance(node, ast.ClassDef):
            for base in [*node.bases, *(k.value for k in node.keywords)]:
                visit(base, outer)
            for statement in node.body:
                visit(statement, scope)
        elif isinstance(node, _FUNCTION_NODES):
            args = node.args
            for default in [*args.defaults, *(d for d in args.kw_defaults if d)]:
                visit(default, outer)
            every = [
                *args.posonlyargs,
                *args.args,
                *args.kwonlyargs,
                args.vararg,
                args.kwarg,
            ]
            for arg in filter(None, every):
                bind(scope, arg.arg, Binding("param", arg, param_owner=node))
            for statement in node.body if isinstance(node.body, list) else [node.body]:
                visit(statement, scope)
        else:
            # A comprehension's first iterable runs in the enclosing scope.
            for i, generator in enumerate(node.generators):
                visit(generator.iter, outer if i == 0 else scope)
                for name in _store_names(generator.target):
                    bind(scope, name.id, Binding("assign", generator.iter))
                for condition in generator.ifs:
                    visit(condition, scope)
            for part in ("elt", "key", "value"):
                if hasattr(node, part):
                    visit(getattr(node, part), scope)

    module.scopes[module.tree] = Scope(module.tree, None)
    for statement in module.tree.body:
        visit(statement, module.module_scope)
    for target, value in writes:
        root = _container_root(target)
        scope = _resolve(module, module.scope_of.get(root), getattr(root, "id", ""))
        if scope is not None:
            scope.written.setdefault(root.id, []).append(value)
    return module


def _resolve(module: Module, scope: Scope | None, name: str) -> Scope | None:
    """The scope that binds ``name`` as read from ``scope``; None for a builtin
    (or an unindexed read). A class body's names are invisible to the
    functions nested in it."""
    current = scope
    while current:
        if name in current.declared_global:
            current = module.module_scope
        if name in current.bindings:
            return current
        parent = current.parent
        while (
            parent
            and isinstance(parent.node, ast.ClassDef)
            and not isinstance(current.node, ast.ClassDef)
        ):
            parent = parent.parent
        current = parent
    return None


def call_time_inputs(
    package: Package, module: Module, root: ast.AST
) -> tuple[str, ...]:
    """Every binding through which ``root`` can read data that exists only
    while the code runs, as ``"<kind> <name> at <file>:<line>"``.

    The walk follows each name ``root`` reads to the code producing its value
    — every assignment, loop target and container write to it, a function's
    whole body, a package import into its own module — and counts as a
    call-time input:

    - a parameter, unless its function is a private module-level builder that
      only its own module calls, directly, in which case each call's argument
      for it is walked instead;
    - an import outside ``ENV_FREE_IMPORTS`` — ``os.environ``, a registry,
      or a package module bound by ``import`` rather than ``from … import``;
    - a builtin outside ``PURE_BUILTINS``;
    - an exception.

    A write through an alias — a container handed to a function that fills it
    — is not traced: the walk follows bindings and the writes made through a
    binding's own name.
    """
    inputs: set[str] = set()
    walked: set[int] = set()

    def walk(mod: Module, node: ast.AST) -> None:
        if id(node) in walked:
            return
        walked.add(id(node))
        for child in ast.walk(node):
            if child in mod.scope_of:
                read(mod, child, node)
            elif isinstance(child, ast.Attribute) and child.value in mod.scope_of:
                member(mod, child)

    def where(mod: Module, node: ast.AST) -> str:
        return f"{mod.rel}:{node.lineno}"

    def read(mod: Module, name: ast.Name, inside: ast.AST) -> None:
        scope = _resolve(mod, mod.scope_of[name], name.id)
        if scope is None:
            if name.id not in PURE_BUILTINS:
                inputs.add(f"builtin {name.id} at {where(mod, name)}")
        elif scope.node is mod.tree or not _contains(inside, scope.node):
            values(mod, scope, name.id, where(mod, name))

    def values(mod: Module, scope: Scope, name: str, at: str) -> None:
        for binding in scope.bindings[name]:
            if binding.kind in {"assign", "def"}:
                walk(mod, binding.source)
            elif binding.kind == "param":
                builder_arguments(mod, binding, at)
            elif binding.kind == "import":
                imported(mod, binding, at)
            else:
                inputs.add(f"{binding.kind} {name} at {at}")
        for value in scope.written.get(name, ()):
            walk(mod, value)

    def builder_arguments(mod: Module, binding: Binding, at: str) -> None:
        function, param = binding.param_owner, binding.source.arg
        is_builder = (
            isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
            and function.name.startswith("_")
            and mod.scopes[function].parent is mod.module_scope
            and not _imported_elsewhere(package, mod, function.name)
        )
        if not is_builder:
            inputs.add(f"parameter {param} at {at}")
            return
        for ref, ref_scope in mod.scope_of.items():
            if ref.id != function.name or _resolve(mod, ref_scope, ref.id) is not (
                mod.module_scope
            ):
                continue
            call = mod.calls.get(id(ref))
            argument = _argument_for(function, call, param) if call else None
            if argument is None:
                inputs.add(f"parameter {param} of {function.name} at {where(mod, ref)}")
            else:
                walk(mod, argument)

    def imported(mod: Module, binding: Binding, at: str) -> None:
        node, alias = binding.source, binding.alias
        if isinstance(node, ast.ImportFrom):
            target = package.import_target(mod, node)
            if target is not None:
                # A submodule's members are followed one attribute read at a
                # time, by `member`.
                if package.submodule(mod, node, alias.name) is None:
                    exported(package.modules[target], alias.name, at)
                return
            dotted = f"{node.module}.{alias.name}"
        else:
            dotted = alias.name
        prefixes = {
            ".".join(dotted.split(".")[:n]) for n in range(1, dotted.count(".") + 2)
        }
        if prefixes.isdisjoint(ENV_FREE_IMPORTS):
            inputs.add(f"import {dotted} at {at}")

    def exported(other: Module, name: str, at: str) -> None:
        scope = other.module_scope
        if name not in scope.bindings:
            inputs.add(f"unbound {other.rel}:{name} at {at}")
            return
        values(other, scope, name, at)

    def member(mod: Module, attribute: ast.Attribute) -> None:
        base = attribute.value
        scope = _resolve(mod, mod.scope_of[base], base.id)
        for binding in scope.bindings[base.id] if scope else ():
            if binding.kind == "import" and isinstance(binding.source, ast.ImportFrom):
                submodule = package.submodule(mod, binding.source, binding.alias.name)
                if submodule is not None:
                    exported(submodule, attribute.attr, where(mod, attribute))

    walk(module, root)
    return tuple(sorted(inputs))


def _imported_elsewhere(package: Package, module: Module, name: str) -> bool:
    return any(
        isinstance(node, ast.ImportFrom)
        and package.import_target(other, node) == module.path
        and any(alias.name == name for alias in node.names)
        for other in package.modules.values()
        for node in ast.walk(other.tree)
    )


def _argument_for(
    function: ast.FunctionDef, call: ast.Call, param: str
) -> ast.AST | None:
    """The expression ``call`` passes for ``param``, its default when omitted,
    or None when a ``*args``/``**kwargs`` spread hides the mapping."""
    if any(isinstance(a, ast.Starred) for a in call.args) or any(
        k.arg is None for k in call.keywords
    ):
        return None
    for keyword in call.keywords:
        if keyword.arg == param:
            return keyword.value
    args = function.args
    positional = [a.arg for a in [*args.posonlyargs, *args.args]]
    if param in positional and positional.index(param) < len(call.args):
        return call.args[positional.index(param)]
    defaults = dict(
        zip(positional[len(positional) - len(args.defaults) :], args.defaults)
    )
    defaults.update((a.arg, d) for a, d in zip(args.kwonlyargs, args.kw_defaults) if d)
    return defaults.get(param)


def _enclosing_function(module: Module, node: ast.AST) -> str:
    named = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    owners = sorted(
        (scope_node.lineno, scope_node.name)
        for scope_node in module.scopes
        if isinstance(scope_node, named) and _contains(scope_node, node)
    )
    return ".".join(name for _, name in owners) or "<module>"


def _regex_names(module: Module) -> tuple[set[str], set[str]]:
    """Local names bound to a regex module, and to one of its pattern functions."""
    modules: set[str] = set()
    functions: set[str] = set()
    for node in ast.walk(module.tree):
        if isinstance(node, ast.Import):
            modules |= {
                a.asname or a.name for a in node.names if a.name in REGEX_MODULES
            }
        elif isinstance(node, ast.ImportFrom) and node.module in REGEX_MODULES:
            functions |= {
                a.asname or a.name for a in node.names if a.name in PATTERN_FUNCTIONS
            }
    return modules, functions


def regex_sites(package: Package) -> list[Site]:
    """Every pattern-function use whose pattern is not a literal, with the
    call-time inputs its pattern can reach. A pattern function referenced
    without being called (``map(re.compile, xs)``) hides its pattern from this
    walk, so it reports as reading call-time data."""
    sites = []
    for module in package.modules.values():
        modules, functions = _regex_names(module)
        for node in ast.walk(module.tree):
            is_reference = (
                isinstance(node, ast.Attribute)
                and node.value in module.scope_of
                and node.value.id in modules
                and node.attr in PATTERN_FUNCTIONS
            ) or (node in module.scope_of and node.id in functions)
            if not is_reference:
                continue
            call = module.calls.get(id(node))
            pattern = call and (
                call.args[0]
                if call.args
                else next((k.value for k in call.keywords if k.arg == "pattern"), None)
            )
            if isinstance(pattern, ast.Constant):
                continue
            inputs = (
                call_time_inputs(package, module, pattern)
                if pattern is not None
                else (f"uncalled {ast.unparse(node)} at {module.rel}:{node.lineno}",)
            )
            sites.append(
                Site(
                    module.rel,
                    node.lineno,
                    _enclosing_function(module, node),
                    ast.unparse(pattern if pattern is not None else node),
                    inputs,
                )
            )
    return sorted(sites, key=lambda site: (site.rel, site.line))


_SITES = regex_sites(Package(PACKAGE_ROOT))


def test_dynamic_regex_inventory_is_non_empty() -> None:
    # The guard is vacuous if the walk stops finding dynamic sites; the package
    # builds well over this many patterns from composed constants today, in
    # both the engine and the detectors.
    assert len(_SITES) >= 15, _SITES
    assert {"secrets/engine.py", "secrets/detectors.py"} <= {s.rel for s in _SITES}


def test_no_regex_pattern_reads_call_time_data() -> None:
    flagged = {(s.rel, s.function, s.pattern): s for s in _SITES if s.inputs}
    unreviewed = {
        key: flagged[key].inputs for key in set(flagged) - set(REVIEWED_CALL_TIME_SITES)
    }
    assert not unreviewed, (
        "regex patterns that read call-time data, so their size scales with it. "
        "Build the pattern from module constants or shipped data, or match "
        f"without a regex (substring search):\n{unreviewed}"
    )
    stale = set(REVIEWED_CALL_TIME_SITES) - set(flagged)
    assert not stale, f"reviewed entries that no longer read call-time data: {stale}"


def test_a_load_time_builder_is_followed_through_its_callers() -> None:
    # Positive marker for the builder rule on live code: FIELD_VALUE_RE is
    # compiled inside _field_value_re(nested), whose every call is at module
    # scope with a literal — the walk must reach those calls and pass the site.
    (site,) = [s for s in _SITES if s.function == "_field_value_re"]
    assert site.inputs == ()


_FUNCTION_SCOPED = """\
import re

def value_regex(parts):
    return re.compile("|".join(parts))
"""

# An env secret's value with a character class spliced between its
# characters, compiled once per value: the size defect this guard is for.
_ENV_VALUE_SPLICE = """\
import re
_INVISIBLE = "[\\u200b\\u00ad]*"

def _env_value_re(value):
    return re.compile(_INVISIBLE.join(re.escape(ch) for ch in value))

def redact(text, env):
    for value in env.values():
        text = _env_value_re(value).sub("[REDACTED]", text)
    return text
"""

_MODULE_ENV = """\
import os
import re

_SOURCE = os.environ.get("PATTERN", "a+")
PATTERN_RE = re.compile(_SOURCE)
"""

_MODULE_STATE_SET_BY_A_CALLER = """\
import re

_PARTS = []

def register(part):
    _PARTS.append(part)

def matcher():
    return re.compile("|".join(_PARTS))
"""

_MODULE_CONSTANTS = """\
import re

_NOUNS = ("token", "secret")
_NOUN = "(?:" + "|".join(_NOUNS) + ")"

def _keyword_pattern(name, value):
    return re.compile(name + r"\\s*=\\s*" + f"(?P<v>{value})")

KEYWORD_RE = _keyword_pattern(_NOUN, r"[a-z]{8}")
SUFFIX_RE = re.compile(f"{_NOUN}_(?:key|pass)", re.IGNORECASE)
"""


# A module-scope pattern whose constant is another module's env read.
_CROSS_MODULE_ENV = """\
import re
from .settings import SOURCE

PATTERN_RE = re.compile(SOURCE)
"""
_SETTINGS = """\
import os

SOURCE = os.environ["PATTERN"]
"""

# A pattern function handed over as a value compiles patterns this walk
# never sees.
_UNCALLED = """\
import re

PATTERNS = list(map(re.compile, ["a+", "b+"]))
"""


def _fixture_sites(tmp_path: Path, source: str) -> list[Site]:
    package = tmp_path / "fixture_pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "settings.py").write_text(_SETTINGS, encoding="utf-8")
    (package / "mod.py").write_text(source, encoding="utf-8")
    return regex_sites(Package(package))


@pytest.mark.parametrize(
    "source, expected",
    [
        (_FUNCTION_SCOPED, [["parameter parts"]]),
        (_ENV_VALUE_SPLICE, [["parameter env"]]),
        (_MODULE_ENV, [["import os"]]),
        (_MODULE_STATE_SET_BY_A_CALLER, [["parameter part"]]),
        (_CROSS_MODULE_ENV, [["import os"]]),
        (_UNCALLED, [["uncalled re.compile"]]),
    ],
    ids=[
        "function-scoped",
        "env-value-splice",
        "module-env",
        "module-state-set-by-a-caller",
        "cross-module-env",
        "uncalled",
    ],
)
def test_guard_names_a_call_time_input(tmp_path: Path, source: str, expected) -> None:
    sites = _fixture_sites(tmp_path, source)
    assert [[i.split(" at ")[0] for i in s.inputs] for s in sites] == expected


def test_guard_passes_a_module_constant_pattern(tmp_path: Path) -> None:
    sites = _fixture_sites(tmp_path, _MODULE_CONSTANTS)
    # Positive marker: both dynamic sites were found — the builder's, reached
    # only through its module-scope caller, and the module-scope one.
    assert [(s.function, s.inputs) for s in sites] == [
        ("_keyword_pattern", ()),
        ("<module>", ()),
    ]
