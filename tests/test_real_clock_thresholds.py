"""A clock reading may decide a Python test's verdict only through the budget
helper.

Twin of ``test/real-clock-thresholds.test.mjs``, which states the rule: a test of
a deadline, budget or timer drives an injected clock (``monkeypatch`` on the
module's ``time``, a stubbed deadline); a test of COST calls
``assert_under_budget`` in ``tests/_budget.py`` — one warm run against an
absolute ceiling ten times or more above the linear cost — the one module here
allowed to read a clock for a verdict.

A threshold is an ``assert`` comparing a real-clock reading — directly, through
a name assigned from one, or through a function returning one — against
something that is not itself a clock reading. A reading could also arrive
through an ACCESSOR imported from the harness, because the taint is per-file and
the clock itself is not in sight; the harness exports none
(:data:`CLOCK_ACCESSORS`), and a test below fails when a function of it starts
returning a reading. Reading a clock anywhere else is fine: a polling deadline,
a socket wait, a timestamp. Those decide how long a test waits, never whether
it passes. Parsed with :mod:`ast`, not grepped, so a mention in a string or a
comment is not a reading.
"""

import ast
import inspect

import pytest

from tests import _budget
from tests._helpers import REPO_ROOT

#: The budget helper: the one place a clock reading may decide a verdict.
HARNESS = {"tests/_budget.py"}

#: Every real-clock read the scan recognizes, as ``time.<name>()``. The list is
#: the guard's whole vocabulary; a test below proves each entry is detected.
CLOCK_READS = (
    "time",
    "time_ns",
    "monotonic",
    "monotonic_ns",
    "perf_counter",
    "perf_counter_ns",
    "process_time",
    "process_time_ns",
)

#: Functions that hand a test a clock reading without the test calling a clock,
#: matched by name wherever they are called (``f(...)`` and ``mod.f(...)``
#: alike). Empty: ``assert_under_budget`` decides inside the harness and returns
#: nothing, and a test below holds every other function of it to the same.
CLOCK_ACCESSORS: tuple[str, ...] = ()

_RELATIONAL = (ast.Lt, ast.LtE, ast.Gt, ast.GtE)


def _is_clock_read(node: ast.AST, bare: set[str]) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr in CLOCK_ACCESSORS or (
            isinstance(func.value, ast.Name)
            and func.value.id == "time"
            and func.attr in CLOCK_READS
        )
    return isinstance(func, ast.Name) and (
        func.id in bare or func.id in CLOCK_ACCESSORS
    )


def _dotted(node: ast.AST) -> str | None:
    """``a.b.c`` for an attribute chain rooted at a plain name, else None."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        head = _dotted(node.value)
        return None if head is None else f"{head}.{node.attr}"
    return None


def _target_names(target: ast.AST):
    """The names an assignment target binds: ``x``, ``a, b``, and the FULL path of
    an attribute (``self.x``, ``timer.elapsed``) — a bare ``elapsed`` would never
    match the ``ast.Attribute`` a later read of ``timer.elapsed`` loads."""
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, ast.Attribute):
        path = _dotted(target)
        if path is not None:
            yield path
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            yield from _target_names(element)


_FUNCTIONS = (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef)


def _outside_functions(root: ast.AST):
    """``root`` and its descendants, not descending into a nested function. A
    function VALUE is not a reading: a clock inside a lambda handed to the code
    under test reaches no assertion. What a named function RETURNS is followed
    separately."""
    if isinstance(root, _FUNCTIONS):
        return
    yield root
    for child in ast.iter_child_nodes(root):
        yield from _outside_functions(child)


def scan(source: str) -> tuple[list[str], int]:
    """Every real-clock threshold in ``source`` as ``line: text``, and how many
    clock reads it holds at all."""
    tree = ast.parse(source)
    # `from time import monotonic` makes a bare `monotonic()` a reading too.
    bare = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "time"
        for alias in node.names
        if alias.name in CLOCK_READS
    }
    tainted: set[str] = set()

    def derived(root: ast.AST | None) -> bool:
        if root is None:
            return False
        for node in _outside_functions(root):
            if _is_clock_read(node, bare):
                return True
            if isinstance(node, ast.Call) and _dotted(node.func) in tainted:
                return True
            if isinstance(node, (ast.Name, ast.Attribute)) and _dotted(node) in tainted:
                return True
        return False

    # Name-based and module-wide, to a fixed point, so a reading reaches an
    # assertion through any number of hops. Coarse on purpose: a name reused
    # for something unrelated is flagged, and renaming it is the fix.
    before = -1
    while len(tainted) != before:
        before = len(tainted)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and derived(node.value):
                for target in node.targets:
                    tainted.update(_target_names(target))
            elif isinstance(node, (ast.AugAssign, ast.AnnAssign, ast.NamedExpr)):
                if derived(node.value):
                    tainted.update(_target_names(node.target))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if any(
                    isinstance(ret, ast.Return) and derived(ret.value)
                    for stmt in node.body
                    for ret in _outside_functions(stmt)
                ):
                    tainted.add(node.name)

    thresholds = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assert):
            continue
        for cmp in ast.walk(node.test):
            if not isinstance(cmp, ast.Compare):
                continue
            operands = [cmp.left, *cmp.comparators]
            for op, left, right in zip(cmp.ops, operands, operands[1:]):
                # A clock against a clock (`after >= before`) is ordering, not
                # a threshold the machine's speed can push either side of.
                if isinstance(op, _RELATIONAL) and derived(left) != derived(right):
                    thresholds.append(f"{cmp.lineno}: {ast.unparse(cmp)}")
    reads = sum(1 for node in ast.walk(tree) if _is_clock_read(node, bare))
    return thresholds, reads


def _test_files() -> list[str]:
    return sorted(
        path.relative_to(REPO_ROOT).as_posix()
        for path in (REPO_ROOT / "tests").rglob("*.py")
    )


_RESULTS = {
    path: scan((REPO_ROOT / path).read_text(encoding="utf-8")) for path in _test_files()
}


def test_no_test_outside_the_harness_asserts_against_a_real_clock():
    offenders = [
        f"{path}:{hit}"
        for path, (thresholds, _reads) in _RESULTS.items()
        if path not in HARNESS
        for hit in thresholds
    ]
    assert offenders == [], (
        "drive an injected clock for a deadline/budget/timer test, or bound "
        "cost with assert_under_budget from tests/_budget.py"
    )


def test_the_scan_reads_the_real_tree_and_finds_its_clock_reads():
    """Non-vacuity: a scan that parsed nothing, or a vocabulary that no longer
    matches how this tree reads a clock, would report zero offenders forever."""
    assert len(_RESULTS) > 50, sorted(_RESULTS)
    outside = sum(
        reads for path, (_t, reads) in _RESULTS.items() if path not in HARNESS
    )
    assert outside > 0, "no clock read found outside the harness"
    for path in HARNESS:
        assert path in _RESULTS, f"{path} is exempt but no longer exists"
        assert _RESULTS[path][1] > 0, f"{path} no longer reads a clock"
        # Positive marker for the invariant itself: the harness holds exactly
        # one clock-against-ceiling verdict, and the scan sees it. A helper that
        # stopped deciding — or a scan that stopped recognizing its idiom —
        # would leave every budget in the tree checking nothing.
        assert len(_RESULTS[path][0]) == 1, _RESULTS[path][0]
    # ...and that verdict is reached from the tests: a helper nothing calls
    # exempts a file for no reason.
    callers = [
        path
        for path in _RESULTS
        if path not in HARNESS
        and "assert_under_budget(" in (REPO_ROOT / path).read_text(encoding="utf-8")
    ]
    assert len(callers) >= 4, callers


def _clock_reading_functions(source: str) -> set[str]:
    """The public functions in ``source`` that reach a real clock, through any
    chain of the module's own functions, AND return a value. By call graph rather
    than by data flow, so a pure helper (say, one fitting a curve to readings)
    that shares parameter names with the readings beside it is not swept in."""
    tree = ast.parse(source)
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    def calls(fn):
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                yield _dotted(node.func) or ""

    reaching: set[str] = set()
    before = -1
    while len(reaching) != before:
        before = len(reaching)
        for name, fn in functions.items():
            if any(
                call.startswith("time.")
                and call.split(".")[1] in CLOCK_READS
                or call in reaching
                for call in calls(fn)
            ):
                reaching.add(name)
    return {
        name
        for name in reaching
        if not name.startswith("_")
        and any(
            isinstance(node, ast.Return) and node.value is not None
            for stmt in functions[name].body
            for node in _outside_functions(stmt)
        )
    }


def test_every_listed_accessor_exists_in_the_harness():
    """A vocabulary entry for a function that was renamed away detects nothing
    and says nothing, so each one is checked against the live module."""
    for name in CLOCK_ACCESSORS:
        assert callable(getattr(_budget, name)), name
    assert callable(_budget.assert_under_budget)


def test_no_clock_returning_function_of_the_harness_is_missing_from_the_vocabulary():
    """Enumerated from a call-graph scan of the harness's own source, so a new
    accessor that returns a reading fails here instead of escaping every file
    that imports it."""
    returning = _clock_reading_functions(inspect.getsource(_budget))
    assert returning == set(CLOCK_ACCESSORS)


def test_the_accessor_scan_finds_a_function_that_returns_a_reading_and_only_that():
    """Non-vacuity for the check above, which now expects the harness to return
    no reading at all: the empty answer must come from the source, not from a
    scan that finds nothing anywhere."""
    source = (
        "import time\n"
        "def _since(s):\n    return time.process_time() - s\n"
        "def measure(call):\n    s = time.process_time()\n    call()\n"
        "    return _since(s)\n"
        "def assert_fast(call):\n    s = time.process_time()\n    call()\n"
        "    assert _since(s) < 5\n"
        "def pure(x):\n    return x * 2\n"
    )
    assert _clock_reading_functions(source) == {"measure"}


# The hops a reading takes to an assertion inside one file, each of which the
# taint has to follow — the shapes the cost gates themselves used before every
# clock verdict moved into the budget helper.
_HOPS = {
    "an attribute of a returned reading": (
        "import time\ndef curve():\n    s = time.process_time()\n    work()\n"
        "    return Growth(time.process_time() - s)\n"
        "growth = curve()\nassert growth.exponent < 1.35\n"
    ),
    "a subscript of a returned reading": (
        "import time\ndef costs():\n    s = time.process_time()\n    work()\n"
        "    return [time.process_time() - s]\n"
        "assert costs()[0] < BUDGET\n"
    ),
    "a module-qualified clock": (
        "import time\ns = time.perf_counter()\nwork()\n"
        "spent = time.perf_counter() - s\nassert spent < 1.0\n"
    ),
}


@pytest.mark.parametrize("idiom", sorted(_HOPS))
def test_flags_a_reading_across_each_hop(idiom):
    thresholds, reads = scan(_HOPS[idiom])
    assert len(thresholds) == 1, thresholds
    assert reads >= 1


# Each idiom the guard must catch, built around every clock read in the
# vocabulary, so a read that falls out of detection fails here by name.
_OFFENDERS = {
    "direct": "import time\nt0 = time.{r}()\nwork()\nassert time.{r}() - t0 < 1.0\n",
    "via a name": (
        "import time\nstarted = time.{r}()\nwork()\n"
        "elapsed = time.{r}() - started\nassert elapsed < 0.5, elapsed\n"
    ),
    "via a helper's return": (
        "import time\ndef seconds():\n    best = float('inf')\n"
        "    for _ in range(5):\n        s = time.{r}()\n        work()\n"
        "        best = min(best, time.{r}() - s)\n    return best\n"
        "def growth():\n    return seconds() / seconds()\n"
        "assert growth() < LIMIT\n"
    ),
    "against a named constant": (
        "import time\ns = time.{r}()\nassert time.{r}() - s < S.BUDGET / 2\n"
    ),
    "via an assigned attribute": (
        "import time\ntimer = Timer()\ns = time.{r}()\nwork()\n"
        "timer.elapsed = time.{r}() - s\nassert timer.elapsed < LIMIT\n"
    ),
    "imported bare": (
        "from time import {r}\ns = {r}()\nwork()\nassert {r}() - s < 3\n"
    ),
}


@pytest.mark.parametrize("idiom", sorted(_OFFENDERS))
@pytest.mark.parametrize("read", CLOCK_READS)
def test_flags_each_clock_read_in_each_idiom(read, idiom):
    thresholds, reads = scan(_OFFENDERS[idiom].format(r=read))
    assert len(thresholds) == 1, thresholds
    assert reads >= 1


# The uses that decide how long a test waits, never whether it passes.
_BENIGN = {
    "a polling deadline": (
        "import time\ndeadline = time.monotonic() + 10\n"
        "while time.monotonic() < deadline and not ready():\n    sleep(0.05)\n"
        "assert ready()\n"
    ),
    "a driven clock": (
        "clock = [0.0]\nmonkeypatch.setattr(E, 'time', ns(monotonic=lambda: clock[0]))\n"
        "clock[0] += 1.0\nassert charged() == 1.0\n"
    ),
    "a timestamp": (
        "import time\nold = time.time() - 3600\nos.utime(p, (old, old))\n"
        "assert stale(p)\n"
    ),
    "clock ordering": (
        "import time\na = time.monotonic()\nb = time.monotonic()\nassert b >= a\n"
    ),
    "an untainted attribute beside a tainted one": (
        "import time\ntimer = Timer()\ntimer.elapsed = time.monotonic() - time.monotonic()\n"
        "timer.count = 3\nassert timer.count < LIMIT\nassert other.elapsed < LIMIT\n"
    ),
    "a harness verdict": (
        "from tests._budget import assert_under_budget\n"
        "assert_under_budget('x', lambda k: lambda: run(k), 2.0)\n"
    ),
    "a mention in a string": "assert 'time.monotonic() - started < 10' in doc\n",
}


@pytest.mark.parametrize("idiom", sorted(_BENIGN))
def test_does_not_flag(idiom):
    assert scan(_BENIGN[idiom])[0] == []
