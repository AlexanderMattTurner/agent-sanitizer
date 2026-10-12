"""No Python test outside the cost-gate harness passes or fails on a real clock.

Twin of ``test/real-clock-thresholds.test.mjs``, which states the rule: a test of
a deadline, budget or timer drives an injected clock (``monkeypatch`` on the
module's ``time``, a stubbed deadline); a test of COST goes through
``tests/_growth.py``, the one module here allowed to read a clock for a verdict.

A threshold is an ``assert`` comparing a real-clock reading — directly, through
a name assigned from one, or through a function returning one — against
something that is not itself a clock reading. Reading a clock anywhere else is
fine: a polling deadline, a socket wait, a timestamp. Those decide how long a
test waits, never whether it passes. Parsed with :mod:`ast`, not grepped, so a
mention in a string or a comment is not a reading.
"""

import ast

import pytest

from tests._helpers import REPO_ROOT

#: The cost-gate harness: the one place a clock reading may decide a verdict.
HARNESS = {"tests/_growth.py"}

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

_RELATIONAL = (ast.Lt, ast.LtE, ast.Gt, ast.GtE)


def _is_clock_read(node: ast.AST, bare: set[str]) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute):
        return (
            isinstance(func.value, ast.Name)
            and func.value.id == "time"
            and func.attr in CLOCK_READS
        )
    return isinstance(func, ast.Name) and func.id in bare


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
        "drive an injected clock for a deadline/budget/timer test, or measure "
        "cost through tests/_growth.py"
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
    "a mention in a string": "assert 'time.monotonic() - started < 10' in doc\n",
}


@pytest.mark.parametrize("idiom", sorted(_BENIGN))
def test_does_not_flag(idiom):
    assert scan(_BENIGN[idiom])[0] == []
