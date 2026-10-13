"""The one growth estimator every Python complexity gate classifies with.

Twin of ``growth`` in ``test/helpers/cpu-timing.mjs``, and it reads the same
thresholds from the same file (``tests/data/growth-exponents.json``), so a gate
in either language means the same thing by "linear". The thresholds and the
measurements behind them are documented in that module's header.

A gate fits HOW cost grows, not how much one size cost against another. Cost is
sampled at three or more geometrically spaced sizes and the verdict is the
least-squares slope of ln(cost) against ln(size) — the ``k`` in cost ~ n^k —
classified against one shared pair of thresholds: a gate passes below
:data:`LINEAR_MAX_EXPONENT`, a positive control must read above
:data:`SUPERLINEAR_MIN_EXPONENT`. No gate carries a number of its own.

Two samplers feed the one fit:

- :func:`opcode_growth` counts interpreted bytecode operations. The count is
  identical on every machine and every run, so one sample per size is exact.
- :func:`cpu_growth` reads ``time.process_time``, the only measure that sees
  work done inside a C builtin (one ``str`` slice is one opcode however many
  megabytes it copies). Every size is sampled :data:`ROUNDS` times,
  INTERLEAVED, keeping each size's fastest per-call reading, with every timed
  block about as long as one call at the largest size. Noise only ever ADDS
  CPU time, so the minimum is the reading closest to the code's own cost; the
  interleave makes a burst of load land on every size alike; and the fit means
  one misread size moves the verdict by a fraction of its error. A single ratio
  of two samples had none of those: one garbage collection on one side read
  ~580x, and a slow runner read a quadratic control at 12.99x against a limit
  of 15.
"""

import json
import math
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass

from tests._helpers import REPO_ROOT

_EXPONENTS = json.loads(
    (REPO_ROOT / "tests" / "data" / "growth-exponents.json").read_text(encoding="utf-8")
)
#: A gate passes when its fitted exponent is BELOW this.
LINEAR_MAX_EXPONENT: float = _EXPONENTS["linear_max_exponent"]
#: A positive control passes when its fitted exponent is ABOVE this.
SUPERLINEAR_MIN_EXPONENT: float = _EXPONENTS["superlinear_min_exponent"]

# Sampling constants, the same values as the JS twin's (ROUNDS, MIN_BLOCK_MS,
# MAX_BLOCK_MS in test/helpers/cpu-timing.mjs), which documents why each.
#: Interleaved rounds of :func:`cpu_growth`; each size keeps its fastest.
ROUNDS = 5
#: A timed block lasts at least this long, however cheap one call is, so that a
#: microsecond regex scan is a measurement rather than clock granularity.
_MIN_BLOCK_SECONDS = 0.005
#: ...and is matched to the largest size's call only up to this long; past it
#: a block is one call.
_MAX_BLOCK_SECONDS = 0.05

#: ``call_for(size, attempt)`` builds the zero-argument call to measure at
#: ``size``. Only that call is measured, so building the input and any setup the
#: entry point's caller would do happens outside the number. ``attempt`` counts
#: up from 0 and every call the sampler makes gets a distinct one: inputs at one
#: size should differ only by a unit (``size + attempt``), so an entry point that
#: memoizes on its argument is timed on the work rather than on cache hits.
CallFor = Callable[[int, int], Callable[[], object]]
#: How many distinct inputs each size of :func:`cpu_growth` cycles through (the
#: JS twin's ``BLOCK_RING``).
_BLOCK_RING = 8


@dataclass(frozen=True)
class Growth:
    """A fitted curve: the exponent, and the per-call cost each size read."""

    exponent: float
    sizes: tuple[int, ...]
    costs: tuple[float, ...]

    def __str__(self) -> str:
        costs = "/".join(f"{c:.4g}" for c in self.costs)
        sizes = "/".join(str(s) for s in self.sizes)
        return f"exponent {self.exponent:.2f} over n={sizes} (cost {costs})"


def geometric_sizes(lo: int, hi: int, count: int = 4) -> tuple[int, ...]:
    """``count`` sizes from ``lo`` to ``hi`` inclusive, every step the same
    RATIO — which is what a log-log fit weighs evenly."""
    assert count >= 3 and hi > lo, "a growth fit needs three or more sizes"
    step = (hi / lo) ** (1 / (count - 1))
    return tuple(round(lo * step**i) for i in range(count))


def fit_exponent(sizes, costs) -> float:
    """Least-squares slope of ln(cost) against ln(size)."""
    assert all(c > 0 for c in costs), (
        f"a cost of zero has no logarithm — the measured call did nothing: {costs}"
    )
    xs = [math.log(s) for s in sizes]
    ys = [math.log(c) for c in costs]
    mx = sum(xs) / len(xs)
    my = sum(ys) / len(ys)
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    return num / den


def _opcodes(call) -> int:
    """Interpreted bytecode operations executed by ``call``.

    ``sys.settrace`` with per-frame ``f_trace_opcodes`` counts the interpreter's
    own steps rather than the host's speed.
    """
    count = 0

    def trace(frame, event, _arg):
        nonlocal count
        if event == "call":
            frame.f_trace_opcodes = True
            return trace
        if event == "opcode":
            count += 1
        return trace

    # Restore whatever tracer was installed (a coverage plugin's), not None:
    # clearing it would silently stop coverage for every later test that runs
    # in this process.
    previous = sys.gettrace()
    sys.settrace(trace)
    try:
        call()
    finally:
        sys.settrace(previous)
    return count


def opcode_growth(call_for: CallFor, sizes) -> Growth:
    """Opcode-count growth across ``sizes``.

    A warm-up call at the smallest size first: an entry point that builds a
    mapping or compiles a prefilter lazily would otherwise charge that one-time
    cost to whichever size ran first and flatten the curve. The warm-up and the
    measured call take different ``attempt`` inputs, so a memoizing entry point
    is not counted on the warm-up's cache hit.
    """
    call_for(sizes[0], 0)()
    costs = tuple(_opcodes(call_for(size, 1)) for size in sizes)
    return Growth(fit_exponent(sizes, costs), tuple(sizes), costs)


def _visit_order(count: int) -> list[int]:
    """The order :func:`cpu_growth` visits ``count`` sizes in on its even rounds
    (0, 2, 1, 3 for four), reversed on odd rounds. The JS twin's ``visitOrder``
    explains why ascending order lets one fast stretch cover half the curve."""
    return [*range(0, count, 2), *range(1, count, 2)]


def cpu_growth(call_for: CallFor, sizes) -> Growth:
    """CPU-time growth across ``sizes``: interleaved fastest-of-:data:`ROUNDS`
    per-call ``process_time``, every block matched to the largest size's cost
    (between :data:`_MIN_BLOCK_SECONDS` and :data:`_MAX_BLOCK_SECONDS`).

    Process time rather than wall clock, so another process loading the runner
    charges nothing. Blocks are matched because fastest-of-N is fair only
    between blocks of similar length — a short block reliably finds a quiet
    slot and a long one never does."""
    single = []
    for size in sizes:
        # The warm-up pays lazy setup and first-touch allocation at this size.
        # When even that is past the block cap it sizes the block (one call);
        # otherwise one more call, now warm, does. Each call has its own input,
        # built before the clock starts.
        call = call_for(size, 0)
        start = time.process_time()
        call()
        spent = time.process_time() - start
        if spent < _MAX_BLOCK_SECONDS:
            call = call_for(size, 1)
            start = time.process_time()
            call()
            spent = time.process_time() - start
        single.append(spent)
    block = min(_MAX_BLOCK_SECONDS, max(_MIN_BLOCK_SECONDS, *single))
    repeats = [max(1, math.ceil(block / max(s, 1e-6))) for s in single]
    rings = [[call_for(size, 2 + i) for i in range(_BLOCK_RING)] for size in sizes]
    taken = [0] * len(sizes)
    best = [math.inf] * len(sizes)
    order = _visit_order(len(sizes))
    for round_ in range(ROUNDS):
        for i in reversed(order) if round_ % 2 else order:
            ring = rings[i]
            start = time.process_time()
            for _ in range(repeats[i]):
                ring[taken[i] % _BLOCK_RING]()
                taken[i] += 1
            best[i] = min(best[i], (time.process_time() - start) / repeats[i])
    return Growth(fit_exponent(sizes, best), tuple(sizes), tuple(best))


#: How many times over a call must fit its budget: it passes when its
#: FASTEST of :data:`ROUNDS` runs is under ``budget / BUDGET_HEADROOM``. The
#: budget guards against a runaway scan (seconds, or unbounded); an ordinary
#: payload costs milliseconds, so ten-fold headroom keeps a loaded runner from
#: reading as a regression while a payload that genuinely nears the budget still
#: fails. It lives here rather than in the exponents file because it is not a
#: growth threshold and the JS twin has no use for it.
BUDGET_HEADROOM = 10


def assert_fits_budget(name: str, call: Callable[[], object], budget_seconds: float):
    """A representative call fits ``budget_seconds`` with :data:`BUDGET_HEADROOM`
    to spare, read as the fastest of :data:`ROUNDS` ``process_time`` runs.

    Noise only ever ADDS CPU time, so the minimum is the reading closest to the
    call's own cost: a loaded runner cannot fail it, and only a call whose
    unloaded cost is within the headroom of the budget can."""
    fastest = math.inf
    for _ in range(ROUNDS):
        start = time.process_time()
        call()
        fastest = min(fastest, time.process_time() - start)
    assert fastest < budget_seconds / BUDGET_HEADROOM, (
        f"{name} took {fastest:.4g}s CPU at best; it must fit the "
        f"{budget_seconds}s budget with {BUDGET_HEADROOM}x headroom"
    )


def assert_linear(name: str, growth: Growth) -> None:
    """The gate: ``growth`` classifies as at most linear."""
    assert growth.exponent < LINEAR_MAX_EXPONENT, (
        f"{name} grew super-linearly: {growth}; linear is below {LINEAR_MAX_EXPONENT}"
    )


def assert_superlinear(name: str, growth: Growth) -> None:
    """The positive control: ``growth`` classifies as super-linear, or the
    harness cannot see the defect class the gates beside it exist for."""
    assert growth.exponent > SUPERLINEAR_MIN_EXPONENT, (
        f"{name} is a deliberate super-linear control but read {growth}; it must "
        f"exceed {SUPERLINEAR_MIN_EXPONENT}, so every linear verdict beside it is "
        "suspect"
    )
