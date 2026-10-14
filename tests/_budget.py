"""The one way a Python test may turn a clock reading into a verdict: an ABSOLUTE
budget, generous enough that only a change in complexity class can break it.

Twin of ``test/helpers/budget.mjs``, whose header gives the rationale. In short:
each gate runs its entry point ONCE, after a warm-up, on an input sized so the
linear implementation costs tenths of a second at most, and fails when that one
run exceeds a ceiling at least ten times what the linear code was measured at.
A path gone super-linear overshoots the ceiling by another order of magnitude;
a constant-factor slowdown passes, by design. The fitted growth exponents this
replaced resolved finer changes and flaked on loaded runners because of it.

``time.process_time`` rather than wall clock, so another process loading the
runner charges nothing. No mutation runner drives the Python suite, so unlike
the JS twin there is nothing to stand down for.
``tests/test_real_clock_thresholds.py`` fails any other test that compares a
clock reading against a threshold.
"""

import time
from collections.abc import Callable

#: ``call_for(attempt)`` builds the zero-argument call to time. Attempt 0 is the
#: warm-up, attempt 1 the timed run; both are built before the clock starts, and
#: they should differ by a unit so an entry point that memoizes on its argument
#: is timed on the work rather than on a cache hit.
CallFor = Callable[[int], Callable[[], object]]


def assert_under_budget(name: str, call_for: CallFor, ceiling_seconds: float) -> None:
    """One warm run of ``call_for(1)`` costs at most ``ceiling_seconds`` of CPU."""
    warm = call_for(0)
    timed = call_for(1)
    warm()
    start = time.process_time()
    timed()
    spent = time.process_time() - start
    # Printed on the green path too (visible with `pytest -s`), so a runner
    # these ceilings were never measured on can report its own numbers.
    print(f"{name}: {spent:.3f}s CPU (ceiling {ceiling_seconds}s)")
    assert spent <= ceiling_seconds, (
        f"{name} took {spent:.3f}s of CPU, over its {ceiling_seconds}s ceiling — "
        "a ceiling ten times what the linear code costs, so this is a change of "
        "complexity class, not a slow runner"
    )
