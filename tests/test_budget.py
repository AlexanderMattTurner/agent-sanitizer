"""The budget helper is the sole verdict for every Python cost gate, so its own
polarity is pinned here: a run inside its ceiling passes, one over it raises
with the name and the reading."""

import re

import pytest

from tests._budget import assert_under_budget


def _work(n: int) -> int:
    acc = 0
    for i in range(n):
        acc = (acc + i * 31) % 1_000_003
    return acc


def test_passes_inside_its_ceiling_and_builds_both_calls_first(capsys):
    built = []

    def call_for(attempt):
        built.append(attempt)
        return lambda: _work(10_000 + attempt)

    assert_under_budget("label", call_for, 60.0)
    assert built == [0, 1]
    assert re.fullmatch(
        r"label: \d+\.\d{3}s CPU \(ceiling 60\.0s\)\n", capsys.readouterr().out
    )


def test_raises_over_its_ceiling_naming_the_reading():
    with pytest.raises(AssertionError) as raised:
        assert_under_budget("slow path", lambda _: lambda: _work(2_000_000), 0.0)
    assert re.match(
        r"slow path took \d+\.\d{3}s of CPU, over its 0\.0s ceiling", str(raised.value)
    )
