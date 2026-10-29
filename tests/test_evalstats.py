"""Evaluation statistics (C11.9): Wilson intervals and McNemar's exact test."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from refmon.evalstats import mcnemar_exact, wilson_interval


def test_wilson_matches_known_values():
    lo, hi = wilson_interval(0, 10)
    assert lo == 0.0 and hi == pytest.approx(0.2775, abs=1e-3)
    lo, hi = wilson_interval(10, 10)
    assert lo == pytest.approx(0.7225, abs=1e-3) and hi == 1.0
    # the defining property: each end is a proportion whose own 95 % band just reaches the estimate
    lo, hi = wilson_interval(81, 100)
    for edge in (lo, hi):
        assert abs(0.81 - edge) == pytest.approx(
            1.959964 * (edge * (1 - edge) / 100) ** 0.5, rel=1e-4
        )


def test_wilson_of_nothing_is_the_whole_range():
    assert wilson_interval(0, 0) == (0.0, 1.0)
    with pytest.raises(ValueError):
        wilson_interval(5, 3)


@given(n=st.integers(min_value=1, max_value=2000), data=st.data())
def test_wilson_interval_contains_the_estimate_and_stays_in_range(n, data):
    k = data.draw(st.integers(min_value=0, max_value=n))
    lo, hi = wilson_interval(k, n)
    assert 0.0 <= lo <= k / n <= hi <= 1.0
    assert wilson_interval(k, n, 0.99)[1] - wilson_interval(k, n, 0.99)[0] >= hi - lo


def test_mcnemar_exact_values():
    assert mcnemar_exact(0, 0) == 1.0
    assert mcnemar_exact(10, 0) == pytest.approx(2 * 0.5**10)
    assert mcnemar_exact(5, 5) == 1.0
    assert mcnemar_exact(3, 9) == pytest.approx(0.1460, abs=1e-3)


@given(a=st.integers(0, 60), b=st.integers(0, 60))
def test_mcnemar_is_symmetric_and_a_probability(a, b):
    assert mcnemar_exact(a, b) == mcnemar_exact(b, a)
    assert 0.0 <= mcnemar_exact(a, b) <= 1.0
