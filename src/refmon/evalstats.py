"""Evaluation statistics (CLAUDE.md C11.9): detection rates with Wilson 95 % intervals (catalogs are
small) and versions compared on the same corpus with McNemar's test. Pure functions, used by the
reproduction script; they are not part of the pipeline."""

from __future__ import annotations

import math
from statistics import NormalDist


def wilson_interval(successes: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    """The Wilson score interval of a proportion; (0, 1) when there is nothing to estimate."""
    if n <= 0:
        return 0.0, 1.0
    if not 0 <= successes <= n:
        raise ValueError("successes must be between 0 and n")
    z = NormalDist().inv_cdf(1.0 - (1.0 - confidence) / 2.0)
    p = successes / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2.0 * n)) / denom
    half = z * math.sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n)) / denom
    low = 0.0 if successes == 0 else max(0.0, centre - half)
    high = 1.0 if successes == n else min(1.0, centre + half)
    return low, high


def mcnemar_exact(only_first: int, only_second: int) -> float:
    """Two-sided exact McNemar p-value from the discordant pairs: `only_first` pairs that only the
    first version got right, `only_second` that only the second did. 1.0 when there are none."""
    n = only_first + only_second
    if n == 0:
        return 1.0
    low = min(only_first, only_second)
    tail = sum(math.comb(n, i) for i in range(low + 1)) / 2.0**n
    return min(1.0, 2.0 * tail)
