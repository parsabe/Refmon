"""Rate anomalies (CLAUDE.md C11.6): the Poisson tail test for bursts, CUSUM for slow drift, and
exponential moving averages for the baselines.

Burst: with baseline rate lambda per window, alert when P(X >= k) < alpha for the k events seen.
Drift: CUSUM on z-scores, S_t = max(0, S_{t-1} + z_t - k) with z_t = (x_t - mu) / sigma, alert when
S_t > h (k and h in standard deviations; design decision D11). Baselines are exponential moving
averages and are frozen while an incident is open, so an attacker cannot teach the baseline.
"""

from __future__ import annotations

import math
import sys
from dataclasses import dataclass


def poisson_tail(k: int, lam: float) -> float:
    """P(X >= k) for X ~ Poisson(lam), summed from the upper tail so tiny values stay exact."""
    if k <= 0:
        return 1.0
    if lam <= 0.0:
        return 0.0
    term = math.exp(-lam + k * math.log(lam) - math.lgamma(k + 1))
    total, i = term, k
    while term > total * sys.float_info.epsilon or i < lam:
        term *= lam / (i + 1)
        total += term
        i += 1
    return min(1.0, total)


def burst_is_anomalous(k: int, lam: float, alpha: float) -> bool:
    return poisson_tail(k, lam) < alpha


def z_score(x: float, mean: float, sigma: float) -> float:
    return (x - mean) / sigma if sigma > 0.0 else 0.0


@dataclass
class Cusum:
    """One-sided CUSUM over z-scores. `peek` shows the statistic a value would produce."""

    k: float
    h: float
    s: float = 0.0

    def peek(self, z: float) -> float:
        return max(0.0, self.s + z - self.k)

    def update(self, z: float) -> bool:
        self.s = self.peek(z)
        return self.s > self.h


@dataclass
class Ema:
    """Exponential moving average. While frozen it ignores updates."""

    value: float
    beta: float
    frozen: bool = False

    def update(self, x: float) -> float:
        if not self.frozen:
            self.value = (1.0 - self.beta) * self.value + self.beta * x
        return self.value
