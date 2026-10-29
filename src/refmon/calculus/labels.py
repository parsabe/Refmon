"""Label strength (C11.1, C11.2): decay with a half-life, attenuation along an edge, noisy-OR."""

from collections.abc import Iterable


def decay(s0: float, dt: float, half_life: float | None) -> float:
    """s(t) = s0 * 2^(-dt / T_half). `None` is T_half = infinity (a persistent label)."""
    if half_life is None or dt <= 0:
        return s0
    return s0 * 2.0 ** (-dt / half_life)


def attenuate(parent_strength: float, edge: float = 1.0) -> float:
    """s_child = s_parent * a_e with a_e in (0, 1]."""
    if not 0.0 < edge <= 1.0:
        raise ValueError("attenuation must be in (0, 1]")
    return parent_strength * edge


def noisy_or(strengths: Iterable[float]) -> float:
    """s = 1 - prod(1 - s_i). In [0, 1] and never below the largest input."""
    product = 1.0
    for s in strengths:
        product *= 1.0 - s
    return 1.0 - product
