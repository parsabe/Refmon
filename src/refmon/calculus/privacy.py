"""Privacy mathematics (CLAUDE.md C11.8): Laplace noise on aggregate counts, k-anonymity
suppression for dashboards, and Bloom-filter threat lists.

Counts sent to the server get Laplace noise with scale 1 / epsilon (sensitivity 1 per device).
Dashboards drop any group with fewer than k devices. A threat list ships as a Bloom filter sized for
a false-positive rate (policy, at most 0.1 %); a local hit is only a hint and has to be confirmed
against the exact list before any action.
"""

from __future__ import annotations

import hashlib
import math
import random
from collections.abc import Mapping


def laplace_noise(epsilon: float, rng: random.Random, sensitivity: float = 1.0) -> float:
    """A sample from Laplace(0, sensitivity / epsilon) by inverse transform."""
    if epsilon <= 0.0:
        raise ValueError("epsilon must be positive")
    u = rng.random() - 0.5
    scale = sensitivity / epsilon
    return -scale * math.copysign(1.0, u) * math.log(1.0 - 2.0 * abs(u))


def noisy_count(count: int, epsilon: float, rng: random.Random) -> float:
    return count + laplace_noise(epsilon, rng)


def suppress_small_groups(devices_per_group: Mapping[str, int], k: int) -> dict[str, int]:
    """Keep only groups with at least k devices (k-anonymity)."""
    return {group: n for group, n in devices_per_group.items() if n >= k}


def bloom_size(items: int, false_positive_rate: float) -> tuple[int, int]:
    """(bits m, hash functions k_h) for n items: m = -n ln p / (ln 2)^2, k_h = (m / n) ln 2."""
    n = max(items, 1)
    m = math.ceil(-n * math.log(false_positive_rate) / math.log(2.0) ** 2)
    return m, max(1, round(m / n * math.log(2.0)))


def bloom_false_positive_rate(items: int, bits: int, hashes: int) -> float:
    """(1 - e^(-k_h n / m))^(k_h)."""
    return (1.0 - math.exp(-hashes * items / bits)) ** hashes


class BloomFilter:
    def __init__(self, items: int, false_positive_rate: float) -> None:
        self.bits, self.hashes = bloom_size(items, false_positive_rate)
        self.items = items
        self._array = bytearray((self.bits + 7) // 8)

    def _positions(self, digest: str):
        raw = hashlib.sha256(digest.encode()).digest()
        h1 = int.from_bytes(raw[:8], "big")
        h2 = int.from_bytes(raw[8:16], "big") | 1  # odd, so double hashing covers all positions
        return [(h1 + i * h2) % self.bits for i in range(self.hashes)]

    def add(self, digest: str) -> None:
        for pos in self._positions(digest):
            self._array[pos // 8] |= 1 << (pos % 8)

    def might_contain(self, digest: str) -> bool:
        return all(self._array[pos // 8] >> (pos % 8) & 1 for pos in self._positions(digest))

    def expected_false_positive_rate(self) -> float:
        return bloom_false_positive_rate(self.items, self.bits, self.hashes)
