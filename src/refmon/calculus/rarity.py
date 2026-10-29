"""Contract rarity (CLAUDE.md C11.3): how surprising is this kind of event for this role?

p(e | role) = (n_e + alpha) / (N + alpha * K) with Laplace smoothing, K = observed kinds + 1 (the
extra one stands for "never seen"). Surprisal is -log2 p in bits. The Good-Turing estimate
n1 / N, the share of events whose kind was seen exactly once, says how likely the next event is a
kind never seen before; a baseline is mature when that is below the policy threshold. A learned
contract and the surprisal signal only count for a role whose baseline is mature (missing
information never generates evidence).
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping


def laplace_probability(count: int, total: int, kinds: int, alpha: float = 1.0) -> float:
    """p(e) for an event kind seen `count` times in `total` events of a role with `kinds` kinds."""
    return (count + alpha) / (total + alpha * (kinds + 1))


def surprisal_bits(probability: float) -> float:
    if not 0.0 < probability <= 1.0:
        raise ValueError("a probability is in (0, 1]")
    return -math.log2(probability)


def good_turing_unseen(counts: Mapping[str, int]) -> float:
    """n1 / N: the probability mass of kinds not yet seen. 1.0 for an empty baseline."""
    total = sum(counts.values())
    if total == 0:
        return 1.0
    return sum(1 for n in counts.values() if n == 1) / total


def is_mature(counts: Mapping[str, int], threshold: float) -> bool:
    return good_turing_unseen(counts) < threshold


class Baseline:
    """Counts of event kinds per role, from a learning run or observe-mode counting."""

    def __init__(self, counts: Mapping[str, Mapping[str, int]] | None = None, alpha: float = 1.0):
        self.alpha = alpha
        self.counts: dict[str, Counter[str]] = {
            role: Counter(kinds) for role, kinds in (counts or {}).items()
        }

    def update(self, role: str, kind: str, n: int = 1) -> None:
        self.counts.setdefault(role, Counter())[kind] += n

    def total(self, role: str) -> int:
        return sum(self.counts.get(role, {}).values())

    def probability(self, role: str, kind: str) -> float:
        counts = self.counts.get(role, Counter())
        return laplace_probability(
            counts.get(kind, 0), sum(counts.values()), len(counts), self.alpha
        )

    def surprisal(self, role: str, kind: str) -> float:
        return surprisal_bits(self.probability(role, kind))

    def unseen(self, role: str) -> float:
        return good_turing_unseen(self.counts.get(role, {}))

    def mature(self, role: str, threshold: float) -> bool:
        return role in self.counts and is_mature(self.counts[role], threshold)

    def as_dict(self) -> dict[str, dict[str, int]]:
        return {role: dict(sorted(kinds.items())) for role, kinds in sorted(self.counts.items())}
