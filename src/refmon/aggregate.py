"""What a fleet dashboard may see (CLAUDE.md C11.8): counts per ATT&CK tactic, in devices.

Each device contributes at most one to a tactic (sensitivity 1), the count gets Laplace noise with
epsilon from the policy, and a tactic seen on fewer than `k_anonymity` devices is left out before
any noise is added, so a small group never shows up at all.
"""

from __future__ import annotations

import random
from collections import defaultdict
from collections.abc import Iterable

from .calculus.privacy import noisy_count, suppress_small_groups
from .policy import Policy
from .schemas import Verdict


def devices_per_tactic(verdicts: Iterable[Verdict]) -> dict[str, int]:
    seen: dict[str, set[str]] = defaultdict(set)
    for v in verdicts:
        for tactic in v.tactics:
            seen[tactic].add(v.device)
    return {tactic: len(devices) for tactic, devices in seen.items()}


def dashboard(verdicts: Iterable[Verdict], policy: Policy, rng: random.Random) -> dict[str, float]:
    visible = suppress_small_groups(devices_per_tactic(verdicts), policy.math.k_anonymity)
    return {
        tactic: noisy_count(count, policy.math.dp_epsilon, rng)
        for tactic, count in sorted(visible.items())
    }
