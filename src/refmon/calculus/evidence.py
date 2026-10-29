"""Evidence combination and cost-based thresholds (CLAUDE.md C11.4, C11.5).

    L = ln(pi / (1 - pi)) + sum over questions q of max over signals j in q of (w_j * s_j)

Within a question only the strongest signal counts (correlated signals); across the three
questions the evidence adds. Block when L >= ln(C_false_block / C_missed); hold when
L >= ln(C_hold / (h * C_missed)). Overrides bypass the thresholds. The contract gate caps a block at
hold when the story has no Contract signal. Everything here is a pure function of its arguments.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from ..schemas import Contribution, Decision, Question


def prior_log_odds(prior: float) -> float:
    if not 0.0 < prior < 1.0:
        raise ValueError("the prior attack rate is in (0, 1)")
    return math.log(prior / (1.0 - prior))


def block_threshold(costs: Mapping[str, float]) -> float:
    return math.log(costs["false_block"] / costs["missed_attack"])


def hold_threshold(costs: Mapping[str, float], catch_rate: float) -> float:
    return math.log(costs["hold"] / (catch_rate * costs["missed_attack"]))


@dataclass(frozen=True)
class Evidence:
    question: str  # origin | contract | effect
    signal: str
    strength: float


def contributions(
    evidence: Iterable[Evidence], weights: Mapping[str, float]
) -> tuple[Contribution, ...]:
    """Every signal as a contribution (weight x strength, in nats); per question only the
    largest is `counted`. Ties go to the earlier signal name, so the result is deterministic."""
    listed = [
        Contribution(
            question=Question(e.question), signal=e.signal, weight=weights.get(e.signal, 0.0),
            strength=min(1.0, max(0.0, e.strength)),
            nats=weights.get(e.signal, 0.0) * min(1.0, max(0.0, e.strength)),
            counted=False,
        )
        for e in sorted(evidence, key=lambda e: (e.question, e.signal))
    ]  # fmt: skip
    best: dict[str, int] = {}
    for index, c in enumerate(listed):
        if c.question.value not in best or c.nats > listed[best[c.question.value]].nats:
            best[c.question.value] = index
    chosen = set(best.values())
    return tuple(c.model_copy(update={"counted": i in chosen}) for i, c in enumerate(listed))


def log_odds(prior: float, contribs: Iterable[Contribution]) -> float:
    return prior_log_odds(prior) + sum(c.nats for c in contribs if c.counted)


@dataclass(frozen=True)
class Outcome:
    decision: Decision
    crossed: str | None  # "block" | "hold" | None
    gated: bool  # the block threshold was crossed but there was no Contract signal


def decide(
    log_odds_: float,
    block_at: float,
    hold_at: float,
    *,
    has_contract_signal: bool,
    override: Decision | None = None,
) -> Outcome:
    if override is not None:
        return Outcome(override, None, False)
    if log_odds_ >= block_at:
        if has_contract_signal:
            return Outcome(Decision.BLOCK, "block", False)
        return Outcome(Decision.HOLD, "block", True)  # the contract gate (D13)
    if log_odds_ >= hold_at:
        return Outcome(Decision.HOLD, "hold", False)
    return Outcome(Decision.ALLOW, None, False)


def reestimate_weights(
    attack_stories: Iterable[Iterable[str]], benign_stories: Iterable[Iterable[str]]
) -> dict[str, float]:
    """Re-estimate w_j = ln(P(j | attack) / P(j | benign)) from labeled stories, each given as the
    set of signal names it showed, with Laplace smoothing (add one to both counts of a signal)."""
    attacks = [set(s) for s in attack_stories]
    benigns = [set(s) for s in benign_stories]
    names = set().union(*attacks, *benigns) if attacks or benigns else set()
    weights = {}
    for name in sorted(names):
        a = sum(name in s for s in attacks)
        b = sum(name in s for s in benigns)
        p_attack = (a + 1) / (len(attacks) + 2)
        p_benign = (b + 1) / (len(benigns) + 2)
        weights[name] = math.log(p_attack / p_benign)
    return weights
