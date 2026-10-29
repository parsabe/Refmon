"""Judge: the three questions and the overrides for one story (CLAUDE.md Part A).

Origin fails when the strongest label in the story is at least `origin_strength`. Contract fails on
any Contract signal, including those carried by persistent labels (D21). Effect fails on any Effect
signal. An Effect that a role's contract allows is ignored unless the story carries an external
origin label (D23). Overrides come first. `rule_decision` is the plain 3/2/1 rule; `decision` is
the evidence calculus (C11) when the policy uses it, else the same as the rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..calculus import evidence as calc
from ..policy import Policy
from ..rules import rule_id
from ..schemas import Contribution, Decision, Effect, Mode, Override
from .link import StoryRecord
from .signals import Signal
from .tag import Tagger

_OVERRIDE_ORDER = [
    ("self_tamper", Override.SELF_TAMPER),
    ("canary", Override.CANARY),
    ("protected_asset", Override.PROTECTED_ASSET),
]
_OVERRIDE_RULE = {
    Override.SELF_TAMPER: "OVR-SELF-TAMPER",
    Override.CANARY: "OVR-CANARY",
    Override.PROTECTED_ASSET: "OVR-PROTECTED-ASSET",
    Override.TRUSTED_ROOT: "OVR-TRUSTED-ROOT",
}
_FORCED = {
    Override.SELF_TAMPER: Decision.BLOCK,
    Override.CANARY: Decision.BLOCK,
    Override.PROTECTED_ASSET: Decision.BLOCK,
    Override.TRUSTED_ROOT: Decision.ALLOW,
}


@dataclass
class Judgement:
    story_id: str
    ts: object
    origin_strength: float
    signals: list[Signal]  # effective signals: allowed Effects dropped, carried evidence added
    failed: dict[str, bool]
    override: Override | None
    rule_decision: Decision
    effects: tuple[Effect, ...] = ()
    gated: bool = False
    mode: Mode = Mode.OBSERVE
    disabled_rules: tuple[str, ...] = ()
    protection_reasons: tuple[str, ...] = ()  # virtual patching that applied: component:advisory
    # filled by the evidence calculus (C11)
    decision: Decision = Decision.ALLOW
    log_odds: float | None = None
    prior_log_odds: float | None = None
    contributions: tuple[Contribution, ...] = ()
    threshold_crossed: str | None = None
    detail: dict = field(default_factory=dict)

    @property
    def fail_count(self) -> int:
        return sum(self.failed.values())


_MODE_RANK = {Mode.OBSERVE: 0, Mode.WARN: 1, Mode.BLOCK: 2}


def _actor_facts(event, policy: Policy) -> dict[str, str]:
    actor = event.actor
    return {
        "user": actor.user,
        "role": actor.role,
        "device": event.device,
        "group": policy.user_groups.get(actor.user, ""),
    }


def _effect_of(signal_name: str) -> Effect | None:
    base = signal_name.removeprefix("effect_").removesuffix("_repeated")
    try:
        return Effect(base)
    except ValueError:
        return None


def judge(rec: StoryRecord, tagger: Tagger, policy: Policy) -> Judgement:
    ts = rec.last_ts
    thr = policy.thresholds.origin_strength
    strengths = {i: tagger.strength(i, ts) for i in rec.label_ids}
    origin = max(strengths.values(), default=0.0)
    labeled = origin >= thr

    signals: list[Signal] = []
    for s in rec.signals:
        if s.allowed and not labeled:
            continue  # in role and nothing external behind it (D23)
        signals.append(s)
    for lid in sorted(rec.label_ids):  # D21: Contract evidence carried by persistent labels
        label = tagger.labels[lid]
        if (label.persistent or label.contract_evidence) and strengths[lid] >= thr:
            for name in label.contract_evidence:
                signals.append(Signal(name, strengths[lid], f"label:{lid}", carried=True))

    # protections the policy switched off (Phase 6); the self-test alerts only for enabled ones
    signals = [s for s in signals if policy.rule_enabled(rule_id(s.name), s.role or None)]
    labeled = labeled and policy.rule_enabled("R-ORI-EXTERNAL")

    facts = [_actor_facts(e, policy) for e in rec.events]
    disabled = policy.disabled_rules(facts, ts.date())
    if disabled:  # exceptions switch rules off for the actors in scope until they expire
        signals = [s for s in signals if rule_id(s.name) not in disabled]
        labeled = labeled and "R-ORI-EXTERNAL" not in disabled

    override = None
    for flag, ov in _OVERRIDE_ORDER:
        if flag in rec.flags and policy.rule_enabled(_OVERRIDE_RULE[ov]):
            override = ov
            break
    if (
        override is None
        and rec.trusted
        and not labeled
        and policy.rule_enabled(_OVERRIDE_RULE[Override.TRUSTED_ROOT])
    ):
        override = Override.TRUSTED_ROOT

    failed = {
        "origin": labeled,
        "contract": any(s.question == "contract" for s in signals),
        "effect": any(s.question == "effect" for s in signals),
    }
    n = sum(failed.values())
    d = policy.decisions
    rule = (
        _FORCED[override]
        if override
        else (d.fails_3 if n >= 3 else d.fails_2 if n == 2 else d.fails_0_1)
    )
    effects = tuple(dict.fromkeys(e for s in signals if (e := _effect_of(s.name)) is not None))
    # The mode of a story is the strongest mode among the rules that fired; overrides and stories
    # without a firing rule use the global mode.
    modes = [policy.rule_mode(rule_id(s.name), s.role or None) for s in signals]
    if labeled:
        modes.append(policy.rule_mode("R-ORI-EXTERNAL"))
    mode = policy.mode if override or not modes else max(modes, key=_MODE_RANK.get)
    reasons = sorted(
        {
            setting.reason
            for s in signals
            if (setting := policy.rule_setting(rule_id(s.name), s.role or None)) is not None
            and setting.reason
        }
    )
    j = Judgement(
        rec.story.story_id, ts, origin, signals, failed, override, rule, effects,
        decision=rule, mode=mode, disabled_rules=tuple(sorted(disabled)),
        protection_reasons=tuple(reasons),
    )  # fmt: skip
    if policy.uses_calculus:
        _apply_calculus(j, policy, labeled)
    return j


def _apply_calculus(j: Judgement, policy: Policy, labeled: bool) -> None:
    """C11.4 and C11.5: contributions, log-odds, thresholds and the contract gate."""
    m = policy.math
    evidence = [calc.Evidence(s.question, s.name, s.strength) for s in j.signals]
    if labeled:
        evidence.append(calc.Evidence("origin", "origin_external", j.origin_strength))
    j.contributions = calc.contributions(evidence, m.weights)
    j.prior_log_odds = calc.prior_log_odds(m.prior_attack)
    j.log_odds = calc.log_odds(m.prior_attack, j.contributions)
    outcome = calc.decide(
        j.log_odds,
        calc.block_threshold(m.costs),
        calc.hold_threshold(m.costs, m.hold_catch_rate),
        has_contract_signal=j.failed["contract"],
        override=_FORCED[j.override] if j.override else None,
    )
    j.decision, j.threshold_crossed, j.gated = outcome.decision, outcome.crossed, outcome.gated
