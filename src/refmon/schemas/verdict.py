"""Verdict schema: the outcome of judging one story, with everything needed to explain it.

Carries both the classic fail count (human-readable explanation, fallback when no weights are
configured) and the evidence-calculus breakdown from C11 (contributions, log-odds, threshold).
"""

import math
from typing import Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from .common import ATTACK_TACTICS, Decision, Effect, Identifier, Mode, Override, Question

_TOLERANCE = 1e-9


class QuestionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    failed: bool
    strength: float = Field(default=0.0, ge=0.0, le=1.0)
    reasons: tuple[Identifier, ...] = ()


class Contribution(BaseModel):
    """One signal's share of the log-odds: weight x strength, in nats (C11.4)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    question: Question
    signal: Identifier
    weight: float
    strength: float = Field(ge=0.0, le=1.0)
    nats: float
    # Within a question only the strongest signal counts; the others may be listed for
    # transparency but do not enter the sum.
    counted: bool = True

    @model_validator(mode="after")
    def _nats_is_weight_times_strength(self) -> Self:
        if not math.isclose(self.nats, self.weight * self.strength, abs_tol=_TOLERANCE):
            raise ValueError("nats must equal weight x strength")
        return self


class Verdict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    verdict_id: Identifier
    story_id: Identifier
    device: Identifier
    ts: AwareDatetime
    mode: Mode
    decision: Decision
    # What the plain 3/2/1 fail rule (or an override) gives for the same story (design decision D1).
    rule_decision: Decision | None = None
    origin: QuestionResult
    contract: QuestionResult
    effect: QuestionResult
    effects: tuple[Effect, ...] = ()
    override: Override | None = None
    summary: str = Field(default="", max_length=1000)
    tactics: tuple[str, ...] = ()  # MITRE ATT&CK Enterprise tactic names
    users: tuple[Identifier, ...] = ()  # who was involved; pseudonyms once the verdict leaves
    # Extra protection (virtual patching) that applied to this story: component:advisory.
    virtual_patch: tuple[Identifier, ...] = ()
    prior_log_odds: float | None = None
    log_odds: float | None = None
    contributions: tuple[Contribution, ...] = ()
    threshold_crossed: Literal["block", "hold"] | None = None
    # Block threshold crossed, but no Contract signal and no override: capped at hold
    # (docs/design-decisions.md, D13).
    contract_gate: bool = False

    @property
    def fail_count(self) -> int:
        return sum(q.failed for q in (self.origin, self.contract, self.effect))

    @model_validator(mode="after")
    def _tactics_are_attack_names(self) -> Self:
        unknown = [t for t in self.tactics if t not in ATTACK_TACTICS]
        if unknown:
            raise ValueError(f"not MITRE ATT&CK Enterprise tactic names: {unknown}")
        return self

    @model_validator(mode="after")
    def _override_fixes_decision(self) -> Self:
        forced = {
            Override.CANARY: Decision.BLOCK,
            Override.PROTECTED_ASSET: Decision.BLOCK,
            Override.SELF_TAMPER: Decision.BLOCK,
            Override.TRUSTED_ROOT: Decision.ALLOW,
        }
        if self.override is not None and self.decision != forced[self.override]:
            raise ValueError(f"override {self.override} forces decision {forced[self.override]}")
        return self

    @model_validator(mode="after")
    def _contract_gate_caps_block_at_hold(self) -> Self:
        if not self.contract_gate:
            return self
        if self.override is not None:
            raise ValueError("the contract gate does not apply to an override")
        if self.threshold_crossed != "block" or self.decision != Decision.HOLD:
            raise ValueError("contract_gate means the block threshold was crossed and hold applied")
        if self.contract.failed:
            raise ValueError("contract_gate means there was no Contract signal")
        return self

    @model_validator(mode="after")
    def _contributions_sum_to_log_odds(self) -> Self:
        if self.log_odds is None:
            if self.contributions or self.prior_log_odds is not None:
                raise ValueError("contributions and prior_log_odds require log_odds")
            return self
        if self.prior_log_odds is None:
            raise ValueError("log_odds requires prior_log_odds")
        counted = [c for c in self.contributions if c.counted]
        per_question = [c.question for c in counted]
        if len(per_question) != len(set(per_question)):
            raise ValueError("at most one counted contribution per question")
        total = self.prior_log_odds + sum(c.nats for c in counted)
        if not math.isclose(self.log_odds, total, abs_tol=_TOLERANCE):
            raise ValueError("log_odds must equal prior_log_odds plus the counted contributions")
        return self
