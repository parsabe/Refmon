from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from refmon.schemas import Verdict

T0 = datetime(2026, 10, 28, 10, 2, 15, tzinfo=UTC)


def question(failed: bool, strength: float = 0.0) -> dict:
    return {"failed": failed, "strength": strength}


def verdict(**overrides) -> dict:
    data = {
        "verdict_id": "v-1",
        "story_id": "st-1",
        "device": "dev-7f3a",
        "ts": T0,
        "mode": "observe",
        "decision": "block",
        "origin": question(True, 1.0),
        "contract": question(True, 1.0),
        "effect": question(True, 1.0),
    }
    data.update(overrides)
    return data


def contribution(question_: str, signal: str, weight: float, strength: float = 1.0) -> dict:
    return {
        "question": question_,
        "signal": signal,
        "weight": weight,
        "strength": strength,
        "nats": weight * strength,
    }


def test_fail_count():
    assert Verdict.model_validate(verdict()).fail_count == 3
    two = Verdict.model_validate(verdict(effect=question(False), decision="hold"))
    assert two.fail_count == 2


def test_overrides_force_their_decision():
    Verdict.model_validate(verdict(override="canary"))
    Verdict.model_validate(verdict(override="protected_asset"))
    Verdict.model_validate(
        verdict(override="trusted_root", decision="allow", origin=question(False))
    )
    with pytest.raises(ValidationError):
        Verdict.model_validate(verdict(override="canary", decision="allow"))
    with pytest.raises(ValidationError):
        Verdict.model_validate(verdict(override="trusted_root", decision="block"))


def test_contributions_must_sum_to_log_odds():
    # C11 worked check for S01: prior -6.91 + 0.8 + 1.0 + max(2.5, 2.0) = -2.61
    prior = -6.91
    parts = [
        contribution("origin", "origin_external", 0.8),
        contribution("contract", "contract_external_exec", 1.0),
        contribution("effect", "effect_fetch", 2.5),
        contribution("effect", "effect_hide", 2.0) | {"counted": False},
    ]
    good = verdict(prior_log_odds=prior, log_odds=prior + 4.3, contributions=parts)
    assert Verdict.model_validate(good).log_odds == pytest.approx(-2.61)
    with pytest.raises(ValidationError):
        Verdict.model_validate(verdict(prior_log_odds=prior, log_odds=-2.0, contributions=parts))


def test_only_one_counted_contribution_per_question():
    parts = [
        contribution("effect", "effect_fetch", 2.5),
        contribution("effect", "effect_hide", 2.0),
    ]
    with pytest.raises(ValidationError):
        Verdict.model_validate(verdict(prior_log_odds=0.0, log_odds=4.5, contributions=parts))


def test_contribution_nats_must_be_weight_times_strength():
    bad = contribution("origin", "origin_external", 0.8, 0.5) | {"nats": 0.8}
    with pytest.raises(ValidationError):
        Verdict.model_validate(verdict(prior_log_odds=0.0, log_odds=0.8, contributions=[bad]))


def test_evidence_fields_go_together():
    with pytest.raises(ValidationError):
        Verdict.model_validate(verdict(log_odds=-2.0))  # no prior
    with pytest.raises(ValidationError):
        Verdict.model_validate(verdict(prior_log_odds=-6.9))  # no log_odds
    with pytest.raises(ValidationError):
        Verdict.model_validate(verdict(contributions=[contribution("origin", "o", 1.0)]))


def test_verdict_round_trips_through_json():
    parsed = Verdict.model_validate(verdict(effects=["fetch", "hide"], summary="Blocked."))
    assert Verdict.model_validate_json(parsed.model_dump_json()) == parsed


def test_tampering_with_refmon_itself_is_an_override_block():
    Verdict.model_validate(verdict(override="self_tamper"))
    with pytest.raises(ValidationError):
        Verdict.model_validate(verdict(override="self_tamper", decision="hold"))


def gated(**overrides) -> dict:
    """Block threshold crossed, no Contract signal: decision capped at hold (D13)."""
    return (
        verdict(
            decision="hold",
            contract=question(False),
            threshold_crossed="block",
            contract_gate=True,
        )
        | overrides
    )


def test_contract_gate_records_a_block_capped_at_hold():
    assert Verdict.model_validate(gated()).contract_gate is True
    assert Verdict.model_validate(verdict()).contract_gate is False


@pytest.mark.parametrize(
    "bad",
    [
        {"decision": "block"},  # a capped verdict cannot also be a block
        {"threshold_crossed": "hold"},  # the gate only caps a crossed block threshold
        {"threshold_crossed": None},
        {"contract": question(True, 1.0)},  # there was a Contract signal, so no gate
        {"override": "canary", "decision": "block"},  # overrides are never gated
    ],
)
def test_contract_gate_needs_its_preconditions(bad):
    with pytest.raises(ValidationError):
        Verdict.model_validate(gated(**bad))
