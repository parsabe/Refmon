from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from refmon.schemas import Label

T0 = datetime(2026, 10, 28, 10, 2, 15, tzinfo=UTC)


def label(**overrides) -> dict:
    data = {
        "label_id": "L-91",
        "origin": "external",
        "source_class": "inbound_request",
        "created": T0,
        "strength": 1.0,
    }
    data.update(overrides)
    return data


def test_label_defaults_to_non_persistent_without_parents():
    parsed = Label.model_validate(label())
    assert parsed.persistent is False
    assert parsed.parents == ()


@pytest.mark.parametrize("strength", [-0.1, 1.1])
def test_label_strength_must_be_in_unit_interval(strength):
    with pytest.raises(ValidationError):
        Label.model_validate(label(strength=strength))


def test_label_cannot_be_its_own_parent():
    with pytest.raises(ValidationError):
        Label.model_validate(label(parents=["L-91"]))


def test_label_origin_is_external_only():
    with pytest.raises(ValidationError):
        Label.model_validate(label(origin="internal"))


def test_label_round_trips_through_json():
    parsed = Label.model_validate(label(parents=["L-1", "L-2"], persistent=True))
    assert Label.model_validate_json(parsed.model_dump_json()) == parsed


def test_a_persistent_label_carries_contract_evidence():
    parsed = Label.model_validate(
        label(persistent=True, contract_evidence=["contract_external_exec"])
    )
    assert parsed.contract_evidence == ("contract_external_exec",)
    assert Label.model_validate_json(parsed.model_dump_json()) == parsed


def test_any_label_can_carry_contract_evidence():
    """v1.1 (A49): evidence is no longer limited to persistent labels; a label that has it does
    not decay (tests/test_v11.py)."""
    assert (
        Label.model_validate(label(contract_evidence=["contract_external_exec"])).persistent
        is False
    )
    assert Label.model_validate(label()).contract_evidence == ()
