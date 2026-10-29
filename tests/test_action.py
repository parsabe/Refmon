from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from refmon.schemas import (
    ALLOWED_TARGETS,
    UNDO_OPS,
    Action,
    ActionType,
    Target,
    TargetKind,
    UndoRecord,
)

T0 = datetime(2026, 10, 28, 10, 2, 15, tzinfo=UTC)
FP = "hmac:" + "ab" * 16


def action(type_="kill_process_tree", target=None, **overrides) -> dict:
    data = {
        "action_id": "a-1",
        "ts": T0,
        "type": type_,
        "target": target or {"kind": "process", "ref": "p-211"},
        "story_id": "st-1",
    }
    data.update(overrides)
    return data


def test_action_target_must_fit_the_action_type():
    Action.model_validate(action())
    Action.model_validate(action("quarantine_file", {"kind": "file", "ref": FP}))
    with pytest.raises(ValidationError):
        Action.model_validate(action("quarantine_file", {"kind": "process", "ref": "p-211"}))
    with pytest.raises(ValidationError):
        Action.model_validate(action("isolate_host", {"kind": "process", "ref": "p-211"}))


def test_files_and_persistence_items_are_named_by_fingerprint_only():
    with pytest.raises(ValidationError):
        Target(kind=TargetKind.FILE, ref="web_root")
    with pytest.raises(ValidationError):
        Target(kind=TargetKind.PROCESS, ref=FP)
    assert Target(kind=TargetKind.PERSISTENCE_ITEM, ref=FP).ref == FP


def test_undo_record_is_reversible_exactly_when_it_has_an_op():
    target = Target(kind=TargetKind.FILE, ref=FP)
    UndoRecord(action_id="a-1", target=target, op="release_quarantine", reversible=True)
    UndoRecord(action_id="a-1", target=target, op=None, reversible=False)
    with pytest.raises(ValidationError):
        UndoRecord(action_id="a-1", target=target, op=None, reversible=True)
    with pytest.raises(ValidationError):
        UndoRecord(action_id="a-1", target=target, op="release_quarantine", reversible=False)


def test_every_action_type_has_an_undo_policy_and_a_target_kind():
    assert set(ActionType) == set(UNDO_OPS) == set(ALLOWED_TARGETS)


def test_action_round_trips_through_json():
    parsed = Action.model_validate(action("quarantine_file", {"kind": "file", "ref": FP}))
    assert Action.model_validate_json(parsed.model_dump_json()) == parsed
