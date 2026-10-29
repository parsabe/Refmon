from datetime import UTC, datetime

import pytest

from refmon.enforcer import SimulatedEnforcer
from refmon.schemas import UNDO_OPS, Action, ActionType, Target, TargetKind

T0 = datetime(2026, 10, 28, 10, 2, 15, tzinfo=UTC)
FP = "hmac:" + "ab" * 16

TARGETS = {
    TargetKind.PROCESS: Target(kind=TargetKind.PROCESS, ref="p-211"),
    TargetKind.FILE: Target(kind=TargetKind.FILE, ref=FP),
    TargetKind.PERSISTENCE_ITEM: Target(kind=TargetKind.PERSISTENCE_ITEM, ref=FP),
    TargetKind.HOST: Target(kind=TargetKind.HOST, ref="dev-7f3a"),
}


def make(action_type: ActionType, action_id: str = "a-1") -> Action:
    from refmon.schemas import ALLOWED_TARGETS

    return Action(
        action_id=action_id,
        ts=T0,
        type=action_type,
        target=TARGETS[ALLOWED_TARGETS[action_type]],
        story_id="st-1",
    )


def test_act_records_the_action_and_its_undo_record():
    enforcer = SimulatedEnforcer()
    action = make(ActionType.QUARANTINE_FILE)
    result = enforcer.act(action)
    assert result.ok
    assert result.detail == "applied"
    assert enforcer.actions == [action]
    assert result.undo == enforcer.undo_records["a-1"]
    assert result.undo.op == "release_quarantine"
    assert result.undo.target == action.target


@pytest.mark.parametrize("action_type", list(ActionType))
def test_undo_record_follows_the_undo_table(action_type):
    result = SimulatedEnforcer().act(make(action_type))
    assert result.undo.op == UNDO_OPS[action_type]
    assert result.undo.reversible == (UNDO_OPS[action_type] is not None)


def test_reversible_action_can_be_undone_once():
    enforcer = SimulatedEnforcer()
    enforcer.act(make(ActionType.CUT_NETWORK))
    assert enforcer.undo("a-1").ok
    assert enforcer.undone == ["a-1"]
    again = enforcer.undo("a-1")
    assert not again.ok
    assert again.detail == "already_undone"


def test_kill_cannot_be_undone():
    enforcer = SimulatedEnforcer()
    enforcer.act(make(ActionType.KILL_PROCESS_TREE))
    result = enforcer.undo("a-1")
    assert not result.ok
    assert result.detail == "not_reversible"
    assert enforcer.undone == []


def test_unknown_action_cannot_be_undone():
    result = SimulatedEnforcer().undo("a-404")
    assert not result.ok
    assert result.detail == "unknown_action_id"


def test_duplicate_action_id_is_refused_and_not_recorded_twice():
    enforcer = SimulatedEnforcer()
    enforcer.act(make(ActionType.HOLD))
    second = enforcer.act(make(ActionType.KILL_PROCESS_TREE))
    assert not second.ok
    assert second.detail == "duplicate_action_id"
    assert len(enforcer.actions) == 1
    assert enforcer.undo_records["a-1"].op == "release_hold"
