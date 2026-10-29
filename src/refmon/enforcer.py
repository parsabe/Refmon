"""SimulatedEnforcer: records Actions with undo records, for tests and replay.

Without a world it only records what was asked and what could be reversed. With a `SimWorld`
(Phase 3) it also applies each action to the modelled processes, files and persistence items, so
that tests can check what a block touched and that `undo` restores the prior state.
"""

from __future__ import annotations

from .schemas import UNDO_OPS, Action, ActionResult, UndoRecord
from .simworld import SimWorld


class SimulatedEnforcer:
    def __init__(self, world: SimWorld | None = None) -> None:
        self.world = world
        self.actions: list[Action] = []
        self.results: list[ActionResult] = []
        self.undo_records: dict[str, UndoRecord] = {}
        self.undone: list[str] = []
        self._actions_by_id: dict[str, Action] = {}
        self._prior: dict[str, object | None] = {}

    def act(self, action: Action) -> ActionResult:
        if action.action_id in self.undo_records:
            result = ActionResult(
                action_id=action.action_id, ok=False, detail="duplicate_action_id"
            )
            self.results.append(result)
            return result
        detail, prior = "applied", None
        if self.world is not None:
            detail, prior = self.world.apply(action)
        self.actions.append(action)
        self._actions_by_id[action.action_id] = action
        op = UNDO_OPS[action.type]
        if detail != "applied":
            record = UndoRecord(
                action_id=action.action_id, target=action.target, op=None, reversible=False
            )
            result = ActionResult(action_id=action.action_id, ok=False, detail=detail, undo=record)
        else:
            record = UndoRecord(
                action_id=action.action_id, target=action.target, op=op, reversible=op is not None
            )
            self._prior[action.action_id] = prior
            result = ActionResult(
                action_id=action.action_id, ok=True, detail="applied", undo=record
            )
        self.undo_records[action.action_id] = record
        self.results.append(result)
        return result

    def undo(self, action_id: str) -> ActionResult:
        record = self.undo_records.get(action_id)
        if record is None:
            detail = "unknown_action_id"
        elif not record.reversible:
            detail = "not_reversible"
        elif action_id in self.undone:
            detail = "already_undone"
        else:
            if self.world is not None:
                self.world.revert(self._actions_by_id[action_id], self._prior.get(action_id))
            self.undone.append(action_id)
            detail = "undone"
        result = ActionResult(action_id=action_id, ok=detail == "undone", detail=detail)
        self.results.append(result)
        return result
