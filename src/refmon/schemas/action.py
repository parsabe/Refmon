"""Action schema: what the Enforcer is asked to do, plus the undo record kept for each action."""

from enum import StrEnum
from typing import Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, model_validator

from .common import Fingerprint, Identifier


class ActionType(StrEnum):
    HOLD = "hold"
    BLOCK = "block"
    KILL_PROCESS_TREE = "kill_process_tree"
    CUT_NETWORK = "cut_network"
    QUARANTINE_FILE = "quarantine_file"
    REVERT_PERSISTENCE = "revert_persistence"
    RESTORE_FILE = "restore_file"
    ISOLATE_HOST = "isolate_host"


class TargetKind(StrEnum):
    PROCESS = "process"
    FILE = "file"
    PERSISTENCE_ITEM = "persistence_item"
    HOST = "host"


class UndoOp(StrEnum):
    RELEASE_HOLD = "release_hold"
    RESTORE_NETWORK = "restore_network"
    RELEASE_QUARANTINE = "release_quarantine"
    REINSTATE_PERSISTENCE = "reinstate_persistence"
    RESTORE_PRIOR_STATE = "restore_prior_state"
    LIFT_ISOLATION = "lift_isolation"


ALLOWED_TARGETS: dict[ActionType, TargetKind] = {
    ActionType.HOLD: TargetKind.PROCESS,
    ActionType.BLOCK: TargetKind.PROCESS,
    ActionType.KILL_PROCESS_TREE: TargetKind.PROCESS,
    ActionType.CUT_NETWORK: TargetKind.PROCESS,
    ActionType.QUARANTINE_FILE: TargetKind.FILE,
    ActionType.REVERT_PERSISTENCE: TargetKind.PERSISTENCE_ITEM,
    ActionType.RESTORE_FILE: TargetKind.FILE,
    ActionType.ISOLATE_HOST: TargetKind.HOST,
}

# What undoes each action. None = cannot be undone (a killed process stays killed; a blocked
# operation never happened).
UNDO_OPS: dict[ActionType, UndoOp | None] = {
    ActionType.HOLD: UndoOp.RELEASE_HOLD,
    ActionType.BLOCK: None,
    ActionType.KILL_PROCESS_TREE: None,
    ActionType.CUT_NETWORK: UndoOp.RESTORE_NETWORK,
    ActionType.QUARANTINE_FILE: UndoOp.RELEASE_QUARANTINE,
    ActionType.REVERT_PERSISTENCE: UndoOp.REINSTATE_PERSISTENCE,
    ActionType.RESTORE_FILE: UndoOp.RESTORE_PRIOR_STATE,
    ActionType.ISOLATE_HOST: UndoOp.LIFT_ISOLATION,
}


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: TargetKind
    # Processes and hosts are named by id. Files and persistence items are named by the fingerprint
    # of their path, so the core never holds a raw path; the platform adapter maps it back.
    ref: Identifier | Fingerprint

    @model_validator(mode="after")
    def _ref_matches_kind(self) -> Self:
        by_fingerprint = self.kind in (TargetKind.FILE, TargetKind.PERSISTENCE_ITEM)
        if by_fingerprint != self.ref.startswith("hmac:"):
            expected = "a fingerprint" if by_fingerprint else "an id"
            raise ValueError(f"{self.kind} targets are named by {expected}")
        return self


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: Identifier
    ts: AwareDatetime
    type: ActionType
    target: Target
    story_id: Identifier
    verdict_id: Identifier | None = None

    @model_validator(mode="after")
    def _target_fits_type(self) -> Self:
        expected = ALLOWED_TARGETS[self.type]
        if self.target.kind != expected:
            raise ValueError(f"{self.type} acts on a {expected}, not a {self.target.kind}")
        return self


class UndoRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: Identifier
    target: Target
    op: UndoOp | None
    reversible: bool

    @model_validator(mode="after")
    def _reversible_iff_op(self) -> Self:
        if self.reversible != (self.op is not None):
            raise ValueError("reversible must be true exactly when an undo op is given")
        return self


class ActionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: Identifier
    ok: bool
    detail: Identifier
    undo: UndoRecord | None = None
