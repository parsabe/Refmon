"""What the Gate says to people: a question to the user (endpoint hold), a notice to the admin
(server hold, a block, a timeout) or a warning (warn mode). Text is built from fixed phrases and
role/question names only, never from event content."""

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from .common import Identifier


class UserPrompt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hold_id: Identifier
    story_id: Identifier
    device: Identifier
    text: str = Field(max_length=800)
    # "continue" is not offered when all three questions failed (CLAUDE.md Phase 3).
    options: tuple[Literal["stop", "continue"], ...]
    deadline: AwareDatetime  # no answer by then means stop


class AdminNotice(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal[
        "hold",
        "blocked",
        "still_quarantined",
        "warning",
        "exposure_escalated",  # virtual patching switched on for a role (A44)
        "exposure_approval_needed",  # the role's policy flag asks for an approval first
        "exposure_reverted",
    ]
    hold_id: Identifier | None = None
    story_id: Identifier | None = None  # absent for notices that are not about one story
    device: Identifier | None = None
    role: Identifier | None = None  # exposure notices name the role they tighten
    text: str = Field(max_length=800)
    action_ids: tuple[Identifier, ...] = ()
    ts: AwareDatetime
