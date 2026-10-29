"""Story schema: a set of related events that is judged as one unit."""

from typing import Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from .common import Identifier


class Story(BaseModel):
    # Mutable: the Link stage appends to a story while it is open.
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    story_id: Identifier
    device: Identifier
    opened_at: AwareDatetime
    last_event_at: AwareDatetime
    event_ids: list[Identifier] = Field(default_factory=list)
    label_ids: list[Identifier] = Field(default_factory=list)
    process_ids: list[Identifier] = Field(default_factory=list)
    closed: bool = False

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.last_event_at < self.opened_at:
            raise ValueError("last_event_at is before opened_at")
        for name in ("event_ids", "label_ids", "process_ids"):
            values = getattr(self, name)
            if len(values) != len(set(values)):
                raise ValueError(f"{name} contains duplicates")
        return self
