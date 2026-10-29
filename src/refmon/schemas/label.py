"""Label schema (C3): provenance carried by processes, files and persistence items."""

from typing import Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from .common import Identifier, Origin, SourceClass


class Label(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    label_id: Identifier
    origin: Origin
    source_class: SourceClass
    created: AwareDatetime
    strength: float = Field(ge=0.0, le=1.0)
    parents: tuple[Identifier, ...] = ()
    persistent: bool = False
    # Contract signals present in the story that created this persistent item. When the item runs
    # later, they apply to the new story (design decision D21). v1.1 (A49): any label can carry
    # evidence, and a label that carries it does not decay.
    contract_evidence: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def _no_self_parent(self) -> Self:
        if self.label_id in self.parents:
            raise ValueError("a label cannot be its own parent")
        return self
