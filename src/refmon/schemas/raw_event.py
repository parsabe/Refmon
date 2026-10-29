"""RawEvent: what a sensor hands to Observe (docs/design-decisions.md, D5).

It may carry the content itself (`object.content`) and free-text attribute values such as a
domain. That is allowed only in memory and in lab fixtures made of harmless stand-ins. Observe
turns it into an `Event`; nothing that is stored, recorded or sent off the device is a RawEvent.
"""

from typing import Annotated, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .common import Fingerprint, Identifier
from .event import EventBase, check_attr_values

RawAttrValue = (
    bool
    | int
    | Annotated[float, Field(allow_inf_nan=False)]
    | Annotated[str, StringConstraints(max_length=256)]
)

MAX_CONTENT_CHARS = 65536


class RawObjectRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    class_: Identifier = Field(alias="class")
    content: str | None = Field(default=None, max_length=MAX_CONTENT_CHARS)
    fingerprint: Fingerprint | None = None

    @model_validator(mode="after")
    def _content_or_fingerprint(self) -> Self:
        if self.content is not None and self.fingerprint is not None:
            raise ValueError("give content or fingerprint, not both")
        return self


class RawEvent(EventBase):
    object: RawObjectRef
    attrs: dict[Identifier, RawAttrValue] = Field(default_factory=dict)

    @field_validator("attrs")
    @classmethod
    def _source_class_is_known(cls, value: dict) -> dict:
        return check_attr_values(value)
