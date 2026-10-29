"""Event schemas (C2): the normalized unit every sensor and replay file produces.

There are two forms (docs/design-decisions.md, D5):
- `RawEvent` (raw_event.py): what a sensor emits to Observe. May carry content, in memory only.
- `Event`: what Observe emits. Fingerprints only. The only form that is stored or recorded.

Conventions:
- `exec`: `actor` is the process that spawns; the spawned process shows up in later events
  with `actor.parent` set to the spawner.
- `object.fingerprint` is the HMAC of the content (command, request body, file, ...). Events carry
  no raw content; `attrs` holds only short identifiers, numbers and flags.
"""

from datetime import UTC
from typing import Annotated, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
)

from .common import EVENT_ATTR_KEYS, EventType, Fingerprint, Identifier, SourceClass, check_role

AttrValue = bool | int | Annotated[float, Field(allow_inf_nan=False)] | Identifier


class Actor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: Identifier
    parent: Identifier | None = None
    role: str
    interactive: bool
    user: Identifier

    @field_validator("role")
    @classmethod
    def _role_is_known(cls, value: str, info: ValidationInfo) -> str:
        return check_role(value, (info.context or {}).get("extra_roles", ()))


def check_attr_values(attrs: dict) -> dict:
    """Value checks for the attributes whose values come from a fixed set."""
    source_class = attrs.get("source_class")
    if source_class is not None and source_class not in set(SourceClass):
        raise ValueError(f"unknown source_class: {source_class!r}")
    if "signed" in attrs:
        # Three-valued: true, false, or "unknown" when the sensor cannot check signatures.
        # Missing information never generates evidence (CLAUDE.md Part A), so "unknown" is a value
        # of its own and is never coerced to false. 1 and 0 are not accepted as booleans.
        signed = attrs["signed"]
        if not (isinstance(signed, bool) or signed == "unknown"):
            raise ValueError(f"signed must be true, false or 'unknown', not {signed!r}")
    return attrs


class EventBase(BaseModel):
    """Fields and behaviour shared by the raw and the observed form."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: Identifier
    ts: AwareDatetime
    device: Identifier
    type: EventType
    actor: Actor

    @field_validator("ts")
    @classmethod
    def _to_utc(cls, value):
        return value.astimezone(UTC)

    def to_json_line(self) -> str:
        return self.model_dump_json(by_alias=True, exclude_none=True)

    @classmethod
    def from_json_line(cls, line: str, *, extra_roles: tuple[str, ...] = ()) -> Self:
        return cls.model_validate_json(line, context={"extra_roles": extra_roles})


class ObjectRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    class_: Identifier = Field(alias="class")
    fingerprint: Fingerprint | None = None


class Event(EventBase):
    object: ObjectRef
    attrs: dict[Identifier, AttrValue] = Field(default_factory=dict)

    @field_validator("attrs")
    @classmethod
    def _attrs_are_on_the_allowlist(cls, value: dict) -> dict:
        unknown = sorted(value.keys() - EVENT_ATTR_KEYS)
        if unknown:
            raise ValueError(f"attribute keys not on the allowlist: {unknown}")
        return check_attr_values(value)
