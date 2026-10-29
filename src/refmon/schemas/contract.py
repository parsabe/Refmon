"""Role contract schema (C4): what a role is allowed to do. Anything outside it is a Contract fail.

For each list field, `None` means "not constrained by this contract" and `[]` means "nothing is
allowed". `may_write` holds path-group names (the `paths:` wrapper in the C4 example is flattened).

Universal contract (design decision D19): four behaviours are forbidden for every role unless the
role's own contract allows them, so these fields default to False, not None. An allowed behaviour
raises neither a Contract signal nor its Effect signal.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationInfo, field_validator

from .common import Identifier, check_role


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    role: str
    may_exec: tuple[Identifier, ...] | None = None
    may_write: tuple[Identifier, ...] | None = None
    may_connect: tuple[Identifier, ...] | None = None
    may_read_assets: tuple[Identifier, ...] | None = None
    may_persist: bool | None = None
    may_change_privilege: bool | None = None
    external_content_exec: Literal["allow", "deny"] | None = None
    # Launcher contract (D20): start an executable or script that carries an external label and
    # has no valid code signature.
    unsigned_external_exec: Literal["allow", "deny"] | None = None
    # Universal contract (D19).
    may_tamper: bool = False  # stop security tools, alter or clear logs
    may_mass_change: bool = False  # many files changed beyond the Poisson threshold
    may_fan_out: bool = False  # connect to many internal hosts beyond the Poisson threshold
    may_repeat_large_responses: bool = False  # repeated response anomalies to one client

    @field_validator("role")
    @classmethod
    def _role_is_known(cls, value: str, info: ValidationInfo) -> str:
        return check_role(value, (info.context or {}).get("extra_roles", ()))
