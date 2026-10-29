"""Exposure stage (CLAUDE.md C5, Phase 5): which components are exposed, and virtual patching.

Input is a component inventory (name, version, role, exposed, plus runtimes that are easy to miss:
containers, runtimes bundled in desktop applications and appliances, decentrally run servers) and a
local advisory file (component, affected versions, severity, an optional verified workaround).
Advisories are read from files, never fetched. For each component the state is one of

    patched      no advisory affects the installed version
    mitigated    affected, but the advisory's workaround flag is verified active in the inventory
    exposed      affected, no verified workaround, and the component is reachable (exposed: true)
    end_of_life  no fix will ever come; always treated as exposed
    not_reachable  affected and unmitigated but not exposed (listed, never escalated)

For an exposed or end-of-life component the role it runs under is escalated, and only that role:
its contract rules switch to the policy's `escalate_mode` (block) and its outbound network is
restricted to the destinations its contract lists. This is virtual patching. It is derived from the
inventory and advisories every time they change, so it reverts by itself when the inventory shows a
fixed version, a verified workaround or a replacement. It only tightens: nothing is relaxed and no
policy file is changed. `ExposureManager.effective_policy` is the signed policy plus this overlay.

An escalation needs no approval by default (A44): it applies at once, the administrator is told
immediately, and it ends by itself. A role listed in the policy's `exposure.require_approval`
waits instead: the administrator is told that an approval is needed, and the overlay for that role
applies once `ExposureManager.approve` is called. A role that is already tightened is never
loosened by a policy edit.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import signing
from .policy import Policy, RuleSetting
from .rules import CONTRACT_RULE_IDS
from .schemas import AdminNotice
from .yamlio import read_document


class ExposureState(StrEnum):
    PATCHED = "patched"
    MITIGATED = "mitigated"
    EXPOSED = "exposed"
    END_OF_LIFE = "end_of_life"
    NOT_REACHABLE = "not_reachable"


ESCALATING = {ExposureState.EXPOSED, ExposureState.END_OF_LIFE}
_NAME = r"^[A-Za-z0-9_.:@-]{1,64}$"


class Component(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=_NAME)
    version: str
    role: str
    exposed: bool
    kind: Literal[
        "package", "service", "container", "bundled_runtime", "appliance", "decentral_server"
    ] = "package"
    host: str = Field(default="", pattern=r"^[A-Za-z0-9_.:@-]{0,64}$")
    end_of_life: bool = False
    flags: dict[str, bool] = Field(default_factory=dict)  # configuration flags a workaround needs


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    components: list[Component] = Field(default_factory=list)


class Workaround(BaseModel):
    model_config = ConfigDict(extra="forbid")

    flag: str
    value: bool = True


class Advisory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=_NAME)
    component: str
    affected: str = ""  # version constraints, e.g. ">=3.0,<3.1.4"; empty with end_of_life
    fixed_in: str | None = None
    severity: Literal["low", "medium", "high", "critical"] = "high"
    workaround: Workaround | None = None
    end_of_life: bool = False  # the affected versions will never be fixed


class Advisories(BaseModel):
    model_config = ConfigDict(extra="forbid")

    advisories: list[Advisory] = Field(default_factory=list)

    @field_validator("advisories")
    @classmethod
    def _unique_ids(cls, value: list[Advisory]) -> list[Advisory]:
        ids = [a.id for a in value]
        if len(ids) != len(set(ids)):
            raise ValueError("advisory ids must be unique")
        return value


# -- versions -------------------------------------------------------------------------------------


def parse_version(text: str) -> tuple[int, ...]:
    """'3.1.4' -> (3, 1, 4). Only the leading dotted integers count; '3.1.4-rc1' is 3.1.4."""
    match = re.match(r"^\s*v?(\d+(?:\.\d+)*)", text)
    if not match:
        raise ValueError(f"not a version: {text!r}")
    parts = [int(p) for p in match.group(1).split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()  # 3.1.0 == 3.1
    return tuple(parts)


_OPS = {
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "<=": lambda a, b: a <= b,
    ">=": lambda a, b: a >= b,
    "<": lambda a, b: a < b,
    ">": lambda a, b: a > b,
}


def satisfies(version: str, constraints: str) -> bool:
    """True when `version` meets every comma-separated constraint ('>=3.0,<3.1.4')."""
    have = parse_version(version)
    for part in constraints.split(","):
        part = part.strip()
        if not part:
            continue
        match = re.match(r"^(==|!=|<=|>=|<|>)\s*(.+)$", part)
        if not match:
            raise ValueError(f"bad version constraint: {part!r}")
        if not _OPS[match.group(1)](have, parse_version(match.group(2))):
            return False
    return True


# -- loading --------------------------------------------------------------------------------------


def _read(path: Path | str, trusted_keys: Iterable[str] | None) -> dict:
    document = read_document(path)
    if trusted_keys is not None and not signing.verify(document, list(trusted_keys)):
        raise ValueError(f"{Path(path).name} is not signed by a trusted key")
    return {k: v for k, v in document.items() if k != signing.SIGNATURE_FIELD}


def load_inventory(path: Path | str, trusted_keys: Iterable[str] | None = None) -> Inventory:
    return Inventory.model_validate(_read(path, trusted_keys))


def load_advisories(path: Path | str, trusted_keys: Iterable[str] | None = None) -> Advisories:
    return Advisories.model_validate(_read(path, trusted_keys))


# -- assessment -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class ComponentExposure:
    component: str
    version: str
    role: str
    kind: str
    state: ExposureState
    advisories: tuple[str, ...] = ()
    severity: str = ""

    @property
    def escalates(self) -> bool:
        return self.state in ESCALATING

    @property
    def reason(self) -> str:
        """Identifier-safe reason naming the component and the advisory (or end of life)."""
        why = self.advisories[0] if self.advisories else "end_of_life"
        return f"{self.component}:{why}"[:64]


@dataclass(frozen=True)
class Exposure:
    items: tuple[ComponentExposure, ...] = ()

    def by_state(self, state: ExposureState) -> list[ComponentExposure]:
        return [i for i in self.items if i.state is state]

    @property
    def escalated(self) -> dict[str, list[ComponentExposure]]:
        """role -> the components that put it under extra protection."""
        out: dict[str, list[ComponentExposure]] = {}
        for item in self.items:
            if item.escalates:
                out.setdefault(item.role, []).append(item)
        return out


_ORDER = [
    ExposureState.END_OF_LIFE,
    ExposureState.EXPOSED,
    ExposureState.NOT_REACHABLE,
    ExposureState.MITIGATED,
    ExposureState.PATCHED,
]


def assess(inventory: Inventory, advisories: Advisories) -> Exposure:
    items = []
    for comp in inventory.components:
        states: list[tuple[ExposureState, Advisory | None]] = []
        if comp.end_of_life:
            states.append((ExposureState.END_OF_LIFE, None))
        for adv in advisories.advisories:
            if adv.component != comp.name:
                continue
            if adv.end_of_life and (not adv.affected or satisfies(comp.version, adv.affected)):
                states.append((ExposureState.END_OF_LIFE, adv))
            elif adv.affected and satisfies(comp.version, adv.affected):
                fix = adv.workaround
                if fix is not None and comp.flags.get(fix.flag) is fix.value:
                    states.append((ExposureState.MITIGATED, adv))
                elif comp.exposed:
                    states.append((ExposureState.EXPOSED, adv))
                else:
                    states.append((ExposureState.NOT_REACHABLE, adv))
        state = next((s for s in _ORDER if any(x[0] is s for x in states)), ExposureState.PATCHED)
        matching = [a for s, a in states if s is state and a is not None]
        severity = max((a.severity for a in matching), key=_SEVERITY.index, default="")
        items.append(
            ComponentExposure(
                comp.name,
                comp.version,
                comp.role,
                comp.kind,
                state,
                tuple(a.id for a in matching),
                severity,
            )
        )
    return Exposure(tuple(items))


_SEVERITY = ["low", "medium", "high", "critical"]


# -- virtual patching -----------------------------------------------------------------------------


def overlay(base: Policy, exposure: Exposure, roles: Iterable[str] | None = None) -> Policy:
    """The signed policy plus extra protection for the escalated roles only (never relaxes).

    `roles` limits the overlay to those roles (the ones whose escalation applies; a role that waits
    for an approval is left out). By default every escalated role is included.
    """
    escalated = exposure.escalated
    if roles is not None:
        escalated = {r: items for r, items in escalated.items() if r in set(roles)}
    if not escalated:
        return base
    mode = base.exposure.escalate_mode
    rules = list(base.rules)
    for role, items in sorted(escalated.items()):
        reason = items[0].reason
        for rule_id in CONTRACT_RULE_IDS:
            rules.append(RuleSetting(id=rule_id, mode=mode, role=role, reason=reason))
    restricted = sorted({*base.restricted_network_roles, *escalated})
    return base.model_copy(update={"rules": rules, "restricted_network_roles": restricted})


@dataclass(frozen=True)
class ExposureChange:
    escalated: tuple[str, ...]  # roles newly under extra protection
    reverted: tuple[str, ...]  # roles back to normal
    pending: tuple[str, ...] = ()  # roles newly waiting for an administrator's approval


class ExposureManager:
    """Keeps the exposure list and the effective policy up to date as the inventory changes."""

    def __init__(self, base: Policy, notifier=None) -> None:
        self.base = base
        self.exposure = Exposure()
        self.effective_policy = base
        self.notifier = notifier  # anything with notify_admin(AdminNotice); None: nobody is told
        self.applied: set[str] = set()  # roles whose overlay is in force
        self.pending: set[str] = set()  # escalated roles waiting for an approval
        self.approved: dict[str, str] = {}  # role -> approver

    def update(
        self, inventory: Inventory, advisories: Advisories, now: datetime | None = None
    ) -> ExposureChange:
        self.exposure = assess(inventory, advisories)
        return self._refresh(now)

    def rebase(self, base: Policy, now: datetime | None = None) -> ExposureChange:
        """A new signed policy arrived: keep the overlay on top of it."""
        self.base = base
        return self._refresh(now)

    def approve(self, role: str, by: str, now: datetime | None = None) -> ExposureChange:
        """An administrator accepts the escalation of a role that waits for it."""
        if role not in self.pending:
            raise ValueError(f"role {role!r} has no escalation waiting for approval")
        self.approved[role] = by
        return self._refresh(now)

    def _refresh(self, now: datetime | None) -> ExposureChange:
        wanted = set(self.exposure.escalated)
        need = set(self.base.exposure.require_approval)
        self.approved = {r: who for r, who in self.approved.items() if r in wanted}
        # A role that is already tightened stays tightened: a policy edit never loosens it.
        applied = {r for r in wanted if r not in need or r in self.approved or r in self.applied}
        pending = wanted - applied
        change = ExposureChange(
            tuple(sorted(applied - self.applied)),
            tuple(sorted(self.applied - applied)),
            tuple(sorted(pending - self.pending)),
        )
        self.applied, self.pending = applied, pending
        self.effective_policy = overlay(self.base, self.exposure, applied)
        self._tell(change, now or datetime.now(UTC))
        return change

    def _tell(self, change: ExposureChange, now: datetime) -> None:
        if self.notifier is None:
            return
        escalated = self.exposure.escalated

        def notice(kind: str, role: str, text: str) -> None:
            self.notifier.notify_admin(AdminNotice(kind=kind, role=role, text=text, ts=now))

        for role in change.pending:
            why = escalated[role][0].reason
            notice(
                "exposure_approval_needed", role,
                f"Role {role} runs an exposed component ({why}). Extra protection for it waits "
                "for your approval; until then it runs as before.",
            )  # fmt: skip
        for role in change.escalated:
            why = escalated[role][0].reason
            by = self.approved.get(role)
            tail = f" Approved by {by}." if by else ""
            notice(
                "exposure_escalated", role,
                f"Extra protection is on for role {role} because of {why}. It only tightens and "
                f"ends by itself when the component is fixed or replaced.{tail}",
            )  # fmt: skip
        for role in change.reverted:
            notice(
                "exposure_reverted", role,
                f"Extra protection for role {role} ended: nothing exposed runs under it any more.",
            )  # fmt: skip
