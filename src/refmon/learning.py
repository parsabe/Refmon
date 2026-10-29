"""Contract learning mode (CLAUDE.md Phase 2, C4: "contracts can be generated in learning mode as
proposals and must be approved by a human").

For a configurable period (`policy.learning.period`) the learner only counts what each role
does. It judges nothing, emits no verdict and acts on nothing. At the end it writes a *proposal*:
for every role, the changes to its contract that would let what was observed pass. A proposal
changes nothing by itself. A human approves it (all of it, or chosen changes), `apply_proposal`
turns an approved proposal into new policy data, and that policy still has to be signed to load.

Changes that remove a restriction the current contract imposes (for example `external_content_exec:
deny` becomes `allow`) are marked `relax`. Approving "everything" does not include them; a human
has to ask for them. The counts per role and behaviour kind are kept in the proposal; Phase 4b uses
the same counts as the baseline for contract rarity and baseline maturity (C11.3).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .behaviour import behaviour_kind
from .pipeline.observe import Observe
from .pipeline.rates import CountedRates
from .pipeline.tag import Tagger
from .policy import Policy
from .schemas import Event, EventType, RawEvent

LIST_FIELDS = ("may_exec", "may_connect", "may_write", "may_read_assets")
BOOL_ALLOWANCES = {
    "persist": "may_persist",
    "priv_change": "may_change_privilege",
    "tamper": "may_tamper",
    "mass_change": "may_mass_change",
    "fan_out": "may_fan_out",
    "repeat_large_responses": "may_repeat_large_responses",
}


class Change(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    role: str
    field: str
    op: Literal["add", "set"]
    value: str | bool | None
    count: int  # how often the behaviour behind this change was observed
    relax: bool = False  # removes a restriction that the current contract imposes
    approved: bool = False


class RoleProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str
    events: int
    observed: dict[str, int]  # behaviour kind -> count
    new_contract: bool  # the role had no contract in the policy
    unseen_probability: float  # Good-Turing n1 / N: how likely the next event is a new kind
    changes: list[Change] = Field(default_factory=list)


class Approval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    by: str
    at: str


class ContractProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["proposed", "approved"] = "proposed"
    events: int
    first_event: str
    last_event: str
    period_seconds: float
    roles: dict[str, RoleProposal] = Field(default_factory=dict)
    approvals: list[Approval] = Field(default_factory=list)

    def changes(self) -> list[Change]:
        return [c for r in self.roles.values() for c in r.changes]


@dataclass
class _Counts:
    kinds: Counter[str] = field(default_factory=Counter)
    execs_external: int = 0
    unsigned_external: int = 0
    rich: Counter[str] = field(default_factory=Counter)  # allowance name -> count
    lists: dict[str, Counter[str]] = field(
        default_factory=lambda: {f: Counter() for f in LIST_FIELDS}
    )
    wrote_executable: int = 0

    @property
    def total(self) -> int:
        return sum(self.kinds.values())


class ContractLearner:
    """Counts what each role does during the learning period. Implements the Core protocol."""

    def __init__(self, policy: Policy, key: bytes = b"refmon-learning-key") -> None:
        self.policy = policy
        self._key = key
        self.observe = Observe(policy, key)
        self.tagger = Tagger(policy)
        self.rates = CountedRates(policy)
        self.roles: dict[str, _Counts] = {}
        self.events = 0
        self.first: datetime | None = None
        self.last: datetime | None = None
        self.skipped_after_period = 0

    def new_stream(self) -> None:
        """Start another recording with its own timeline; counts are kept, other state is reset."""
        self.observe = Observe(self.policy, self._key)
        self.tagger = Tagger(self.policy)
        self.rates = CountedRates(self.policy)
        self.first = None

    # -- the Core protocol: counts, produces nothing ----------------------------------------------

    def process(self, event: RawEvent | Event) -> list:
        self.learn(event)
        return []

    @property
    def active(self) -> bool:
        return True

    def in_period(self, ts: datetime) -> bool:
        return (
            self.first is None or (ts - self.first).total_seconds() <= self.policy.learning.period
        )

    def learn(self, event: RawEvent | Event) -> bool:
        """Count one event. False when the learning period is over (the event is ignored)."""
        ev = self.observe(event)
        if not self.in_period(ev.ts):
            self.skipped_after_period += 1
            return False
        if self.first is None:
            self.first = ev.ts
        self.last = ev.ts
        self.events += 1
        tg = self.tagger.process(ev)
        role = ev.actor.role
        counts = self.roles.setdefault(role, _Counts())
        counts.kinds[behaviour_kind(ev)] += 1
        self._behaviours(ev, tg, counts)
        return True

    def _behaviours(self, ev: Event, tg, counts: _Counts) -> None:
        attrs, typ, ts = ev.attrs, ev.type, ev.ts
        role = ev.actor.role
        thr = self.policy.thresholds.origin_strength
        a_strength = self.tagger.combined(tg.actor_labels, ts)
        o_strength = self.tagger.combined(tg.object_labels, ts)
        root = self.tagger.root_of(ev.actor.id)
        t = ts.timestamp()
        if typ is EventType.EXEC:
            counts.lists["may_exec"][attrs.get("exec_class", "unknown")] += 1
            if a_strength >= thr or o_strength >= thr:
                counts.execs_external += 1
            if o_strength >= thr and attrs.get("signed") is False:
                counts.unsigned_external += 1
        elif typ is EventType.NET_CONNECT:
            dest = attrs.get("destination_class", "unknown")
            counts.lists["may_connect"][dest] += 1
            d = self.policy.destination(dest)
            if (
                d is not None
                and d.internal
                and self.rates.lateral(root, role, t, ev.object.fingerprint)
            ):
                counts.rich["fan_out"] += 1
        elif typ is EventType.FILE_WRITE:
            if attrs.get("executable") is True:
                counts.wrote_executable += 1
            elif attrs.get("path_group"):
                counts.lists["may_write"][attrs["path_group"]] += 1
            if self.rates.mass_change(root, role, t, ev.object.fingerprint):
                counts.rich["mass_change"] += 1
        elif typ is EventType.ASSET_ACCESS:
            counts.lists["may_read_assets"][attrs.get("protected_asset") or ev.object.class_] += 1
        elif typ is EventType.PERSIST:
            counts.rich["persist"] += 1
        elif typ is EventType.PRIV_CHANGE:
            counts.rich["priv_change"] += 1
        elif typ is EventType.SECURITY_TAMPER:
            counts.rich["tamper"] += 1
        elif typ is EventType.RESPONSE_OUT:
            nbytes = attrs.get("bytes")
            if isinstance(nbytes, (int, float)):
                _, repeated = self.rates.response(
                    ev.object.fingerprint or ev.actor.id, role, t, float(nbytes)
                )
                if repeated:
                    counts.rich["repeat_large_responses"] += 1

    # -- the proposal ----------------------------------------------------------------------------

    def proposal(self) -> ContractProposal:
        skip = set(self.policy.learning.skip_roles)
        out: dict[str, RoleProposal] = {}
        serial = 0
        for role in sorted(self.roles):
            if role in skip:
                continue
            counts = self.roles[role]
            n1 = sum(1 for n in counts.kinds.values() if n == 1)
            existing = self.policy.contract_for(role)
            rp = RoleProposal(
                role=role,
                events=counts.total,
                observed=dict(sorted(counts.kinds.items())),
                new_contract=existing is None,
                unseen_probability=n1 / counts.total if counts.total else 1.0,
            )
            for change in self._changes(role, counts, existing):
                serial += 1
                rp.changes.append(change.model_copy(update={"id": f"c-{serial}"}))
            out[role] = rp
        return ContractProposal(
            events=self.events,
            first_event=self.first.isoformat() if self.first else "",
            last_event=self.last.isoformat() if self.last else "",
            period_seconds=self.policy.learning.period,
            roles=out,
        )

    def _changes(self, role: str, counts: _Counts, existing) -> list[Change]:
        found: list[Change] = []

        def add(field_: str, op: str, value, count: int, relax: bool = False) -> None:
            found.append(
                Change(id="", role=role, field=field_, op=op, value=value, count=count, relax=relax)
            )

        for field_ in LIST_FIELDS:
            observed = counts.lists[field_]
            current = getattr(existing, field_) if existing is not None else None
            if existing is None:
                if field_ == "may_write" and counts.wrote_executable:
                    continue  # a role that writes executables stays unconstrained for writes
                if not observed:
                    add(field_, "set", "[]", 0)  # observed to do nothing of this kind
                for value, n in sorted(observed.items()):
                    add(field_, "add", value, n)
            elif current is not None:
                if "any" in current:
                    continue
                for value, n in sorted(observed.items()):
                    if value not in current:
                        add(field_, "add", value, n)
        if existing is not None and existing.may_write is not None and counts.wrote_executable:
            add("may_write", "set", None, counts.wrote_executable, relax=True)

        for kind, field_ in BOOL_ALLOWANCES.items():
            seen = counts.rich[kind]
            current = getattr(existing, field_) if existing is not None else None
            if seen and current is not True:
                add(
                    field_,
                    "set",
                    True,
                    seen,
                    relax=current is False and field_ in ("may_persist", "may_change_privilege"),
                )
            elif (
                not seen and existing is None and field_ in ("may_persist", "may_change_privilege")
            ):
                add(field_, "set", False, 0)

        if (
            counts.execs_external
            and existing is not None
            and existing.external_content_exec == "deny"
        ):
            add("external_content_exec", "set", "allow", counts.execs_external, relax=True)
        if (
            counts.unsigned_external
            and existing is not None
            and existing.unsigned_external_exec == "deny"
        ):
            add("unsigned_external_exec", "set", "allow", counts.unsigned_external, relax=True)
        return found


# -- approval and application ---------------------------------------------------------------------


def approve(
    proposal: ContractProposal,
    approver: str,
    *,
    change_ids: set[str] | None = None,
    include_relax: bool = False,
    at: str = "",
) -> ContractProposal:
    """A human approves changes. With no `change_ids`, every change that does not relax a
    restriction is approved; relaxing changes need `include_relax=True` or to be named."""
    if not approver.strip():
        raise ValueError("an approval needs the name of the approving person")
    roles = {}
    for role, rp in proposal.roles.items():
        changes = []
        for c in rp.changes:
            named = change_ids is not None and c.id in change_ids
            default = change_ids is None and (include_relax or not c.relax)
            changes.append(c.model_copy(update={"approved": c.approved or named or default}))
        roles[role] = rp.model_copy(update={"changes": changes})
    approvals = [*proposal.approvals, Approval(by=approver, at=at)]
    return proposal.model_copy(
        update={"roles": roles, "approvals": approvals, "status": "approved"}
    )


def apply_proposal(policy_data: dict[str, Any], proposal: ContractProposal) -> dict[str, Any]:
    """New policy data with the approved changes applied. Unapproved changes are left out."""
    if proposal.status != "approved" or not proposal.approvals:
        raise PermissionError("only a proposal approved by a person can be applied")
    data = {**policy_data}
    contracts = {role: dict(spec) for role, spec in data.get("contracts", {}).items()}
    for change in proposal.changes():
        if not change.approved:
            continue
        spec = contracts.setdefault(change.role, {})
        if change.op == "add":
            values = spec.get(change.field)
            values = [] if values is None else list(values)
            if change.value not in values:
                values.append(change.value)
            spec[change.field] = values
        elif change.value == "[]":
            spec.setdefault(change.field, [])
        else:
            spec[change.field] = change.value
    data["contracts"] = contracts
    created = {
        rp.role
        for rp in proposal.roles.values()
        if rp.new_contract and any(c.approved for c in rp.changes)
    }
    if created:  # Phase 4b enforces a learned contract only once its baseline is mature
        data["learned_roles"] = sorted({*data.get("learned_roles", []), *created})
    return data


def write_proposal(proposal: ContractProposal, path: Path | str) -> None:
    text = yaml.safe_dump(proposal.model_dump(mode="json"), sort_keys=False)
    Path(path).write_text(text, encoding="utf-8")


def read_proposal(path: Path | str) -> ContractProposal:
    return ContractProposal.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
