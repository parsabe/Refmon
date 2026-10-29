"""Rule packs (CLAUDE.md C6, Phase 2 and Phase 6): versioned, signed bundles of rules and contracts.

A pack is a YAML document with a detached signature, like the policy. The policy pins the packs it
uses by name, version and signature (`rule_packs`). Loading verifies the signature, then merges the
pack into the policy data.

Loading a pack never weakens what the policy already enforces without approval. A pack may add
roles, contracts and rule settings, and may tighten what exists. A change that loosens it (a rule
setting in a lower mode or switched off, a contract that allows more: a longer allow-list, a lifted
restriction, an allowance that was off) is a *weakening*; it is rejected (`PackWeakens`) unless the
signed policy carries a `pack_approvals` entry for that pack and version that accepts it. A pack
older than the one already loaded is a downgrade and is refused by `PolicyStore`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import signing
from .policy import RuleSetting
from .schemas import Contract, Mode
from .yamlio import read_document

_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


class PackRejected(ValueError):
    """A pack that cannot be loaded. `code` says why: unsigned, bad_signature, invalid, ..."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class PackConflict(PackRejected):
    def __init__(self, message: str) -> None:
        super().__init__("conflict", message)


class PackWeakens(PackRejected):
    def __init__(self, ids: list[str]) -> None:
        super().__init__("weakens", "would weaken the policy without approval: " + ", ".join(ids))
        self.ids = ids


def version_key(version: str) -> tuple[int, int, int]:
    match = _VERSION.match(version)
    if not match:
        raise ValueError(f"a pack version looks like 2.0.0, not {version!r}")
    return int(match[1]), int(match[2]), int(match[3])


class RulePack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    version: str
    publisher: str = ""
    extra_roles: list[str] = Field(default_factory=list)
    rules: list[RuleSetting] = Field(default_factory=list)
    contracts: dict[str, dict[str, Any]] = Field(default_factory=dict)
    signature: str = ""

    @field_validator("version")
    @classmethod
    def _semver(cls, value: str) -> str:
        version_key(value)
        return value

    @field_validator("contracts")
    @classmethod
    def _contracts_are_contracts(cls, value: dict) -> dict:
        return value  # checked against the real role list when merged


def read_pack(path: Path | str, trusted_keys: Iterable[str]) -> RulePack:
    """Read a pack file and verify its signature. Raises PackRejected."""
    try:
        document = read_document(path)
    except (OSError, ValueError, yaml.YAMLError) as error:
        raise PackRejected("unreadable", f"{path}: {error}") from error
    if not document.get(signing.SIGNATURE_FIELD):
        raise PackRejected("unsigned", f"rule pack {Path(path).name} has no signature")
    if not signing.verify(document, trusted_keys):
        raise PackRejected("bad_signature", f"rule pack {Path(path).name} fails verification")
    try:
        return RulePack.model_validate(document)
    except ValueError as error:
        raise PackRejected("invalid", f"rule pack {Path(path).name}: {error}") from error


_RANK = {Mode.OBSERVE: 0, Mode.WARN: 1, Mode.BLOCK: 2}
_LIST_FIELDS = ("may_exec", "may_write", "may_connect", "may_read_assets")
_UNIVERSAL = ("may_tamper", "may_mass_change", "may_fan_out", "may_repeat_large_responses")
# False restricts, None leaves it open, True allows: a move to the right is a weakening. For
# persistence None and True behave the same (only False raises a Contract signal); for privilege
# True also removes the Effect, so it is weaker than None.
_TRISTATE = {
    "may_persist": {False: 0, None: 1, True: 1},
    "may_change_privilege": {False: 0, None: 1, True: 2},
}
_DENY = {"deny": 0, None: 1, "allow": 1}  # None and allow both leave the behaviour open


def weakenings(base: dict[str, Any], pack: RulePack) -> list[str]:
    """Ids of the changes in `pack` that would loosen what `base` (policy data) enforces."""
    from .policy import Policy  # local: policy imports nothing from here, but keep it lazy

    found: list[str] = []
    current = Policy.parse(base)
    for setting in pack.rules:
        scope = setting.role or "*"
        before = current.rule_mode(setting.id, setting.role)
        if _RANK[setting.mode] < _RANK[before]:
            found.append(f"rule:{setting.id}:{scope}:mode")
        if not setting.enabled and current.rule_enabled(setting.id, setting.role):
            found.append(f"rule:{setting.id}:{scope}:disabled")
    old_contracts = base.get("contracts", {})
    for role, new in pack.contracts.items():
        if role not in old_contracts:
            continue
        old = old_contracts[role]
        # a pack overlays the fields it names; the fields it leaves out keep the policy's value
        for name in _LIST_FIELDS:
            if name not in new:
                continue
            before, after = old.get(name), new[name]
            if before is None:
                continue  # already unconstrained
            if after is None or (set(after) - set(before)):
                found.append(f"contract:{role}:{name}")
        for name in ("may_persist", "may_change_privilege"):
            if name in new and _TRISTATE[name][new[name]] > _TRISTATE[name][old.get(name)]:
                found.append(f"contract:{role}:{name}")
        for name in _UNIVERSAL:
            if new.get(name, False) and not old.get(name, False):
                found.append(f"contract:{role}:{name}")
        for name in ("external_content_exec", "unsigned_external_exec"):
            if name in new and _DENY[new[name]] > _DENY[old.get(name)]:
                found.append(f"contract:{role}:{name}")
    return sorted(set(found))


def merge_pack(
    data: dict[str, Any], pack: RulePack, approved: Iterable[str] = ()
) -> dict[str, Any]:
    """Add the pack to policy data. Tightening and new things are merged; a weakening needs an
    approval (an id in `approved`), else `PackWeakens`."""
    unapproved = [w for w in weakenings(data, pack) if w not in set(approved)]
    if unapproved:
        raise PackWeakens(unapproved)
    merged = {**data}
    roles = list(merged.get("extra_roles", []))
    roles += [r for r in pack.extra_roles if r not in roles]
    merged["extra_roles"] = roles

    contracts = dict(merged.get("contracts", {}))
    for role, spec in pack.contracts.items():
        contracts[role] = {**contracts.get(role, {}), **spec}  # overlay on what the policy has
    merged["contracts"] = contracts

    rules = [dict(r) for r in merged.get("rules", [])]
    for setting in pack.rules:
        new = setting.model_dump(mode="json", exclude_defaults=False)
        index = next(
            (
                i
                for i, r in enumerate(rules)
                if r["id"] == new["id"] and r.get("role") == new["role"]
            ),
            None,
        )
        if index is None:
            rules.append(new)
        else:
            rules[index] = new
    merged["rules"] = rules

    try:  # the merged contracts must still be valid contracts for known roles
        for role, spec in contracts.items():
            Contract.model_validate({"role": role, **spec}, context={"extra_roles": tuple(roles)})
    except ValueError as error:
        raise PackRejected("invalid", f"pack {pack.name}: {error}") from error
    return merged
