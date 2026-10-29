"""The signed YAML policy loader (CLAUDE.md C6, Phase 2).

`load_policy` reads a policy file, verifies its detached signature against the trusted public
keys, resolves the rule packs the policy pins, validates the result and returns a `Policy`.
Anything that fails is rejected with a `PolicyRejected` whose `code` says why. `PolicyStore` wraps
the loader for a running pipeline: a failed reload keeps the last valid policy and records why.

Nothing here changes a policy by itself. A changed policy is written by a human who holds the key.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from . import signing
from .policy import Policy
from .rulepacks import PackRejected, RulePack, merge_pack, read_pack
from .yamlio import read_document, write_document

PACK_DIR = "packs"


class PolicyRejected(ValueError):
    """A policy that cannot be loaded; `code` says why (unsigned, bad_signature, pack_*, ...)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def write_signed(document: dict[str, Any], private_key: str, path: Path | str) -> dict[str, Any]:
    """Sign `document` and write it. Used by the humans who hold the key, never by the pipeline."""
    out = signing.signed(document, private_key)
    write_document(out, path)
    return out


@dataclass(frozen=True)
class LoadedPolicy:
    policy: Policy
    data: dict[str, Any]  # the merged, validated policy data (packs included)
    digest: str  # identifies exactly this policy and these packs
    packs: tuple[tuple[str, str], ...] = ()  # (name, version) of every pack merged
    pack_objects: tuple[RulePack, ...] = field(default=(), compare=False)


def load_policy_data(
    path: Path | str,
    trusted_keys: Iterable[str],
    *,
    pack_keys: Iterable[str] | None = None,
    pack_dir: Path | str | None = None,
) -> LoadedPolicy:
    path = Path(path)
    keys = tuple(trusted_keys)
    try:
        document = read_document(path)
    except (OSError, ValueError, yaml.YAMLError) as error:
        raise PolicyRejected("unreadable", f"{path.name}: {error}") from error
    if not document.get(signing.SIGNATURE_FIELD):
        raise PolicyRejected("unsigned", f"{path.name} has no signature")
    if not signing.verify(document, keys):
        raise PolicyRejected("bad_signature", f"{path.name} fails signature verification")

    body = {k: v for k, v in document.items() if k != signing.SIGNATURE_FIELD}
    directory = Path(pack_dir) if pack_dir else path.parent / PACK_DIR
    publisher_keys = tuple(pack_keys) if pack_keys is not None else keys
    merged, used, objects = body, [], []
    for ref in body.get("rule_packs", []):
        name, version = str(ref.get("name")), str(ref.get("version"))
        try:
            pack = read_pack(directory / f"{name}-{version}.yaml", publisher_keys)
            if (pack.name, pack.version) != (name, version):
                raise PackRejected("mismatch", f"file holds {pack.name} {pack.version}")
            if pack.signature != ref.get("signature"):
                raise PackRejected("mismatch", "the pinned signature differs from the pack's")
            approved = [
                w
                for a in body.get("pack_approvals", [])
                if (a.get("pack"), a.get("version")) == (name, version)
                for w in a.get("accepts", [])
            ]
            merged = merge_pack(merged, pack, approved)
        except PackRejected as error:
            raise PolicyRejected(
                f"pack_{error.code}", f"rule pack {name} {version}: {error}"
            ) from error
        used.append((name, version))
        objects.append(pack)

    try:
        policy = Policy.parse(merged)
    except (ValidationError, ValueError) as error:
        raise PolicyRejected("invalid", f"{path.name}: {error}") from error
    digest = hashlib.sha256(signing.canonical_bytes(merged)).hexdigest()[:16]
    return LoadedPolicy(policy, merged, digest, tuple(used), tuple(objects))


def load_policy(path: Path | str, trusted_keys: Iterable[str], **kw: Any) -> Policy:
    return load_policy_data(path, trusted_keys, **kw).policy


@dataclass(frozen=True)
class Rejection:
    code: str
    message: str


class PolicyStore:
    """The policy a running pipeline uses. A failed reload keeps the last valid policy."""

    def __init__(
        self,
        path: Path | str,
        trusted_keys: Iterable[str],
        *,
        pack_keys: Iterable[str] | None = None,
        pack_dir: Path | str | None = None,
    ) -> None:
        self.path = Path(path)
        self._keys = tuple(trusted_keys)
        self._pack_keys = tuple(pack_keys) if pack_keys is not None else None
        self._pack_dir = pack_dir
        self.rejections: list[Rejection] = []
        self._loaded = self._load()  # the first load must succeed: there is nothing to fall back to

    def _load(self) -> LoadedPolicy:
        return load_policy_data(
            self.path, self._keys, pack_keys=self._pack_keys, pack_dir=self._pack_dir
        )

    @property
    def policy(self) -> Policy:
        return self._loaded.policy

    @property
    def digest(self) -> str:
        return self._loaded.digest

    @property
    def packs(self) -> tuple[tuple[str, str], ...]:
        return self._loaded.packs

    def reload(self) -> bool:
        """Load the file again. True when a (possibly identical) valid policy is now in force."""
        try:
            loaded = self._load()
            self._refuse_downgrade(loaded)
        except PolicyRejected as error:
            self.rejections.append(Rejection(error.code, str(error)))
            return False
        self._loaded = loaded
        return True

    def _refuse_downgrade(self, loaded: LoadedPolicy) -> None:
        """A pack older than the one in force is an attempt to bring back what a newer one fixed."""
        from .rulepacks import version_key

        current = dict(self._loaded.packs)
        for name, version in loaded.packs:
            if name in current and version_key(version) < version_key(current[name]):
                raise PolicyRejected(
                    "pack_downgrade", f"rule pack {name} {version} is older than {current[name]}"
                )
