"""Pseudonymization and four-eyes re-identification (CLAUDE.md Phase 4).

Anything that leaves the device names devices and users by pseudonym: a keyed hash of the value, so
the same user always gets the same pseudonym on one device and nobody can compute it without the
key. The mapping back to the real value lives in a `Vault`, encrypted at rest. Opening it takes a
request, and the request takes approval signatures from `reidentify_requires` different approvers
(Ed25519, over the request id), none of them the requester. Every use is written to a hash-chained
`AuditLog`, successful or not; changing or dropping an entry breaks the chain.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cryptography.fernet import Fernet

from . import signing

_GENESIS = "0" * 64


class ReidentificationDenied(PermissionError):
    pass


@dataclass(frozen=True)
class Approval:
    approver: str
    signature: str


def approval_message(request_id: str, pseudonym: str, purpose: str) -> bytes:
    return f"refmon-reidentify|{request_id}|{pseudonym}|{purpose}".encode()


class AuditLog:
    """Append-only log of every re-identification attempt, hash-chained."""

    def __init__(self, path: Path | str | None = None, clock: Callable[[], datetime] | None = None):
        self.path = Path(path) if path else None
        self._clock = clock or (lambda: datetime.now(UTC))
        self.entries: list[dict] = []

    def append(self, event: str, **fields: object) -> dict:
        previous = self.entries[-1]["hash"] if self.entries else _GENESIS
        entry = {
            "seq": len(self.entries) + 1,
            "ts": self._clock().isoformat(timespec="seconds"),
            "event": event,
            **fields,
            "prev": previous,
        }
        entry["hash"] = self._digest(entry)
        self.entries.append(entry)
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    @staticmethod
    def _digest(entry: dict) -> str:
        body = {k: v for k, v in entry.items() if k != "hash"}
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()

    @classmethod
    def verify_entries(cls, entries: list[dict]) -> bool:
        previous = _GENESIS
        for number, entry in enumerate(entries, start=1):
            if entry.get("seq") != number or entry.get("prev") != previous:
                return False
            if entry.get("hash") != cls._digest(entry):
                return False
            previous = entry["hash"]
        return True

    def verify(self) -> bool:
        return self.verify_entries(self.entries)


@dataclass
class _Request:
    pseudonym: str
    purpose: str
    requester: str
    open: bool = True


class Vault:
    def __init__(
        self,
        approvers: dict[str, str],  # approver name -> Ed25519 public key
        required: int,
        audit: AuditLog,
        *,
        key: bytes | None = None,
    ) -> None:
        if required < 2:
            raise ValueError("four-eyes re-identification needs at least two approvers")
        self._approvers = dict(approvers)
        self._required = required
        self.audit = audit
        self._fernet = Fernet(key or Fernet.generate_key())
        self._sealed: dict[str, bytes] = {}
        self._requests: dict[str, _Request] = {}
        self._ids = itertools.count(1)

    def register(self, pseudonym: str, value: str) -> None:
        self._sealed[pseudonym] = self._fernet.encrypt(value.encode())

    def knows(self, pseudonym: str) -> bool:
        return pseudonym in self._sealed

    def open_request(self, pseudonym: str, purpose: str, requester: str) -> str:
        request_id = f"rq-{next(self._ids)}"
        self._requests[request_id] = _Request(pseudonym, purpose, requester)
        self.audit.append(
            "request_opened", request=request_id, pseudonym=pseudonym, requester=requester,
            purpose=purpose,
        )  # fmt: skip
        return request_id

    def complete(self, request_id: str, approvals: list[Approval]) -> str:
        """Return the real value if enough different approvers signed this request."""
        request = self._requests.get(request_id)
        if request is None or not request.open:
            self.audit.append("denied", request=request_id, reason="unknown_or_used_request")
            raise ReidentificationDenied("unknown or already used request")
        message = approval_message(request_id, request.pseudonym, request.purpose)
        valid: set[str] = set()
        used_keys: set[str] = set()
        for approval in approvals:
            key = self._approvers.get(approval.approver)
            if key is None or approval.approver == request.requester:
                continue
            if key not in used_keys and signing.verify_message(message, approval.signature, key):
                valid.add(approval.approver)
                used_keys.add(key)  # one person with two names is still one pair of eyes
        if len(valid) < self._required:
            self.audit.append(
                "denied", request=request_id, pseudonym=request.pseudonym,
                reason="not_enough_approvals", valid_approvers=sorted(valid),
            )  # fmt: skip
            raise ReidentificationDenied(
                f"{self._required} different approvers are needed, {len(valid)} signed"
            )
        sealed = self._sealed.get(request.pseudonym)
        if sealed is None:
            self.audit.append("denied", request=request_id, reason="unknown_pseudonym")
            raise ReidentificationDenied("unknown pseudonym")
        request.open = False  # one use per request
        self.audit.append(
            "reidentified", request=request_id, pseudonym=request.pseudonym,
            approvers=sorted(valid), purpose=request.purpose,
        )  # fmt: skip
        return self._fernet.decrypt(sealed).decode()


@dataclass
class Pseudonymizer:
    key: bytes
    vault: Vault | None = None
    _seen: dict[str, str] = field(default_factory=dict)

    def pseudonym(self, kind: str, value: str) -> str:
        digest = hmac.new(self.key, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()[:16]
        out = f"ps-{kind}-{digest}"
        if out not in self._seen:
            self._seen[out] = kind
            if self.vault is not None:
                self.vault.register(out, value)
        return out

    def device(self, value: str) -> str:
        return self.pseudonym("dev", value)

    def user(self, value: str) -> str:
        return self.pseudonym("usr", value)
