"""Detached signatures for policy files and rule packs (CLAUDE.md C6).

A signed document is a mapping with a `signature` field. The signature is Ed25519 over the canonical
JSON of the rest of the mapping (sorted keys, no whitespace, dates as ISO text), so comments and
formatting in the YAML file do not matter but every value does. Keys travel as base64 of the raw
32 bytes. Verification takes a list of trusted public keys and succeeds if any one verifies.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SIGNATURE_FIELD = "signature"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def generate_keypair() -> tuple[str, str]:
    """Return (private key, public key), both base64 of the raw 32 bytes."""
    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    raw_public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return _b64(raw_private), _b64(raw_public)


def public_key_of(private_key: str) -> str:
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key))
    return _b64(
        private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )


def _plain(value: Any) -> Any:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError(f"cannot sign a {type(value).__name__}")


def canonical_bytes(document: Mapping[str, Any]) -> bytes:
    body = {k: v for k, v in document.items() if k != SIGNATURE_FIELD}
    text = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=_plain
    )
    return text.encode("ascii")


def sign(document: Mapping[str, Any], private_key: str) -> str:
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key))
    return _b64(private.sign(canonical_bytes(document)))


def signed(document: Mapping[str, Any], private_key: str) -> dict[str, Any]:
    """A copy of `document` with its signature field set."""
    out = {k: v for k, v in document.items() if k != SIGNATURE_FIELD}
    out[SIGNATURE_FIELD] = sign(out, private_key)
    return out


def verify(document: Mapping[str, Any], trusted_public_keys: Iterable[str]) -> bool:
    """True when the document's signature verifies under one of the trusted keys."""
    signature = document.get(SIGNATURE_FIELD)
    if not isinstance(signature, str) or not signature:
        return False
    try:
        raw_signature = base64.b64decode(signature, validate=True)
        message = canonical_bytes(document)
    except (binascii.Error, TypeError, ValueError):
        return False
    for key in trusted_public_keys:
        try:
            public = Ed25519PublicKey.from_public_bytes(base64.b64decode(key))
            public.verify(raw_signature, message)
            return True
        except (InvalidSignature, binascii.Error, ValueError):
            continue
    return False


def sign_message(message: bytes, private_key: str) -> str:
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key))
    return _b64(private.sign(message))


def verify_message(message: bytes, signature: str, public_key: str) -> bool:
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key))
        public.verify(base64.b64decode(signature, validate=True), message)
        return True
    except (InvalidSignature, binascii.Error, ValueError):
        return False
