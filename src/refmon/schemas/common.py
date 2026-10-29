"""Shared vocabulary for the schemas (CLAUDE.md Part C)."""

from collections.abc import Iterable
from enum import StrEnum
from typing import Annotated

from pydantic import StringConstraints

# Identifiers and attribute values are short tokens from a controlled vocabulary, never free text.
# No whitespace and no slashes, so a raw command, URL or path cannot ride along in a field that
# is meant to carry only a name or a class.
Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.:@-]{1,64}$")]

# HMAC-SHA256 fingerprint of content. 16-64 hex digits: a full digest is 64, shorter is allowed.
Fingerprint = Annotated[str, StringConstraints(pattern=r"^hmac:[0-9a-f]{16,64}$")]

# The only attribute keys an Event may carry (CLAUDE.md C2). Anything else is rejected, so a value
# that exists only before Observe (domain, host, IP, URL, path) cannot slip through under a new
# key. Observe uses such values to decide a match and then emits only the outcome. Adding a key is
# a change to this set and to C2, never a policy setting.
EVENT_ATTR_KEYS = frozenset(
    {
        "source_class",  # one of SourceClass
        "signed",  # true, false or "unknown": valid code signature on a launched file (D20)
        "trusted_source",  # name of the trusted_sources rule that matched (origin)
        "destination_class",  # name of a policy destinations class, or "unknown"
        "exec_class",  # name of a policy executables class, or "unknown"
        "protected_asset",  # name of the matching policy protected_assets entry
        "threat_list_hit",  # name of the threat list, confirmed against the exact list
        "canary_hit",  # true when a canary URL path or credential was touched
        "input_method",
        "launched_via",
        "hidden_window",
        "encoded_payload",
        "entropy_bits",  # obfuscation features measured before content is dropped (C11.7)
        "encoded_char_ratio",
        "longest_ws_run",
        "path_group",
        "web_root",
        "executable",
        "new_file",
        "persist_kind",
        "bytes",  # size of a response_out
    }
)


# The 14 tactics of MITRE ATT&CK Enterprise: the vocabulary for `Verdict.tactics`.
ATTACK_TACTICS = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)


class EventType(StrEnum):
    CONTENT_IN = "content_in"
    REQUEST_IN = "request_in"
    EXEC = "exec"
    NET_CONNECT = "net_connect"
    FILE_WRITE = "file_write"
    PERSIST = "persist"
    ASSET_ACCESS = "asset_access"
    PRIV_CHANGE = "priv_change"
    SECURITY_TAMPER = "security_tamper"
    USER_INPUT = "user_input"
    ADMIN_INPUT = "admin_input"
    # Beyond C2 (see docs/design-decisions.md, D3-D4): the end of a request bounds how long a
    # process carries a request label; response_out carries sizes only, for rate tests.
    REQUEST_END = "request_end"
    RESPONSE_OUT = "response_out"


class SourceClass(StrEnum):
    WEB = "web"
    MAIL = "mail"
    REMOVABLE = "removable"
    DOWNLOAD = "download"
    INBOUND_REQUEST = "inbound_request"
    OUTBOUND_RESPONSE = "outbound_response"
    PACKAGE = "package"
    AGENT_INPUT = "agent_input"
    INTERNAL = "internal"


class Origin(StrEnum):
    EXTERNAL = "external"


class Question(StrEnum):
    ORIGIN = "origin"
    CONTRACT = "contract"
    EFFECT = "effect"


class Effect(StrEnum):
    FETCH = "fetch"
    HIDE = "hide"
    PERSIST = "persist"
    ESCALATE = "escalate"
    LATERAL = "lateral"
    EXFIL = "exfil"
    TAMPER = "tamper"
    CREDENTIAL = "credential"
    ASSET_ACCESS = "asset_access"
    MASS_CHANGE = "mass_change"
    RESPONSE_ANOMALY = "response_anomaly"
    THREAT_LIST_HIT = "threat_list_hit"


class Decision(StrEnum):
    ALLOW = "allow"
    HOLD = "hold"
    BLOCK = "block"


class Mode(StrEnum):
    OBSERVE = "observe"
    WARN = "warn"
    BLOCK = "block"


class Override(StrEnum):
    CANARY = "canary"
    PROTECTED_ASSET = "protected_asset"
    TRUSTED_ROOT = "trusted_root"
    # Tampering with Refmon itself (stopping it, altering its policy or binaries).
    SELF_TAMPER = "self_tamper"


# Built-in actor roles. Policy can add more; pass them as validation context
# {"extra_roles": [...]} (see check_role).
BASE_ROLES = frozenset(
    {
        "browser",
        "mail",
        "office",
        "launcher",
        "interactive_shell",
        "script_host",
        "package_installer",
        "web_worker",
        "app_server",
        "node_app_server",
        "desktop_app_runtime",
        "db_server",
        "scheduler",
        "agent",
        "system_service",
        "other",
    }
)


def check_role(role: str, extra_roles: Iterable[str] = ()) -> str:
    if role not in BASE_ROLES and role not in set(extra_roles):
        raise ValueError(f"unknown actor role: {role!r}")
    return role
