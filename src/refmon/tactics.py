"""Mapping from what a verdict says to MITRE ATT&CK Enterprise tactic names (Phase 4).

Tactic names only, no technique ids: the pipeline judges behaviour, and a tactic describes what the
behaviour was for. The mapping is a table, so a reviewer can read and change it.
"""

from __future__ import annotations

from .schemas import ATTACK_TACTICS, Effect, Override, Verdict

ORIGIN_TACTIC = "Initial Access"

EFFECT_TACTIC: dict[str, str] = {
    Effect.FETCH: "Command and Control",
    Effect.HIDE: "Defense Evasion",
    Effect.PERSIST: "Persistence",
    Effect.ESCALATE: "Privilege Escalation",
    Effect.LATERAL: "Lateral Movement",
    Effect.EXFIL: "Exfiltration",
    Effect.TAMPER: "Defense Evasion",
    Effect.CREDENTIAL: "Credential Access",
    Effect.ASSET_ACCESS: "Collection",
    Effect.MASS_CHANGE: "Impact",
    Effect.RESPONSE_ANOMALY: "Collection",
    Effect.THREAT_LIST_HIT: "Command and Control",
}

CONTRACT_TACTIC: dict[str, str] = {
    "contract_external_exec": "Execution",
    "contract_web_worker_exec": "Execution",
    "contract_exec_violation": "Execution",
    "contract_unsigned_launch": "Execution",
    "contract_write_executable": "Persistence",
    "contract_write_other": "Persistence",
    "contract_connect_violation": "Command and Control",
    "contract_persist_violation": "Persistence",
    "contract_asset_violation": "Collection",
    "contract_privilege_violation": "Privilege Escalation",
}

OVERRIDE_TACTIC: dict[Override, str] = {
    Override.CANARY: "Credential Access",
    Override.PROTECTED_ASSET: "Credential Access",
    Override.SELF_TAMPER: "Defense Evasion",
}


def tactics_for(verdict: Verdict) -> tuple[str, ...]:
    """The tactics a verdict touches, in ATT&CK order."""
    found: set[str] = set()
    if verdict.origin.failed:
        found.add(ORIGIN_TACTIC)
    for reason in verdict.contract.reasons:
        if reason in CONTRACT_TACTIC:
            found.add(CONTRACT_TACTIC[reason])
    for effect in verdict.effects:
        found.add(EFFECT_TACTIC[effect])
    if verdict.override in OVERRIDE_TACTIC:
        found.add(OVERRIDE_TACTIC[verdict.override])
    return tuple(t for t in ATTACK_TACTICS if t in found)
