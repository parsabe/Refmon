"""Rule identifiers: every signal comes from one rule, named as in the C6 example (R-EFF-FETCH).

The signal names are the weight names of CLAUDE.md C11. Overrides have rule ids too (OVR-...), so
that a protection can be named by the self-test (Phase 6) and in a rule pack.
"""

_PREFIX = {"origin": "R-ORI", "contract": "R-CON", "effect": "R-EFF"}

SIGNAL_NAMES: tuple[str, ...] = (
    "origin_external",
    "contract_external_exec",
    "contract_web_worker_exec",
    "contract_exec_violation",
    "contract_write_executable",
    "contract_write_other",
    "contract_connect_violation",
    "contract_persist_violation",
    "contract_asset_violation",
    "contract_privilege_violation",
    "contract_surprisal",
    "contract_universal_violation",
    "contract_unsigned_launch",
    "effect_fetch",
    "effect_hide",
    "effect_persist",
    "effect_exfil",
    "effect_escalate",
    "effect_lateral",
    "effect_tamper",
    "effect_credential",
    "effect_asset_access",
    "effect_mass_change",
    "effect_response_anomaly",
    "effect_response_anomaly_repeated",
    "effect_threat_list_hit",
)

OVERRIDE_RULES: tuple[str, ...] = (
    "OVR-CANARY",
    "OVR-PROTECTED-ASSET",
    "OVR-SELF-TAMPER",
    "OVR-TRUSTED-ROOT",
)


def rule_id(signal_name: str) -> str:
    """effect_fetch -> R-EFF-FETCH, contract_external_exec -> R-CON-EXTERNAL-EXEC."""
    question, _, rest = signal_name.partition("_")
    return f"{_PREFIX[question]}-{rest.upper().replace('_', '-')}"


SIGNAL_RULE_IDS: frozenset[str] = frozenset(rule_id(n) for n in SIGNAL_NAMES)
RULE_IDS: frozenset[str] = SIGNAL_RULE_IDS | frozenset(OVERRIDE_RULES)
CONTRACT_RULE_IDS: tuple[str, ...] = tuple(
    rule_id(n) for n in SIGNAL_NAMES if n.startswith("contract_")
)
