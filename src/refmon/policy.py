"""The policy model (CLAUDE.md C6, C4, C11) and the reference default policy.

Phase 1 uses `Policy` as plain configuration; Phase 2 adds the signed YAML loader (policy_io.py).
Durations are stored in seconds and written as "30m", "60s", "6h" in YAML.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator, model_validator

from .rules import RULE_IDS, SIGNAL_RULE_IDS
from .schemas import Contract, Decision, Mode

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(value: Any) -> float:
    if isinstance(value, bool):
        raise ValueError("a duration is a number of seconds or a string like '30m'")
    if isinstance(value, (int, float)):
        return float(value)
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhd])\s*", str(value))
    if not match:
        raise ValueError(f"bad duration: {value!r}")
    return float(match.group(1)) * _UNITS[match.group(2)]


Duration = Annotated[float, BeforeValidator(parse_duration)]


def _date_text(value: Any) -> Any:
    return value.isoformat() if isinstance(value, date) else value


DateText = Annotated[str, BeforeValidator(_date_text)]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Thresholds(_Model):
    origin_strength: float = 0.5
    decay_half_life: Duration = 1800.0
    story_quiet_window: Duration = 600.0
    buffer_max_age: Duration = 600.0
    label_alive_floor: float = 0.02  # below this a decayed label is no longer carried


class Decisions(_Model):
    fails_3: Decision = Decision.BLOCK
    fails_2: Decision = Decision.HOLD
    fails_0_1: Decision = Decision.ALLOW
    endpoint_hold_timeout: Duration = 60.0
    server_hold_timeout: str = "keep_quarantined"  # what happens when no admin answers
    server_hold_wait: Duration = 3600.0  # how long a server hold waits for the admin


class TrustedSource(_Model):
    name: str
    # keys: source_class, domain (list), signer (list), actor_role (list), group (list)
    match: dict[str, Any]


class Destination(_Model):
    name: str
    trusted: bool = False
    internal: bool = False
    match: dict[str, list[str]] = Field(default_factory=dict)  # host: [...], cidr: [...]


class ProtectedAsset(_Model):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    name: str
    class_: str = Field(alias="class")
    value: str | None = None


class Canary(_Model):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    name: str
    class_: str = Field(alias="class")  # credential | url_path
    value: str | None = None


class Executable(_Model):
    name: str
    match: dict[str, list[str]] = Field(default_factory=dict)  # program: [...]


class ThreatListSpec(_Model):
    name: str
    kind: str  # host | url | content
    entries: list[str] = Field(default_factory=list)


class Rates(_Model):
    """Counted thresholds (the fallback without weights), and the window of the C11.6 tests."""

    # "counted": the thresholds below. "statistical": Poisson and CUSUM (C11.6). "auto": the
    # statistical tests when the evidence calculus is in use.
    method: Literal["auto", "counted", "statistical"] = "auto"

    window: Duration = 60.0
    # v1.1 (A49): the Poisson and repeat tests also run over this longer window, so a slow burst
    # that never fills one `window` still adds up. It must not be shorter than `window`.
    long_window: Duration = 3600.0
    mass_change_files: int = 50
    lateral_hosts: int = 20
    response_anomaly_bytes: int = 5_000_000
    response_repeat: int = 2
    exfil_bytes: int = 100_000_000
    exfil_bytes_by_role: dict[str, int] = Field(default_factory=dict)


class CusumParams(_Model):
    k: float = 0.5
    h: float = 5.0


class MathParams(_Model):
    prior_attack: float = 0.001
    costs: dict[str, float] = Field(
        default_factory=lambda: {"missed_attack": 1000.0, "false_block": 20.0, "hold": 5.0}
    )
    hold_catch_rate: float = 0.7
    weights: dict[str, float] = Field(default_factory=dict)
    surprisal_max_bits: float = 12.0
    baseline_maturity_unseen: float = 0.01
    poisson_alpha: float = 1.0e-6
    cusum: CusumParams = Field(default_factory=CusumParams)
    entropy_max_bits: float = 5.2
    ws_run_max: int = 64
    dp_epsilon: float = 1.0
    k_anonymity: int = 5
    # Baseline rates per role for the Poisson tests: expected events per window (C11.6).
    baseline_rate: dict[str, float] = Field(default_factory=dict)
    baseline_rate_default: float = 3.0
    # The same for the long window (v1.1, A49): expected events per long window, per kind or per
    # `kind:role`. An expert estimate: ten short-window baselines, i.e. a process is assumed busy
    # in one short window out of six over an hour.
    baseline_rate_long: dict[str, float] = Field(default_factory=dict)
    baseline_rate_long_default: float = 30.0
    ema_beta: float = 0.1  # smoothing of the exponential moving averages of the baselines
    bloom_fp_rate: float = 0.001  # false-positive target of shipped threat lists
    # Attenuation a_e in (0, 1] of a label along an edge of a given kind (C11.2): "write" for a
    # file written by a labeled process, "persist" for a persistence item. 1.0 when not listed.
    attenuation: dict[str, float] = Field(default_factory=dict)
    # Baseline outbound bytes per window and role for CUSUM (mean and sigma).
    baseline_bytes: dict[str, tuple[float, float]] = Field(default_factory=dict)
    baseline_bytes_default: tuple[float, float] = (1_000_000.0, 500_000.0)


class Exposure(_Model):
    inventory: str | None = None
    advisories: str | None = None
    escalate_mode: Mode = Mode.BLOCK
    # Roles whose escalation waits for an administrator's approval (A44). By default an escalation
    # applies at once, the administrator is told immediately, and it ends by itself.
    require_approval: list[str] = Field(default_factory=list)


class RulePackRef(_Model):
    name: str
    version: str
    signature: str = ""


class Exception_(_Model):
    """A scoped, expiring switch-off of signal rules (C6). Overrides cannot be excepted."""

    id: str
    reason: str
    scope: dict[str, str]  # keys: user, role, device, group
    disables: list[str]
    expires: DateText  # ISO date, the last day the exception applies

    @field_validator("reason")
    @classmethod
    def _has_a_reason(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("an exception needs a reason")
        return value

    @field_validator("scope")
    @classmethod
    def _is_scoped(cls, value: dict[str, str]) -> dict[str, str]:
        unknown = sorted(set(value) - {"user", "role", "device", "group"})
        if not value or unknown:
            raise ValueError(
                f"an exception needs a scope of user, role, device or group: {unknown}"
            )
        return value

    @field_validator("disables")
    @classmethod
    def _disables_known_signal_rules(cls, value: list[str]) -> list[str]:
        bad = sorted(set(value) - SIGNAL_RULE_IDS)
        if not value or bad:
            raise ValueError(f"an exception disables known signal rules, not {bad or 'nothing'}")
        return value

    @field_validator("expires")
    @classmethod
    def _expires_is_a_date(cls, value: str) -> str:
        date.fromisoformat(value)
        return value


class RuleSetting(_Model):
    """The mode of one rule, optionally for one role only (Phase 5 raises it for exposed roles)."""

    id: str
    mode: Mode = Mode.OBSERVE
    role: str | None = None
    # False switches the protection off. The self-test (Phase 6) knows which protections the
    # signed policy switched off on purpose and does not alert for those.
    enabled: bool = True
    # Set on settings the Exposure stage derives (virtual patching): "component:advisory".
    reason: str | None = None

    @field_validator("id")
    @classmethod
    def _known_rule(cls, value: str) -> str:
        if value not in RULE_IDS:
            raise ValueError(f"unknown rule id {value!r}")
        return value


class Learning(_Model):
    period: Duration = 7 * 86400.0  # how long contract learning only counts what roles do
    # Roles whose behaviour is not a workload: `other` is whatever no role covers (Phase 7 metric).
    skip_roles: list[str] = Field(default_factory=lambda: ["other"])


class Reporting(_Model):
    destination: str = "local"
    pseudonymize: bool = True
    reidentify_requires: int = 2


class Tune(_Model):
    """Feedback proposals (Phase 4): how long a proposed exception lasts."""

    exception_days: int = 30


class SelfTest(_Model):
    interval: Duration = 21600.0


class Heartbeat(_Model):
    """Heartbeat (Phase 6): how often an instance reports, and when silence is an alert."""

    interval: Duration = 60.0
    stale_after: Duration = 180.0
    # Sensor capabilities the protections rely on; a missing one is reported as degraded.
    required_capabilities: list[str] = Field(
        default_factory=lambda: [
            "process_ancestry",
            "request_in",
            "file_writes",
            "network_connections",
            "privilege_changes",
            "signature_check",
        ]
    )


class PackApproval(_Model):
    """A person accepted these weakenings from a rule pack. It sits in the signed policy, so the
    approval is signed too."""

    pack: str
    version: str
    accepts: list[str]  # weakening ids, as the pack analysis names them
    by: str


class Policy(_Model):
    version: int = 2
    mode: Mode = Mode.OBSERVE
    # "rule": the plain 3/2/1 fail rule decides. "calculus": the evidence calculus decides. "auto":
    # the calculus when weights are configured, else the rule (the fallback of CLAUDE.md Part A).
    # Both are always computed; this picks the final decision.
    engine: Literal["auto", "rule", "calculus"] = "auto"
    thresholds: Thresholds = Field(default_factory=Thresholds)
    decisions: Decisions = Field(default_factory=Decisions)
    trusted_sources: list[TrustedSource] = Field(default_factory=list)
    destinations: list[Destination] = Field(default_factory=list)
    protected_assets: list[ProtectedAsset] = Field(default_factory=list)
    canaries: list[Canary] = Field(default_factory=list)
    web_roots: list[str] = Field(default_factory=list)
    contracts: dict[str, Contract] = Field(default_factory=dict)
    extra_roles: list[str] = Field(default_factory=list)
    non_carrier_roles: list[str] = Field(default_factory=lambda: ["browser", "mail", "launcher"])
    # Roles that are the channel itself: their events do not link unrelated stories (Link).
    non_process_keyed_roles: list[str] = Field(default_factory=lambda: ["browser", "mail"])
    server_roles: list[str] = Field(
        default_factory=lambda: ["web_worker", "app_server", "node_app_server", "db_server"]
    )
    # Device id -> "endpoint" or "server": which hold flow a story on that device gets (Gate).
    # A device not listed counts as a server if one of the story's roles is a server role.
    devices: dict[str, Literal["endpoint", "server"]] = Field(default_factory=dict)
    executables: list[Executable] = Field(default_factory=list)
    threat_lists: list[ThreatListSpec] = Field(default_factory=list)
    user_groups: dict[str, str] = Field(default_factory=dict)
    rates: Rates = Field(default_factory=Rates)
    exposure: Exposure = Field(default_factory=Exposure)
    rule_packs: list[RulePackRef] = Field(default_factory=list)
    exceptions: list[Exception_] = Field(default_factory=list)
    rules: list[RuleSetting] = Field(default_factory=list)
    learning: Learning = Field(default_factory=Learning)
    # Roles whose contract was created by learning mode (Phase 4b enforces it once mature).
    learned_roles: list[str] = Field(default_factory=list)
    # Roles whose outbound network is limited to what their contract lists (virtual patching).
    # Derived by the Exposure stage from the inventory; a policy file does not set it.
    restricted_network_roles: list[str] = Field(default_factory=list)
    # Roles whose contract says exec is exceptional (C11 weight contract_web_worker_exec).
    strict_exec_roles: list[str] = Field(default_factory=lambda: ["web_worker", "node_app_server"])
    credential_classes: list[str] = Field(
        default_factory=lambda: ["credential_store", "key_material"]
    )
    reporting: Reporting = Field(default_factory=Reporting)
    tune: Tune = Field(default_factory=Tune)
    self_test: SelfTest = Field(default_factory=SelfTest)
    heartbeat: Heartbeat = Field(default_factory=Heartbeat)
    pack_approvals: list[PackApproval] = Field(default_factory=list)
    math: MathParams = Field(default_factory=MathParams)

    @model_validator(mode="before")
    @classmethod
    def _contracts_know_their_role(cls, data: Any) -> Any:
        if isinstance(data, dict) and isinstance(data.get("contracts"), dict):
            data = dict(data)
            data["contracts"] = {
                role: ({"role": role, **c} if isinstance(c, dict) else c)
                for role, c in data["contracts"].items()
            }
        return data

    def model_post_init(self, __context: Any) -> None:
        for role, contract in self.contracts.items():
            if contract.role != role:
                raise ValueError(f"contract for {role!r} names role {contract.role!r}")

    @classmethod
    def parse(cls, data: dict) -> Policy:
        """Validate a policy dict, letting contracts name the roles the policy adds."""
        return cls.model_validate(data, context={"extra_roles": tuple(data.get("extra_roles", ()))})

    def rule_setting(self, rule_id: str, role: str | None = None) -> RuleSetting | None:
        """The setting that applies: a role-specific one, then a general one. A later setting for
        the same rule and role wins, so a derived overlay can only be added after the signed ones;
        among settings of equal scope the stricter mode wins."""
        rank = {Mode.OBSERVE: 0, Mode.WARN: 1, Mode.BLOCK: 2}
        for want_role in (role, None):
            found = [s for s in self.rules if s.id == rule_id and s.role == want_role]
            if found:
                return max(found, key=lambda s: rank[s.mode])
        return None

    def rule_enabled(self, rule_id: str, role: str | None = None) -> bool:
        """False when a setting for this rule (for the role, else general) switches it off."""
        for want_role in (role, None):
            found = [s for s in self.rules if s.id == rule_id and s.role == want_role]
            if found:
                return all(s.enabled for s in found)
        return True

    def rule_mode(self, rule_id: str, role: str | None = None) -> Mode:
        """Mode of a rule: a role-specific setting, then a general one, then the global mode."""
        setting = self.rule_setting(rule_id, role)
        return setting.mode if setting is not None else self.mode

    def disabled_rules(self, facts: list[dict[str, str]], today: date) -> set[str]:
        """Rule ids switched off by exceptions that are in scope and not yet expired.

        `facts` describes the actors of a story (user, role, device, group); an exception applies
        when every scope key matches some actor.
        """
        out: set[str] = set()
        for ex in self.exceptions:
            if date.fromisoformat(ex.expires) < today:
                continue
            if any(all(f.get(k) == v for k, v in ex.scope.items()) for f in facts):
                out.update(ex.disables)
        return out

    @property
    def uses_calculus(self) -> bool:
        if self.engine == "auto":
            return bool(self.math.weights)
        return self.engine == "calculus"

    @property
    def engine_fallback(self) -> bool:
        """`auto` without weights: the plain 3/2/1 rule decides because nothing else can (A28)."""
        return self.engine == "auto" and not self.math.weights

    @property
    def decision_engine(self) -> str:
        if self.engine_fallback:
            return "rule_fallback"
        return "calculus" if self.uses_calculus else "rule"

    @property
    def statistical_rates(self) -> bool:
        if self.rates.method == "auto":
            return self.uses_calculus
        return self.rates.method == "statistical"

    def platform_for(self, device: str, roles: set[str]) -> str:
        kind = self.devices.get(device)
        if kind is not None:
            return kind
        return "server" if roles & set(self.server_roles) else "endpoint"

    def destination(self, name: str) -> Destination | None:
        return next((d for d in self.destinations if d.name == name), None)

    def contract_for(self, role: str) -> Contract | None:
        return self.contracts.get(role)

    def validation_context(self) -> dict:
        return {"extra_roles": tuple(self.extra_roles)}


# --- reference default policy ---------------------------------------------------------------

WEIGHTS: dict[str, float] = {
    "origin_external": 0.8,
    "contract_external_exec": 1.0,
    "contract_web_worker_exec": 3.0,
    "contract_exec_violation": 2.5,
    "contract_write_executable": 3.5,
    "contract_write_other": 1.0,
    "contract_connect_violation": 2.5,
    "contract_persist_violation": 3.5,
    "contract_asset_violation": 2.5,
    "contract_privilege_violation": 3.5,
    "contract_surprisal": 2.0,
    "contract_universal_violation": 2.0,
    "contract_unsigned_launch": 1.5,
    "effect_fetch": 2.5,
    "effect_hide": 2.0,
    "effect_persist": 2.5,
    "effect_exfil": 2.5,
    "effect_escalate": 2.5,
    "effect_lateral": 3.5,
    "effect_tamper": 3.0,
    "effect_credential": 3.5,
    "effect_asset_access": 1.5,
    "effect_mass_change": 2.5,
    "effect_response_anomaly": 1.5,
    "effect_response_anomaly_repeated": 3.5,
    "effect_threat_list_hit": 4.5,
}


def default_policy_dict() -> dict:
    return {
        "version": 2,
        "mode": "observe",
        "extra_roles": [
            "backup_job",
            "vuln_scanner",
            "patch_tool",
            "elevation_tool",
            "deploy_tool",
        ],
        "trusted_sources": [
            {
                "name": "official-python-index",
                "match": {
                    "source_class": "download",
                    "domain": ["pypi.org", "files.pythonhosted.org"],
                },
            },
            {
                "name": "university-software-portal",
                "match": {"source_class": "download", "domain": ["software.example.edu"]},
            },
            {
                "name": "deploy-artifacts",
                "match": {"source_class": "download", "domain": ["artifacts.example.internal"]},
            },
        ],
        "destinations": [
            {
                "name": "package_index",
                "trusted": True,
                "match": {"host": ["pypi.org", "files.pythonhosted.org"]},
            },
            {"name": "db_server", "trusted": True, "match": {"host": ["db.example.internal"]}},
            {
                "name": "cache_server",
                "trusted": True,
                "match": {"host": ["cache.example.internal"]},
            },
            {
                "name": "backup_host",
                "trusted": True,
                "match": {"host": ["backup.example.internal"]},
            },
            {"name": "partner_api", "trusted": False, "match": {"host": ["api.partner.example"]}},
            {
                "name": "internal_network",
                "trusted": False,
                "internal": True,
                "match": {"cidr": ["10.0.0.0/8", "192.168.0.0/16"]},
            },
        ],
        "protected_assets": [
            {"name": "browser-passwords", "class": "credential_store"},
            {"name": "app-config-secrets", "class": "path_group", "value": "app_secrets"},
        ],
        "canaries": [
            {"name": "fake-db-credentials", "class": "credential", "value": "canary-db-password"},
            {"name": "canary-admin-url", "class": "url_path", "value": "/admin-backup-old"},
        ],
        "web_roots": ["main_site"],
        "devices": {"dev-7f3a": "endpoint", "dev-b21c": "server"},
        "executables": [
            {"name": "print_helper", "match": {"program": ["lpr", "cups-print"]}},
            {"name": "build_tool", "match": {"program": ["npm-build", "make"]}},
            {"name": "agent_tools", "match": {"program": ["git-status", "list-files"]}},
        ],
        "threat_lists": [
            {"name": "known-bad-hosts", "kind": "host", "entries": ["bad.example.invalid"]}
        ],
        "contracts": {
            "web_worker": {
                "may_exec": [],
                "may_write": ["cache", "sessions", "uploads_non_executable"],
                "may_connect": ["db_server", "cache_server"],
                "may_read_assets": [],
                "may_change_privilege": False,
            },
            "node_app_server": {
                "may_exec": ["build_tool"],
                "may_write": ["app_data"],
                "may_connect": ["db_server", "cache_server", "partner_api"],
                "may_read_assets": [],
                "may_change_privilege": False,
            },
            "app_server": {"may_change_privilege": False, "may_exec": []},
            "interactive_shell": {"external_content_exec": "deny"},
            "launcher": {"unsigned_external_exec": "deny"},
            "office": {"may_exec": ["print_helper"]},
            "package_installer": {"may_connect": ["package_index"], "may_persist": False},
            "agent": {
                "may_exec": ["agent_tools"],
                "external_content_exec": "deny",
                "may_connect": ["package_index"],
            },
            "browser": {"may_connect": ["any"], "may_read_assets": ["browser-passwords"]},
            "mail": {"may_connect": ["any"]},
            "backup_job": {"may_mass_change": True, "may_connect": ["backup_host"]},
            "vuln_scanner": {"may_fan_out": True, "may_connect": ["internal_network"]},
            "patch_tool": {"may_tamper": True},
            "elevation_tool": {"may_change_privilege": True},
        },
        "rates": {
            "window": "60s",
            "long_window": "1h",
            "mass_change_files": 50,
            "lateral_hosts": 20,
            "response_anomaly_bytes": 5_000_000,
            "response_repeat": 2,
            "exfil_bytes": 100_000_000,
            "exfil_bytes_by_role": {"backup_job": 100_000_000_000},
        },
        "exposure": {
            "inventory": "inventory.yaml",
            "advisories": "advisories.yaml",
            "escalate_mode": "block",
        },
        "math": {
            "weights": dict(WEIGHTS),
            # Expected anomalous responses per client and window: rare in benign traffic (the b of
            # the rate-tested signals in docs/weights-proposal.md is 0.01).
            "baseline_rate": {"response_anomaly": 0.01},
            # v1.1: ten short windows (A49), same reasoning.
            "baseline_rate_long": {"response_anomaly": 0.1},
            # Outbound bytes per window: the nightly backup role moves tens of gigabytes.
            "baseline_bytes": {"backup_job": [5.0e10, 2.0e10]},
        },
    }


def default_policy(**overrides: Any) -> Policy:
    data = default_policy_dict()
    data.update(overrides)
    return Policy.parse(data)
