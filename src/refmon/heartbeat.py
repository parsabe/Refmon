"""Heartbeat (CLAUDE.md Phase 6): "I am alive, this is my state", and the alert when it stops.

Each pipeline instance reports: alive, the policy version and digest, the status of the last
self-test, every protection the signed policy switched off, and every sensor capability that is
missing, as *degraded protection* (for example a sensor that cannot check code signatures leaves the
launcher contract without evidence: the signal is absent, not raised, and the heartbeat says so).
The heartbeat names the device by pseudonym and carries no content. A missing heartbeat is an alert.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from .alerts import Alert, AlertLog
from .policy import Policy
from .pseudonym import Pseudonymizer
from .schemas import Identifier
from .selftest import SelfTestReport

# Which protections stop working when a sensor capability is missing.
CAPABILITY_PROTECTIONS: dict[str, tuple[str, ...]] = {
    "signature_check": ("R-CON-UNSIGNED-LAUNCH",),
    "process_ancestry": ("R-ORI-EXTERNAL", "R-CON-WEB-WORKER-EXEC", "R-CON-EXTERNAL-EXEC"),
    "request_in": ("R-ORI-EXTERNAL", "R-EFF-RESPONSE-ANOMALY", "R-EFF-RESPONSE-ANOMALY-REPEATED"),
    "file_writes": (
        "R-CON-WRITE-EXECUTABLE",
        "R-CON-WRITE-OTHER",
        "R-EFF-PERSIST",
        "R-EFF-MASS-CHANGE",
    ),
    "network_connections": (
        "R-CON-CONNECT-VIOLATION",
        "R-EFF-FETCH",
        "R-EFF-LATERAL",
        "R-EFF-EXFIL",
    ),
    "privilege_changes": ("R-CON-PRIVILEGE-VIOLATION", "R-EFF-ESCALATE"),
}


class Degraded(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: Identifier
    protections: tuple[Identifier, ...]
    reason: str = Field(max_length=200)


class SelfTestStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    last_run: AwareDatetime | None = None
    passed: int = 0
    failed: tuple[Identifier, ...] = ()
    skipped: int = 0


class Heartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    device: Identifier  # a pseudonym
    ts: AwareDatetime
    alive: bool = True
    policy_version: int
    policy_digest: Identifier
    self_test: SelfTestStatus
    disabled_protections: tuple[Identifier, ...] = ()
    degraded: tuple[Degraded, ...] = ()
    policy_rejections: int = 0
    # Which engine decides: "calculus", "rule" (chosen) or "rule_fallback" (no weights, A28).
    decision_engine: Identifier = "calculus"

    @property
    def healthy(self) -> bool:
        return (
            self.alive
            and not self.self_test.failed
            and not self.degraded
            and self.decision_engine != "rule_fallback"
        )


def degraded_from(
    policy: Policy, provided: Iterable[str] | None, signed_unknown_seen: bool = False
) -> tuple[Degraded, ...]:
    """Capabilities the policy relies on that the sensor does not provide (or showed it lacks)."""
    have = None if provided is None else set(provided)
    missing = []
    for capability in policy.heartbeat.required_capabilities:
        absent = have is not None and capability not in have
        observed = capability == "signature_check" and signed_unknown_seen
        if absent or observed:
            why = (
                "the sensor reported signed=unknown, so it cannot check signatures"
                if observed and not absent
                else "the sensor does not provide this capability"
            )
            missing.append(
                Degraded(
                    capability=capability,
                    protections=CAPABILITY_PROTECTIONS.get(capability, ()),
                    reason=why,
                )
            )
    return tuple(missing)


def build(
    *,
    device: str,
    pseudonymizer: Pseudonymizer,
    policy: Policy,
    policy_digest: str,
    now: datetime,
    selftest: SelfTestReport | None = None,
    capabilities: Iterable[str] | None = None,
    signed_unknown_seen: bool = False,
    rejections: int = 0,
) -> Heartbeat:
    status = SelfTestStatus()
    if selftest is not None:
        status = SelfTestStatus(
            last_run=selftest.ts, passed=len(selftest.passed), failed=tuple(selftest.failed),
            skipped=len(selftest.skipped),
        )  # fmt: skip
    switched_off = sorted({s.id.replace("_", "-") for s in policy.rules if not s.enabled})
    return Heartbeat(
        device=pseudonymizer.device(device), ts=now, policy_version=policy.version,
        policy_digest=policy_digest, self_test=status, disabled_protections=tuple(switched_off),
        degraded=degraded_from(policy, capabilities, signed_unknown_seen),
        policy_rejections=rejections, decision_engine=policy.decision_engine,
    )  # fmt: skip


@dataclass
class HeartbeatMonitor:
    """Watches the heartbeats of the devices it expects; silence is an alert."""

    stale_after: float
    alerts: AlertLog = field(default_factory=AlertLog)
    last_seen: dict[str, datetime] = field(default_factory=dict)
    last: dict[str, Heartbeat] = field(default_factory=dict)
    _alerted: set[str] = field(default_factory=set)

    def expect(self, device: str, since: datetime) -> None:
        """A device that must report; counts as heard at `since` until its first heartbeat."""
        self.last_seen.setdefault(device, since)

    def receive(self, heartbeat: Heartbeat) -> list[Alert]:
        raised = []
        self.last_seen[heartbeat.device] = heartbeat.ts
        self.last[heartbeat.device] = heartbeat
        self._alerted.discard(heartbeat.device)
        for failed in heartbeat.self_test.failed:
            raised.append(
                self.alerts.raise_(
                    "selftest_failed", failed, f"protection {failed} is not working", heartbeat.ts
                )
            )
        for item in heartbeat.degraded:
            raised.append(
                self.alerts.raise_(
                    "degraded_protection", item.capability,
                    f"degraded protection: {item.capability} is missing", heartbeat.ts,
                )
            )  # fmt: skip
        if heartbeat.decision_engine == "rule_fallback":
            raised.append(
                self.alerts.raise_(
                    "degraded_protection", "decision_engine",
                    "degraded protection: no weights are configured, so the plain 3/2/1 rule "
                    "decides instead of the evidence calculus", heartbeat.ts,
                )
            )  # fmt: skip
        return raised

    def check(self, now: datetime) -> list[Alert]:
        """Alerts for every expected device whose last heartbeat is too old (once per silence)."""
        raised = []
        for device, seen in sorted(self.last_seen.items()):
            silent = (now - seen).total_seconds()
            if silent > self.stale_after and device not in self._alerted:
                self._alerted.add(device)
                raised.append(
                    self.alerts.raise_(
                        "heartbeat_missing", device,
                        f"no heartbeat from this device for {int(silent)} seconds", now,
                    )
                )  # fmt: skip
        return raised
