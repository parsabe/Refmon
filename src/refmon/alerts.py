"""Alerts the pipeline raises about itself (Phase 6): a protection that does not work, a missing
heartbeat, a rejected policy. The text is built from fixed phrases and identifiers only."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from .schemas import Identifier


class Alert(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["selftest_failed", "heartbeat_missing", "policy_rejected", "degraded_protection"]
    subject: Identifier  # the protection, device or policy the alert is about
    message: str = Field(max_length=300)
    ts: AwareDatetime


class AlertLog:
    def __init__(self) -> None:
        self.alerts: list[Alert] = []

    def raise_(self, kind: str, subject: str, message: str, ts: datetime) -> Alert:
        alert = Alert(kind=kind, subject=subject, message=message, ts=ts)
        self.alerts.append(alert)
        return alert

    def of_kind(self, kind: str) -> list[Alert]:
        return [a for a in self.alerts if a.kind == kind]
