"""Health of the live daemon (CLAUDE.md Phase 6, wired into `refmon serve`).

While `serve` runs, a health thread:

- runs the self-test on the schedule of the signed policy (`self_test.interval`, and once at start):
  harmless synthetic stories, one per enabled protection, against an isolated copy of the live
  pipeline; a protection that does not reach its expected decision is an alert;
- writes a heartbeat every `heartbeat.interval` to `<workdir>/heartbeat.json`: alive, policy version
  and digest, self-test status, and every sensor capability the live barrier does not have, reported
  as degraded protection (missing information never generates evidence, it is reported instead);
- checks that the sandbox watcher is still running;
- checks the policy file: a change that fails its signature is an alert and the last valid policy
  stays in force; a validly signed change is adopted;
- runs the read-only rootkit scan every `rootkit_interval` seconds.

Conditions are tracked as a set: a notification goes out when a condition appears and when it
clears, not on every tick. A daemon cannot report its own death, so `refmon health` (run from cron
or a systemd timer) reads the heartbeat file from outside and alerts when it is stale or the process
is gone.
"""

from __future__ import annotations

import contextlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import heartbeat as heartbeat_module
from .alerts import AlertLog
from .notify import Notification, NotificationHub
from .policy_io import PolicyRejected, load_policy_data
from .schemas import Decision
from .selftest import SelfTestScheduler

if TYPE_CHECKING:
    from .live import LiveBarrier

HEARTBEAT_FILE = "heartbeat.json"
CHECK_STATE_FILE = "health-check.json"
# The live barrier senses file writes in its sandbox and nothing else on the host: it judges what is
# sent to it. Every other capability the policy relies on is reported as degraded protection.
LIVE_CAPABILITIES: tuple[str, ...] = ("file_writes",)


@dataclass(frozen=True)
class Condition:
    """Something wrong right now. `key` identifies it across ticks."""

    key: str
    category: str  # notification category
    severity: str
    title: str
    message: str
    subject: str


@dataclass
class HealthState:
    started: datetime
    last_beat: datetime | None = None
    last_rootkit: float | None = None
    beats: int = 0
    conditions: dict[str, Condition] = field(default_factory=dict)


class HealthMonitor:
    def __init__(
        self,
        barrier: LiveBarrier,
        *,
        rootkit_interval_s: float = 3600.0,
        watcher_stale_s: float = 30.0,
        capabilities: tuple[str, ...] = LIVE_CAPABILITIES,
        clock=time.monotonic,
    ) -> None:
        self.barrier = barrier
        self.hub: NotificationHub = barrier.hub
        self.rootkit_interval_s = rootkit_interval_s
        self.watcher_stale_s = watcher_stale_s
        self.capabilities = capabilities
        self.clock = clock
        self.scheduler = SelfTestScheduler(barrier.pipeline, barrier, AlertLog())
        self.state = HealthState(started=datetime.now(UTC))
        self.policy_rejections = 0
        self._policy_stat = _stat(barrier.policy_path)
        self._policy_rejected = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.heartbeat_path = barrier.workdir / HEARTBEAT_FILE
        self.last_heartbeat: heartbeat_module.Heartbeat | None = None

    # -- one step, deterministic for tests ----------------------------------------------------

    def tick(self, now: datetime | None = None) -> None:
        now = now or datetime.now(UTC)
        barrier = self.barrier
        with barrier._lock:
            self._check_policy(now)
            self.scheduler.alerts = AlertLog()  # the report keeps what this run found
            report = self.scheduler.tick(now)
            if report is not None:
                barrier._log_line(
                    f"SELF-TEST passed={len(report.passed)} failed={len(report.failed)} "
                    f"skipped={len(report.skipped)}"
                )
        self._maybe_rootkit()
        changed = self._transition(self._conditions(), now)
        beat_due = self.state.last_beat is None or (
            (now - self.state.last_beat).total_seconds() >= barrier.policy.heartbeat.interval
        )
        if beat_due or changed:  # `refmon health` sees a new problem at once
            self.write_heartbeat(now)

    def _conditions(self) -> dict[str, Condition]:
        out: dict[str, Condition] = {}
        last = self.scheduler.last
        if last is not None:
            for protection in last.failed:
                out[f"selftest:{protection}"] = Condition(
                    f"selftest:{protection}", "alert", "critical", "Protection not working",
                    f"the self-test of {protection} did not reach its expected decision on a "
                    "synthetic story; attacks it covers may pass until it is fixed",
                    protection,
                )  # fmt: skip
        if self._policy_rejected:
            out["policy_rejected"] = Condition(
                "policy_rejected", "alert", "critical", "Policy rejected",
                "the policy file on disk changed and fails its signature or validation; "
                "the last valid policy stays in force",
                "policy",
            )  # fmt: skip
        missing = heartbeat_module.degraded_from(self.barrier.policy, self.capabilities)
        if missing:
            names = sorted(item.capability for item in missing)
            out[f"degraded:{','.join(names)}"] = Condition(
                f"degraded:{','.join(names)}", "degraded", "warning", "Degraded protection",
                f"no host sensor for {', '.join(names)}: the live barrier judges only commands "
                "sent through `refmon guard` and files in its sandbox, not everything on the host",
                ",".join(names),
            )  # fmt: skip
        if self.watcher_stopped():
            out["watcher"] = Condition(
                "watcher", "alert", "critical", "Sandbox watcher stopped",
                "new files in the sandbox and the web root are no longer checked or quarantined",
                "sandbox_watcher",
            )  # fmt: skip
        rootkit = rootkit_condition(self.barrier)  # the newest scan, also one started by hand
        if rootkit is not None:
            out[rootkit.key] = rootkit
        return out

    def watcher_stopped(self) -> bool:
        thread = self.barrier._watcher_thread
        if thread is None:  # never started (tests, or a barrier without a watcher)
            return False
        if self.barrier._stop_event.is_set():
            return False
        if not thread.is_alive():
            return True
        return self.clock() - self.barrier.watcher_beat > self.watcher_stale_s

    def _transition(self, current: dict[str, Condition], now: datetime) -> bool:
        """Notify what appeared and what cleared; True when anything changed."""
        before = self.state.conditions
        new = [c for k, c in current.items() if k not in before]
        cleared = [c for k, c in before.items() if k not in current]
        self.state.conditions = current
        # one notification per kind of new problem, not one per protection
        groups: dict[tuple[str, str, str], list[Condition]] = {}
        for cond in new:
            groups.setdefault((cond.category, cond.severity, cond.title), []).append(cond)
        for (category, severity, title), conds in groups.items():
            message = "; ".join(c.message for c in conds)
            self.barrier.notify(
                Notification(
                    category=category, severity=severity, title=title, message=message,
                    device=self.barrier.device_pseudonym, ts=now,
                    details={"subjects": [c.subject for c in conds]},
                )
            )  # fmt: skip
            self.barrier._log_line(f"HEALTH {severity.upper()} {title}: {message}")
        if cleared:
            by_cat: dict[str, list[Condition]] = {}
            for cond in cleared:
                by_cat.setdefault(cond.category, []).append(cond)
            for category, conds in by_cat.items():
                names = ", ".join(sorted(c.subject for c in conds))
                self.barrier.notify(
                    Notification(
                        category=category, severity="info", title="Recovered",
                        message=f"no longer failing: {names}",
                        device=self.barrier.device_pseudonym, ts=now,
                        details={"subjects": sorted(c.subject for c in conds)},
                    )
                )  # fmt: skip
                self.barrier._log_line(f"HEALTH RECOVERED {names}")
        return bool(new or cleared)

    # -- the checks ---------------------------------------------------------------------------

    def _check_policy(self, now: datetime) -> None:
        barrier = self.barrier
        stat = _stat(barrier.policy_path)
        if stat == self._policy_stat:
            return
        self._policy_stat = stat
        try:
            loaded = load_policy_data(barrier.policy_path, [barrier._public_key()])
        except (PolicyRejected, OSError, ValueError) as exc:
            self.policy_rejections += 1
            self._policy_rejected = True
            barrier._log_line(f"POLICY REJECTED ({type(exc).__name__}); last valid policy kept")
            return
        self._policy_rejected = False
        if loaded.digest != barrier.policy_digest:
            barrier.adopt_policy(loaded, why="signed policy file changed on disk")

    def _maybe_rootkit(self) -> None:
        if self.rootkit_interval_s <= 0:
            return
        now = self.clock()
        if self.state.last_rootkit is not None and (
            now - self.state.last_rootkit < self.rootkit_interval_s
        ):
            return
        self.state.last_rootkit = now
        if self.state.beats == 0:
            return  # the barrier scanned when it started
        self.barrier.trigger_rootkit_scan()

    # -- heartbeat ----------------------------------------------------------------------------

    def write_heartbeat(self, now: datetime) -> dict[str, Any]:
        barrier = self.barrier
        with barrier._lock:
            beat = heartbeat_module.build(
                device=barrier.device_name, pseudonymizer=barrier.pseudonymizer,
                policy=barrier.policy, policy_digest=barrier.policy_digest, now=now,
                selftest=self.scheduler.last, capabilities=self.capabilities,
                rejections=self.policy_rejections,
            )  # fmt: skip
            mode = barrier.policy.mode.value
            interval = barrier.policy.heartbeat.interval
            stale_after = barrier.policy.heartbeat.stale_after
        self.last_heartbeat = beat
        self.state.last_beat = now
        self.state.beats += 1
        doc = {
            "heartbeat": beat.model_dump(mode="json"),
            "pid": os.getpid(),
            "started": self.state.started.isoformat(timespec="seconds"),
            "mode": mode,
            "interval": interval,
            "stale_after": stale_after,
            "problems": [
                {
                    "category": c.category,
                    "severity": c.severity,
                    "title": c.title,
                    "subject": c.subject,
                }
                for c in self.state.conditions.values()
            ],
            "notifications": {
                "sent": self.hub.sent,
                "failed": self.hub.failed,
                "dropped": self.hub.dropped,
                "channels": self.hub.describe(),
            },
        }
        tmp = self.heartbeat_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.heartbeat_path)
        return doc

    def snapshot(self) -> dict[str, Any]:
        last = self.scheduler.last
        return {
            "beats": self.state.beats,
            "last_heartbeat": self.state.last_beat.isoformat(timespec="seconds")
            if self.state.last_beat
            else None,
            "selftest": None
            if last is None
            else {
                "ts": last.ts.isoformat(timespec="seconds"),
                "passed": len(last.passed),
                "failed": list(last.failed),
                "skipped": len(last.skipped),
            },
            "problems": [
                {
                    "severity": c.severity,
                    "title": c.title,
                    "subject": c.subject,
                    "message": c.message,
                }
                for c in self.state.conditions.values()
            ],
            "notifications": {
                "sent": self.hub.sent,
                "failed": self.hub.failed,
                "dropped": self.hub.dropped,
                "channels": self.hub.describe(),
                "recent": [n.to_dict() for n in self.hub.history[-10:]],
            },
        }

    # -- thread -------------------------------------------------------------------------------

    def start(self, poll_s: float = 1.0) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()

        def _loop() -> None:
            while True:
                try:
                    self.tick()
                except Exception as exc:  # the health loop must outlive any one failing check
                    with contextlib.suppress(OSError):
                        self.barrier._log_line(f"HEALTH CHECK ERROR {type(exc).__name__}: {exc}")
                if self._stop.wait(poll_s):
                    return

        self._thread = threading.Thread(target=_loop, name="refmon-health", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)


def rootkit_condition(barrier: LiveBarrier) -> Condition | None:
    report = barrier.last_rootkit
    if report.calculus_decision is Decision.ALLOW:
        return None
    kinds = sorted({f.kind for f in report.findings})
    decision = report.calculus_decision.value
    return Condition(
        f"rootkit:{decision}:{','.join(kinds)}",
        "rootkit",
        "critical" if report.calculus_decision is Decision.BLOCK else "warning",
        f"Rootkit scan: {decision.upper()}",
        f"{len(report.findings)} finding(s): {', '.join(kinds)} "
        f"(L={report.log_odds:.2f} nats); run `refmon scan-rootkit` for details",
        "rootkit_scan",
    )


def _stat(path: Path) -> tuple[int, int, int] | None:
    try:
        st = path.stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size, st.st_ino)


# -- `refmon health`: the outside view ---------------------------------------------------------


def check_health(workdir: Path, now: datetime | None = None) -> tuple[int, dict[str, Any]]:
    """0 healthy; 1 not running (no heartbeat, stale heartbeat or the process is gone);
    2 running with a problem (self-test failed, policy rejected, watcher stopped, rootkit finding).
    Degraded capabilities are listed but do not count: the live barrier always lacks them."""
    now = now or datetime.now(UTC)
    path = workdir / HEARTBEAT_FILE
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 1, {"status": "not_running", "reason": f"no heartbeat file at {path}"}
    beat = doc.get("heartbeat", {})
    ts = datetime.fromisoformat(beat.get("ts", "1970-01-01T00:00:00+00:00"))
    age = (now - ts).total_seconds()
    stale_after = float(doc.get("stale_after", 180.0))
    info: dict[str, Any] = {
        "device": beat.get("device", "unknown"),
        "pid": doc.get("pid"),
        "mode": doc.get("mode"),
        "heartbeat_age_s": round(age, 1),
        "stale_after_s": stale_after,
        "policy_digest": beat.get("policy_digest"),
        "self_test": beat.get("self_test"),
        "problems": doc.get("problems", []),
        "notifications": doc.get("notifications", {}),
    }
    pid = doc.get("pid")
    if isinstance(pid, int) and not _pid_alive(pid):
        return 1, {**info, "status": "not_running", "reason": f"process {pid} is gone"}
    if age > stale_after:
        return 1, {
            **info,
            "status": "stale",
            "reason": f"no heartbeat for {int(age)} s (stale after {int(stale_after)} s)",
        }
    serious = [p for p in info["problems"] if p.get("category") != "degraded"]
    if serious:
        titles = sorted({p.get("title", "?") for p in serious})
        return 2, {**info, "status": "problem", "reason": "; ".join(titles)}
    return 0, {**info, "status": "healthy", "reason": "heartbeat fresh, self-test passing"}


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def notify_on_change(
    workdir: Path, code: int, info: dict[str, Any], hub: NotificationHub, now: datetime
) -> bool:
    """Send a notification when the outside view changes (healthy -> not, or back), so a cron
    job every few minutes alerts once per outage. True when one was sent."""
    state_path = workdir / CHECK_STATE_FILE
    try:
        last = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        last = {"code": 0, "reason": ""}
    changed = (last.get("code"), last.get("reason")) != (code, info.get("reason"))
    if not changed:
        return False
    if code == 0 and last.get("code", 0) == 0:
        sent = False
    else:
        if code == 0:
            note = Notification(
                "alert", "info", "Recovered", f"Refmon daemon healthy again ({info['reason']})",
                info.get("device", "unknown"), now,
            )  # fmt: skip
        else:
            title = "Refmon daemon not running" if code == 1 else "Refmon daemon has a problem"
            note = Notification(
                "alert", "critical", title, info["reason"], info.get("device", "unknown"), now,
                {"status": info["status"]},
            )  # fmt: skip
        hub.send(note)
        hub.flush()
        sent = True
    with contextlib.suppress(OSError):
        state_path.write_text(
            json.dumps({"code": code, "reason": info.get("reason"), "ts": now.isoformat()}) + "\n",
            encoding="utf-8",
        )
    return sent
