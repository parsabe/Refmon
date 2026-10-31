"""Rootkit detection scanners and sensor for Refmon.

Combines six rootkit scanning techniques in pure, read-only Python (plus an optional bridge to
installed `unhide`, `chkrootkit` and `rkhunter` binaries) while preserving Refmon's rules:

  1. `linker_preload` (`chkrootkit` / `rkhunter`): `/etc/ld.so.preload`, `LD_PRELOAD`, `LD_AUDIT`,
     ephemeral `LD_LIBRARY_PATH` dirs, and shared libraries mapped from ephemeral or deleted files.
  2. `fileless_memory` (`osquery` / EDR): `memfd:` execution, unlinked `(deleted)` executables,
     execution from `/dev/shm` or `/tmp`, `TracerPid` (`ptrace` injection), and anonymous `rwxp`
     memory regions.
  3. `kernel_module_crossview` (`unhide` / `rkhunter`): two-pass cross-view comparison between
     `/sys/module/*/initstate` (`V_sys`) and `/proc/modules` (`V_proc`), plus forced kernel taint
     bits (`insmod -f`, `rmmod -f`); proprietary/unsigned GPU driver bits (`P`, `O`, `E`) are
     recorded as context only and never trigger false alarms.
  4. `pid_crossview` (`unhide` passive): two-pass cross-view comparison between `/proc` directory
     enumeration (`V_enum`) and `/proc/<pid>/task/*` thread-group / own-UID ancestry (`V_direct`),
     without sending signals or reading other users' private command lines.
  5. `network_crossview_sniffer` (`chkrootkit` `ifpromisc` + `unhide-tcp`): two-pass comparison
     between `/proc/net/sockstat` (`TCP: inuse`) and visible lines in `/proc/net/tcp` (catching
     `tcp4_seq_show` socket hiding), plus `IFF_PROMISC` (`0x100`) interface sniffer checks.
  6. `external_tools` (optional adapter): queries `unhide`, `chkrootkit` or `rkhunter` when
     explicitly enabled and installed; missing tools report `unavailable` and never add evidence.

Privacy & safety:
  * Read-only inspection only; never sends `kill()` signals or binds network ports.
  * Process environment, executable link and memory maps are read only for `target_uid`
    (default `os.getuid()`), never across other users on a shared multi-user host.
  * Every raw path, module or subject name is converted in memory to an `hmac:...` fingerprint
    before appearing in any `RootkitFinding` or `Event`.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .calculus import evidence as calc
from .core import RunReport, run_pipeline
from .enforcer import SimulatedEnforcer
from .interfaces import AnyEvent
from .pipeline import Pipeline
from .policy import Policy, default_policy
from .schemas import Actor, Decision, EventType, RawEvent, RawObjectRef

IFF_PROMISC = 0x100
TAINT_FORCED_MODULE = 1 << 1  # bit 1 ('F'): module force-loaded (insmod -f)
TAINT_FORCED_RMMOD = 1 << 2  # bit 2 ('R'): module force-unloaded (rmmod -f)
TAINT_PROPRIETARY = 1 << 0  # bit 0 ('P'): proprietary module (e.g. GPU driver)
TAINT_OOT_MODULE = 1 << 12  # bit 12 ('O'): out-of-tree module
TAINT_UNSIGNED_MODULE = 1 << 13  # bit 13 ('E'): unsigned module

EPHEMERAL_DIRS = ("/tmp", "/var/tmp", "/dev/shm", "/run/shm")
EXTERNAL_SCANNERS = ("unhide", "chkrootkit", "rkhunter")

# Log-likelihood weights in nats for the standalone rootkit summary calculus, aligned with C11:
# high-certainty subversion crosses block; ambiguous single-signal anomalies (lone rwxp JIT or
# lone promiscuous capture) land in hold unless corroborated.
SCANNER_WEIGHTS: dict[str, float] = {
    "etc_ld_so_preload": 5.5,
    "process_ld_preload": 5.2,
    "process_ld_audit": 5.2,
    "ephemeral_ld_library_path": 3.5,
    "deleted_or_ephemeral_so": 4.8,
    "memfd_execution": 5.5,
    "deleted_executable": 5.0,
    "ephemeral_executable": 4.2,
    "ptrace_attached": 4.8,
    "anonymous_rwx_memory": 2.2,
    "hidden_kernel_module": 6.0,
    "kernel_forced_taint": 5.0,
    "hidden_pid_discrepancy": 5.8,
    "hidden_tcp_socket": 5.2,
    "promiscuous_interface": 2.4,
    "external_scanner_hit": 4.8,
}


@dataclass(frozen=True)
class ScanConfig:
    """Parameters for read-only rootkit scanning and two-pass discrepancy persistence."""

    proc_root: Path = Path("/proc")
    sys_root: Path = Path("/sys")
    etc_root: Path = Path("/etc")
    passes: int = 2
    pass_interval_s: float = 0.05
    race_prob: float = 1e-3  # per-pass transient churn rate p_race
    max_crossview_nats: float = 8.0
    max_rwx_Normal_regions: int = 0  # > this many anonymous rwxp regions raises a finding
    socket_slack: int = 1  # tolerate 1 transient socket between sockstat and /proc/net/tcp
    target_uid: int | None = None  # None -> os.getuid()
    self_pid: int | None = None  # None -> os.getpid()
    run_external: bool = False
    external_timeout_s: float = 30.0
    device: str = "local-host"


@dataclass(frozen=True)
class RootkitFinding:
    """One privacy-safe finding emitted by a scanner family (fingerprints only, never raw paths)."""

    scanner: str
    kind: str
    question: str  # "contract" | "effect"
    severity: str  # "high" | "medium"
    subject_fingerprint: str
    nats: float
    self_tamper: bool = False
    count: int = 1


@dataclass(frozen=True)
class RootkitScanReport:
    """Complete mathematical and pipeline verdict for a multi-scanner rootkit sweep."""

    scanned_at: str
    passes: int
    own_processes_inspected: int
    kernel_modules_checked: int
    network_interfaces_checked: int
    capabilities: dict[str, str]
    context_notes: tuple[str, ...]
    findings: tuple[RootkitFinding, ...]
    prior_log_odds: float
    log_odds: float
    hold_threshold: float
    block_threshold: float
    calculus_decision: Decision
    pipeline_decision: Decision
    self_tamper: bool
    verdicts_emitted: int
    actions_emitted: int

    def to_dict(self) -> dict[str, object]:
        return {
            "scanned_at": self.scanned_at,
            "passes": self.passes,
            "own_processes_inspected": self.own_processes_inspected,
            "kernel_modules_checked": self.kernel_modules_checked,
            "network_interfaces_checked": self.network_interfaces_checked,
            "capabilities": dict(self.capabilities),
            "context_notes": list(self.context_notes),
            "prior_log_odds": round(self.prior_log_odds, 4),
            "log_odds": round(self.log_odds, 4),
            "hold_threshold": round(self.hold_threshold, 4),
            "block_threshold": round(self.block_threshold, 4),
            "calculus_decision": self.calculus_decision.value,
            "pipeline_decision": self.pipeline_decision.value,
            "self_tamper": self.self_tamper,
            "verdicts_emitted": self.verdicts_emitted,
            "actions_emitted": self.actions_emitted,
            "findings": [
                {
                    "scanner": f.scanner,
                    "kind": f.kind,
                    "question": f.question,
                    "severity": f.severity,
                    "subject_fingerprint": f.subject_fingerprint,
                    "nats": round(f.nats, 4),
                    "self_tamper": f.self_tamper,
                    "count": f.count,
                }
                for f in self.findings
            ],
        }


def crossview_nats(passes: int, race_prob: float = 1e-3, cap: float = 8.0) -> float:
    """Log-likelihood ratio ln((1 - beta) / p_race^k) in nats for a discrepancy persisting across
    `passes` snapshots, bounded at `cap` so a deterministic platform quirk cannot diverge."""
    if passes < 1 or not (0.0 < race_prob < 1.0):
        raise ValueError("passes >= 1 and race_prob in (0, 1) required")
    detection_power = 0.99
    raw = math.log(detection_power) - passes * math.log(race_prob)
    return min(cap, max(0.0, raw))


def _fp(key: bytes, text: str) -> str:
    norm = " ".join(text.split())
    return "hmac:" + hmac.new(key, norm.encode("utf-8"), hashlib.sha256).hexdigest()


def _starts_ephemeral(path: str) -> bool:
    if path.startswith("/memfd:"):
        return True
    return any(path == d or path.startswith(f"{d}/") for d in EPHEMERAL_DIRS)


class RootkitScanner:
    """Read-only, multi-engine Linux rootkit scanner safe for unprivileged shared servers."""

    def __init__(
        self,
        config: ScanConfig | None = None,
        *,
        key: bytes = b"refmon-device-key",
    ) -> None:
        if not key:
            raise ValueError("RootkitScanner requires a non-empty HMAC key")
        self.config = config or ScanConfig()
        self._key = key
        self._raw_subjects: dict[str, str] = {}

    def _record_fp(self, raw_subject: str) -> str:
        digest = _fp(self._key, raw_subject)
        self._raw_subjects[digest] = raw_subject
        return digest

    def scan(self) -> tuple[list[RootkitFinding], dict[str, str], list[str], tuple[int, int, int]]:
        """Run all enabled scanners and return (findings, capabilities, notes, counts)."""
        self._raw_subjects.clear()
        cfg = self.config
        uid = os.getuid() if cfg.target_uid is None else cfg.target_uid
        self_pid = os.getpid() if cfg.self_pid is None else cfg.self_pid
        passes = max(1, cfg.passes)

        net_sysfs = (cfg.sys_root / "class" / "net").is_dir()
        caps: dict[str, str] = {
            "proc_fs": "available" if cfg.proc_root.is_dir() else "unavailable",
            "sys_module": "available" if (cfg.sys_root / "module").is_dir() else "unavailable",
            "net_sysfs": "available" if net_sysfs else "unavailable",
        }
        for tool in EXTERNAL_SCANNERS:
            caps[f"ext_{tool}"] = "available" if shutil.which(tool) else "not_installed"

        notes: list[str] = []
        findings: list[RootkitFinding] = []

        # 1 & 2. Linker preload + fileless / hollowed / ptrace inspection on own-UID processes.
        f_pre, own_count = self._scan_preload_and_processes(uid, self_pid)
        findings.extend(f_pre)

        # 3 & 4 & 5. Multi-pass cross-view snapshots (modules, PIDs, sockets) + kernel taint/net.
        mod_sets: list[set[str]] = []
        pid_sets: list[set[int]] = []
        tcp_gaps: list[int] = []
        tcp6_gaps: list[int] = []
        mod_count = 0

        for idx in range(passes):
            if idx > 0 and cfg.pass_interval_s > 0:
                time.sleep(cfg.pass_interval_s)
            hidden_mods, n_mods = self._snapshot_hidden_modules()
            mod_count = max(mod_count, n_mods)
            mod_sets.append(hidden_mods)
            pid_sets.append(self._snapshot_hidden_pids(uid))
            g4, g6 = self._snapshot_hidden_tcp_Gap()
            tcp_gaps.append(g4)
            tcp6_gaps.append(g6)

        cv_weight = crossview_nats(passes, cfg.race_prob, cfg.max_crossview_nats)

        persistent_mods = set.intersection(*mod_sets) if mod_sets else set()
        for mod_name in sorted(persistent_mods):
            findings.append(
                RootkitFinding(
                    scanner="kernel_module_crossview",
                    kind="hidden_kernel_module",
                    question="effect",
                    severity="high",
                    subject_fingerprint=self._record_fp(f"kmod:{mod_name}"),
                    nats=max(SCANNER_WEIGHTS["hidden_kernel_module"], cv_weight),
                )
            )

        persistent_pids = set.intersection(*pid_sets) if pid_sets else set()
        for pid in sorted(persistent_pids):
            findings.append(
                RootkitFinding(
                    scanner="pid_crossview",
                    kind="hidden_pid_discrepancy",
                    question="effect",
                    severity="high",
                    subject_fingerprint=self._record_fp(f"pid:{pid}"),
                    nats=max(SCANNER_WEIGHTS["hidden_pid_discrepancy"], cv_weight),
                )
            )

        min_tcp_gap = min(tcp_gaps) if tcp_gaps else 0
        if min_tcp_gap > cfg.socket_slack:
            findings.append(
                RootkitFinding(
                    scanner="network_crossview_sniffer",
                    kind="hidden_tcp_socket",
                    question="effect",
                    severity="high",
                    subject_fingerprint=self._record_fp(f"tcp4_hidden:{min_tcp_gap}"),
                    nats=max(SCANNER_WEIGHTS["hidden_tcp_socket"], cv_weight),
                    count=min_tcp_gap,
                )
            )

        min_tcp6_gap = min(tcp6_gaps) if tcp6_gaps else 0
        if min_tcp6_gap > cfg.socket_slack:
            findings.append(
                RootkitFinding(
                    scanner="network_crossview_sniffer",
                    kind="hidden_tcp_socket",
                    question="effect",
                    severity="high",
                    subject_fingerprint=self._record_fp(f"tcp6_hidden:{min_tcp6_gap}"),
                    nats=max(SCANNER_WEIGHTS["hidden_tcp_socket"], cv_weight),
                    count=min_tcp6_gap,
                )
            )

        taint_findings, taint_notes = self._scan_kernel_taint()
        findings.extend(taint_findings)
        notes.extend(taint_notes)

        promisc_findings, iface_count = self._scan_promiscuous_interfaces()
        findings.extend(promisc_findings)

        if cfg.run_external:
            findings.extend(self._scan_external_tools())

        return findings, caps, notes, (own_count, mod_count, iface_count)

    # -- Scanner 1 & 2: Preload, linker, fileless exe, ptrace, anonymous rwxp ---------------------

    def _scan_preload_and_processes(
        self, uid: int, self_pid: int
    ) -> tuple[list[RootkitFinding], int]:
        findings: list[RootkitFinding] = []
        cfg = self.config

        preload_file = cfg.etc_root / "ld.so.preload"
        if preload_file.is_file():
            try:
                raw_lines = preload_file.read_text(encoding="utf-8", errors="replace").splitlines()
                entries = [
                    ln.strip() for ln in raw_lines if ln.strip() and not ln.strip().startswith("#")
                ]
            except OSError:
                entries = []
            for entry in entries:
                findings.append(
                    RootkitFinding(
                        scanner="linker_preload",
                        kind="etc_ld_so_preload",
                        question="contract",
                        severity="high",
                        subject_fingerprint=self._record_fp(f"etc_preload:{entry}"),
                        nats=SCANNER_WEIGHTS["etc_ld_so_preload"],
                        self_tamper=True,  # global ld.so.preload injects into Refmon itself
                    )
                )

        if not cfg.proc_root.is_dir():
            return findings, 0

        inspected = 0
        for entry in sorted(cfg.proc_root.iterdir(), key=lambda p: p.name):
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            try:
                if entry.stat().st_uid != uid:
                    continue
            except OSError:
                continue
            inspected += 1
            is_self = pid == self_pid
            findings.extend(self._inspect_own_process(entry, pid, is_self))

        return findings, inspected

    def _inspect_own_process(self, proc_dir: Path, pid: int, is_self: bool) -> list[RootkitFinding]:
        out: list[RootkitFinding] = []

        # 1a. Environment check (LD_PRELOAD, LD_AUDIT, ephemeral LD_LIBRARY_PATH)
        try:
            raw_env = (proc_dir / "environ").read_bytes()
            items = [chunk.decode("utf-8", errors="replace") for chunk in raw_env.split(b"\x00")]
        except OSError:
            items = []

        for item in items:
            if "=" not in item:
                continue
            k, val = item.split("=", 1)
            val = val.strip()
            if not val:
                continue
            if k == "LD_PRELOAD":
                out.append(
                    RootkitFinding(
                        scanner="linker_preload",
                        kind="process_ld_preload",
                        question="contract",
                        severity="high",
                        subject_fingerprint=self._record_fp(f"pid:{pid}:LD_PRELOAD:{val}"),
                        nats=SCANNER_WEIGHTS["process_ld_preload"],
                        self_tamper=is_self,
                    )
                )
            elif k == "LD_AUDIT":
                out.append(
                    RootkitFinding(
                        scanner="linker_preload",
                        kind="process_ld_audit",
                        question="contract",
                        severity="high",
                        subject_fingerprint=self._record_fp(f"pid:{pid}:LD_AUDIT:{val}"),
                        nats=SCANNER_WEIGHTS["process_ld_audit"],
                        self_tamper=is_self,
                    )
                )
            elif k == "LD_LIBRARY_PATH":
                parts = [seg for seg in val.split(":") if _starts_ephemeral(seg)]
                if parts:
                    out.append(
                        RootkitFinding(
                            scanner="linker_preload",
                            kind="ephemeral_ld_library_path",
                            question="contract",
                            severity="medium",
                            subject_fingerprint=self._record_fp(
                                f"pid:{pid}:LD_LIBRARY_PATH:{':'.join(parts)}"
                            ),
                            nats=SCANNER_WEIGHTS["ephemeral_ld_library_path"],
                            self_tamper=is_self,
                        )
                    )

        # 2a. Executable symlink check (memfd:, deleted binary, /dev/shm or /tmp binary)
        exe_link = proc_dir / "exe"
        try:
            target = os.readlink(exe_link)
        except OSError:
            target = ""

        if target:
            clean_target = target.removesuffix(" (deleted)")
            if target.startswith("/memfd:") or clean_target.startswith("/memfd:"):
                out.append(
                    RootkitFinding(
                        scanner="fileless_memory",
                        kind="memfd_execution",
                        question="effect",
                        severity="high",
                        subject_fingerprint=self._record_fp(f"pid:{pid}:memfd:{target}"),
                        nats=SCANNER_WEIGHTS["memfd_execution"],
                    )
                )
            elif target.endswith(" (deleted)"):
                out.append(
                    RootkitFinding(
                        scanner="fileless_memory",
                        kind="deleted_executable",
                        question="effect",
                        severity="high",
                        subject_fingerprint=self._record_fp(f"pid:{pid}:deleted:{target}"),
                        nats=SCANNER_WEIGHTS["deleted_executable"],
                    )
                )
            elif _starts_ephemeral(clean_target):
                out.append(
                    RootkitFinding(
                        scanner="fileless_memory",
                        kind="ephemeral_executable",
                        question="contract",
                        severity="high",
                        subject_fingerprint=self._record_fp(f"pid:{pid}:ephemeral_exe:{target}"),
                        nats=SCANNER_WEIGHTS["ephemeral_executable"],
                    )
                )

        # 2b. TracerPid check (ptrace attachment)
        try:
            status_lines = (
                (proc_dir / "status").read_text(encoding="utf-8", errors="replace").splitlines()
            )
        except OSError:
            status_lines = []

        for line in status_lines:
            if line.startswith("TracerPid:"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) != 0:
                    tracer = int(parts[1])
                    out.append(
                        RootkitFinding(
                            scanner="fileless_memory",
                            kind="ptrace_attached",
                            question="effect",
                            severity="high",
                            subject_fingerprint=self._record_fp(f"pid:{pid}:tracer:{tracer}"),
                            nats=SCANNER_WEIGHTS["ptrace_attached"],
                            self_tamper=is_self,
                        )
                    )
                break

        # 1b & 2c. Memory maps: anonymous rwxp regions + deleted/ephemeral shared objects
        try:
            maps_lines = (
                (proc_dir / "maps").read_text(encoding="utf-8", errors="replace").splitlines()
            )
        except OSError:
            maps_lines = []

        anon_rwx = 0
        bad_libs: set[str] = set()
        for line in maps_lines:
            fields = line.split(None, 5)
            if len(fields) < 5:
                continue
            perms, inode = fields[1], fields[4]
            pathname = fields[5].strip() if len(fields) == 6 else ""
            is_rwx = "r" in perms and "w" in perms and "x" in perms
            if is_rwx and inode == "0" and (not pathname or pathname.startswith("[anon")):
                anon_rwx += 1
            if "x" in perms and pathname and ".so" in pathname:
                stripped = pathname.removesuffix(" (deleted)")
                if pathname.endswith(" (deleted)") or _starts_ephemeral(stripped):
                    bad_libs.add(pathname)

        for lib in sorted(bad_libs):
            out.append(
                RootkitFinding(
                    scanner="linker_preload",
                    kind="deleted_or_ephemeral_so",
                    question="contract",
                    severity="high",
                    subject_fingerprint=self._record_fp(f"pid:{pid}:so:{lib}"),
                    nats=SCANNER_WEIGHTS["deleted_or_ephemeral_so"],
                    self_tamper=is_self,
                )
            )

        if anon_rwx > self.config.max_rwx_Normal_regions:
            out.append(
                RootkitFinding(
                    scanner="fileless_memory",
                    kind="anonymous_rwx_memory",
                    question="effect",
                    severity="medium",
                    subject_fingerprint=self._record_fp(f"pid:{pid}:anon_rwx"),
                    nats=SCANNER_WEIGHTS["anonymous_rwx_memory"],
                    self_tamper=is_self,
                    count=anon_rwx,
                )
            )

        return out

    # -- Scanner 3: Kernel module cross-view + kernel taint decoding ------------------------------

    def _snapshot_hidden_modules(self) -> tuple[set[str], int]:
        proc_modules = self.config.proc_root / "modules"
        sys_module_dir = self.config.sys_root / "module"
        if not proc_modules.is_file() or not sys_module_dir.is_dir():
            return set(), 0
        try:
            proc_set = {
                line.split()[0]
                for line in proc_modules.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip()
            }
            # Only loadable kernel modules carry `initstate` in /sys/module/<name>/initstate;
            # built-in subsystems do not, giving an exact 1-to-1 invariant on clean kernels.
            sys_set = {p.parent.name for p in sys_module_dir.glob("*/initstate")}
        except OSError:
            return set(), 0
        return sys_set - proc_set, len(sys_set)

    def _scan_kernel_taint(self) -> tuple[list[RootkitFinding], list[str]]:
        taint_path = self.config.proc_root / "sys" / "kernel" / "tainted"
        if not taint_path.is_file():
            return [], []
        try:
            mask = int(taint_path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return [], []

        findings: list[RootkitFinding] = []
        notes: list[str] = []

        forced_flags: list[str] = []
        if mask & TAINT_FORCED_MODULE:
            forced_flags.append("forced_insmod")
        if mask & TAINT_FORCED_RMMOD:
            forced_flags.append("forced_rmmod")
        if forced_flags:
            label = "+".join(forced_flags)
            findings.append(
                RootkitFinding(
                    scanner="kernel_module_crossview",
                    kind="kernel_forced_taint",
                    question="effect",
                    severity="high",
                    subject_fingerprint=self._record_fp(f"kernel_taint:{label}"),
                    nats=SCANNER_WEIGHTS["kernel_forced_taint"],
                )
            )

        benign_driver_bits: list[str] = []
        if mask & TAINT_PROPRIETARY:
            benign_driver_bits.append("P:proprietary")
        if mask & TAINT_OOT_MODULE:
            benign_driver_bits.append("O:out_of_tree")
        if mask & TAINT_UNSIGNED_MODULE:
            benign_driver_bits.append("E:unsigned_module")
        if benign_driver_bits:
            notes.append(
                "kernel taint context (normal on GPU/DKMS nodes, not scored as rootkit): "
                + ", ".join(benign_driver_bits)
            )
        return findings, notes

    # -- Scanner 4: Passive PID cross-view --------------------------------------------------------

    def _snapshot_hidden_pids(self, uid: int) -> set[int]:
        proc = self.config.proc_root
        if not proc.is_dir():
            return set()
        try:
            enum_pids = {int(p.name) for p in proc.iterdir() if p.name.isdigit()}
        except OSError:
            return set()

        # Discover PIDs referenced via thread-group task directories or own-UID PPid links that
        # exist on direct lookup `(proc / str(pid)).exists()` while omitted from readdir("/proc").
        referenced: set[int] = set()
        for pid in enum_pids:
            pdir = proc / str(pid)
            try:
                if pdir.stat().st_uid != uid:
                    continue
            except OSError:
                continue
            task_dir = pdir / "task"
            if task_dir.is_dir():
                try:
                    for t_entry in task_dir.iterdir():
                        if t_entry.name.isdigit():
                            referenced.add(int(t_entry.name))
                except OSError:
                    pass
            try:
                for line in (pdir / "status").read_text(errors="replace").splitlines():
                    if line.startswith("PPid:"):
                        ppid = int(line.split()[1])
                        if ppid > 0:
                            referenced.add(ppid)
                        break
            except (OSError, ValueError, IndexError):
                pass

        hidden: set[int] = set()
        for candidate in referenced - enum_pids:
            # Ignore non-leader threads that legitimately live under /proc/<tgid>/task/<tid>
            # unless their status reports Thread Group ID == candidate (a hidden process leader).
            cdir = proc / str(candidate)
            if not cdir.exists():
                continue
            tgid = _read_tgid(cdir)
            if tgid is None or tgid == candidate:
                hidden.add(candidate)
        return hidden

    # -- Scanner 5: Network sockstat cross-view & promiscuous sniffer check -----------------------

    def _snapshot_hidden_tcp_Gap(self) -> tuple[int, int]:
        net_dir = self.config.proc_root / "net"
        gap4 = _protocol_gap(net_dir / "sockstat", "TCP:", net_dir / "tcp")
        gap6 = _protocol_gap(net_dir / "sockstat6", "TCP6:", net_dir / "tcp6")
        return gap4, gap6

    def _scan_promiscuous_interfaces(self) -> tuple[list[RootkitFinding], int]:
        net_class = self.config.sys_root / "class" / "net"
        if not net_class.is_dir():
            return [], 0
        findings: list[RootkitFinding] = []
        count = 0
        for flags_file in sorted(net_class.glob("*/flags")):
            count += 1
            iface = flags_file.parent.name
            try:
                flags = int(flags_file.read_text(encoding="utf-8").strip(), 16)
            except (OSError, ValueError):
                continue
            if flags & IFF_PROMISC:
                findings.append(
                    RootkitFinding(
                        scanner="network_crossview_sniffer",
                        kind="promiscuous_interface",
                        question="effect",
                        severity="medium",
                        subject_fingerprint=self._record_fp(f"iface_promisc:{iface}"),
                        nats=SCANNER_WEIGHTS["promiscuous_interface"],
                    )
                )
        return findings, count

    # -- Scanner 6: Optional external scanner bridge (unhide / chkrootkit / rkhunter) -------------

    def _scan_external_tools(self) -> list[RootkitFinding]:
        out: list[RootkitFinding] = []
        commands: list[tuple[str, list[str]]] = [
            ("unhide", ["unhide", "sys"]),
            ("chkrootkit", ["chkrootkit", "-q"]),
        ]
        for name, cmd in commands:
            exe = shutil.which(cmd[0])
            if not exe:
                continue
            try:
                proc = subprocess.run(
                    [exe, *cmd[1:]],
                    capture_output=True,
                    text=True,
                    timeout=self.config.external_timeout_s,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            suspicious = [
                ln.strip()
                for ln in (proc.stdout + "\n" + proc.stderr).splitlines()
                if "INFECTED" in ln or "Hidden" in ln
            ]
            if suspicious:
                out.append(
                    RootkitFinding(
                        scanner="external_tools",
                        kind="external_scanner_hit",
                        question="effect",
                        severity="high",
                        subject_fingerprint=self._record_fp(f"ext:{name}:{len(suspicious)}"),
                        nats=SCANNER_WEIGHTS["external_scanner_hit"],
                        count=len(suspicious),
                    )
                )
        return out


def _read_tgid(proc_dir: Path) -> int | None:
    try:
        for line in (proc_dir / "status").read_text(errors="replace").splitlines():
            if line.startswith("Tgid:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def _protocol_gap(sockstat_path: Path, prefix: str, table_path: Path) -> int:
    if not sockstat_path.is_file() or not table_path.is_file():
        return 0
    try:
        inuse = None
        tw = 0
        for line in sockstat_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith(prefix):
                tokens = line.split()
                for i, tok in enumerate(tokens[:-1]):
                    if tok == "inuse":
                        inuse = int(tokens[i + 1])
                    elif tok == "tw":
                        tw = int(tokens[i + 1])
                break
        if inuse is None:
            return 0
        lines = table_path.read_text(encoding="utf-8", errors="replace").splitlines()
        visible = max(0, len(lines) - 1)  # minus header row
        # /proc/net/tcp lists both active (inuse) and timewait (tw) sockets via tcp4_seq_show
        return max(0, (inuse + tw) - visible)
    except (OSError, ValueError):
        return 0


class RootkitSensor:
    """Refmon `Sensor` adapter: streams rootkit findings into `Pipeline` as privacy-safe events."""

    def __init__(
        self,
        scanner: RootkitScanner | None = None,
        *,
        findings: list[RootkitFinding] | None = None,
        device: str = "local-host",
    ) -> None:
        self.scanner = scanner or RootkitScanner()
        self._preset_findings = findings
        self.device = device
        self.last_findings: list[RootkitFinding] = []

    def emit(self, sink: Callable[[AnyEvent], None]) -> None:
        if self._preset_findings is not None:
            findings = list(self._preset_findings)
        else:
            findings, _, _, _ = self.scanner.scan()
        self.last_findings = findings
        now = datetime.now(UTC)
        actor = Actor(
            id="proc:rootkit-scan",
            parent=None,
            role="system_service",
            interactive=False,
            user="scanner",
        )
        for idx, finding in enumerate(findings, 1):
            ev_id = f"rk-{idx:06d}"
            if finding.severity == "high" or finding.self_tamper:
                obj_cls = "refmon_component" if finding.self_tamper else "kernel_or_runtime"
                sink(
                    RawEvent(
                        event_id=ev_id,
                        ts=now,
                        device=self.device,
                        type=EventType.SECURITY_TAMPER,
                        actor=actor,
                        object=RawObjectRef.model_validate(
                            {"class": obj_cls, "fingerprint": finding.subject_fingerprint}
                        ),
                    )
                )
            else:
                # Medium-confidence standalone anomaly (e.g. lone anonymous rwxp JIT or promisc):
                # emit `exec` with `hidden_window=True` -> `effect_hide` (+2.0 nats -> HOLD),
                # never killing a benign process unless paired with a contract/tamper violation.
                sink(
                    RawEvent(
                        event_id=ev_id,
                        ts=now,
                        device=self.device,
                        type=EventType.EXEC,
                        actor=actor,
                        object=RawObjectRef.model_validate(
                            {"class": "memory_region", "fingerprint": finding.subject_fingerprint}
                        ),
                        attrs={"hidden_window": True, "exec_class": "service_bin"},
                    )
                )


def evaluate_rootkit_scan(
    config: ScanConfig | None = None,
    *,
    policy: Policy | None = None,
    key: bytes = b"refmon-device-key",
) -> tuple[RootkitScanReport, RunReport]:
    """Run all rootkit scanners, score with the Bayesian evidence calculus, and run `Pipeline`."""
    pol = default_policy() if policy is None else policy
    cfg = config or ScanConfig()
    scanner = RootkitScanner(cfg, key=key)
    findings, caps, notes, (own_n, mod_n, iface_n) = scanner.scan()

    prior_lo = calc.prior_log_odds(pol.math.prior_attack)
    hold_thr = calc.hold_threshold(pol.math.costs, pol.math.hold_catch_rate)
    block_thr = calc.block_threshold(pol.math.costs)

    # Group by scanner family: max within each family (correlated), sum across orthogonal families.
    by_scanner: dict[str, float] = {}
    has_contract = False
    self_tamper = False
    for f in findings:
        by_scanner[f.scanner] = max(by_scanner.get(f.scanner, 0.0), f.nats)
        if f.question == "contract" or f.severity == "high":
            has_contract = True
        if f.self_tamper:
            self_tamper = True

    total_lo = prior_lo + sum(by_scanner.values())
    outcome = calc.decide(
        total_lo,
        block_thr,
        hold_thr,
        has_contract_signal=has_contract,
        override=Decision.BLOCK if self_tamper else None,
    )
    calc_decision = outcome.decision

    pipe = Pipeline(pol, key=key, gate=True)
    enforcer = SimulatedEnforcer()
    sensor = RootkitSensor(scanner, findings=findings, device=cfg.device)
    run_rep = run_pipeline(sensor, pipe, enforcer)
    best = pipe.best()
    pipe_decision = best.decision if best is not None else Decision.ALLOW

    report = RootkitScanReport(
        scanned_at=datetime.now(UTC).isoformat(timespec="seconds"),
        passes=max(1, cfg.passes),
        own_processes_inspected=own_n,
        kernel_modules_checked=mod_n,
        network_interfaces_checked=iface_n,
        capabilities=caps,
        context_notes=tuple(notes),
        findings=tuple(findings),
        prior_log_odds=prior_lo,
        log_odds=total_lo,
        hold_threshold=hold_thr,
        block_threshold=block_thr,
        calculus_decision=calc_decision,
        pipeline_decision=pipe_decision,
        self_tamper=self_tamper,
        verdicts_emitted=len(run_rep.verdicts),
        actions_emitted=len(run_rep.actions),
    )
    return report, run_rep


def format_scan_report(report: RootkitScanReport) -> str:
    """Human-readable summary for CLI output (contains fingerprints only, zero raw paths)."""
    lines = [
        "Refmon Rootkit & Stealth Scanner",
        f"  scanned at             {report.scanned_at}",
        f"  two-view passes        {report.passes}",
        f"  own processes checked  {report.own_processes_inspected}",
        f"  kernel modules checked {report.kernel_modules_checked}",
        f"  net interfaces checked {report.network_interfaces_checked}",
        f"  prior log-odds (nats)  {report.prior_log_odds:+.2f}",
        f"  total log-odds (nats)  {report.log_odds:+.2f}"
        f"  (hold >= {report.hold_threshold:+.2f}, block >= {report.block_threshold:+.2f})",
        f"  calculus decision      {report.calculus_decision.value.upper()}",
        f"  pipeline verdict       {report.pipeline_decision.value.upper()}"
        + (" (OVR-SELF-TAMPER)" if report.self_tamper else ""),
        f"  findings               {len(report.findings)}",
    ]
    for note in report.context_notes:
        lines.append(f"  note                   {note}")
    for f in report.findings:
        tamper = " [SELF_TAMPER]" if f.self_tamper else ""
        lines.append(
            f"  - [{f.severity.upper()}] {f.scanner}/{f.kind}: "
            f"+{f.nats:.2f} nats (count={f.count}, {f.subject_fingerprint[:21]}...){tamper}"
        )
    return "\n".join(lines)
