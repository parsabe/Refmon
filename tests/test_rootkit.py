"""Tests for the multi-engine rootkit scanners, cross-view persistence math and Pipeline sensor."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from refmon.cli import main as cli_main
from refmon.rootkit import (
    RootkitScanner,
    ScanConfig,
    crossview_nats,
    evaluate_rootkit_scan,
    format_scan_report,
)
from refmon.schemas import Decision, Override


def _make_clean_tree(base: Path) -> tuple[Path, Path, Path]:
    proc = base / "proc"
    sys_ = base / "sys"
    etc = base / "etc"
    (proc / "sys" / "kernel").mkdir(parents=True)
    (proc / "net").mkdir(parents=True)
    (sys_ / "module" / "ext4").mkdir(parents=True)
    (sys_ / "module" / "nvidia").mkdir(parents=True)
    (sys_ / "module" / "kernel_builtin_param").mkdir(parents=True)  # no initstate -> ignored
    (sys_ / "class" / "net" / "eth0").mkdir(parents=True)
    etc.mkdir(parents=True)

    (sys_ / "module" / "ext4" / "initstate").write_text("live\n")
    (sys_ / "module" / "nvidia" / "initstate").write_text("live\n")
    (proc / "modules").write_text("ext4 900000 1 - Live 0x0\nnvidia 50000000 4 - Live 0x0\n")
    # 12289 = P (1) + O (4096) + E (8192), standard proprietary GPU driver taint
    (proc / "sys" / "kernel" / "tainted").write_text("12289\n")
    (sys_ / "class" / "net" / "eth0" / "flags").write_text("0x1003\n")
    (proc / "net" / "sockstat").write_text("sockets: used 4\nTCP: inuse 1 orphan 0 tw 0 alloc 2\n")
    (proc / "net" / "tcp").write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue\n"
        "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000\n"
    )

    p100 = proc / "100"
    (p100 / "task" / "100").mkdir(parents=True)
    (p100 / "environ").write_bytes(b"PATH=/usr/bin:/bin\x00LANG=C.UTF-8\x00")
    (p100 / "status").write_text("Name:\tpython3\nTgid:\t100\nPid:\t100\nPPid:\t1\nTracerPid:\t0\n")
    (p100 / "maps").write_text(
        "55a00000-55a01000 r-xp 00000000 08:01 12345 /usr/bin/python3.12\n"
        "7f000000-7f002000 rw-p 00000000 00:00 0 [heap]\n"
    )
    (p100 / "exe").symlink_to("/usr/bin/python3")
    return proc, sys_, etc


def _cfg(proc: Path, sys_: Path, etc: Path, **over) -> ScanConfig:
    defaults = {
        "proc_root": proc,
        "sys_root": sys_,
        "etc_root": etc,
        "passes": 2,
        "pass_interval_s": 0.0,
        "target_uid": os.getuid(),
        "self_pid": 100,
    }
    defaults.update(over)
    return ScanConfig(**defaults)


def test_clean_tree_with_gpu_taint_is_allowed_with_zero_findings(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    report, run_rep = evaluate_rootkit_scan(_cfg(proc, sys_, etc))
    assert report.findings == ()
    assert report.calculus_decision is Decision.ALLOW
    assert report.pipeline_decision is Decision.ALLOW
    assert run_rep.verdicts == []
    assert any("P:proprietary" in n for n in report.context_notes)


def test_crossview_nats_increases_with_passes_and_respects_cap():
    n1 = crossview_nats(1, race_prob=1e-2, cap=20.0)
    n2 = crossview_nats(2, race_prob=1e-2, cap=20.0)
    assert n2 > n1 > 4.0
    assert crossview_nats(5, race_prob=1e-3, cap=8.0) == 8.0
    with pytest.raises(ValueError):
        crossview_nats(0)


def test_etc_ld_so_preload_triggers_self_tamper_block_and_redacts_raw_path(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    raw_so = "/var/tmp/stealth_hook.so"
    (etc / "ld.so.preload").write_text(f"# comment\n{raw_so}\n")

    report, _ = evaluate_rootkit_scan(_cfg(proc, sys_, etc))
    assert report.self_tamper is True
    assert report.calculus_decision is Decision.BLOCK
    assert report.pipeline_decision is Decision.BLOCK
    assert any(f.kind == "etc_ld_so_preload" for f in report.findings)
    rendered = format_scan_report(report) + json.dumps(report.to_dict())
    assert raw_so not in rendered
    assert "hmac:" in rendered


def test_process_ld_preload_on_self_triggers_self_tamper_override(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    (proc / "100" / "environ").write_bytes(b"LD_PRELOAD=/dev/shm/rk.so\x00PATH=/usr/bin\x00")

    report, run_rep = evaluate_rootkit_scan(_cfg(proc, sys_, etc, self_pid=100))
    assert report.self_tamper is True
    assert report.pipeline_decision is Decision.BLOCK
    assert run_rep.verdicts[0].override is Override.SELF_TAMPER


def test_memfd_and_deleted_executables_are_blocked(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    p200 = proc / "200"
    p200.mkdir()
    (p200 / "environ").write_bytes(b"PATH=/usr/bin\x00")
    (p200 / "status").write_text("Name:\tworker\nTgid:\t200\nPid:\t200\nPPid:\t1\nTracerPid:\t0\n")
    (p200 / "maps").write_text("")
    (p200 / "exe").symlink_to("/memfd:implant (deleted)")

    report, _ = evaluate_rootkit_scan(_cfg(proc, sys_, etc))
    assert any(f.kind == "memfd_execution" for f in report.findings)
    assert report.calculus_decision is Decision.BLOCK
    assert report.pipeline_decision is Decision.BLOCK


def test_ptrace_tracer_pid_and_deleted_shared_object_detected(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    p300 = proc / "300"
    p300.mkdir()
    (p300 / "environ").write_bytes(b"LD_LIBRARY_PATH=/dev/shm/evil:/usr/lib\x00")
    (p300 / "status").write_text("Name:\tsvc\nTgid:\t300\nPid:\t300\nPPid:\t1\nTracerPid:\t999\n")
    (p300 / "maps").write_text(
        "7f100000-7f105000 r-xp 00000000 00:19 555 /dev/shm/inject.so (deleted)\n"
    )

    report, _ = evaluate_rootkit_scan(_cfg(proc, sys_, etc))
    kinds = {f.kind for f in report.findings}
    assert {"ptrace_attached", "deleted_or_ephemeral_so", "ephemeral_ld_library_path"} <= kinds
    assert report.calculus_decision is Decision.BLOCK
    assert "/dev/shm/inject.so" not in json.dumps(report.to_dict())


def test_lone_anonymous_rwx_region_holds_without_false_block(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    (proc / "100" / "maps").write_text("7f200000-7f204000 rwxp 00000000 00:00 0 \n")

    report, _ = evaluate_rootkit_scan(_cfg(proc, sys_, etc, self_pid=9999))
    assert [f.kind for f in report.findings] == ["anonymous_rwx_memory"]
    assert report.calculus_decision is Decision.HOLD
    assert report.pipeline_decision is Decision.HOLD


def test_hidden_kernel_module_caught_by_sysfs_vs_proc_modules_crossview(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    # `diamorphine` unlinked itself from /proc/modules but its kobject stays in /sys/module
    (sys_ / "module" / "diamorphine").mkdir(parents=True)
    (sys_ / "module" / "diamorphine" / "initstate").write_text("live\n")

    report, _ = evaluate_rootkit_scan(_cfg(proc, sys_, etc))
    assert any(f.kind == "hidden_kernel_module" for f in report.findings)
    assert report.calculus_decision is Decision.BLOCK
    assert "diamorphine" not in format_scan_report(report)


def test_transient_single_pass_module_churn_is_suppressed_by_two_pass_intersection(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    scanner = RootkitScanner(_cfg(proc, sys_, etc, passes=2))
    snapshots = [({"transient_mod"}, 3), (set(), 2)]
    with patch.object(scanner, "_snapshot_hidden_modules", side_effect=snapshots):
        findings, _, _, _ = scanner.scan()
    assert [f for f in findings if f.kind == "hidden_kernel_module"] == []


def test_forced_kernel_module_taint_is_flagged(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    (proc / "sys" / "kernel" / "tainted").write_text(str(1 << 1) + "\n")  # insmod -f

    report, _ = evaluate_rootkit_scan(_cfg(proc, sys_, etc))
    assert any(f.kind == "kernel_forced_taint" for f in report.findings)
    assert report.calculus_decision is Decision.BLOCK


def test_hidden_tcp_sockets_and_promiscuous_sniffer_detected(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    # sockstat says 5 active TCP sockets, /proc/net/tcp shows only 1 -> 4 hidden by tcp4_seq_show
    (proc / "net" / "sockstat").write_text("sockets: used 9\nTCP: inuse 5 orphan 0 tw 0 alloc 7\n")
    (sys_ / "class" / "net" / "eth0" / "flags").write_text("0x1103\n")  # IFF_PROMISC (0x100) set

    report, _ = evaluate_rootkit_scan(_cfg(proc, sys_, etc))
    kinds = {f.kind for f in report.findings}
    assert "hidden_tcp_socket" in kinds
    assert "promiscuous_interface" in kinds
    assert report.calculus_decision is Decision.BLOCK


def test_hidden_pid_detected_when_omitted_from_proc_getdents(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    # Process 100 has PPid 777, which exists on direct lookup /proc/777 but is hidden from iterdir
    p777 = proc / "777"
    p777.mkdir()
    (p777 / "status").write_text("Name:\trk\nTgid:\t777\nPid:\t777\nPPid:\t1\nTracerPid:\t0\n")
    (proc / "100" / "status").write_text(
        "Name:\tpython3\nTgid:\t100\nPid:\t100\nPPid:\t777\nTracerPid:\t0\n"
    )

    real_iterdir = Path.iterdir

    def hooked_iterdir(self_path: Path):
        for item in real_iterdir(self_path):
            if self_path == proc and item.name == "777":
                continue  # simulate getdents64 rootkit hiding PID 777
            yield item

    with patch.object(Path, "iterdir", hooked_iterdir):
        report, _ = evaluate_rootkit_scan(_cfg(proc, sys_, etc))
    assert any(f.kind == "hidden_pid_discrepancy" for f in report.findings)
    assert report.calculus_decision is Decision.BLOCK


def test_cli_scan_rootkit_runs_read_only_on_live_host(capsys):
    code = cli_main(["scan-rootkit", "--json", "--passes", "2", "--interval-ms", "10"])
    payload = json.loads(capsys.readouterr().out)
    assert code in (0, 1)
    assert payload["passes"] == 2
    assert payload["calculus_decision"] in {"allow", "hold", "block"}
    assert "proc_fs" in payload["capabilities"]
