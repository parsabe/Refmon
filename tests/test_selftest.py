"""Self-test and heartbeat (CLAUDE.md Phase 6): disabling a protection makes its self-test alert,
a stale heartbeat raises an alert, tests are never incidents."""

from datetime import timedelta

import pytest

from evhelp import T0, ev
from refmon.alerts import AlertLog
from refmon.calculus.rarity import Baseline
from refmon.gate import RecordingNotifier
from refmon.heartbeat import (
    CAPABILITY_PROTECTIONS,
    HeartbeatMonitor,
    build,
    degraded_from,
)
from refmon.pipeline import Pipeline
from refmon.policy import Policy, RuleSetting, default_policy, default_policy_dict
from refmon.pseudonym import Pseudonymizer
from refmon.schemas import Mode
from refmon.selftest import SELFTEST_PREFIX, SelfTestScheduler, build_catalog

NOW = T0 + timedelta(hours=1)


def live(policy=None, **kw):
    return Pipeline(policy or default_policy(), gate=True, notifier=RecordingNotifier(), **kw)


def scheduler(pipe, intent=None):
    return SelfTestScheduler(pipe, intent or default_policy(), AlertLog())


def tampered(pipe, *protections):
    """Switch protections off in the LIVE pipeline only (the signed policy still wants them)."""
    off = [RuleSetting(id=p, enabled=False) for p in protections]
    pipe.set_policy(pipe.policy.model_copy(update={"rules": [*pipe.policy.rules, *off]}))


# -- the catalog --------------------------------------------------------------------------------------------------


def test_every_signal_rule_and_override_has_a_self_test():
    from refmon.rules import RULE_IDS

    covered = {c.protection for c in build_catalog()}
    # rarity needs a baseline and has its own case below
    assert RULE_IDS - {"R-CON-SURPRISAL"} <= covered
    assert {"DECISION-BLOCK", "GATE-CONTRACT", "BENIGN-ALLOW", "CONTAIN-KILL"} <= covered


def test_on_a_healthy_pipeline_every_applicable_protection_passes():
    report = scheduler(live()).run(NOW)
    assert report.failed == [] and report.ok
    assert len(report.passed) >= 30
    assert dict((r.protection, r.reason) for r in report.results if r.status == "skipped") == {
        "CONTAIN-KILL": "the global mode is not block"
    }


def test_in_block_mode_the_containment_is_tested_too():
    report = scheduler(live(default_policy(mode="block")), default_policy(mode="block")).run(NOW)
    assert report.ok and "CONTAIN-KILL" in report.passed and report.skipped == []


def test_the_rule_engine_fallback_is_self_tested_too():
    plain = default_policy(engine="rule")
    report = scheduler(live(plain), plain).run(NOW)
    assert report.ok
    assert "GATE-CONTRACT" in report.skipped  # the contract gate is part of the calculus


# -- "disabling a protection in a test makes its self-test alert" -----------------------------------------


SWITCHABLE = [c.protection for c in build_catalog() if c.protection.startswith(("R-", "OVR-"))]


@pytest.mark.parametrize("protection", SWITCHABLE)
def test_disabling_a_protection_makes_its_self_test_alert(protection):
    pipe = live()
    tampered(pipe, protection)
    sched = scheduler(pipe)  # the signed policy still enables it
    report = sched.run(NOW)
    assert protection in report.failed
    [alert] = [a for a in report.alerts if a.subject == protection]
    assert alert.kind == "selftest_failed"
    assert alert.message == f"protection {protection} is not working"
    assert sched.alerts.of_kind("selftest_failed")


def test_disabling_one_protection_does_not_make_the_others_fail():
    pipe = live()
    tampered(pipe, "R-EFF-TAMPER")
    report = scheduler(pipe).run(NOW)
    assert "R-EFF-TAMPER" in report.failed
    assert "R-EFF-HIDE" in report.passed and "R-EFF-FETCH" in report.passed


def test_a_broken_decision_stage_is_found_by_the_decision_cases(monkeypatch):
    import refmon.pipeline.judge as judge_module
    from refmon.calculus.evidence import Outcome
    from refmon.schemas import Decision

    monkeypatch.setattr(
        judge_module.calc, "decide", lambda *a, **k: Outcome(Decision.ALLOW, None, False)
    )
    report = scheduler(live()).run(NOW)
    assert {"DECISION-BLOCK", "GATE-CONTRACT"} <= set(report.failed)
    assert "BENIGN-ALLOW" in report.passed


def test_a_gate_that_does_nothing_is_found_by_the_containment_case(monkeypatch):
    import refmon.gate as gate_module

    monkeypatch.setattr(gate_module.Gate, "handle", lambda self, *a, **k: [])
    report = scheduler(live(default_policy(mode="block")), default_policy(mode="block")).run(NOW)
    assert report.failed == ["CONTAIN-KILL"]


def test_a_pipeline_with_tampered_weights_over_blocks_and_fails_the_benign_case():
    pipe = live()
    data = default_policy_dict()
    data["math"]["weights"]["origin_external"] = 6.0  # the live pipeline's weights were raised
    pipe.set_policy(Policy.parse(data))
    report = scheduler(pipe).run(NOW)
    assert "BENIGN-ALLOW" in report.failed


def test_a_crash_inside_a_protection_counts_as_that_protection_failing(monkeypatch):
    import refmon.pipeline.pipeline as pipeline_module

    real = pipeline_module.extract

    def boom(ev_, *a, **k):
        if ev_.device.startswith(SELFTEST_PREFIX) and ev_.type.value == "security_tamper":
            raise RuntimeError("broken")
        return real(ev_, *a, **k)

    monkeypatch.setattr(pipeline_module, "extract", boom)
    report = scheduler(live()).run(NOW)
    assert {"R-EFF-TAMPER", "OVR-SELF-TAMPER"} <= set(report.failed)


# -- what the signed policy intends -----------------------------------------------------------------------------


def test_a_protection_the_signed_policy_switched_off_is_skipped_not_alerted():
    intent = default_policy(rules=[{"id": "R-EFF-HIDE", "enabled": False}])
    pipe = live(intent)
    report = scheduler(pipe, intent).run(NOW)
    assert "R-EFF-HIDE" in report.skipped and report.ok
    assert dict((r.protection, r.reason) for r in report.results)["R-EFF-HIDE"] == (
        "switched off by the signed policy"
    )
    assert report.alerts == []


def test_a_case_that_does_not_apply_to_a_custom_policy_is_skipped_with_the_reason():
    data = default_policy_dict()
    del data["contracts"]["office"]
    custom = Policy.parse(data)
    report = scheduler(live(custom), custom).run(NOW)
    reasons = dict((r.protection, r.reason) for r in report.results)
    assert reasons["R-CON-EXEC-VIOLATION"] == "office has no exec contract"
    assert report.ok


def test_a_surprisal_case_exists_only_with_a_mature_baseline():
    counts = {"write:cache": 3000, "connect:db_server": 1000, "write:sessions": 100}
    pipe = live(baseline=Baseline({"web_worker": counts}))
    report = scheduler(pipe).run(NOW)
    assert "R-CON-SURPRISAL" in report.passed
    assert "R-CON-SURPRISAL" not in scheduler(live()).run(NOW).passed


def test_the_schedule_comes_from_the_policy():
    sched = scheduler(live(), default_policy(self_test={"interval": "6h"}))
    assert sched.tick(NOW) is not None
    assert sched.tick(NOW + timedelta(hours=5, minutes=59)) is None
    assert sched.tick(NOW + timedelta(hours=6)) is not None


# -- tests are never incidents ---------------------------------------------------------------------------------


def test_the_live_pipeline_never_sees_a_self_test_story():
    pipe = live(default_policy(mode="block"))
    notifier = pipe.gate.notifier
    before = (len(pipe.linker.records), len(pipe.tagger.labels), len(pipe.tagger.procs))
    scheduler(pipe, default_policy(mode="block")).run(NOW)
    assert (len(pipe.linker.records), len(pipe.tagger.labels), len(pipe.tagger.procs)) == before
    assert pipe.gate.holds == {} and notifier.prompts == [] and notifier.notices == []
    assert pipe.observe.buffer == type(pipe.observe.buffer)()
    assert pipe.last == {}


def test_a_self_test_does_not_teach_the_live_baselines():
    pipe = live()
    pipe.process(ev("file_write", "other", "p-1", f=1, t=0))
    before = {k: v.value for k, v in pipe.rates._baselines.items()}
    scheduler(pipe).run(NOW)
    assert {k: v.value for k, v in pipe.rates._baselines.items()} == before
    assert not pipe.rates._incident


def test_the_live_policy_is_not_changed_by_a_run():
    pipe = live()
    before = pipe.policy.model_dump()
    scheduler(pipe).run(NOW)
    assert pipe.policy.model_dump() == before


def test_a_self_test_event_uses_the_reserved_device_and_placeholder_content_only():
    from refmon.selftest import Story

    cases = build_catalog()
    story = Story("x", 7, NOW, default_policy())
    for case in cases[:12]:
        case.build(story)
    assert story.events and all(e.device == f"{SELFTEST_PREFIX}7" for e in story.events)
    assert all(e.actor.user == "selftest" for e in story.events)


def test_a_real_event_on_a_device_named_like_a_test_is_judged_normally():
    pipe = live(default_policy(mode="block"))
    events = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("exec", "web_worker", "p-1", f=2, t=1, exec_class="unknown"),
        ev("net_connect", "web_worker", "p-1", f=3, t=2, destination_class="unknown"),
    ]
    renamed = [e.model_copy(update={"device": "selftest-evil"}) for e in events]
    out = [o for e in renamed for o in pipe.process(e)]
    assert out  # nothing is suppressed: the self-test never touches the live pipeline's input


# -- heartbeat ---------------------------------------------------------------------------------------------------


def heartbeat(**kw):
    pseudo = Pseudonymizer(b"k" * 32)
    args = {
        "device": "dev-7f3a", "pseudonymizer": pseudo, "policy": default_policy(),
        "policy_digest": "abc123", "now": NOW,
    }  # fmt: skip
    return build(**{**args, **kw})


def test_a_heartbeat_reports_alive_policy_and_self_test_status_under_a_pseudonym():
    report = scheduler(live()).run(NOW)
    hb = heartbeat(selftest=report, capabilities=default_policy().heartbeat.required_capabilities)
    assert hb.alive and hb.healthy
    assert hb.policy_version == 2 and hb.policy_digest == "abc123"
    assert hb.device.startswith("ps-dev-") and "7f3a" not in hb.model_dump_json()
    assert hb.self_test.passed == len(report.passed) and hb.self_test.failed == ()


def test_a_missing_sensor_capability_is_reported_as_degraded_protection():
    hb = heartbeat(capabilities=["process_ancestry", "request_in", "file_writes",
                                 "network_connections", "privilege_changes"])  # fmt: skip
    [item] = hb.degraded
    assert item.capability == "signature_check"
    assert item.protections == ("R-CON-UNSIGNED-LAUNCH",)
    assert not hb.healthy


def test_a_sensor_that_says_nothing_about_its_capabilities_is_not_assumed_broken():
    assert heartbeat(capabilities=None).degraded == ()


def test_signed_unknown_in_the_stream_shows_the_signature_check_is_missing():
    hb = heartbeat(capabilities=None, signed_unknown_seen=True)
    assert [d.capability for d in hb.degraded] == ["signature_check"]
    assert "signed=unknown" in hb.degraded[0].reason


def test_every_required_capability_maps_to_protections():
    for cap in default_policy().heartbeat.required_capabilities:
        assert CAPABILITY_PROTECTIONS[cap]
    assert degraded_from(default_policy(), []).__len__() == len(
        default_policy().heartbeat.required_capabilities
    )


def test_switched_off_protections_are_listed():
    policy = default_policy(rules=[{"id": "R-EFF-HIDE", "enabled": False}])
    assert heartbeat(policy=policy).disabled_protections == ("R-EFF-HIDE",)


def test_a_stale_heartbeat_raises_an_alert_once_and_a_new_one_rearms_it():
    monitor = HeartbeatMonitor(stale_after=default_policy().heartbeat.stale_after)
    hb = heartbeat()
    assert monitor.receive(hb) == []
    assert monitor.check(NOW + timedelta(seconds=179)) == []
    [alert] = monitor.check(NOW + timedelta(seconds=181))
    assert alert.kind == "heartbeat_missing" and alert.subject == hb.device
    assert monitor.check(NOW + timedelta(seconds=400)) == []  # already told
    monitor.receive(heartbeat(now=NOW + timedelta(seconds=500)))
    assert monitor.check(NOW + timedelta(seconds=600)) == []
    assert len(monitor.check(NOW + timedelta(seconds=900))) == 1  # silent again


def test_a_device_that_never_reports_is_an_alert_too():
    monitor = HeartbeatMonitor(stale_after=180)
    monitor.expect("ps-dev-0000000000000001", NOW)
    assert monitor.check(NOW + timedelta(seconds=60)) == []
    [alert] = monitor.check(NOW + timedelta(seconds=200))
    assert alert.kind == "heartbeat_missing"


def test_the_heartbeat_carries_a_failed_self_test_and_degradation_to_the_monitor():
    pipe = live()
    tampered(pipe, "R-EFF-FETCH")
    report = scheduler(pipe).run(NOW)
    hb = heartbeat(selftest=report, capabilities=["process_ancestry"])
    assert "R-EFF-FETCH" in hb.self_test.failed
    monitor = HeartbeatMonitor(stale_after=180)
    kinds = [a.kind for a in monitor.receive(hb)]
    assert "selftest_failed" in kinds and "degraded_protection" in kinds


def test_the_heartbeat_interval_and_staleness_come_from_the_policy():
    p = default_policy(heartbeat={"interval": "30s", "stale_after": "90s"})
    assert (p.heartbeat.interval, p.heartbeat.stale_after) == (30.0, 90.0)


def test_global_mode_changes_are_visible_to_the_probe():
    pipe = live(default_policy(mode="warn"))
    sched = scheduler(pipe, default_policy(mode="warn"))
    assert sched.run(NOW).ok
    assert pipe.policy.mode is Mode.WARN
