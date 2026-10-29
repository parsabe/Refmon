"""The reviewer's answers after Phase 7 (A44, A45). None of them changes a decision: warn mode stays
notice-only, an exposure escalation tells the administrator at once and may wait for an approval
when the policy asks for it, and the fall back to the 3/2/1 rule is logged and reported."""

import logging
from datetime import timedelta
from pathlib import Path

import pytest

from evhelp import T0, ev
from refmon.exposure import ExposureManager, load_advisories, load_inventory
from refmon.gate import RecordingNotifier
from refmon.heartbeat import HeartbeatMonitor, build
from refmon.pipeline import Pipeline
from refmon.policy import default_policy, default_policy_dict
from refmon.pseudonym import Pseudonymizer
from refmon.schemas import ActionType, Mode

FIXTURES = Path(__file__).parent / "exposure"
ADVISORIES = load_advisories(FIXTURES / "advisories.yaml")
NOW = T0 + timedelta(hours=1)


def inventory(name):
    return load_inventory(FIXTURES / name)


# -- warn mode stays notice-only (A17, confirmed) --------------------------------------------------


def test_warn_mode_tells_and_touches_nothing():
    notifier = RecordingNotifier()
    pipe = Pipeline(default_policy(mode="warn", engine="rule"), gate=True, notifier=notifier)
    out = []
    for e in (
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("exec", "web_worker", "p-1", f=2, t=1, exec_class="unknown"),
        ev("net_connect", "web_worker", "p-1", f=3, t=2, destination_class="unknown"),
    ):
        out += pipe.process(e)
    assert [o for o in out if getattr(o, "type", None) in set(ActionType)] == []
    assert notifier.prompts == [] and notifier.notices
    assert {n.kind for n in notifier.notices} == {"warning"}


# -- exposure escalation: no approval by default, the administrator hears at once -------------------


def test_an_escalation_applies_at_once_and_the_admin_is_told_immediately():
    notifier = RecordingNotifier()
    manager = ExposureManager(default_policy(mode="observe"), notifier)
    change = manager.update(inventory("s16.inventory.exposed.yaml"), ADVISORIES, NOW)
    assert change.escalated == ("web_worker",) and change.pending == ()
    assert manager.effective_policy.rule_mode("R-CON-WEB-WORKER-EXEC", "web_worker") is Mode.BLOCK
    [notice] = notifier.notices
    assert notice.kind == "exposure_escalated" and notice.role == "web_worker" and notice.ts == NOW
    assert "webshop:ADV-2026-001" in notice.text and notice.story_id is None


def test_the_reversion_is_reported_too_and_nothing_is_said_when_nothing_changes():
    notifier = RecordingNotifier()
    manager = ExposureManager(default_policy(mode="observe"), notifier)
    manager.update(inventory("s16.inventory.exposed.yaml"), ADVISORIES, NOW)
    manager.update(inventory("s16.inventory.exposed.yaml"), ADVISORIES, NOW)  # same state
    manager.update(inventory("s16.inventory.patched.yaml"), ADVISORIES, NOW)
    assert [n.kind for n in notifier.notices] == ["exposure_escalated", "exposure_reverted"]


def flagged(*roles):
    data = default_policy_dict()
    data["mode"] = "observe"
    data["exposure"] = {**data["exposure"], "require_approval": list(roles)}
    return type(default_policy()).parse(data)


def test_a_role_flagged_for_approval_waits_and_runs_as_before_until_it_is_approved():
    notifier = RecordingNotifier()
    manager = ExposureManager(flagged("web_worker"), notifier)
    change = manager.update(inventory("s16.inventory.exposed.yaml"), ADVISORIES, NOW)
    assert (change.escalated, change.pending) == ((), ("web_worker",))
    assert manager.effective_policy is manager.base  # nothing tightened yet
    assert [n.kind for n in notifier.notices] == ["exposure_approval_needed"]

    change = manager.approve("web_worker", "admin-anna", NOW)
    assert change.escalated == ("web_worker",)
    assert manager.effective_policy.rule_mode("R-CON-WEB-WORKER-EXEC", "web_worker") is Mode.BLOCK
    assert [n.kind for n in notifier.notices] == ["exposure_approval_needed", "exposure_escalated"]
    assert "admin-anna" in notifier.notices[-1].text


def test_only_the_flagged_role_waits_the_others_escalate_at_once():
    manager = ExposureManager(flagged("web_worker"))
    manager.update(inventory("s28.inventory.eol.yaml"), ADVISORIES, NOW)
    assert manager.exposure.escalated.keys() == {"node_app_server"}
    assert manager.applied == {"node_app_server"} and manager.pending == set()


def test_an_approval_needs_a_waiting_role_and_ends_with_the_exposure():
    manager = ExposureManager(flagged("web_worker"))
    with pytest.raises(ValueError):
        manager.approve("web_worker", "admin-anna", NOW)
    manager.update(inventory("s16.inventory.exposed.yaml"), ADVISORIES, NOW)
    manager.approve("web_worker", "admin-anna", NOW)
    manager.update(inventory("s16.inventory.patched.yaml"), ADVISORIES, NOW)
    assert manager.applied == set() and manager.approved == {}
    manager.update(inventory("s16.inventory.exposed.yaml"), ADVISORIES, NOW)
    assert manager.pending == {"web_worker"}  # a new exposure needs a new approval


def test_a_policy_edit_never_loosens_a_role_that_is_already_tightened():
    manager = ExposureManager(default_policy(mode="observe"))
    manager.update(inventory("s16.inventory.exposed.yaml"), ADVISORIES, NOW)
    manager.rebase(flagged("web_worker"), NOW)  # the flag now asks for an approval
    assert manager.applied == {"web_worker"} and manager.pending == set()
    assert manager.effective_policy.rule_mode("R-CON-WEB-WORKER-EXEC", "web_worker") is Mode.BLOCK


# -- the fall back to the 3/2/1 rule is logged and reported (A28) ----------------------------------


def no_weights():
    data = default_policy_dict()
    data["math"] = {**data["math"], "weights": {}}
    return type(default_policy()).parse(data)


def test_the_fallback_to_the_plain_rule_is_logged(caplog):
    with caplog.at_level(logging.WARNING, logger="refmon.pipeline"):
        Pipeline(no_weights())
    assert "decision engine fallback" in caplog.text and "3/2/1" in caplog.text


def test_no_log_when_the_calculus_or_an_explicit_rule_engine_is_in_use(caplog):
    with caplog.at_level(logging.WARNING, logger="refmon.pipeline"):
        Pipeline(default_policy())
        Pipeline(default_policy(engine="rule"))  # chosen, not a fallback
    assert caplog.text == ""


def test_a_reload_that_loses_the_weights_is_logged(caplog):
    pipe = Pipeline(default_policy())
    with caplog.at_level(logging.WARNING, logger="refmon.pipeline"):
        pipe.set_policy(no_weights())
        pipe.set_policy(no_weights())  # still the fallback: said once
    assert caplog.text.count("decision engine fallback") == 1


def heartbeat(policy):
    return build(
        device="dev-7f3a", pseudonymizer=Pseudonymizer(b"k" * 32), policy=policy,
        policy_digest="abc123", now=NOW,
    )  # fmt: skip


def test_the_heartbeat_reports_the_engine_and_the_fallback_is_degraded_protection():
    assert heartbeat(default_policy()).decision_engine == "calculus"
    assert heartbeat(default_policy()).healthy
    assert heartbeat(default_policy(engine="rule")).decision_engine == "rule"
    hb = heartbeat(no_weights())
    assert hb.decision_engine == "rule_fallback" and not hb.healthy
    monitor = HeartbeatMonitor(stale_after=180)
    [alert] = monitor.receive(hb)
    assert alert.kind == "degraded_protection" and alert.subject == "decision_engine"
    assert monitor.receive(heartbeat(default_policy())) == []
