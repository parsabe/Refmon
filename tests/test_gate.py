"""Gate (CLAUDE.md Phase 3): the mode downgrade and the two hold flows."""

from datetime import timedelta

import pytest

from evhelp import T0, ev
from refmon.enforcer import SimulatedEnforcer
from refmon.gate import HoldState, RecordingNotifier
from refmon.pipeline import Pipeline
from refmon.policy import default_policy
from refmon.schemas import Action, ActionType, Decision, Mode, Verdict
from refmon.simworld import SimWorld


def run(events, policy, *, notifier=None):
    pipe = Pipeline(policy, gate=True, notifier=notifier or RecordingNotifier())
    out = []
    for e in events:
        out.extend(pipe.process(e))
    return pipe, out


def actions(out):
    return [o for o in out if isinstance(o, Action)]


def kinds(out):
    return [(a.type.value, a.target.ref) for a in actions(out)]


# Two fails (origin + effect): a hold. A process with no contract that handles an inbound request
# and then connects to an unknown host. The device decides which hold flow it gets.
def hold_events(role="other", pid="p-1"):
    return [
        ev("request_in", role, pid, f=1, source_class="inbound_request", t=0),
        ev("net_connect", role, pid, f=2, t=2, destination_class="unknown"),
    ]


def endpoint_hold_events():
    return hold_events("other", "p-1")


def server_hold_events():  # an app server is a server role, so the story is a server story
    return hold_events("app_server", "p-9")


def block_policy(**kw):
    # the hold flows are tested on the plain fail rule, whose decisions the policy maps
    return default_policy(mode="block", engine="rule", **kw)


# -- mode downgrade ------------------------------------------------------------------------------------------


def test_observe_never_acts_but_the_verdict_is_still_emitted():
    pipe, out = run(endpoint_hold_events(), default_policy(mode="observe"))
    assert any(isinstance(o, Verdict) for o in out)
    assert actions(out) == []
    assert pipe.gate.holds == {}


def test_warn_never_blocks_it_tells_and_does_nothing_to_the_system():
    events = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("exec", "web_worker", "p-1", f=2, t=1, exec_class="unknown"),
        ev("net_connect", "web_worker", "p-1", f=3, t=2, destination_class="unknown"),
    ]
    notifier = RecordingNotifier()
    pipe, out = run(events, default_policy(mode="warn", engine="rule"), notifier=notifier)
    assert [j.decision for j in pipe.judgements().values()] == [Decision.BLOCK]
    assert actions(out) == []
    assert [n.kind for n in notifier.notices] == ["warning", "warning"]  # hold, then block rank
    assert notifier.prompts == []


def test_a_rule_setting_can_raise_one_rule_to_block_while_the_global_mode_observes():
    events = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("exec", "web_worker", "p-1", f=2, t=1, exec_class="unknown"),
        ev("net_connect", "web_worker", "p-1", f=3, t=2, destination_class="unknown"),
    ]
    settings = [{"id": "R-CON-WEB-WORKER-EXEC", "mode": "block", "role": "web_worker"}]
    _, out = run(events, default_policy(mode="observe", rules=settings))
    assert ("kill_process_tree", "p-1") in kinds(out)


def test_the_effective_mode_is_the_verdicts_mode():
    _, out = run(endpoint_hold_events(), default_policy(mode="warn"))
    assert {v.mode for v in out if isinstance(v, Verdict)} == {Mode.WARN}


# -- endpoint hold -------------------------------------------------------------------------------------------


def test_an_endpoint_hold_pauses_the_labeled_process_and_asks_in_plain_language():
    notifier = RecordingNotifier()
    _pipe, out = run(endpoint_hold_events(), block_policy(), notifier=notifier)
    assert kinds(out) == [("hold", "p-1")]
    [prompt] = notifier.prompts
    assert prompt.options == ("stop", "continue")
    assert "Do you want it to stop" in prompt.text
    assert "came in from outside" in prompt.text
    assert prompt.deadline == T0 + timedelta(seconds=2 + 60)
    assert notifier.notices == []


def test_no_answer_in_time_means_stop_and_the_story_is_contained():
    pipe, _ = run(endpoint_hold_events(), block_policy())
    [case] = pipe.gate.holds.values()
    res = pipe.gate.tick(case.deadline - timedelta(seconds=1))
    assert res == [] and case.state is HoldState.PENDING
    res = pipe.gate.tick(case.deadline)
    assert case.state is HoldState.CONTAINED
    assert ("kill_process_tree", "p-1") in [(a.type.value, a.target.ref) for a in res]


def test_a_late_event_resolves_an_expired_hold_through_the_pipeline():
    events = [*endpoint_hold_events(), ev("exec", "other", "p-9", f=9, t=500, exec_class="unknown")]
    _, out = run(events, block_policy())
    assert any(a.type is ActionType.KILL_PROCESS_TREE for a in actions(out))


def test_continue_releases_the_hold():
    pipe, _ = run(endpoint_hold_events(), block_policy())
    [case] = pipe.gate.holds.values()
    res = pipe.gate.answer_user(case.hold_id, "continue", case.started + timedelta(seconds=5))
    assert res.undo == case.action_ids and res.actions == []
    assert case.state is HoldState.RELEASED


def test_stop_contains_the_story_like_a_block():
    pipe, _ = run(endpoint_hold_events(), block_policy())
    [case] = pipe.gate.holds.values()
    res = pipe.gate.answer_user(case.hold_id, "stop", case.started + timedelta(seconds=5))
    assert ("kill_process_tree", "p-1") in [(a.type.value, a.target.ref) for a in res.actions]


def test_an_answer_after_the_deadline_counts_as_stop():
    pipe, _ = run(endpoint_hold_events(), block_policy())
    [case] = pipe.gate.holds.values()
    res = pipe.gate.answer_user(case.hold_id, "continue", case.deadline + timedelta(seconds=1))
    assert res.actions and case.state is HoldState.CONTAINED


def test_continue_is_not_offered_when_all_three_questions_failed():
    events = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("exec", "web_worker", "p-1", f=2, t=1, exec_class="unknown"),
        ev("net_connect", "web_worker", "p-1", f=3, t=2, destination_class="unknown"),
    ]
    notifier = RecordingNotifier()
    policy = block_policy(decisions={"fails_3": "hold"}, devices={"dev-1": "endpoint"})
    pipe, _ = run(events, policy, notifier=notifier)
    prompt = notifier.prompts[-1]
    assert prompt.options == ("stop",)
    [case] = [c for c in pipe.gate.holds.values()]
    assert not case.can_continue
    with pytest.raises(ValueError, match="not offered"):
        pipe.gate.answer_user(case.hold_id, "continue", case.started)


def test_only_stop_or_continue_are_valid_answers():
    pipe, _ = run(endpoint_hold_events(), block_policy())
    [case] = pipe.gate.holds.values()
    with pytest.raises(ValueError):
        pipe.gate.answer_user(case.hold_id, "maybe", case.started)
    with pytest.raises(ValueError):
        pipe.gate.answer_user("h-404", "stop", case.started)


# -- server hold --------------------------------------------------------------------------------------------


def server_policy(**kw):
    return block_policy(**kw)


def test_a_server_hold_pauses_quarantines_and_tells_the_admin_not_the_user():
    events = [
        *server_hold_events(),
        ev("file_write", "app_server", "p-9", f=7, t=3, path_group="uploads", new_file=True),
    ]
    notifier = RecordingNotifier()
    pipe, out = run(events, server_policy(), notifier=notifier)
    [case] = pipe.gate.holds.values()
    assert case.platform == "server"
    assert notifier.prompts == []
    assert [n.kind for n in notifier.notices] == ["hold"]
    assert ("hold", "p-9") in kinds(out)
    assert ("quarantine_file", events[-1].object.fingerprint) in kinds(out)


def test_a_server_hold_without_an_answer_stays_quarantined():
    pipe, _ = run(server_hold_events(), server_policy())
    [case] = pipe.gate.holds.values()
    assert pipe.gate.tick(case.deadline + timedelta(hours=1)) == []
    assert case.state is HoldState.KEPT_QUARANTINED
    assert pipe.gate.notifier.notices[-1].kind == "still_quarantined"
    res = pipe.gate.answer_admin(case.hold_id, "release", case.deadline + timedelta(hours=2))
    assert res.undo == case.action_ids
    assert case.state is HoldState.RELEASED


def test_an_admin_can_confirm_and_contain():
    pipe, _ = run(server_hold_events(), server_policy())
    [case] = pipe.gate.holds.values()
    res = pipe.gate.answer_admin(case.hold_id, "confirm", case.started)
    assert ("kill_process_tree", "p-9") in [(a.type.value, a.target.ref) for a in res.actions]
    with pytest.raises(ValueError):
        pipe.gate.answer_admin(case.hold_id, "release", case.started)


def test_the_user_cannot_answer_a_server_hold():
    pipe, _ = run(server_hold_events(), server_policy())
    [case] = pipe.gate.holds.values()
    with pytest.raises(ValueError):
        pipe.gate.answer_user(case.hold_id, "continue", case.started)


def test_the_platform_comes_from_the_device_or_else_from_the_roles():
    p = default_policy(devices={"dev-9": "endpoint"})
    assert p.platform_for("dev-9", {"web_worker"}) == "endpoint"
    assert p.platform_for("dev-x", {"web_worker"}) == "server"
    assert p.platform_for("dev-x", {"browser"}) == "endpoint"


# -- blocking is latched and idempotent ----------------------------------------------------------------------------


def test_no_action_is_issued_twice_and_a_blocked_story_stays_blocked():
    events = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("exec", "web_worker", "p-1", f=2, t=1, exec_class="unknown"),
        ev("net_connect", "web_worker", "p-1", f=3, t=2, destination_class="unknown"),
        ev("net_connect", "web_worker", "p-1", f=3, t=3, destination_class="unknown"),
        ev("file_write", "web_worker", "p-1", f=8, t=4, path_group="cache", new_file=True),
    ]
    _, out = run(events, block_policy())
    keys = kinds(out)
    assert len(keys) == len(set(keys))
    assert ("quarantine_file", events[-1].object.fingerprint) in keys  # added after the block


def test_the_action_carries_the_story_and_verdict_it_belongs_to():
    _, out = run(endpoint_hold_events(), block_policy())
    verdict = [o for o in out if isinstance(o, Verdict)][-1]
    for a in actions(out):
        assert a.verdict_id == verdict.verdict_id
        assert a.story_id == verdict.story_id


def test_run_through_the_enforcer_the_world_changes(tmp_path):
    events = endpoint_hold_events()
    enforcer = SimulatedEnforcer(SimWorld.from_events(events))
    pipe = Pipeline(block_policy(), gate=True)
    for e in events:
        for o in pipe.process(e):
            if isinstance(o, Action):
                assert enforcer.act(o).ok
    assert enforcer.world.process["p-1"] == "paused"
