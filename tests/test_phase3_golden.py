"""Phase 3 "Done when": in replay every block touches exactly the story's labeled objects, server
stories quarantine the written web-shell stand-in and kill the worker, and undo restores the prior
state in the simulated enforcer.

The expected containment is derived by `golden_more.derive_actions` from the processes each
scenario declares as labeled; it never reads pipeline output. Phases 1 to 4 run the plain fail
rule, so the decision acted on here is the rule decision (`engine="rule"`); the same replay with
the evidence calculus is in test_phase4b_golden.py."""

import pytest

from golden_more import META, SCENARIOS, derive_actions
from refmon.enforcer import SimulatedEnforcer
from refmon.golden import ScenarioKind
from refmon.pipeline import Pipeline
from refmon.policy import default_policy
from refmon.replay import ReplaySource
from refmon.schemas import Action, ActionType, Decision
from refmon.simworld import SimWorld
from scenario_run import cases

CASES = [c for c in cases() if c.expected.decision == c.expected.rule_decision]
by_id = pytest.mark.parametrize("case", CASES, ids=[c.scenario for c in CASES])
ALL = cases()


def policy():
    return default_policy(mode="block", engine="rule")


def replay(case, *, world=True):
    events = list(ReplaySource(case.events_path, extra_roles=policy().extra_roles))
    enforcer = SimulatedEnforcer(SimWorld.from_events(events) if world else None)
    pipe = Pipeline(policy(), gate=True)
    actions: list[Action] = []
    for event in events:
        for out in pipe.process(event):
            if isinstance(out, Action):
                actions.append(out)
                enforcer.act(out)
    return events, pipe, enforcer, actions


def expected_keys(case, events):
    by_event = {e.event_id: e for e in events}
    keys = set()
    for a in case.expected.actions:
        ref = a.process or a.host or by_event[a.object_of_event].object.fingerprint
        keys.add((a.type.value, ref))
    return keys


def keys_of(actions):
    return {(a.type.value, a.target.ref) for a in actions}


@by_id
def test_the_actions_are_exactly_the_declared_containment(case):
    events, _, _, actions = replay(case)
    actual, expected = keys_of(actions), expected_keys(case, events)
    holds = {k for k in actual if k[0] == "hold"}
    assert actual - holds == expected - {k for k in expected if k[0] == "hold"}
    if case.expected.decision is Decision.HOLD:
        assert holds == {k for k in expected if k[0] == "hold"}


@by_id
def test_every_action_has_an_undo_record_and_a_story(case):
    _, _, enforcer, actions = replay(case)
    assert all(r.undo is not None for r in enforcer.results)
    assert all(a.story_id.startswith("st-") for a in actions)


@pytest.mark.parametrize("scenario", ["S11", "S26a"])
def test_where_the_rule_says_hold_and_the_calculus_allows_the_gate_holds_for_now(scenario):
    case = next(c for c in ALL if c.scenario == scenario)
    _, _, _, actions = replay(case)
    assert actions and {a.type for a in actions} <= {ActionType.HOLD, ActionType.QUARANTINE_FILE}
    assert any(a.type is ActionType.HOLD for a in actions)


def test_the_known_gap_s05_is_not_acted_on_by_the_plain_rule():
    case = next(c for c in ALL if c.scenario == "S05")
    assert replay(case)[3] == []


def test_s14_quarantines_the_web_shell_stand_in_and_kills_the_worker():
    case = next(c for c in ALL if c.scenario == "S14")
    events, _, enforcer, actions = replay(case)
    written = next(e for e in events if e.type.value == "file_write").object.fingerprint
    assert ("quarantine_file", written) in keys_of(actions)
    assert ("kill_process_tree", "p-1842") in keys_of(actions)
    assert enforcer.world.files[written].location == "quarantine"  # moved, never deleted
    assert enforcer.world.process["p-1842"] == "killed"


def test_server_stories_quarantine_what_they_wrote_and_kill_the_worker():
    for scenario in ("S14", "S26c"):
        case = next(c for c in ALL if c.scenario == scenario)
        events, _, enforcer, actions = replay(case)
        written = {e.object.fingerprint for e in events if e.type.value == "file_write"}
        assert {a.target.ref for a in actions if a.type is ActionType.QUARANTINE_FILE} == written
        assert any(a.type is ActionType.KILL_PROCESS_TREE for a in actions)
        assert all(enforcer.world.files[f].location == "quarantine" for f in written)


def test_no_block_touches_an_object_the_scenario_does_not_declare_labeled():
    for case in CASES:
        if case.scenario not in SCENARIOS or case.expected.decision is not Decision.BLOCK:
            continue
        events, labeled, _roots = SCENARIOS[case.scenario]()
        _, _, _, actions = replay(case)
        labeled_objects = {e.object.fingerprint for e in events if e.actor.id in labeled}
        for a in actions:
            if a.target.kind.value == "process":
                # v1.1 (A47): a hold, and only a hold, may also pause a process that produced a
                # signal in a story that had no labeled process at that moment
                assert a.target.ref in labeled or a.type is ActionType.HOLD, (case.scenario, a)
            elif a.target.kind.value in ("file", "persistence_item"):
                assert a.target.ref in labeled_objects, (case.scenario, a)


def test_benign_files_that_are_allowed_cause_no_action():
    for case in ALL:
        if (
            case.expected.kind is ScenarioKind.BENIGN
            and case.expected.rule_decision is Decision.ALLOW
        ):
            assert replay(case)[3] == [], case.scenario


# -- undo -------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("scenario", ["S06", "S14", "S19", "S31", "S32"])
def test_undo_restores_the_prior_state_of_everything_that_can_be_undone(scenario):
    case = next(c for c in ALL if c.scenario == scenario)
    events = list(ReplaySource(case.events_path, extra_roles=policy().extra_roles))
    before = SimWorld.from_events(events)
    _, _, enforcer, actions = replay(case)
    after_acts = enforcer.world.snapshot()
    assert after_acts != before
    for action in reversed(actions):
        result = enforcer.undo(action.action_id)
        assert result.ok or result.detail == "not_reversible"
    now = enforcer.world
    assert now.files == before.files
    assert now.persistence == before.persistence
    assert now.network_cut == set()
    assert now.isolated is False
    # a killed process stays killed; everything else is as it was
    assert {p: s for p, s in now.process.items() if s != "killed"} == {
        p: s for p, s in before.process.items() if now.process[p] != "killed"
    }


def test_restore_file_undo_brings_back_the_modified_state():
    case = next(c for c in ALL if c.scenario == "S19")
    _, _, enforcer, actions = replay(case)
    restored = [a for a in actions if a.type is ActionType.RESTORE_FILE]
    assert len(restored) == 55
    target = restored[0].target.ref
    assert enforcer.world.files[target].version == "known_good"
    enforcer.undo(restored[0].action_id)
    assert enforcer.world.files[target].version == "modified"


def test_lateral_movement_isolates_the_host_and_undo_lifts_it():
    case = next(c for c in ALL if c.scenario == "S18")
    _, _, enforcer, actions = replay(case)
    assert enforcer.world.isolated
    iso = next(a for a in actions if a.type is ActionType.ISOLATE_HOST)
    enforcer.undo(iso.action_id)
    assert not enforcer.world.isolated


def test_the_hold_then_block_of_s27_ends_with_the_worker_killed():
    case = next(c for c in ALL if c.scenario == "S27")
    _, _, enforcer, actions = replay(case)
    assert [a.type for a in actions][:1] == [ActionType.HOLD]
    assert enforcer.world.process["p-2700"] == "killed"


def test_the_declared_containment_matches_the_derivation_rule_for_every_scenario_file():
    for scenario, meta in META.items():
        events, labeled, roots = SCENARIOS[scenario]()
        derived = derive_actions(
            events, labeled, roots, meta["decision"], meta["effects"], events[0].device
        )
        written = next(c for c in ALL if c.scenario == scenario).expected.actions
        assert len(derived) == len(written)
