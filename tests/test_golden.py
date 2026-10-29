"""Hygiene checks that apply to every golden file (the verdicts themselves are in
test_phase1_golden.py): files validate, stream through an empty core, carry no raw content, and the
declared containment points at real things in the stream."""

import re

import pytest

import golden_builder
from refmon.core import EmptyCore, run_pipeline
from refmon.enforcer import SimulatedEnforcer
from refmon.golden import ExpectedVerdict, GoldenCase, ScenarioKind
from refmon.policy import default_policy
from refmon.replay import ReplaySource
from refmon.schemas import EVENT_ATTR_KEYS, Decision, EventType, Override, SourceClass
from scenario_run import cases

CASES = cases()
ROLES = tuple(default_policy().extra_roles)
PHASE_0 = {"S01", "S02", "S09", "S10", "S11", "S13", "S14"}

# The plain 3/2/1 fail rule from CLAUDE.md Part A. Only the tests spell it out; the pipeline reads
# these mappings from policy.
FAIL_RULE = {0: Decision.ALLOW, 1: Decision.ALLOW, 2: Decision.HOLD, 3: Decision.BLOCK}
OVERRIDE_DECISION = {
    Override.CANARY: Decision.BLOCK,
    Override.PROTECTED_ASSET: Decision.BLOCK,
    Override.SELF_TAMPER: Decision.BLOCK,
    Override.TRUSTED_ROOT: Decision.ALLOW,
}
EXTERNAL = {s.value for s in SourceClass} - {"internal"}

by_id = pytest.mark.parametrize("case", CASES, ids=[c.scenario for c in CASES])
MALICIOUS = [c for c in CASES if c.expected.kind is ScenarioKind.MALICIOUS]
malicious_by_id = pytest.mark.parametrize("case", MALICIOUS, ids=[c.scenario for c in MALICIOUS])


def stream(case: GoldenCase):
    return ReplaySource(case.events_path, extra_roles=ROLES)


def test_the_original_phase_0_scenarios_are_still_there():
    assert {c.scenario for c in CASES} >= PHASE_0


def test_committed_files_match_the_builder():
    assert golden_builder.main(["--check"]) == 0


@by_id
def test_rule_decision_is_the_plain_fail_rule_or_the_override(case: GoldenCase):
    expected = case.expected
    if expected.override is not None:
        assert expected.rule_decision is OVERRIDE_DECISION[expected.override]
    else:
        assert expected.rule_decision is FAIL_RULE[expected.fail_count]


def test_only_the_documented_scenarios_differ_between_rule_and_final_decision():
    differing = {c.scenario for c in CASES if c.expected.decision != c.expected.rule_decision}
    assert differing == {"S05", "S11", "S26a"}
    assert all(c.expected.decided_in_phase == "4b" for c in CASES if c.scenario in differing)


def test_a_differing_rule_decision_must_be_explained():
    base = {
        "scenario": "S99",
        "title": "t",
        "kind": "benign",
        "platform": "endpoint",
        "decision": "allow",
        "rule_decision": "hold",
    }
    with pytest.raises(ValueError, match="explain"):
        ExpectedVerdict.model_validate(base)
    assert ExpectedVerdict.model_validate(base | {"notes": "calculus overrules the rule"})


@by_id
def test_events_validate_and_stream_through_an_empty_core(case: GoldenCase):
    events = list(stream(case))
    assert events
    enforcer = SimulatedEnforcer()
    report = run_pipeline(stream(case), EmptyCore(), enforcer)
    assert report.events == len(events)
    assert report.verdicts == [] and report.actions == [] and enforcer.actions == []


@by_id
def test_events_carry_no_raw_content(case: GoldenCase):
    for event in stream(case):
        assert event.attrs.keys() <= EVENT_ATTR_KEYS
        for value in event.attrs.values():
            if isinstance(value, str):
                assert re.fullmatch(r"[A-Za-z0-9_.:@-]{1,64}", value)
        if event.object.fingerprint is not None:
            assert re.fullmatch(r"hmac:[0-9a-f]{64}", event.object.fingerprint)


@by_id
def test_expected_actions_point_at_things_in_the_stream(case: GoldenCase):
    events = {e.event_id: e for e in stream(case)}
    process_ids = {e.actor.id for e in events.values()}
    devices = {e.device for e in events.values()}
    for action in case.expected.actions:
        if action.process is not None:
            assert action.process in process_ids
        elif action.host is not None:
            assert action.host in devices
        else:
            assert action.object_of_event in events
            assert events[action.object_of_event].object.fingerprint is not None


@by_id
def test_blocked_and_allowed_scenarios_have_consistent_expectations(case: GoldenCase):
    expected = case.expected
    if expected.decision is Decision.BLOCK:
        assert expected.actions, "a block must say what gets contained"
    if expected.decision is Decision.ALLOW:
        assert expected.actions == ()


@malicious_by_id
def test_malicious_streams_start_from_untrusted_external_input(case: GoldenCase):
    if case.scenario == "S05":
        return  # typed by hand: no external input is visible, which is the known gap
    sources = [
        e
        for e in stream(case)
        if e.type in (EventType.CONTENT_IN, EventType.REQUEST_IN)
        and e.attrs.get("source_class") in EXTERNAL
        and "trusted_source" not in e.attrs
    ]
    assert sources


@malicious_by_id
def test_malicious_scenarios_reach_their_dangerous_action(case: GoldenCase):
    # Guard against a truncated stream: each malicious file must reach a dangerous action.
    dangerous = {
        EventType.NET_CONNECT, EventType.FILE_WRITE, EventType.PERSIST, EventType.PRIV_CHANGE,
        EventType.ASSET_ACCESS, EventType.SECURITY_TAMPER, EventType.RESPONSE_OUT, EventType.EXEC,
    }  # fmt: skip
    assert {e.type for e in stream(case)} & dangerous


def test_there_are_malicious_scenarios_to_parametrize_over():
    assert len(MALICIOUS) >= 20


@pytest.mark.parametrize("scenario", ["S13", "S14"])
def test_server_requests_are_closed_by_a_request_end(scenario):
    case = next(c for c in CASES if c.scenario == scenario)
    events = list(stream(case))
    opened = [e for e in events if e.type is EventType.REQUEST_IN]
    closed = [e for e in events if e.type is EventType.REQUEST_END]
    assert [e.object.fingerprint for e in closed] == [e.object.fingerprint for e in opened]
    assert events.index(closed[0]) > events.index(opened[0])


def test_the_trusted_scenarios_come_from_trusted_sources_and_the_admin_one_is_internal():
    for scenario in ("S09", "S24", "S37"):
        case = next(c for c in CASES if c.scenario == scenario)
        content = [e for e in stream(case) if e.type is EventType.CONTENT_IN]
        assert content and all("trusted_source" in e.attrs for e in content)
    s10 = next(c for c in CASES if c.scenario == "S10")
    assert {e.attrs.get("source_class") for e in stream(s10)} - {None} == {"internal"}
