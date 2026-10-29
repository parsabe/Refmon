"""Phase 4b "Done when": the full scenario catalog reaches its expected decisions with the example
default weights, S11 is allowed, S05 is held, and every verdict's contributions sum exactly to its
log-odds. From here on golden tests assert `decision` instead of `rule_decision`."""

import math

import pytest

from refmon.calculus.evidence import block_threshold, hold_threshold, prior_log_odds
from refmon.coverage import gaps, parse_coverage_map
from refmon.enforcer import SimulatedEnforcer
from refmon.golden import ScenarioKind
from refmon.pipeline import Pipeline
from refmon.policy import default_policy
from refmon.replay import ReplaySource
from refmon.schemas import Action, Decision, Verdict
from refmon.simworld import SimWorld
from scenario_run import ROOT, cases, run_case, summary

CASES = cases()
by_id = pytest.mark.parametrize("case", CASES, ids=[c.scenario for c in CASES])
KNOWN_GAPS = {"S05", "S22"}


def test_the_default_policy_uses_the_calculus_and_the_statistical_rate_tests():
    p = default_policy()
    assert p.uses_calculus and p.statistical_rates
    assert not default_policy(engine="rule").uses_calculus
    assert not default_policy(math={}).uses_calculus  # no weights: the fail rule is the fallback


@by_id
def test_the_pipeline_reaches_the_expected_decision(case):
    result = summary(run_case(case), "decision")
    expected = case.expected
    assert result["decision"] is expected.decision
    assert result["override"] == (expected.override.value if expected.override else None)


@by_id
def test_the_classic_fail_count_is_still_reported_beside_the_log_odds(case):
    result = summary(run_case(case), "decision")
    assert result["questions"] == {q.value for q in case.expected.questions_failed}
    assert result["effects"] == {e.value for e in case.expected.effects}


def test_s11_is_allowed_and_s05_is_held():
    by = {c.scenario: c for c in CASES}
    assert summary(run_case(by["S11"]), "decision")["decision"] is Decision.ALLOW
    assert summary(run_case(by["S05"]), "decision")["decision"] is Decision.HOLD
    assert (
        summary(run_case(by["S11"]))["decision"] is Decision.HOLD
    )  # the plain rule still holds it


def verdicts_of(case):
    pipe = Pipeline(default_policy())
    out = []
    for e in ReplaySource(case.events_path, extra_roles=default_policy().extra_roles):
        out += [o for o in pipe.process(e) if isinstance(o, Verdict)]
    return out


@by_id
def test_every_verdicts_contributions_sum_exactly_to_its_log_odds(case):
    for v in verdicts_of(case):
        assert v.log_odds is not None
        counted = [c for c in v.contributions if c.counted]
        assert v.log_odds == pytest.approx(
            v.prior_log_odds + sum(c.nats for c in counted), abs=1e-12
        )
        assert len({c.question for c in counted}) == len(counted)
        for c in v.contributions:
            assert c.nats == pytest.approx(c.weight * c.strength, abs=1e-12)
        assert v.prior_log_odds == pytest.approx(prior_log_odds(0.001))


@by_id
def test_the_threshold_a_verdict_crossed_is_consistent_with_its_log_odds(case):
    p = default_policy()
    block = block_threshold(p.math.costs)
    hold = hold_threshold(p.math.costs, p.math.hold_catch_rate)
    for v in verdicts_of(case):
        if v.override is not None:
            assert v.threshold_crossed is None
        elif v.threshold_crossed == "block":
            assert v.log_odds >= block
            assert (v.decision is Decision.BLOCK) == (not v.contract_gate)
        elif v.threshold_crossed == "hold":
            assert hold <= v.log_odds < block and v.decision is Decision.HOLD
        else:
            assert v.log_odds < hold


def test_the_contract_gate_is_recorded_exactly_where_it_applied():
    gated = {c.scenario for c in CASES if run_case(c).best().gated}
    # block threshold crossed with no Contract signal. Earlier verdicts of other stories can be
    # gated for a moment (S18 and S21 before their Contract signal arrives); only these end there.
    assert gated == {"S22", "S49", "S50"}
    transient = {c.scenario for c in CASES if any(v.contract_gate for v in verdicts_of(c))}
    assert transient - gated <= {"S18", "S21"}


def test_the_worked_check_numbers_of_the_specification():
    by = {c.scenario: c for c in CASES}
    for scenario, expected in {"S01": -2.61, "S11": -5.11, "S05": -4.41, "S13": -0.61}.items():
        j = run_case(by[scenario]).best()
        assert j.log_odds == pytest.approx(expected, abs=0.03)  # label decay moves it by hundredths
    assert math.isclose(block_threshold(default_policy().math.costs), math.log(20 / 1000))


@by_id
def test_malicious_files_are_not_missed_except_the_documented_gaps(case):
    expected = case.expected
    if expected.kind is not ScenarioKind.MALICIOUS or case.scenario in KNOWN_GAPS:
        return
    assert summary(run_case(case), "decision")["decision"] is Decision.BLOCK


@by_id
def test_benign_files_are_not_blocked(case):
    if case.expected.kind is ScenarioKind.BENIGN:
        assert summary(run_case(case), "decision")["decision"] is not Decision.BLOCK


def test_the_coverage_map_has_no_family_without_a_passing_scenario_on_decision():
    passing = set()
    for case in CASES:
        r = summary(run_case(case), "decision")
        if r["decision"] is case.expected.decision:
            passing.add(case.scenario)
    assert gaps(parse_coverage_map(ROOT / "CLAUDE.md"), passing) == []


# -- containment under the calculus --------------------------------------------------------------------


def replay_with_gate(case):
    policy = default_policy(mode="block")
    events = list(ReplaySource(case.events_path, extra_roles=policy.extra_roles))
    enforcer = SimulatedEnforcer(SimWorld.from_events(events))
    pipe = Pipeline(policy, gate=True)
    actions = []
    for event in events:
        for out in pipe.process(event):
            if isinstance(out, Action):
                actions.append(out)
                enforcer.act(out)
    return events, actions


@by_id
def test_the_actions_follow_the_final_decision(case):
    events, actions = replay_with_gate(case)
    by_event = {e.event_id: e for e in events}
    expected = {
        (a.type.value, a.process or a.host or by_event[a.object_of_event].object.fingerprint)
        for a in case.expected.actions
    }
    actual = {(a.type.value, a.target.ref) for a in actions}
    holds = {k for k in actual if k[0] == "hold"}
    assert actual - holds == {k for k in expected if k[0] != "hold"}
    if case.expected.decision is Decision.HOLD:
        assert holds == {k for k in expected if k[0] == "hold"}


def test_s11_and_s26a_cause_no_action_now_that_the_calculus_allows_them():
    for scenario in ("S11", "S26a"):
        case = next(c for c in CASES if c.scenario == scenario)
        assert replay_with_gate(case)[1] == []
