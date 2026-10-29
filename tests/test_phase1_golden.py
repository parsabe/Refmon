"""Phase 1 "Done when": every golden file reaches its rule_decision, malicious files fail all three
questions (or have their documented override), benign ones at most one (with the documented
exceptions), and the coverage map shows no attack family without a passing scenario."""

import re
from pathlib import Path

import pytest

from refmon.coverage import ADAPTIVE, gaps, parse_coverage_map
from refmon.golden import ScenarioKind
from refmon.schemas import Decision
from scenario_run import cases, run_case, summary

ROOT = Path(__file__).resolve().parent.parent
CASES = cases()
ids = [c.scenario for c in CASES]
by_id = pytest.mark.parametrize("case", CASES, ids=ids)

KNOWN_GAPS = {"S05", "S22"}


def test_every_non_adaptive_scenario_of_the_catalog_has_a_golden_file():
    text = (ROOT / "CLAUDE.md").read_text()
    catalog = set(re.findall(r"^\| (S\d+[a-z]?) +\|", text, flags=re.M))
    assert {c.scenario for c in CASES} == catalog - ADAPTIVE


@by_id
def test_kind_and_final_decision_match_the_c8_table(case):
    text = (ROOT / "CLAUDE.md").read_text()
    row = re.search(
        rf"^\| {case.scenario} +\| (.*?) +\| (malicious|benign|adaptive) +\| (.*?) +\|$",
        text,
        flags=re.M,
    )
    assert row, case.scenario
    assert case.expected.kind.value == row.group(2)
    spelled = {"S22": "hold", "S27": "block"}  # C8 words these as prose, see the golden notes
    first = spelled.get(case.scenario) or row.group(3).split()[0].strip(",;")
    assert case.expected.decision.value == first


@by_id
def test_the_pipeline_reaches_the_rule_decision(case):
    result = summary(run_case(case))
    expected = case.expected
    assert result["decision"] is expected.rule_decision
    assert result["questions"] == {q.value for q in expected.questions_failed}
    assert result["effects"] == {e.value for e in expected.effects}
    assert result["override"] == (expected.override.value if expected.override else None)


@by_id
def test_malicious_files_fail_three_questions_or_have_their_override(case):
    expected = case.expected
    if expected.kind is not ScenarioKind.MALICIOUS:
        return
    result = summary(run_case(case))
    if case.scenario in KNOWN_GAPS:
        assert result["fails"] < 3
    else:
        assert result["fails"] == 3 or result["override"] is not None


@by_id
def test_benign_files_fail_at_most_one_question_except_the_documented_ones(case):
    expected = case.expected
    if expected.kind is not ScenarioKind.BENIGN:
        return
    fails = summary(run_case(case))["fails"]
    documented = expected.decision is Decision.HOLD or expected.rule_decision != expected.decision
    assert fails <= 1 or documented or expected.override is not None, case.scenario


def test_coverage_map_has_no_attack_family_without_a_passing_scenario():
    passing = set()
    for case in CASES:
        result = summary(run_case(case))
        if result["decision"] is case.expected.rule_decision and result["questions"] == {
            q.value for q in case.expected.questions_failed
        }:
            passing.add(case.scenario)
    assert gaps(parse_coverage_map(ROOT / "CLAUDE.md"), passing) == []


def test_every_non_adaptive_family_in_the_map_has_scenarios_on_both_sides():
    for family in parse_coverage_map(ROOT / "CLAUDE.md"):
        mal = [s for s in family.malicious if s not in ADAPTIVE]
        ben = [s for s in family.benign if s not in ADAPTIVE]
        if mal or ben:
            assert mal and ben, family.name
