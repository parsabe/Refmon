"""Report (CLAUDE.md Phase 4): plain-language summaries and ATT&CK tactic names."""

import pytest

from evhelp import ev
from refmon.gate import RecordingNotifier
from refmon.pipeline import Pipeline
from refmon.policy import default_policy
from refmon.pseudonym import Pseudonymizer
from refmon.replay import ReplaySource
from refmon.report import Reporter, compose
from refmon.schemas import ATTACK_TACTICS, Decision, Effect, Mode, QuestionResult, Verdict
from refmon.tactics import tactics_for
from scenario_run import cases


def run_case_reported(scenario, mode="block", pseudonymize=False):
    case = next(c for c in cases() if c.scenario == scenario)
    policy = default_policy(mode=mode, reporting={"pseudonymize": pseudonymize})
    pipe = Pipeline(policy, gate=True, notifier=RecordingNotifier())
    reporter = Reporter(pipe, Pseudonymizer(b"k" * 32))
    for event in ReplaySource(case.events_path, extra_roles=policy.extra_roles):
        reporter.consume(pipe.process(event))
    return reporter


def final(reporter):
    rank = {"allow": 0, "hold": 1, "block": 2}
    return max(
        reporter.reports.values(), key=lambda r: (rank[r.verdict.decision.value], r.verdict.ts)
    )


def test_a_blocked_clickfix_story_is_explained_in_three_parts():
    report = final(run_case_reported("S01"))
    assert report.verdict.decision is Decision.BLOCK
    assert "came in from a web page" in report.what_happened
    assert "ran a command that was copied in from outside" in report.what_happened
    assert "stopped the program" in report.action_taken
    assert "Tell the user" in report.next_step
    assert report.verdict.summary.startswith("What happened:")
    assert len(report.verdict.summary) <= 1000


def test_tactics_are_attack_names_in_attack_order():
    report = final(run_case_reported("S01"))
    assert report.verdict.tactics == (
        "Initial Access",
        "Execution",
        "Defense Evasion",
        "Command and Control",
    )
    assert set(report.verdict.tactics) <= set(ATTACK_TACTICS)
    order = [ATTACK_TACTICS.index(t) for t in report.verdict.tactics]
    assert order == sorted(order)


def test_every_effect_and_override_maps_to_a_known_tactic():
    from refmon.tactics import EFFECT_TACTIC, OVERRIDE_TACTIC

    assert set(EFFECT_TACTIC) == set(Effect)
    assert set(EFFECT_TACTIC.values()) <= set(ATTACK_TACTICS)
    assert set(OVERRIDE_TACTIC.values()) <= set(ATTACK_TACTICS)


def test_a_verdict_with_a_non_attack_tactic_is_rejected():
    q = QuestionResult(failed=False)
    with pytest.raises(ValueError, match="ATT&CK"):
        Verdict(
            verdict_id="v-1", story_id="st-1", device="d", ts="2026-10-28T10:00:00Z",
            mode=Mode.BLOCK, decision=Decision.ALLOW, origin=q, contract=q, effect=q,
            tactics=("Magic",),
        )  # fmt: skip


@pytest.mark.parametrize("scenario", ["S01", "S08", "S13", "S14", "S19", "S20", "S34"])
def test_blocked_scenarios_name_what_was_done_to_the_story(scenario):
    report = final(run_case_reported(scenario))
    assert report.verdict.decision is Decision.BLOCK
    assert "Refmon " in report.action_taken and "stopped" in report.action_taken
    assert report.verdict.tactics


def test_the_web_shell_story_says_files_were_quarantined_not_deleted():
    report = final(run_case_reported("S14"))
    assert "quarantine (nothing was deleted)" in report.action_taken
    assert "Persistence" in report.verdict.tactics


def test_a_server_hold_tells_the_service_desk_an_administrator_must_decide():
    report = final(run_case_reported("S50"))
    assert report.verdict.decision is Decision.HOLD
    assert report.platform == "server"
    assert "administrator" in report.action_taken
    assert "administrator must" in report.next_step


def test_an_endpoint_hold_says_the_user_was_asked():
    report = final(run_case_reported("S49"))
    assert "the user was asked" in report.action_taken.lower()
    assert "without one the program is stopped" in report.next_step


def test_observe_and_warn_say_that_nothing_was_changed():
    for mode, word in (("observe", "observe mode"), ("warn", "warn mode")):
        report = final(run_case_reported("S13", mode=mode))
        assert word in report.action_taken
        assert "Nothing was stopped or changed" in report.action_taken


def test_an_override_is_explained():
    assert "decoy" in final(run_case_reported("S08")).what_happened
    assert "protected data" in final(run_case_reported("S34")).what_happened


def test_the_summary_contains_no_fingerprint_and_no_identifier_of_the_story():
    for scenario in ("S01", "S14", "S19", "S21"):
        report = final(run_case_reported(scenario))
        assert "hmac:" not in report.verdict.summary
        assert "p-" not in report.what_happened.replace("program", "")


def test_export_replaces_device_and_users_by_pseudonyms():
    reporter = run_case_reported("S01", pseudonymize=True)
    report = final(reporter)
    assert report.verdict.device == "dev-7f3a"  # local form keeps the real names
    out = reporter.export(report)
    assert out.device.startswith("ps-dev-") and "7f3a" not in out.device
    assert out.users and all(u.startswith("ps-usr-") for u in out.users)
    assert "alice" not in out.model_dump_json()


def test_export_without_a_pseudonymizer_is_refused_when_the_policy_asks_for_pseudonyms():
    policy = default_policy(mode="block")
    pipe = Pipeline(policy, gate=True)
    reporter = Reporter(pipe, None)
    for e in [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("exec", "web_worker", "p-1", f=2, t=1, exec_class="unknown"),
        ev("net_connect", "web_worker", "p-1", f=3, t=2, destination_class="unknown"),
    ]:
        reporter.consume(pipe.process(e))
    with pytest.raises(ValueError, match="pseudonymizer"):
        reporter.export(final(reporter))


def test_the_same_user_gets_the_same_pseudonym_and_different_users_different_ones():
    p = Pseudonymizer(b"k" * 32)
    assert p.user("alice") == p.user("alice")
    assert p.user("alice") != p.user("bob")
    assert p.user("alice") != Pseudonymizer(b"j" * 32).user("alice")
    assert p.user("alice") != p.device("alice")


def test_tactics_for_a_story_without_findings_is_empty():
    q = QuestionResult(failed=False)
    v = Verdict(
        verdict_id="v-1", story_id="st-1", device="d", ts="2026-10-28T10:00:00Z",
        mode=Mode.BLOCK, decision=Decision.ALLOW, origin=q, contract=q, effect=q,
    )  # fmt: skip
    assert tactics_for(v) == ()
    assert compose(v, [], set(), "endpoint").what_happened == "Nothing unusual was found."
