"""Contract learning mode (CLAUDE.md Phase 2): counts only, writes a proposal, a human approves."""

import copy

import pytest

from evhelp import ev
from refmon import signing
from refmon.golden import ScenarioKind
from refmon.learning import (
    ContractLearner,
    apply_proposal,
    approve,
    behaviour_kind,
    read_proposal,
    write_proposal,
)
from refmon.policy import Policy, default_policy, default_policy_dict
from refmon.policy_io import load_policy, write_signed
from refmon.replay import ReplaySource
from scenario_run import cases, run_case, summary

BENIGN = [c for c in cases() if c.expected.kind is ScenarioKind.BENIGN]


def learn(policy, scenarios, learner_cls=ContractLearner):
    learner = learner_cls(policy)
    wanted = [c for c in cases() if c.scenario in scenarios]
    assert {c.scenario for c in wanted} == set(scenarios)
    for case in wanted:
        learner.new_stream()
        for event in ReplaySource(case.events_path, extra_roles=policy.extra_roles):
            learner.learn(event)
    return learner


def contract_fails(policy, case):
    result = summary(run_case(case, policy))
    return "contract" in result["questions"]


# -- counting only ------------------------------------------------------------------------------------


def test_the_learner_produces_nothing_and_acts_on_nothing():
    learner = ContractLearner(default_policy())
    case = next(c for c in cases() if c.scenario == "S13")  # a malicious file
    outputs = []
    for event in ReplaySource(case.events_path, extra_roles=default_policy().extra_roles):
        outputs.extend(learner.process(event))
    assert outputs == []
    assert learner.events == 5 or learner.events > 0


def test_the_learner_counts_what_each_role_does():
    learner = ContractLearner(default_policy())
    for event in [
        ev("net_connect", "web_worker", "p-1", f=1, destination_class="db_server", t=0),
        ev("net_connect", "web_worker", "p-1", f=2, destination_class="db_server", t=1),
        ev("file_write", "web_worker", "p-1", f=3, path_group="cache", t=2),
    ]:
        learner.learn(event)
    assert dict(learner.roles["web_worker"].kinds) == {
        "connect:db_server": 2,
        "write:cache": 1,
    }


def test_events_after_the_learning_period_are_ignored():
    policy = default_policy(learning={"period": "1h"})
    learner = ContractLearner(policy)
    assert learner.learn(ev("net_connect", "web_worker", "p-1", f=1, destination_class="x", t=0))
    assert learner.learn(ev("net_connect", "web_worker", "p-1", f=2, destination_class="x", t=3600))
    assert not learner.learn(
        ev("net_connect", "web_worker", "p-1", f=3, destination_class="x", t=3601)
    )
    assert learner.events == 2
    assert learner.skipped_after_period == 1


def test_every_event_kind_has_a_behaviour_kind():
    assert (
        behaviour_kind(ev("exec", "agent", "p-1", exec_class="agent_tools")) == "exec:agent_tools"
    )
    assert behaviour_kind(ev("file_write", "other", "p-1", path_group="cache")) == "write:cache"
    assert (
        behaviour_kind(ev("file_write", "other", "p-1", web_root="main_site", executable=True))
        == "write:main_site:executable"
    )
    assert behaviour_kind(ev("persist", "other", "p-1")) == "persist"
    assert behaviour_kind(ev("content_in", "other", "p-1", source_class="web")) == "content_in:web"


# -- the proposal ---------------------------------------------------------------------------------------


def test_a_role_without_a_contract_gets_a_contract_that_covers_what_it_did():
    learner = ContractLearner(default_policy())
    for event in [
        ev("net_connect", "scheduler", "p-1", f=1, destination_class="package_index", t=0),
        ev("file_write", "scheduler", "p-1", f=2, path_group="sched_state", t=1),
    ]:
        learner.learn(event)
    rp = learner.proposal().roles["scheduler"]
    assert rp.new_contract
    added = {(c.field, c.value) for c in rp.changes}
    assert ("may_connect", "package_index") in added
    assert ("may_write", "sched_state") in added
    assert ("may_persist", False) in added  # never persisted: the contract says so


def test_the_role_other_gets_no_proposal():
    learner = ContractLearner(default_policy())
    learner.learn(ev("persist", "other", "p-1", f=1))
    assert "other" not in learner.proposal().roles


def test_a_role_with_a_contract_only_gets_additions_for_what_is_outside_it():
    learner = ContractLearner(default_policy())
    learner.learn(ev("net_connect", "web_worker", "p-1", f=1, destination_class="db_server", t=0))
    learner.learn(ev("net_connect", "web_worker", "p-1", f=2, destination_class="partner_api", t=1))
    changes = learner.proposal().roles["web_worker"].changes
    assert [(c.field, c.op, c.value) for c in changes] == [("may_connect", "add", "partner_api")]


def test_a_change_that_removes_a_deny_is_marked_relax():
    learner = ContractLearner(default_policy())
    learner.learn(ev("content_in", "browser", "p-1", f=1, source_class="web", t=0))
    learner.learn(ev("exec", "interactive_shell", "p-2", f=1, exec_class="unknown", t=1))
    changes = learner.proposal().roles["interactive_shell"].changes
    [c] = [c for c in changes if c.field == "external_content_exec"]
    assert c.relax and c.value == "allow" and c.count == 1


def test_the_unseen_probability_is_the_good_turing_estimate():
    learner = ContractLearner(default_policy())
    for i, dest in enumerate(["a", "a", "a", "b", "c"]):  # two kinds seen once of five events
        learner.learn(ev("net_connect", "web_worker", "p-1", f=i, destination_class=dest, t=i))
    assert learner.proposal().roles["web_worker"].unseen_probability == pytest.approx(2 / 5)


# -- approval: a human, and only a human, activates ---------------------------------------------------------


def proposal_for_shell():
    learner = ContractLearner(default_policy())
    learner.learn(ev("content_in", "browser", "p-1", f=1, source_class="web", t=0))
    learner.learn(ev("exec", "interactive_shell", "p-2", f=1, exec_class="unknown", t=1))
    learner.learn(ev("net_connect", "web_worker", "p-3", f=2, destination_class="partner_api", t=2))
    return learner.proposal()


def test_an_unapproved_proposal_cannot_be_applied():
    with pytest.raises(PermissionError):
        apply_proposal(default_policy_dict(), proposal_for_shell())


def test_approving_everything_leaves_out_the_relaxing_changes():
    approved = approve(proposal_for_shell(), "alice")
    states = {(c.role, c.field): c.approved for c in approved.changes()}
    assert states[("web_worker", "may_connect")] is True
    assert states[("interactive_shell", "external_content_exec")] is False
    data = apply_proposal(default_policy_dict(), approved)
    assert data["contracts"]["interactive_shell"]["external_content_exec"] == "deny"
    assert "partner_api" in data["contracts"]["web_worker"]["may_connect"]


def test_a_relaxing_change_needs_to_be_asked_for():
    proposal = proposal_for_shell()
    [relax] = [c for c in proposal.changes() if c.relax]
    approved = approve(proposal, "alice", change_ids={relax.id})
    data = apply_proposal(default_policy_dict(), approved)
    assert data["contracts"]["interactive_shell"]["external_content_exec"] == "allow"
    assert data["contracts"]["web_worker"]["may_connect"] == ["db_server", "cache_server"]


def test_an_approval_names_a_person():
    with pytest.raises(ValueError):
        approve(proposal_for_shell(), "  ")


def test_applying_a_proposal_does_not_change_the_data_it_was_given():
    data = default_policy_dict()
    before = copy.deepcopy(data)
    apply_proposal(data, approve(proposal_for_shell(), "alice", include_relax=True))
    assert data == before


def test_a_proposal_is_a_file_and_survives_a_round_trip(tmp_path):
    proposal = proposal_for_shell()
    path = tmp_path / "proposal.yaml"
    write_proposal(proposal, path)
    assert read_proposal(path) == proposal
    assert read_proposal(path).status == "proposed"


def test_an_applied_proposal_still_has_to_be_signed_to_load(tmp_path):
    private, public = signing.generate_keypair()
    data = apply_proposal(default_policy_dict(), approve(proposal_for_shell(), "alice"))
    path = tmp_path / "policy.yaml"
    write_signed(data, private, path)
    assert "partner_api" in load_policy(path, [public]).contract_for("web_worker").may_connect
    path.write_text(path.read_text().replace("partner_api", "any", 1))  # edited afterwards
    with pytest.raises(Exception, match="bad_signature"):
        load_policy(path, [public])


def test_learned_roles_are_recorded_so_that_they_can_be_gated_on_maturity():
    learner = ContractLearner(default_policy())
    learner.learn(ev("net_connect", "scheduler", "p-1", f=1, destination_class="package_index"))
    data = apply_proposal(default_policy_dict(), approve(learner.proposal(), "alice"))
    assert data["learned_roles"] == ["scheduler"]
    assert Policy.parse(data).learned_roles == ["scheduler"]


# -- Done when -----------------------------------------------------------------------------------------------


def test_done_when_learning_on_benign_files_makes_them_pass_with_zero_contract_fails():
    policy = default_policy()
    before = [c.scenario for c in BENIGN if contract_fails(policy, c)]
    assert before  # the default policy does not already cover every benign file (S11, S26a)

    learner = learn(policy, {c.scenario for c in BENIGN})
    approved = approve(learner.proposal(), "alice", include_relax=True)
    learned = Policy.parse(apply_proposal(default_policy_dict(), approved))
    assert [c.scenario for c in BENIGN if contract_fails(learned, c)] == []


def without_the_allowances():
    data = default_policy_dict()
    for role, field in [
        ("backup_job", "may_mass_change"),
        ("vuln_scanner", "may_fan_out"),
        ("patch_tool", "may_tamper"),
    ]:
        del data["contracts"][role][field]
    return data


def test_done_when_learning_on_s46_to_s48_proposes_the_three_allowances():
    policy = Policy.parse(without_the_allowances())
    learner = learn(policy, {"S46", "S47", "S48"})
    proposal = learner.proposal()
    proposed = {(c.role, c.field, c.value) for c in proposal.changes()}
    assert ("backup_job", "may_mass_change", True) in proposed
    assert ("vuln_scanner", "may_fan_out", True) in proposed
    assert ("patch_tool", "may_tamper", True) in proposed

    # without the allowances the three files are not allowed; once approved they are
    for scenario in ("S46", "S47", "S48"):
        case = next(c for c in cases() if c.scenario == scenario)
        assert contract_fails(policy, case)
    learned = Policy.parse(apply_proposal(without_the_allowances(), approve(proposal, "alice")))
    for scenario in ("S46", "S47", "S48"):
        case = next(c for c in cases() if c.scenario == scenario)
        assert not contract_fails(learned, case)
        assert summary(run_case(case, learned))["decision"].value == "allow"
