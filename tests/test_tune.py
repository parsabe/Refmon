"""Tune (CLAUDE.md Phase 4): feedback proposes, a person approves, nothing applies on its own."""

from datetime import date

import pytest

from evhelp import ev, raw
from refmon import signing
from refmon.gate import RecordingNotifier
from refmon.pipeline import Pipeline
from refmon.policy import Policy, default_policy, default_policy_dict
from refmon.policy_io import load_policy, write_signed
from refmon.schemas import Decision, Verdict
from refmon.tune import Feedback, Tuner, apply_suggestion, approve_suggestion

TODAY = date(2026, 10, 29)


def worker_story(pipe):
    out = []
    for e in [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev(
            "net_connect",
            "web_worker",
            "p-1",
            cls="network_endpoint",
            f=3,
            t=2,
            destination_class="partner_api",
        ),
    ]:
        out += pipe.process(e)
    return [o for o in out if isinstance(o, Verdict)][-1]


def tuner(policy=None):
    pipe = Pipeline(policy or default_policy(mode="block"), gate=True, notifier=RecordingNotifier())
    return pipe, Tuner(pipe, lambda: TODAY)


def test_a_false_alarm_proposes_a_scoped_expiring_exception():
    pipe, t = tuner()
    verdict = worker_story(pipe)
    s = t.suggest(Feedback(verdict_id=verdict.verdict_id, kind="false_alarm", by="desk"), verdict)
    ex = s.exception
    assert ex.scope == {"role": "web_worker", "user": "u"}
    assert set(ex.disables) >= {"R-EFF-FETCH", "R-ORI-EXTERNAL"}
    assert ex.expires == "2026-11-28"  # thirty days from the injected date
    assert s.status == "proposed" and s.approvals == []


def test_a_false_alarm_on_a_contract_break_also_proposes_a_contract_extension():
    pipe, t = tuner()
    verdict = worker_story(pipe)
    s = t.suggest(Feedback(verdict_id=verdict.verdict_id, kind="false_alarm", by="desk"), verdict)
    changes = {(c.role, c.field, c.value) for c in s.contract_extension.changes()}
    assert ("web_worker", "may_connect", "partner_api") in changes


def test_the_proposed_expiry_comes_from_policy():
    pipe, t = tuner(default_policy(mode="block", tune={"exception_days": 7}))
    verdict = worker_story(pipe)
    s = t.suggest(Feedback(verdict_id=verdict.verdict_id, kind="false_alarm", by="desk"), verdict)
    assert s.exception.expires == "2026-11-05"


def test_confirmed_proposes_block_list_entries_for_labeled_objects_only():
    pipe, t = tuner()
    verdict = worker_story(pipe)
    s = t.suggest(Feedback(verdict_id=verdict.verdict_id, kind="confirmed", by="desk"), verdict)
    assert s.blocklist.entries == [ev("net_connect", "web_worker", "p-1", f=3).object.fingerprint]
    assert s.exception is None and s.contract_extension is None


def test_an_unlabeled_story_gets_no_block_list_entries():
    pipe, t = tuner()
    out = pipe.process(ev("net_connect", "other", "p-5", f=8, destination_class="unknown"))
    out += pipe.process(ev("net_connect", "other", "p-5", f=9, destination_class="unknown", t=1))
    verdict = pipe.verdict(pipe.linker.records["st-1"], pipe.judge(pipe.linker.records["st-1"]))
    s = t.suggest(Feedback(verdict_id=verdict.verdict_id, kind="confirmed", by="desk"), verdict)
    assert s.blocklist is None


def test_nothing_applies_without_approval():
    pipe, t = tuner()
    verdict = worker_story(pipe)
    s = t.suggest(Feedback(verdict_id=verdict.verdict_id, kind="false_alarm", by="desk"), verdict)
    with pytest.raises(PermissionError):
        apply_suggestion(default_policy_dict(), s)


def test_an_approval_names_a_person_and_what_they_accept():
    pipe, t = tuner()
    verdict = worker_story(pipe)
    s = t.suggest(Feedback(verdict_id=verdict.verdict_id, kind="false_alarm", by="desk"), verdict)
    with pytest.raises(ValueError):
        approve_suggestion(s, " ", ["exception"])
    with pytest.raises(ValueError):
        approve_suggestion(s, "alice", [])
    with pytest.raises(ValueError):
        approve_suggestion(s, "alice", ["blocklist"])  # nothing proposed for that


def test_only_what_the_approver_accepted_is_applied():
    pipe, t = tuner()
    verdict = worker_story(pipe)
    s = t.suggest(Feedback(verdict_id=verdict.verdict_id, kind="false_alarm", by="desk"), verdict)
    base = default_policy_dict()
    only_exception = apply_suggestion(base, approve_suggestion(s, "alice", ["exception"]))
    assert only_exception["exceptions"][0]["id"] == "X-001"
    assert "partner_api" not in only_exception["contracts"]["web_worker"]["may_connect"]
    only_contract = apply_suggestion(base, approve_suggestion(s, "alice", ["contract_extension"]))
    assert "partner_api" in only_contract["contracts"]["web_worker"]["may_connect"]
    assert "exceptions" not in only_contract


def test_an_accepted_exception_changes_the_next_outcome_once_signed(tmp_path):
    pipe, t = tuner()
    verdict = worker_story(pipe)
    s = t.suggest(Feedback(verdict_id=verdict.verdict_id, kind="false_alarm", by="desk"), verdict)
    data = apply_suggestion(default_policy_dict(), approve_suggestion(s, "alice", ["exception"]))
    private, public = signing.generate_keypair()
    write_signed(data, private, tmp_path / "policy.yaml")
    policy = load_policy(tmp_path / "policy.yaml", [public]).model_copy(update={"mode": "block"})
    again, _ = tuner(policy)
    out = []
    for e in [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("net_connect", "web_worker", "p-1", f=3, t=2, destination_class="partner_api"),
    ]:
        out += again.process(e)
    [j] = again.judgements().values()
    assert j.disabled_rules and j.decision is Decision.ALLOW


def test_confirmed_block_list_entries_flag_the_object_in_observe(tmp_path):
    pipe, t = tuner()
    verdict = worker_story(pipe)
    s = t.suggest(Feedback(verdict_id=verdict.verdict_id, kind="confirmed", by="desk"), verdict)
    data = apply_suggestion(default_policy_dict(), approve_suggestion(s, "alice", ["blocklist"]))
    [spec] = [x for x in data["threat_lists"] if x["name"] == "confirmed-local"]
    assert spec["kind"] == "fingerprint" and spec["entries"] == s.blocklist.entries
    policy = Policy.parse(data)
    fp = s.blocklist.entries[0]
    again = Pipeline(policy)
    event = ev("net_connect", "script_host", "p-8", f=3, destination_class="unknown")
    assert event.object.fingerprint == fp
    # an Event passes Observe unchanged; a RawEvent with the same fingerprint is checked
    observed = again.observe(raw("net_connect", "script_host", "p-8", f=3, host="x.invalid"))
    assert observed.attrs["threat_list_hit"] == "confirmed-local"


def test_applying_twice_does_not_duplicate_entries():
    pipe, t = tuner()
    verdict = worker_story(pipe)
    s = t.suggest(Feedback(verdict_id=verdict.verdict_id, kind="confirmed", by="desk"), verdict)
    approved = approve_suggestion(s, "alice", ["blocklist"])
    once = apply_suggestion(default_policy_dict(), approved)
    twice = apply_suggestion(once, approved)
    assert once["threat_lists"] == twice["threat_lists"]


def test_unknown_story_is_an_error():
    pipe, t = tuner()
    verdict = worker_story(pipe)
    with pytest.raises(KeyError):
        t.suggest(
            Feedback(verdict_id="v-1", kind="confirmed", by="d"),
            verdict.model_copy(update={"story_id": "st-404"}),
        )
