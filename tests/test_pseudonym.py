"""Four-eyes re-identification (CLAUDE.md Phase 4): two approvers, every use logged."""

import json

import pytest

from refmon import signing
from refmon.pseudonym import (
    Approval,
    AuditLog,
    Pseudonymizer,
    ReidentificationDenied,
    Vault,
    approval_message,
)


class Setup:
    def __init__(self, tmp_path=None):
        self.keys = {n: signing.generate_keypair() for n in ("alice", "bob", "carol")}
        self.log = AuditLog(tmp_path / "audit.jsonl" if tmp_path else None)
        self.vault = Vault({n: k[1] for n, k in self.keys.items()}, 2, self.log)
        self.pseudo = Pseudonymizer(b"k" * 32, self.vault)
        self.pid = self.pseudo.user("real.person")

    def approval(self, who, rid, purpose="investigation"):
        msg = approval_message(rid, self.pid, purpose)
        return Approval(who, signing.sign_message(msg, self.keys[who][0]))

    def request(self, requester="dana", purpose="investigation"):
        return self.vault.open_request(self.pid, purpose, requester)


def test_two_different_approvers_open_the_vault_once():
    s = Setup()
    rid = s.request()
    assert (
        s.vault.complete(rid, [s.approval("alice", rid), s.approval("bob", rid)]) == "real.person"
    )
    with pytest.raises(ReidentificationDenied):  # a request is good for one use
        s.vault.complete(rid, [s.approval("alice", rid), s.approval("bob", rid)])


@pytest.mark.parametrize(
    "build",
    [
        lambda s, r: [],
        lambda s, r: [s.approval("alice", r)],
        lambda s, r: [s.approval("alice", r), s.approval("alice", r)],
        lambda s, r: [s.approval("alice", r), Approval("bob", "AAAA")],
        lambda s, r: [s.approval("alice", r), Approval("mallory", s.approval("bob", r).signature)],
    ],
    ids=["none", "one", "same twice", "garbled", "unknown approver"],
)
def test_without_two_valid_approvers_nothing_opens(build):
    s = Setup()
    rid = s.request()
    with pytest.raises(ReidentificationDenied):
        s.vault.complete(rid, build(s, rid))


def test_a_signature_for_another_request_or_purpose_does_not_count():
    s = Setup()
    rid, other = s.request(), s.request()
    with pytest.raises(ReidentificationDenied):
        s.vault.complete(rid, [s.approval("alice", other), s.approval("bob", other)])
    with pytest.raises(ReidentificationDenied):
        s.vault.complete(rid, [s.approval("alice", rid, "other purpose"), s.approval("bob", rid)])


def test_the_requester_cannot_approve_their_own_request():
    s = Setup()
    rid = s.request(requester="alice")
    with pytest.raises(ReidentificationDenied):
        s.vault.complete(rid, [s.approval("alice", rid), s.approval("bob", rid)])
    rid = s.request(requester="alice")
    assert s.vault.complete(rid, [s.approval("bob", rid), s.approval("carol", rid)])


def test_one_person_registered_under_two_names_is_one_pair_of_eyes():
    s = Setup()
    s.vault._approvers["alice-again"] = s.keys["alice"][1]
    rid = s.request()
    msg = approval_message(rid, s.pid, "investigation")
    twin = Approval("alice-again", signing.sign_message(msg, s.keys["alice"][0]))
    with pytest.raises(ReidentificationDenied):
        s.vault.complete(rid, [s.approval("alice", rid), twin])


def test_four_eyes_means_at_least_two():
    with pytest.raises(ValueError):
        Vault({}, 1, AuditLog())


def test_every_use_is_logged_including_the_refusals(tmp_path):
    s = Setup(tmp_path)
    rid = s.request()
    with pytest.raises(ReidentificationDenied):
        s.vault.complete(rid, [s.approval("alice", rid)])
    s.vault.complete(rid, [s.approval("alice", rid), s.approval("bob", rid)])
    events = [e["event"] for e in s.log.entries]
    assert events == ["request_opened", "denied", "reidentified"]
    on_disk = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert on_disk == s.log.entries
    assert AuditLog.verify_entries(on_disk)


def test_the_audit_log_detects_changes_and_missing_entries():
    s = Setup()
    for _ in range(3):
        s.request()
    entries = [dict(e) for e in s.log.entries]
    assert AuditLog.verify_entries(entries)
    tampered = [dict(e) for e in entries]
    tampered[1]["requester"] = "someone-else"
    assert not AuditLog.verify_entries(tampered)
    assert not AuditLog.verify_entries(entries[:1] + entries[2:])


def test_the_vault_holds_values_encrypted():
    s = Setup()
    assert b"real.person" not in b"".join(s.vault._sealed.values())
    assert s.vault.knows(s.pid) and not s.vault.knows("ps-usr-0000000000000000")


def test_an_unknown_pseudonym_cannot_be_opened_even_with_approval():
    s = Setup()
    rid = s.vault.open_request("ps-usr-ffffffffffffffff", "x", "dana")
    msg = approval_message(rid, "ps-usr-ffffffffffffffff", "x")
    approvals = [Approval(n, signing.sign_message(msg, s.keys[n][0])) for n in ("alice", "bob")]
    with pytest.raises(ReidentificationDenied):
        s.vault.complete(rid, approvals)
