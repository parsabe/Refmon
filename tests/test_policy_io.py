"""The signed policy loader (CLAUDE.md C6, Phase 2): verification, tampering, rule packs, and the
requirement that changing only the policy changes outcomes."""

import pytest

from evhelp import ev, raw
from refmon import signing
from refmon.policy import Policy, default_policy, default_policy_dict
from refmon.policy_io import (
    PolicyRejected,
    PolicyStore,
    load_policy,
    load_policy_data,
    write_document,
    write_signed,
)
from refmon.rulepacks import RulePack
from refmon.schemas import Decision, Mode, Override
from scenario_run import cases, run_case, run_events, summary


@pytest.fixture
def keys():
    return signing.generate_keypair()


@pytest.fixture
def policy_file(tmp_path, keys):
    path = tmp_path / "policy.yaml"
    write_signed(default_policy_dict(), keys[0], path)
    return path


# -- signing ----------------------------------------------------------------------------------------


def test_a_signature_verifies_and_any_change_breaks_it(keys):
    private, public = keys
    doc = signing.signed({"version": 2, "mode": "observe", "n": [1, 2]}, private)
    assert signing.verify(doc, [public])
    assert not signing.verify({**doc, "mode": "block"}, [public])
    assert not signing.verify({**doc, "n": [1, 2, 3]}, [public])


def test_a_signature_from_another_key_does_not_verify(keys):
    other_private, other_public = signing.generate_keypair()
    doc = signing.signed({"a": 1}, other_private)
    assert not signing.verify(doc, [keys[1]])
    assert signing.verify(doc, [keys[1], other_public])  # any trusted key will do


@pytest.mark.parametrize("signature", [None, "", "not base64!!", "QUJD"])
def test_a_missing_or_garbled_signature_does_not_verify(keys, signature):
    doc = {"a": 1}
    if signature is not None:
        doc["signature"] = signature
    assert not signing.verify(doc, [keys[1]])


def test_formatting_does_not_matter_but_values_do(tmp_path, keys):
    private, public = keys
    path = tmp_path / "p.yaml"
    write_signed(default_policy_dict(), private, path)
    text = path.read_text()
    path.write_text("# a comment\n" + text.replace("\n", "\n\n", 3))
    assert load_policy(path, [public]) == default_policy()


def test_dates_survive_a_round_trip_through_yaml(tmp_path, keys):
    private, public = keys
    data = default_policy_dict()
    data["exceptions"] = [
        {
            "id": "X-1",
            "reason": "r",
            "scope": {"role": "browser"},
            "disables": ["R-EFF-FETCH"],
            "expires": __import__("datetime").date(2027, 3, 31),
        }
    ]
    path = tmp_path / "p.yaml"
    write_signed(data, private, path)
    assert load_policy(path, [public]).exceptions[0].expires == "2027-03-31"


# -- the loader -------------------------------------------------------------------------------------


def test_a_signed_policy_loads_to_the_same_model(policy_file, keys):
    assert load_policy(policy_file, [keys[1]]) == default_policy()


def test_an_unsigned_policy_is_rejected(tmp_path, keys):
    path = tmp_path / "p.yaml"
    write_document(default_policy_dict(), path)
    with pytest.raises(PolicyRejected) as error:
        load_policy(path, [keys[1]])
    assert error.value.code == "unsigned"


def test_a_tampered_policy_is_rejected(policy_file, keys):
    text = policy_file.read_text().replace("mode: observe", "mode: block")
    assert text != policy_file.read_text()
    policy_file.write_text(text)
    with pytest.raises(PolicyRejected) as error:
        load_policy(policy_file, [keys[1]])
    assert error.value.code == "bad_signature"


def test_a_policy_signed_by_an_untrusted_key_is_rejected(tmp_path, keys):
    other_private, _ = signing.generate_keypair()
    path = tmp_path / "p.yaml"
    write_signed(default_policy_dict(), other_private, path)
    with pytest.raises(PolicyRejected) as error:
        load_policy(path, [keys[1]])
    assert error.value.code == "bad_signature"


def test_a_validly_signed_but_invalid_policy_is_rejected(tmp_path, keys):
    data = default_policy_dict()
    data["thresholds"] = {"origin_strength": 0.5, "surprise": 1}
    path = tmp_path / "p.yaml"
    write_signed(data, keys[0], path)
    with pytest.raises(PolicyRejected) as error:
        load_policy(path, [keys[1]])
    assert error.value.code == "invalid"


def test_a_duplicate_key_is_rejected(policy_file, keys):
    policy_file.write_text(policy_file.read_text() + "\nmode: block\n")
    with pytest.raises(PolicyRejected) as error:
        load_policy(policy_file, [keys[1]])
    assert error.value.code == "unreadable"


def test_a_missing_file_is_rejected(tmp_path, keys):
    with pytest.raises(PolicyRejected) as error:
        load_policy(tmp_path / "nope.yaml", [keys[1]])
    assert error.value.code == "unreadable"


def test_the_policy_digest_changes_with_the_content(tmp_path, keys):
    a, b = tmp_path / "a.yaml", tmp_path / "b.yaml"
    write_signed(default_policy_dict(), keys[0], a)
    write_signed({**default_policy_dict(), "mode": "warn"}, keys[0], b)
    assert load_policy_data(a, [keys[1]]).digest != load_policy_data(b, [keys[1]]).digest


# -- last valid policy kept -------------------------------------------------------------------------


def test_a_tampered_reload_keeps_the_last_valid_policy(policy_file, keys):
    store = PolicyStore(policy_file, [keys[1]])
    good_digest = store.digest
    policy_file.write_text(policy_file.read_text().replace("mode: observe", "mode: block"))
    assert store.reload() is False
    assert store.policy.mode is Mode.OBSERVE
    assert store.digest == good_digest
    assert [r.code for r in store.rejections] == ["bad_signature"]


def test_a_valid_reload_replaces_the_policy(policy_file, keys):
    store = PolicyStore(policy_file, [keys[1]])
    write_signed({**default_policy_dict(), "mode": "warn"}, keys[0], policy_file)
    assert store.reload() is True
    assert store.policy.mode is Mode.WARN
    assert store.rejections == []


def test_a_deleted_policy_keeps_the_last_valid_one(policy_file, keys):
    store = PolicyStore(policy_file, [keys[1]])
    policy_file.unlink()
    assert store.reload() is False
    assert store.policy == default_policy()


def test_there_is_no_fallback_when_the_first_load_fails(tmp_path, keys):
    with pytest.raises(PolicyRejected):
        PolicyStore(tmp_path / "missing.yaml", [keys[1]])


# -- rule packs -------------------------------------------------------------------------------------


def make_pack(private, **fields):
    body = {
        "name": "core",
        "version": "2.0.0",
        "publisher": "uni-a",
        "extra_roles": ["ci_runner"],
        "contracts": {"ci_runner": {"may_exec": ["build_tool"], "may_connect": ["package_index"]}},
        "rules": [{"id": "R-EFF-FETCH", "mode": "block", "role": "ci_runner"}],
        **fields,
    }
    return signing.signed(body, private)


def policy_with_pack(tmp_path, keys, pack_doc, ref_signature=None):
    packs = tmp_path / "packs"
    packs.mkdir(exist_ok=True)
    write_document(pack_doc, packs / f"{pack_doc['name']}-{pack_doc['version']}.yaml")
    data = default_policy_dict()
    data["rule_packs"] = [
        {
            "name": pack_doc["name"],
            "version": pack_doc["version"],
            "signature": ref_signature or pack_doc["signature"],
        }
    ]
    path = tmp_path / "policy.yaml"
    write_signed(data, keys[0], path)
    return path


def test_a_pinned_signed_pack_is_merged(tmp_path, keys):
    path = policy_with_pack(tmp_path, keys, make_pack(keys[0]))
    loaded = load_policy_data(path, [keys[1]])
    assert loaded.packs == (("core", "2.0.0"),)
    assert "ci_runner" in loaded.policy.contracts
    assert loaded.policy.rule_mode("R-EFF-FETCH", "ci_runner") is Mode.BLOCK


def test_a_tampered_pack_rejects_the_policy(tmp_path, keys):
    path = policy_with_pack(tmp_path, keys, make_pack(keys[0]))
    pack_file = tmp_path / "packs" / "core-2.0.0.yaml"
    pack_file.write_text(pack_file.read_text().replace("build_tool", "anything"))
    with pytest.raises(PolicyRejected) as error:
        load_policy(path, [keys[1]])
    assert error.value.code == "pack_bad_signature"


def test_an_unsigned_pack_rejects_the_policy(tmp_path, keys):
    doc = make_pack(keys[0])
    del doc["signature"]
    path = policy_with_pack(tmp_path, keys, {**doc, "signature": ""}, ref_signature="x")
    with pytest.raises(PolicyRejected) as error:
        load_policy(path, [keys[1]])
    assert error.value.code == "pack_unsigned"


def test_a_pack_that_is_not_the_pinned_one_is_rejected(tmp_path, keys):
    path = policy_with_pack(tmp_path, keys, make_pack(keys[0]), ref_signature="AAAA")
    with pytest.raises(PolicyRejected) as error:
        load_policy(path, [keys[1]])
    assert error.value.code == "pack_mismatch"


def test_a_missing_pack_rejects_the_policy(tmp_path, keys):
    path = policy_with_pack(tmp_path, keys, make_pack(keys[0]))
    (tmp_path / "packs" / "core-2.0.0.yaml").unlink()
    with pytest.raises(PolicyRejected) as error:
        load_policy(path, [keys[1]])
    assert error.value.code == "pack_unreadable"


def test_a_pack_cannot_loosen_a_role_the_policy_has(tmp_path, keys):
    pack = make_pack(keys[0], contracts={"web_worker": {"may_exec": ["build_tool"]}})
    path = policy_with_pack(tmp_path, keys, pack)
    with pytest.raises(PolicyRejected) as error:
        load_policy(path, [keys[1]])
    assert error.value.code == "pack_weakens"


def test_a_pack_signed_by_a_publisher_key_the_policy_does_not_trust_is_rejected(tmp_path, keys):
    stranger, _ = signing.generate_keypair()
    path = policy_with_pack(tmp_path, keys, make_pack(stranger))
    with pytest.raises(PolicyRejected) as error:
        load_policy(path, [keys[1]])
    assert error.value.code == "pack_bad_signature"


def test_a_tampered_pack_on_reload_keeps_the_last_valid_policy(tmp_path, keys):
    path = policy_with_pack(tmp_path, keys, make_pack(keys[0]))
    store = PolicyStore(path, [keys[1]])
    assert "ci_runner" in store.policy.contracts
    pack_file = tmp_path / "packs" / "core-2.0.0.yaml"
    pack_file.write_text(pack_file.read_text().replace("2.0.0", "2.0.1", 1))
    assert store.reload() is False
    assert "ci_runner" in store.policy.contracts
    assert store.rejections[-1].code.startswith("pack_")


def test_the_pack_model_checks_its_version():
    with pytest.raises(ValueError):
        RulePack(name="core", version="two")


# -- changing only the policy changes outcomes ------------------------------------------------------


def case(scenario):
    return next(c for c in cases() if c.scenario == scenario)


def outcome(scenario, policy):
    return summary(run_case(case(scenario), policy))


def test_the_decision_for_three_fails_comes_from_the_policy():
    assert outcome("S13", default_policy())["decision"] is Decision.BLOCK
    hold = default_policy(decisions={"fails_3": "hold"})
    assert outcome("S13", hold)["decision"] is Decision.HOLD


def test_the_decision_for_two_fails_comes_from_the_policy():
    assert outcome("S49", default_policy())["decision"] is Decision.HOLD
    allow = default_policy(decisions={"fails_2": "allow"})
    assert outcome("S49", allow)["decision"] is Decision.ALLOW


def test_the_origin_strength_threshold_comes_from_the_policy():
    assert "origin" in outcome("S23", default_policy())["questions"]
    strict = default_policy(thresholds={"origin_strength": 1.5})
    assert "origin" not in outcome("S23", strict)["questions"]


def test_a_contract_change_alone_changes_the_outcome():
    data = default_policy_dict()
    data["contracts"]["web_worker"]["may_connect"] = ["db_server", "cache_server", "any"]
    result = outcome("S15", Policy.parse(data))
    assert "contract" not in result["questions"]
    assert result["decision"] is not Decision.BLOCK


def test_the_trusted_source_list_alone_changes_the_outcome():
    event = raw(
        "content_in", "package_installer", "p-1", content="pkg", source_class="download",
        domain="pypi.org",
    )  # fmt: skip
    trusted = run_events([event], default_policy())
    assert [j.override for j in trusted.judgements().values()] == [Override.TRUSTED_ROOT]
    data = default_policy_dict()
    data["trusted_sources"] = []
    untrusted = run_events([event], Policy.parse(data))
    [j] = untrusted.judgements().values()
    assert j.override is None
    assert j.failed["origin"]


def test_a_destination_trust_flag_alone_changes_the_outcome():
    events = [ev("net_connect", "script_host", "p-1", f=1, destination_class="db_server")]
    [j] = run_events(events).judgements().values()
    assert not j.failed["effect"]  # a trusted class, though the role's contract names no classes
    data = default_policy_dict()
    for d in data["destinations"]:
        if d["name"] == "db_server":
            d["trusted"] = False
    [j] = run_events(events, Policy.parse(data)).judgements().values()
    assert j.failed["effect"]
