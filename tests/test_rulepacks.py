"""Rule packs (CLAUDE.md Phase 6): signed, versioned, shareable; loading a pack never weakens an
existing rule without approval; an unsigned pack is rejected."""

import pytest

from refmon import signing
from refmon.policy import default_policy_dict
from refmon.policy_io import (
    PolicyRejected,
    PolicyStore,
    load_policy,
    load_policy_data,
    write_document,
    write_signed,
)
from refmon.rulepacks import PackWeakens, RulePack, merge_pack, weakenings
from refmon.schemas import Mode


@pytest.fixture
def keys():
    return signing.generate_keypair()


@pytest.fixture
def publisher():
    """Another organisation that shares a pack."""
    return signing.generate_keypair()


def pack(private, **fields):
    body = {"name": "uni-b-core", "version": "1.2.0", "publisher": "uni-b", **fields}
    return signing.signed(body, private)


def install(tmp_path, keys, pack_doc, *, approvals=None, extra=None, mode=None):
    packs = tmp_path / "packs"
    packs.mkdir(exist_ok=True)
    write_document(pack_doc, packs / f"{pack_doc['name']}-{pack_doc['version']}.yaml")
    data = default_policy_dict()
    if mode:
        data["mode"] = mode
    data["rule_packs"] = [
        {
            "name": pack_doc["name"],
            "version": pack_doc["version"],
            "signature": pack_doc["signature"],
        }
    ]
    if approvals:
        data["pack_approvals"] = approvals
    data.update(extra or {})
    path = tmp_path / "policy.yaml"
    write_signed(data, keys[0], path)
    return path


def base():
    return default_policy_dict()


# -- Done when: an unsigned pack is rejected ------------------------------------------------------------------


def test_an_unsigned_pack_is_rejected(tmp_path, keys):
    doc = {"name": "uni-b-core", "version": "1.2.0", "rules": []}
    path = install(tmp_path, keys, {**doc, "signature": ""})
    with pytest.raises(PolicyRejected) as error:
        load_policy(path, [keys[1]])
    assert error.value.code == "pack_unsigned"


def test_a_pack_with_no_signature_field_at_all_is_rejected(tmp_path, keys):
    doc = {"name": "uni-b-core", "version": "1.2.0", "rules": []}
    packs = tmp_path / "packs"
    packs.mkdir()
    write_document(doc, packs / "uni-b-core-1.2.0.yaml")
    data = default_policy_dict()
    data["rule_packs"] = [{"name": "uni-b-core", "version": "1.2.0", "signature": "x"}]
    write_signed(data, keys[0], tmp_path / "policy.yaml")
    with pytest.raises(PolicyRejected) as error:
        load_policy(tmp_path / "policy.yaml", [keys[1]])
    assert error.value.code == "pack_unsigned"


# -- sharing between organisations -----------------------------------------------------------------------------------


def test_a_pack_from_another_organisation_loads_when_its_publisher_key_is_trusted(
    tmp_path, keys, publisher
):
    doc = pack(
        publisher[0],
        extra_roles=["ci_runner"],
        contracts={"ci_runner": {"may_exec": ["build_tool"]}},
        rules=[{"id": "R-EFF-FETCH", "mode": "block", "role": "ci_runner"}],
    )
    path = install(tmp_path, keys, doc)
    with pytest.raises(
        PolicyRejected, match="pack_bad_signature"
    ):  # the publisher is not trusted yet
        load_policy(path, [keys[1]])
    loaded = load_policy_data(path, [keys[1]], pack_keys=[publisher[1]])
    assert loaded.packs == (("uni-b-core", "1.2.0"),)
    assert loaded.policy.rule_mode("R-EFF-FETCH", "ci_runner") is Mode.BLOCK


# -- weakening ------------------------------------------------------------------------------------------------------------


def test_a_pack_that_adds_a_role_or_a_stricter_rule_is_not_a_weakening():
    p = RulePack(
        name="p", version="1.0.0", extra_roles=["x"], contracts={"x": {"may_exec": []}},
        rules=[{"id": "R-EFF-FETCH", "mode": "block"}],
    )  # fmt: skip
    assert weakenings(base(), p) == []


def test_a_pack_that_tightens_an_existing_contract_is_merged():
    p = RulePack(
        name="p", version="1.0.0",
        contracts={"web_worker": {"may_connect": ["db_server"], "may_exec": [], "may_write": ["cache"]}},
    )  # fmt: skip
    assert weakenings(base(), p) == []
    merged = merge_pack(base(), p)
    assert merged["contracts"]["web_worker"]["may_connect"] == ["db_server"]


@pytest.mark.parametrize(
    ("contract", "expected"),
    [
        ({"may_exec": ["build_tool"]}, "contract:web_worker:may_exec"),
        (
            {"may_connect": ["db_server", "cache_server", "partner_api"]},
            "contract:web_worker:may_connect",
        ),
        ({"may_connect": ["any"]}, "contract:web_worker:may_connect"),
        ({"may_read_assets": ["browser-passwords"]}, "contract:web_worker:may_read_assets"),
        ({"may_persist": True}, None),  # None -> True: both leave persistence open
        ({"may_change_privilege": True}, "contract:web_worker:may_change_privilege"),
        ({"may_tamper": True}, "contract:web_worker:may_tamper"),
        ({"may_mass_change": True}, "contract:web_worker:may_mass_change"),
        ({"may_fan_out": True}, "contract:web_worker:may_fan_out"),
        ({"may_repeat_large_responses": True}, "contract:web_worker:may_repeat_large_responses"),
    ],
)
def test_each_way_to_loosen_a_contract_is_a_weakening(contract, expected):
    p = RulePack(name="p", version="1.0.0", contracts={"web_worker": contract})
    found = weakenings(base(), p)
    assert found == ([expected] if expected else [])


def test_lifting_a_deny_is_a_weakening_and_adding_one_is_not():
    lifts = RulePack(
        name="p",
        version="1.0.0",
        contracts={"interactive_shell": {"external_content_exec": "allow"}},
    )
    assert weakenings(base(), lifts) == ["contract:interactive_shell:external_content_exec"]
    adds = RulePack(
        name="p", version="1.0.0", contracts={"browser": {"external_content_exec": "deny"}}
    )
    assert weakenings(base(), adds) == []
    explicit = RulePack(
        name="p", version="1.0.0", contracts={"launcher": {"unsigned_external_exec": "allow"}}
    )
    assert weakenings(base(), explicit) == ["contract:launcher:unsigned_external_exec"]
    silent = RulePack(name="p", version="1.0.0", contracts={"launcher": {}})
    assert weakenings(base(), silent) == []  # a field a pack does not name keeps the policy's value


def test_lowering_a_mode_or_switching_a_rule_off_is_a_weakening():
    data = {**base(), "mode": "block"}
    lowers = RulePack(name="p", version="1.0.0", rules=[{"id": "R-EFF-FETCH", "mode": "observe"}])
    assert weakenings(data, lowers) == ["rule:R-EFF-FETCH:*:mode"]
    off = RulePack(
        name="p", version="1.0.0", rules=[{"id": "R-EFF-FETCH", "mode": "block", "enabled": False}]
    )
    assert weakenings(data, off) == ["rule:R-EFF-FETCH:*:disabled"]
    same = RulePack(name="p", version="1.0.0", rules=[{"id": "R-EFF-FETCH", "mode": "block"}])
    assert weakenings(data, same) == []


def test_a_role_setting_that_lowers_a_block_rule_for_one_role_is_a_weakening():
    data = {**base(), "rules": [{"id": "R-EFF-FETCH", "mode": "block", "role": "browser"}]}
    p = RulePack(
        name="p", version="1.0.0", rules=[{"id": "R-EFF-FETCH", "mode": "warn", "role": "browser"}]
    )
    assert weakenings(data, p) == ["rule:R-EFF-FETCH:browser:mode"]


def test_merging_a_weakening_without_approval_is_refused_naming_it():
    p = RulePack(name="p", version="1.0.0", contracts={"web_worker": {"may_exec": ["build_tool"]}})
    with pytest.raises(PackWeakens) as error:
        merge_pack(base(), p)
    assert error.value.ids == ["contract:web_worker:may_exec"]
    assert "without approval" in str(error.value)


def test_an_approval_in_the_signed_policy_lets_exactly_that_weakening_through(
    tmp_path, keys, publisher
):
    loosen = {
        "web_worker": {
            "may_exec": ["build_tool"],
            "may_connect": ["db_server", "cache_server", "any"],
        }
    }
    doc = pack(publisher[0], contracts=loosen)
    refused = install(tmp_path, keys, doc)
    with pytest.raises(PolicyRejected) as error:
        load_policy(refused, [keys[1]], pack_keys=[publisher[1]])
    assert error.value.code == "pack_weakens"

    one = [
        {
            "pack": "uni-b-core",
            "version": "1.2.0",
            "accepts": ["contract:web_worker:may_exec"],
            "by": "alice",
        }
    ]
    partial = install(tmp_path, keys, doc, approvals=one)
    with pytest.raises(PolicyRejected) as error:  # the second weakening is still not approved
        load_policy(partial, [keys[1]], pack_keys=[publisher[1]])
    assert (
        "may_connect" in str(error.value)
        and "may_exec" not in str(error.value).split("approval")[1]
    )

    both = [
        {**one[0], "accepts": ["contract:web_worker:may_exec", "contract:web_worker:may_connect"]}
    ]
    ok = install(tmp_path, keys, doc, approvals=both)
    policy = load_policy(ok, [keys[1]], pack_keys=[publisher[1]])
    assert policy.contract_for("web_worker").may_exec == ("build_tool",)


def test_an_approval_for_another_pack_version_does_not_count(tmp_path, keys, publisher):
    doc = pack(publisher[0], contracts={"web_worker": {"may_exec": ["build_tool"]}})
    stale = [
        {
            "pack": "uni-b-core",
            "version": "1.1.0",
            "accepts": ["contract:web_worker:may_exec"],
            "by": "alice",
        }
    ]
    path = install(tmp_path, keys, doc, approvals=stale)
    with pytest.raises(PolicyRejected) as error:
        load_policy(path, [keys[1]], pack_keys=[publisher[1]])
    assert error.value.code == "pack_weakens"


def test_an_approval_cannot_be_added_by_editing_the_policy_without_the_key(
    tmp_path, keys, publisher
):
    doc = pack(publisher[0], contracts={"web_worker": {"may_exec": ["build_tool"]}})
    path = install(tmp_path, keys, doc)
    text = path.read_text() + (
        "pack_approvals:\n- {pack: uni-b-core, version: 1.2.0, "
        "accepts: ['contract:web_worker:may_exec'], by: mallory}\n"
    )
    path.write_text(text)
    with pytest.raises(PolicyRejected) as error:
        load_policy(path, [keys[1]], pack_keys=[publisher[1]])
    assert error.value.code == "bad_signature"


def test_a_pack_that_lowers_a_block_rule_needs_approval_too(tmp_path, keys, publisher):
    doc = pack(publisher[0], rules=[{"id": "R-EFF-TAMPER", "mode": "observe"}])
    path = install(tmp_path, keys, doc, mode="block")
    with pytest.raises(PolicyRejected) as error:
        load_policy(path, [keys[1]], pack_keys=[publisher[1]])
    assert error.value.code == "pack_weakens" and "R-EFF-TAMPER" in str(error.value)


# -- versions ------------------------------------------------------------------------------------------------------------------


def test_an_older_pack_than_the_one_in_force_is_refused_on_reload(tmp_path, keys, publisher):
    new = pack(publisher[0], version="1.3.0", contracts={"web_worker": {"may_exec": []}})
    path = install(tmp_path, keys, new)
    store = PolicyStore(path, [keys[1]], pack_keys=[publisher[1]])
    assert store.packs == (("uni-b-core", "1.3.0"),)
    old = pack(publisher[0], version="1.1.0", contracts={"web_worker": {"may_exec": []}})
    install(tmp_path, keys, old)  # the policy now pins 1.1.0
    assert store.reload() is False
    assert store.rejections[-1].code == "pack_downgrade"
    assert store.packs == (("uni-b-core", "1.3.0"),)  # the newer pack stays in force


def test_a_newer_pack_replaces_the_older_one(tmp_path, keys, publisher):
    path = install(tmp_path, keys, pack(publisher[0], version="1.1.0"))
    store = PolicyStore(path, [keys[1]], pack_keys=[publisher[1]])
    install(tmp_path, keys, pack(publisher[0], version="1.2.0"))
    assert store.reload() is True and store.packs == (("uni-b-core", "1.2.0"),)


def test_a_pack_loaded_from_a_tampered_file_keeps_the_last_valid_policy(tmp_path, keys, publisher):
    path = install(tmp_path, keys, pack(publisher[0], version="1.1.0"))
    store = PolicyStore(path, [keys[1]], pack_keys=[publisher[1]])
    pack_file = tmp_path / "packs" / "uni-b-core-1.1.0.yaml"
    pack_file.write_text(pack_file.read_text() + "rules:\n- {id: R-EFF-FETCH, mode: observe}\n")
    assert store.reload() is False and store.rejections[-1].code == "pack_bad_signature"
    assert store.packs == (("uni-b-core", "1.1.0"),)
