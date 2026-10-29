"""Policy-driven behaviour: rule ids, per-rule modes, exceptions and the constants that used to be
hard-coded (CLAUDE.md C6, Phase 2 "remove every hard-coded threshold")."""

from datetime import date

import pytest
from pydantic import ValidationError

from evhelp import ev
from refmon.policy import WEIGHTS, Policy, default_policy, default_policy_dict
from refmon.rules import CONTRACT_RULE_IDS, RULE_IDS, SIGNAL_NAMES, rule_id
from refmon.schemas import Decision, Mode
from scenario_run import run_events


def test_the_signal_vocabulary_is_exactly_the_weight_table():
    assert set(SIGNAL_NAMES) == set(WEIGHTS)


def test_rule_ids_follow_the_c6_naming():
    assert rule_id("effect_fetch") == "R-EFF-FETCH"
    assert rule_id("contract_external_exec") == "R-CON-EXTERNAL-EXEC"
    assert rule_id("origin_external") == "R-ORI-EXTERNAL"
    assert "OVR-CANARY" in RULE_IDS
    assert all(r.startswith("R-CON-") for r in CONTRACT_RULE_IDS)


def _worker_story(**policy_overrides):
    events = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("exec", "web_worker", "p-1", f=2, t=1, exec_class="unknown"),
        ev("net_connect", "web_worker", "p-1", f=3, t=2, destination_class="unknown"),
    ]
    return run_events(events, default_policy(**policy_overrides))


def test_a_story_without_rule_settings_uses_the_global_mode():
    [j] = _worker_story(mode="warn").judgements().values()
    assert j.mode is Mode.WARN


def test_a_rule_setting_raises_the_mode_of_a_story_in_which_the_rule_fired():
    settings = [{"id": "R-CON-WEB-WORKER-EXEC", "mode": "block"}]
    [j] = _worker_story(mode="observe", rules=settings).judgements().values()
    assert j.mode is Mode.BLOCK


def test_a_role_specific_setting_applies_to_that_role_only():
    settings = [{"id": "R-CON-WEB-WORKER-EXEC", "mode": "block", "role": "app_server"}]
    [j] = _worker_story(mode="observe", rules=settings).judgements().values()
    assert j.mode is Mode.OBSERVE


def test_a_role_specific_setting_beats_a_general_one():
    p = default_policy(
        rules=[
            {"id": "R-EFF-FETCH", "mode": "warn"},
            {"id": "R-EFF-FETCH", "mode": "block", "role": "web_worker"},
        ]
    )
    assert p.rule_mode("R-EFF-FETCH", "web_worker") is Mode.BLOCK
    assert p.rule_mode("R-EFF-FETCH", "browser") is Mode.WARN
    assert p.rule_mode("R-EFF-FETCH") is Mode.WARN
    assert p.rule_mode("R-EFF-HIDE") is Mode.OBSERVE


def test_an_unknown_rule_id_is_rejected():
    with pytest.raises(ValidationError):
        default_policy(rules=[{"id": "R-EFF-NOPE", "mode": "block"}])


EXCEPTION = {
    "id": "X-001",
    "reason": "Research group installs packages",
    "scope": {"role": "web_worker"},
    "disables": ["R-EFF-FETCH"],
    "expires": "2027-03-31",
}


def test_an_exception_switches_a_rule_off_in_its_scope():
    base = _worker_story().judgements()
    [j0] = base.values()
    assert j0.failed["effect"]
    [j1] = _worker_story(exceptions=[EXCEPTION]).judgements().values()
    assert "effect_fetch" not in {s.name for s in j1.signals}
    assert j1.disabled_rules == ("R-EFF-FETCH",)


def test_an_exception_outside_its_scope_does_nothing():
    other = {**EXCEPTION, "scope": {"role": "browser"}}
    [j] = _worker_story(exceptions=[other]).judgements().values()
    assert j.failed["effect"]
    assert j.disabled_rules == ()


def test_an_expired_exception_does_nothing():
    p = default_policy(exceptions=[{**EXCEPTION, "expires": "2026-10-27"}])
    assert p.disabled_rules([{"role": "web_worker"}], date(2026, 10, 28)) == set()
    assert p.disabled_rules([{"role": "web_worker"}], date(2026, 10, 27)) == {"R-EFF-FETCH"}


def test_an_exception_can_disable_the_origin_rule():
    ex = {**EXCEPTION, "disables": ["R-ORI-EXTERNAL"]}
    [j] = _worker_story(exceptions=[ex]).judgements().values()
    assert not j.failed["origin"]


@pytest.mark.parametrize(
    "change",
    [
        {"reason": "  "},
        {"scope": {}},
        {"scope": {"colour": "red"}},
        {"disables": []},
        {"disables": ["OVR-CANARY"]},  # overrides cannot be excepted
        {"disables": ["R-NOPE"]},
        {"expires": "next week"},
    ],
)
def test_a_malformed_exception_is_rejected(change):
    with pytest.raises(ValidationError):
        default_policy(exceptions=[{**EXCEPTION, **change}])


def test_a_user_group_maps_users_into_exception_scopes():
    p = default_policy(
        user_groups={"u": "research-lab"},
        exceptions=[{**EXCEPTION, "scope": {"group": "research-lab"}}],
    )
    events = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("net_connect", "web_worker", "p-1", f=3, t=2, destination_class="unknown"),
    ]
    [j] = run_events(events, p).judgements().values()
    assert "effect_fetch" not in {s.name for s in j.signals}


def test_strict_exec_roles_come_from_policy():
    events = [ev("exec", "app_server", "p-1", f=2, t=1, exec_class="unknown")]
    [j] = run_events(events).judgements().values()
    assert {s.name for s in j.signals} == {"contract_exec_violation"}
    p = default_policy(strict_exec_roles=["web_worker", "node_app_server", "app_server"])
    [j] = run_events(events, p).judgements().values()
    assert {s.name for s in j.signals} == {"contract_web_worker_exec"}


def test_credential_classes_come_from_policy():
    events = [ev("asset_access", "script_host", "p-1", cls="key_material", f=1)]
    [j] = run_events(events).judgements().values()
    assert "effect_credential" in {s.name for s in j.signals}
    [j] = (
        run_events(events, default_policy(credential_classes=["credential_store"]))
        .judgements()
        .values()
    )
    assert "effect_credential" not in {s.name for s in j.signals}


def test_the_alive_floor_comes_from_policy():
    events = [ev("content_in", "script_host", "p-1", f=1, source_class="web", t=0)]
    later = events[0].ts.replace(hour=events[0].ts.hour + 3)  # six half-lives: strength 1/64
    p = run_events(events)
    [label] = p.tagger.labels
    assert p.tagger.alive([label], later) == ()
    low = run_events(events, default_policy(thresholds={"label_alive_floor": 0.001}))
    assert low.tagger.alive([label], later) == (label,)


def test_channel_roles_come_from_policy():
    events = [
        ev("content_in", "browser", "p-1", f=1, source_class="web", t=0),
        ev("content_in", "browser", "p-2", f=2, source_class="web", t=1),
        ev("net_connect", "browser", "p-1", f=3, t=2, destination_class="package_index"),
    ]
    linked = run_events(events).linker.records
    # browsers do not key stories on the process, so p-1 and p-2 are not joined by it
    assert len(linked) >= 2
    p = default_policy(non_process_keyed_roles=[])
    assert len(run_events(events, p).linker.records) < len(linked)


def test_the_default_decision_for_each_fail_count_comes_from_policy():
    events = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("exec", "web_worker", "p-1", f=2, t=1, exec_class="unknown"),
        ev("net_connect", "web_worker", "p-1", f=3, t=2, destination_class="unknown"),
    ]
    [j] = run_events(events).judgements().values()
    assert j.rule_decision is Decision.BLOCK
    p = default_policy(decisions={"fails_3": "hold"})
    [j] = run_events(events, p).judgements().values()
    assert j.rule_decision is Decision.HOLD


def test_the_default_policy_dict_round_trips_through_the_model():
    assert Policy.parse(default_policy_dict()) == default_policy()
