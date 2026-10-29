"""Phase 5: the Exposure stage and virtual patching (CLAUDE.md C5). S16 shows mode escalation on an
exposed component and reversion after the fixture reports a patched version; S28 and S29 are the
end-of-life and workaround cases. All input comes from local fixture files."""

import hashlib
from datetime import timedelta
from pathlib import Path

import pytest

from evhelp import ev
from refmon import signing
from refmon.coverage import ADAPTIVE, adaptive_gaps, gaps, parse_coverage_map
from refmon.exposure import (
    Advisories,
    ExposureManager,
    ExposureState,
    assess,
    load_advisories,
    load_inventory,
    overlay,
    parse_version,
    satisfies,
)
from refmon.gate import RecordingNotifier
from refmon.pipeline import Pipeline
from refmon.policy import default_policy
from refmon.policy_io import write_signed
from refmon.replay import ReplaySource
from refmon.report import Reporter
from refmon.schemas import Action, ActionType, Decision, Mode, Verdict
from scenario_run import ROOT, cases, run_case, summary

FIXTURES = Path(__file__).parent / "exposure"
ADVISORIES = load_advisories(FIXTURES / "advisories.yaml")


def inventory(name):
    return load_inventory(FIXTURES / name)


def states(inv, advisories=ADVISORIES):
    return {i.component: i.state for i in assess(inventory(inv), advisories).items}


# -- versions and the model -------------------------------------------------------------------------


def test_versions_compare_numerically_not_as_text():
    assert parse_version("3.10.0") > parse_version("3.9.9")
    assert parse_version("3.1.0") == parse_version("3.1")
    assert parse_version("v2.0.1-rc1") == (2, 0, 1)
    with pytest.raises(ValueError):
        parse_version("latest")


@pytest.mark.parametrize(
    ("version", "constraint", "expected"),
    [
        ("3.1.0", ">=3.0,<3.1.4", True),
        ("3.1.4", ">=3.0,<3.1.4", False),
        ("2.9", ">=3.0,<3.1.4", False),
        ("3.1.4", "==3.1.4", True),
        ("3.1.4", "!=3.1.4", False),
        ("12.22", "<=12", False),
        ("12.0", "<=12", True),
        ("1.0", "", True),
    ],
)
def test_version_constraints(version, constraint, expected):
    assert satisfies(version, constraint) is expected


def test_a_bad_constraint_is_an_error():
    with pytest.raises(ValueError):
        satisfies("1.0", "about 1")


def test_advisory_ids_are_unique():
    with pytest.raises(ValueError, match="unique"):
        Advisories.model_validate(
            {"advisories": [{"id": "A-1", "component": "x"}, {"id": "A-1", "component": "y"}]}
        )


# -- states (C5) -------------------------------------------------------------------------------------


def test_an_affected_exposed_component_is_exposed_and_a_fixed_one_is_patched():
    assert states("s16.inventory.exposed.yaml")["webshop"] is ExposureState.EXPOSED
    assert states("s16.inventory.patched.yaml")["webshop"] is ExposureState.PATCHED


def test_an_affected_component_nobody_can_reach_is_listed_but_does_not_escalate():
    exposure = assess(inventory("s16.inventory.exposed.yaml"), ADVISORIES)
    assert set(exposure.escalated) == {"web_worker"}
    assert states("s16.inventory.exposed.yaml")["db-engine"] is ExposureState.PATCHED
    reach = Advisories.model_validate(
        {"advisories": [{"id": "A-9", "component": "cache-lib", "affected": "<3"}]}
    )
    assert states("s16.inventory.exposed.yaml", reach)["cache-lib"] is ExposureState.NOT_REACHABLE


def test_a_verified_workaround_flag_means_mitigated_and_a_missing_flag_means_exposed():
    assert states("s29.inventory.mitigated.yaml")["report-engine"] is ExposureState.MITIGATED
    assert states("s29.inventory.flag_removed.yaml")["report-engine"] is ExposureState.EXPOSED


def test_end_of_life_is_always_exposed_even_when_not_reachable():
    exposure = assess(inventory("s28.inventory.eol.yaml"), ADVISORIES)
    [eol] = exposure.by_state(ExposureState.END_OF_LIFE)
    assert eol.component == "legacy-node" and eol.role == "node_app_server" and eol.escalates
    flagged = Advisories(advisories=[])
    comp = (
        inventory("s28.inventory.eol.yaml").components[0].model_copy(update={"end_of_life": True})
    )
    inv = inventory("s28.inventory.eol.yaml").model_copy(update={"components": [comp]})
    assert assess(inv, flagged).items[0].state is ExposureState.END_OF_LIFE


def test_the_inventory_covers_containers_bundled_runtimes_appliances_and_decentral_servers():
    inv = inventory("easy_to_miss.inventory.yaml")
    assert {c.kind for c in inv.components} == {
        "container", "bundled_runtime", "appliance", "decentral_server"
    }  # fmt: skip
    exposure = assess(inv, ADVISORIES)
    assert {i.role for i in exposure.items if i.escalates} == {
        "web_worker", "node_app_server", "app_server"
    }  # fmt: skip
    assert {i.kind for i in exposure.items if i.escalates} >= {"bundled_runtime", "appliance"}


def test_severity_and_advisories_are_listed_with_the_exposure():
    [item] = [
        i for i in assess(inventory("s16.inventory.exposed.yaml"), ADVISORIES).items if i.escalates
    ]
    assert item.advisories == ("ADV-2026-001",) and item.severity == "critical"
    assert item.reason == "webshop:ADV-2026-001"


def test_advisory_files_can_be_required_to_be_signed(tmp_path):
    private, public = signing.generate_keypair()
    write_signed(
        {"advisories": [{"id": "A-1", "component": "x", "affected": "<2"}]},
        private,
        tmp_path / "a.yaml",
    )
    assert load_advisories(tmp_path / "a.yaml", [public]).advisories[0].id == "A-1"
    (tmp_path / "a.yaml").write_text((tmp_path / "a.yaml").read_text().replace("<2", "<0"))
    with pytest.raises(ValueError, match="not signed"):
        load_advisories(tmp_path / "a.yaml", [public])
    with pytest.raises(ValueError, match="not signed"):
        load_inventory(FIXTURES / "s16.inventory.exposed.yaml", [public])  # unsigned fixture


# -- virtual patching ----------------------------------------------------------------------------------


def test_the_overlay_raises_only_the_exposed_roles_contract_rules_and_restricts_their_network():
    base = default_policy()
    eff = overlay(base, assess(inventory("s16.inventory.exposed.yaml"), ADVISORIES))
    assert eff.rule_mode("R-CON-WEB-WORKER-EXEC", "web_worker") is Mode.BLOCK
    assert eff.rule_mode("R-CON-WRITE-EXECUTABLE", "web_worker") is Mode.BLOCK
    assert eff.rule_mode("R-CON-WEB-WORKER-EXEC", "node_app_server") is Mode.OBSERVE  # not global
    assert eff.rule_mode("R-EFF-FETCH", "web_worker") is Mode.OBSERVE  # contract rules only
    assert eff.restricted_network_roles == ["web_worker"]
    assert (
        base.restricted_network_roles == [] and base.rules == []
    )  # the signed policy is untouched


def test_nothing_is_exposed_nothing_changes():
    base = default_policy()
    assert overlay(base, assess(inventory("s16.inventory.patched.yaml"), ADVISORIES)) is base


def test_the_overlay_never_lowers_a_mode_the_policy_already_sets():
    base = default_policy(
        mode="block", rules=[{"id": "R-CON-WEB-WORKER-EXEC", "mode": "block", "role": "web_worker"}]
    )
    eff = overlay(base, assess(inventory("s16.inventory.exposed.yaml"), ADVISORIES))
    assert eff.rule_mode("R-CON-WEB-WORKER-EXEC", "web_worker") is Mode.BLOCK
    calm = default_policy(exposure={"escalate_mode": "observe"})
    eff = overlay(calm, assess(inventory("s16.inventory.exposed.yaml"), ADVISORIES))
    assert eff.rule_mode("R-CON-WEB-WORKER-EXEC", "web_worker") is Mode.OBSERVE


def test_the_escalation_mode_comes_from_the_policy():
    warn = default_policy(exposure={"escalate_mode": "warn"})
    eff = overlay(warn, assess(inventory("s16.inventory.exposed.yaml"), ADVISORIES))
    assert eff.rule_mode("R-CON-WEB-WORKER-EXEC", "web_worker") is Mode.WARN


def trusted_connect():
    return [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("net_connect", "web_worker", "p-1", f=2, t=1, destination_class="package_index"),
    ]


def signal_names(policy, events=None):
    from scenario_run import run_events

    p = run_events(events or trusted_connect(), policy)
    return {s.name for j in p.judgements().values() for s in j.signals}


def test_an_exposed_roles_outbound_network_is_limited_to_its_contract_destinations():
    base = default_policy()
    # a trusted destination excuses a process without a label (v1.1, A48: not a labeled one)
    unlabeled = [trusted_connect()[1]]
    assert "effect_fetch" not in signal_names(base, unlabeled)
    eff = overlay(base, assess(inventory("s16.inventory.exposed.yaml"), ADVISORIES))
    names = signal_names(eff, unlabeled)
    assert "effect_fetch" in names and "contract_connect_violation" in names
    listed = ev("net_connect", "web_worker", "p-1", f=3, t=2, destination_class="db_server")
    from scenario_run import run_events

    p = run_events([listed], eff)
    assert not {s.name for j in p.judgements().values() for s in j.signals}  # the contract lists it


# -- S16: escalation and reversion in one running pipeline ------------------------------------------


def s13_events():
    case = next(c for c in cases() if c.scenario == "S13")
    return list(ReplaySource(case.events_path, extra_roles=default_policy().extra_roles))


def replay_attack(pipe, round_no):
    """The S13 stream again as a new attack: new ids, new fingerprints, an hour later."""
    out = []
    for e in s13_events():

        def remap(fp):
            return fp and "hmac:" + hashlib.sha256(f"{round_no}{fp}".encode()).hexdigest()

        actor = e.actor.model_copy(
            update={"id": f"{e.actor.id}r{round_no}", "parent": e.actor.parent}
            if e.actor.parent in (None, "p-77")
            else {"id": f"{e.actor.id}r{round_no}", "parent": f"{e.actor.parent}r{round_no}"}
        )
        obj = e.object.model_copy(update={"fingerprint": remap(e.object.fingerprint)})
        e2 = e.model_copy(
            update={
                "event_id": f"r{round_no}-{e.event_id}", "actor": actor, "object": obj,
                "ts": e.ts + timedelta(hours=round_no),
            }
        )  # fmt: skip
        out += pipe.process(e2)
    return out


def acts(out):
    return [o for o in out if isinstance(o, Action)]


def test_s16_escalates_on_an_exposed_component_and_reverts_after_the_patch():
    manager = ExposureManager(default_policy(mode="observe"))
    pipe = Pipeline(manager.effective_policy, gate=True, notifier=RecordingNotifier())

    # 0. nothing is known to be exposed: the global mode is observe, so the attack is only recorded
    before = replay_attack(pipe, 0)
    verdicts = [o for o in before if isinstance(o, Verdict)]
    assert (
        verdicts and verdicts[-1].decision is Decision.BLOCK and verdicts[-1].mode is Mode.OBSERVE
    )
    assert acts(before) == []

    # 1. the inventory shows an exposed, unpatched component: only the web_worker role escalates
    change = manager.update(inventory("s16.inventory.exposed.yaml"), ADVISORIES)
    assert (change.escalated, change.reverted) == (("web_worker",), ())
    pipe.set_policy(manager.effective_policy)
    during = replay_attack(pipe, 1)
    assert any(a.type is ActionType.KILL_PROCESS_TREE for a in acts(during))
    verdicts = [o for o in during if isinstance(o, Verdict)]
    assert verdicts[-1].mode is Mode.BLOCK
    assert verdicts[-1].virtual_patch == ("webshop:ADV-2026-001",)

    # 2. the fixture reports the patched version: the escalation reverts by itself
    change = manager.update(inventory("s16.inventory.patched.yaml"), ADVISORIES)
    assert (change.escalated, change.reverted) == ((), ("web_worker",))
    pipe.set_policy(manager.effective_policy)
    after = replay_attack(pipe, 2)
    assert acts(after) == []
    assert [o for o in after if isinstance(o, Verdict)][-1].mode is Mode.OBSERVE
    assert manager.effective_policy is manager.base


def test_the_verdict_summary_names_the_reason():
    manager = ExposureManager(default_policy(mode="observe"))
    manager.update(inventory("s16.inventory.exposed.yaml"), ADVISORIES)
    pipe = Pipeline(manager.effective_policy, gate=True, notifier=RecordingNotifier())
    reporter = Reporter(pipe, None)
    for e in s13_events():
        reporter.consume(pipe.process(e))
    report = max(reporter.reports.values(), key=lambda r: r.verdict.ts)
    assert "Extra protection was on" in report.what_happened
    assert "webshop" in report.what_happened and "ADV-2026-001" in report.what_happened
    assert "hmac:" not in report.verdict.summary


def test_a_role_that_is_not_exposed_is_not_escalated_by_someone_elses_flaw():
    manager = ExposureManager(default_policy(mode="observe"))
    manager.update(inventory("s16.inventory.exposed.yaml"), ADVISORIES)
    pipe = Pipeline(manager.effective_policy, gate=True)
    other = [
        ev("request_in", "node_app_server", "p-5", f=40, source_class="inbound_request", t=0),
        ev("exec", "node_app_server", "p-5", f=41, t=1, exec_class="unknown"),
        ev("net_connect", "node_app_server", "p-5", f=42, t=2, destination_class="unknown"),
    ]
    out = [o for e in other for o in pipe.process(e)]
    assert acts(out) == []  # same attack, a role with no exposed component: observe mode


def test_a_reloaded_signed_policy_keeps_the_overlay_on_top_of_it():
    manager = ExposureManager(default_policy(mode="observe"))
    manager.update(inventory("s16.inventory.exposed.yaml"), ADVISORIES)
    manager.rebase(default_policy(mode="warn"))
    assert manager.effective_policy.mode is Mode.WARN
    assert manager.effective_policy.restricted_network_roles == ["web_worker"]


# -- S28: end of life -----------------------------------------------------------------------------------


def test_s28_an_end_of_life_runtime_escalates_its_role_until_it_is_replaced():
    manager = ExposureManager(default_policy(mode="observe"))
    change = manager.update(inventory("s28.inventory.eol.yaml"), ADVISORIES)
    assert change.escalated == ("node_app_server",)
    assert (
        manager.effective_policy.rule_mode("R-CON-WEB-WORKER-EXEC", "node_app_server") is Mode.BLOCK
    )
    # a new advisory file, even an empty one, does not lift it: the runtime is still there
    manager.update(inventory("s28.inventory.eol.yaml"), Advisories(advisories=[]))
    assert "node_app_server" in manager.exposure.escalated
    assert (
        manager.exposure.by_state(ExposureState.END_OF_LIFE)[0].reason == "legacy-node:end_of_life"
    )
    manager.update(inventory("s28.inventory.eol.yaml"), ADVISORIES)
    eol = manager.exposure.by_state(ExposureState.END_OF_LIFE)[0]
    assert eol.reason == "legacy-node:ADV-2026-003"
    change = manager.update(inventory("s28.inventory.replaced.yaml"), ADVISORIES)
    assert change.reverted == ("node_app_server",)
    assert manager.effective_policy is manager.base


# -- S29: workaround-only ---------------------------------------------------------------------------------


def test_s29_a_verified_workaround_means_no_escalation_until_the_flag_disappears():
    manager = ExposureManager(default_policy(mode="observe"))
    change = manager.update(inventory("s29.inventory.mitigated.yaml"), ADVISORIES)
    assert change.escalated == () and manager.effective_policy is manager.base
    assert manager.exposure.by_state(ExposureState.MITIGATED)[0].component == "report-engine"
    change = manager.update(inventory("s29.inventory.flag_removed.yaml"), ADVISORIES)
    assert change.escalated == ("app_server",)
    assert manager.effective_policy.rule_mode("R-CON-EXEC-VIOLATION", "app_server") is Mode.BLOCK
    change = manager.update(inventory("s29.inventory.mitigated.yaml"), ADVISORIES)
    assert change.reverted == ("app_server",)


# -- the policy points at local files ----------------------------------------------------------------------------


def test_the_policy_names_the_inventory_and_advisory_files_and_the_escalation_mode():
    p = default_policy()
    assert p.exposure.inventory == "inventory.yaml" and p.exposure.advisories == "advisories.yaml"
    assert p.exposure.escalate_mode is Mode.BLOCK


# -- coverage ------------------------------------------------------------------------------------------------------


def test_the_adaptive_family_of_the_coverage_map_is_covered_by_s16_s28_and_s29():
    families = parse_coverage_map(ROOT / "CLAUDE.md")
    passing = {
        c.scenario
        for c in cases()
        if summary(run_case(c), "decision")["decision"] is c.expected.decision
    }
    assert gaps(families, passing) == []  # Phase 1 view: adaptive scenarios are left to Phase 5
    missing = adaptive_gaps(families, passing)
    assert [m.rsplit(" ", 1)[1] for m in missing] == ["S16", "S28", "S29"]
    assert adaptive_gaps(families, passing | ADAPTIVE) == []


def test_a_version_written_as_a_number_in_yaml_is_refused_not_guessed(tmp_path):
    path = tmp_path / "a.yaml"
    path.write_text("advisories:\n  - {id: A-1, component: x, affected: '<2', fixed_in: 3.10}\n")
    with pytest.raises(ValueError):  # 3.10 would be read as the number 3.1
        load_advisories(path)
