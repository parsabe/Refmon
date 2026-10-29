"""One test per effect type (CLAUDE.md C7) and per override."""

import pytest

from evhelp import ev
from refmon.policy import default_policy
from refmon.schemas import Decision, Override
from scenario_run import run_events

# The counted thresholds of the Phase 1 rate detectors; the statistical tests are in test_rates.py.
COUNTED = default_policy(rates={"method": "counted"})


def names(events, policy=None):
    p = run_events(events, policy)
    return {s.name for j in p.judgements().values() for s in j.signals}


def judge(events, policy=None):
    return max(run_events(events, policy).judgements().values(), key=lambda j: j.ts)


def web():
    return ev("content_in", "browser", "p-0", f=1, source_class="web", t=0)


# -- effects ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "dest", "fires"),
    [
        ("script_host", "unknown", True),
        ("script_host", "package_index", False),  # a trusted class
        ("script_host", "partner_api", True),  # known but untrusted, and no contract for the role
        ("package_installer", "package_index", False),
        ("node_app_server", "partner_api", False),  # in its contract
        ("browser", "unknown", False),  # may_connect: any
    ],
)
def test_fetch(role, dest, fires):
    assert (
        "effect_fetch" in names([ev("net_connect", role, "p-1", destination_class=dest)])
    ) is fires


def test_fetch_does_not_need_a_label_which_is_how_s05_reaches_hold():
    assert "effect_fetch" in names(
        [ev("net_connect", "script_host", "p-1", destination_class="unknown")]
    )


@pytest.mark.parametrize(
    "attrs",
    [
        {"hidden_window": True},
        {"encoded_payload": True},
        {"entropy_bits": 5.9},
        {"longest_ws_run": 500},
    ],
)
def test_hide(attrs):
    assert "effect_hide" in names([ev("exec", "script_host", "p-1", **attrs)])


@pytest.mark.parametrize(
    "attrs", [{}, {"hidden_window": False}, {"entropy_bits": 4.0}, {"longest_ws_run": 3}]
)
def test_hide_does_not_fire_on_ordinary_commands(attrs):
    assert "effect_hide" not in names([ev("exec", "script_host", "p-1", **attrs)])


def test_persist():
    assert "effect_persist" in names([ev("persist", "script_host", "p-1", f=2)])
    web_shell = ev(
        "file_write",
        "script_host",
        "p-1",
        f=2,
        web_root="main_site",
        executable=True,
        new_file=True,
    )
    assert "effect_persist" in names([web_shell])
    assert "effect_persist" not in names(
        [ev("file_write", "script_host", "p-1", f=2, executable=True, new_file=True)]
    )


def test_escalate_counts_only_when_the_contract_does_not_allow_the_change():
    assert "effect_escalate" in names([ev("priv_change", "script_host", "p-1", f=2)])
    assert "effect_escalate" not in names([ev("priv_change", "elevation_tool", "p-1", f=2)])


def test_lateral_needs_a_burst_of_distinct_internal_hosts():
    def hosts(n):
        return [
            ev(
                "net_connect",
                "script_host",
                "p-1",
                f=10 + i,
                t=i * 0.1,
                destination_class="internal_network",
            )
            for i in range(n)
        ]

    assert "effect_lateral" not in names(hosts(19), COUNTED)
    assert "effect_lateral" in names(hosts(20), COUNTED)
    repeated = [
        ev(
            "net_connect",
            "script_host",
            "p-1",
            f=10,
            t=i * 0.1,
            destination_class="internal_network",
        )
        for i in range(40)
    ]
    assert "effect_lateral" not in names(repeated, COUNTED)  # one host many times is not fan-out


def test_exfil_depends_on_volume_and_the_role_threshold():
    assert "effect_exfil" in names(
        [
            ev(
                "net_connect",
                "web_worker",
                "p-1",
                f=2,
                destination_class="db_server",
                bytes=150_000_000,
            )
        ]
    )
    assert "effect_exfil" not in names(
        [ev("net_connect", "web_worker", "p-1", f=2, destination_class="db_server", bytes=1_000)]
    )
    big = ev(
        "net_connect",
        "backup_job",
        "p-1",
        f=2,
        destination_class="backup_host",
        bytes=60_000_000_000,
    )
    assert "effect_exfil" not in names([big])  # below the backup role's own threshold


def test_tamper():
    assert "effect_tamper" in names(
        [ev("security_tamper", "script_host", "p-1", cls="security_tool", f=2)]
    )
    assert "effect_tamper" not in names(
        [ev("security_tamper", "patch_tool", "p-1", cls="security_tool", f=2)]
    )


def test_credential_and_asset_access_count_only_outside_the_roles_assets():
    n = names(
        [
            ev(
                "asset_access",
                "script_host",
                "p-1",
                cls="credential_store",
                f=2,
                protected_asset="browser-passwords",
            )
        ]
    )
    assert {"effect_credential", "effect_asset_access"} <= n
    own = names(
        [
            ev(
                "asset_access",
                "browser",
                "p-1",
                cls="credential_store",
                f=2,
                protected_asset="browser-passwords",
            )
        ]
    )
    assert not {"effect_credential", "effect_asset_access"} & own
    assert "effect_credential" in names(
        [ev("asset_access", "script_host", "p-1", cls="key_material", f=2)]
    )


def test_mass_change_needs_the_policy_number_of_distinct_files():
    def writes(n):
        return [ev("file_write", "script_host", "p-1", f=100 + i, t=i * 0.05) for i in range(n)]

    assert "effect_mass_change" not in names(writes(49), COUNTED)
    assert "effect_mass_change" in names(writes(50), COUNTED)


def test_response_anomaly_and_its_repeat_per_client():
    one = [ev("response_out", "web_worker", "p-1", cls="client", f=7, bytes=20_000_000)]
    assert "effect_response_anomaly" in names(
        one, COUNTED
    ) and "effect_response_anomaly_repeated" not in names(one, COUNTED)
    assert "effect_response_anomaly_repeated" in names(
        [*one, ev("response_out", "web_worker", "p-1", cls="client", f=7, t=1, bytes=20000000)],
        COUNTED,
    )
    other_clients = [
        *one,
        ev("response_out", "web_worker", "p-1", cls="client", f=8, t=1, bytes=20000000),
    ]
    assert "effect_response_anomaly_repeated" not in names(other_clients, COUNTED)
    assert not {"effect_response_anomaly", "effect_response_anomaly_repeated"} & names(
        [ev("response_out", "web_worker", "p-1", cls="client", f=7, bytes=1_000)], COUNTED
    )


def test_threat_list_hit():
    assert "effect_threat_list_hit" in names(
        [ev("net_connect", "browser", "p-1", threat_list_hit="known-bad-hosts")]
    )


# -- overrides ----------------------------------------------------------------------------------------------


def test_override_canary_blocks_whatever_else_is_true():
    j = judge(
        [
            ev(
                "request_in",
                "web_worker",
                "p-1",
                f=1,
                source_class="inbound_request",
                canary_hit=True,
            )
        ]
    )
    assert j.override is Override.CANARY and j.rule_decision is Decision.BLOCK


def test_override_protected_asset_needs_a_labeled_process():
    asset = {"cls": "credential_store", "f": 2, "protected_asset": "browser-passwords"}
    unlabeled = judge([ev("asset_access", "script_host", "p-1", **asset)])
    assert unlabeled.override is None
    labeled = judge(
        [
            web(),
            ev("exec", "interactive_shell", "p-2", f=1, t=1),
            ev("asset_access", "script_host", "p-3", parent="p-2", t=2, **asset),
        ]
    )
    assert labeled.override is Override.PROTECTED_ASSET and labeled.rule_decision is Decision.BLOCK


def test_override_tampering_with_refmon_itself_blocks():
    j = judge([ev("security_tamper", "script_host", "p-1", cls="refmon_component", f=2)])
    assert j.override is Override.SELF_TAMPER and j.rule_decision is Decision.BLOCK
    assert (
        judge([ev("security_tamper", "patch_tool", "p-1", cls="refmon_component", f=2)]).override
        is Override.SELF_TAMPER
    )  # even an allowed role


def test_override_trusted_root_allows_even_with_contract_and_effect_fails():
    j = judge([
        ev("content_in", "package_installer", "p-1", f=1, source_class="download", trusted_source="official-python-index"),
        ev("persist", "package_installer", "p-1", f=2, t=1),
    ])  # fmt: skip
    assert j.failed["contract"] and j.failed["effect"]
    assert j.override is Override.TRUSTED_ROOT and j.rule_decision is Decision.ALLOW


def test_trusted_root_does_not_cover_a_story_that_also_has_a_strong_external_label():
    j = judge([
        ev("content_in", "package_installer", "p-1", f=1, source_class="download", trusted_source="official-python-index"),
        ev("content_in", "package_installer", "p-1", f=2, source_class="web", t=1),
        ev("persist", "package_installer", "p-1", f=3, t=2),
    ])  # fmt: skip
    assert j.override is None and j.failed["origin"]


def test_a_blocking_override_beats_the_trusted_root():
    events = [
        ev(
            "content_in",
            "package_installer",
            "p-1",
            f=1,
            source_class="download",
            trusted_source="official-python-index",
        ),
        ev("security_tamper", "package_installer", "p-1", cls="refmon_component", f=2, t=1),
    ]
    assert judge(events).override is Override.SELF_TAMPER


def test_the_fail_rule_follows_the_policy_not_a_constant():
    events = [
        web(),
        ev("exec", "interactive_shell", "p-2", f=1, t=1),
    ]  # origin + contract = 2 fails
    assert judge(events).rule_decision is Decision.HOLD
    strict = default_policy(
        decisions={"fails_3": "block", "fails_2": "block", "fails_0_1": "allow"}
    )
    assert judge(events, strict).rule_decision is Decision.BLOCK
