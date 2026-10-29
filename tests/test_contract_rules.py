"""One test per contract rule (CLAUDE.md C4, universal and launcher contracts, D19-D21, D23)."""

import pytest

from evhelp import ev
from refmon.policy import default_policy
from scenario_run import run_events


def names(events, policy=None):
    p = run_events(events, policy)
    return {s.name for j in p.judgements().values() for s in j.signals}


def labeled(role, pid, f=1, t=0.0):
    """A label that `role` carries (content ingested from the web)."""
    return ev("content_in", role, pid, f=f, source_class="web", t=t)


# -- external-content exec -------------------------------------------------------------------------


def test_a_shell_executing_labeled_content_breaks_its_contract():
    assert "contract_external_exec" in names(
        [labeled("browser", "p-1"), ev("exec", "interactive_shell", "p-2", f=1, t=1)]
    )


def test_a_labeled_shell_executing_anything_breaks_its_contract():
    n = names(
        [labeled("interactive_shell", "p-1"), ev("exec", "interactive_shell", "p-1", f=9, t=1)]
    )
    assert "contract_external_exec" in n


def test_a_shell_executing_unlabeled_content_is_fine():
    assert names([ev("exec", "interactive_shell", "p-2", f=1)]) == set()


def test_an_agent_with_injected_input_breaks_the_external_exec_contract():
    n = names(
        [labeled("agent", "p-1"), ev("exec", "agent", "p-1", f=9, exec_class="agent_tools", t=1)]
    )
    assert "contract_external_exec" in n


# -- may_exec ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "exec_class", "expected"),
    [
        ("web_worker", "unknown", "contract_web_worker_exec"),
        ("node_app_server", "unknown", "contract_web_worker_exec"),
        ("node_app_server", "build_tool", None),
        ("office", "unknown", "contract_exec_violation"),
        ("office", "print_helper", None),
        ("agent", "unknown", "contract_exec_violation"),
        ("agent", "agent_tools", None),
    ],
)
def test_may_exec(role, exec_class, expected):
    n = names([ev("exec", role, "p-1", exec_class=exec_class)])
    wanted = {"contract_web_worker_exec", "contract_exec_violation"}
    assert (n & wanted) == ({expected} if expected else set())


def test_a_missing_exec_class_counts_as_unknown():
    assert "contract_web_worker_exec" in names([ev("exec", "web_worker", "p-1")])


# -- may_write ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("attrs", "expected"),
    [
        ({"path_group": "cache"}, None),
        ({"path_group": "sessions"}, None),
        ({"path_group": "elsewhere"}, "contract_write_other"),
        (
            {"executable": True, "new_file": True, "web_root": "main_site"},
            "contract_write_executable",
        ),
        ({"executable": True, "path_group": "cache"}, "contract_write_executable"),
    ],
)
def test_may_write(attrs, expected):
    n = names([ev("file_write", "web_worker", "p-1", f=2, **attrs)])
    assert (n & {"contract_write_other", "contract_write_executable"}) == (
        {expected} if expected else set()
    )


def test_a_role_without_a_write_contract_may_write_anywhere():
    assert names([ev("file_write", "script_host", "p-1", f=2, path_group="anywhere")]) == set()


# -- may_connect ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "dest", "violation"),
    [
        ("web_worker", "db_server", False),
        ("web_worker", "cache_server", False),
        ("web_worker", "unknown", True),
        ("web_worker", "partner_api", True),
        ("node_app_server", "partner_api", False),
        ("browser", "unknown", False),  # may_connect: [any]
        ("package_installer", "package_index", False),
        ("package_installer", "unknown", True),
        (
            "script_host",
            "unknown",
            False,
        ),  # no contract: nothing to violate (it still raises the Effect)
    ],
)
def test_may_connect(role, dest, violation):
    assert (
        "contract_connect_violation"
        in names([ev("net_connect", role, "p-1", destination_class=dest)])
    ) is violation


# -- may_persist, may_read_assets, may_change_privilege ----------------------------------------------


def test_may_persist():
    assert "contract_persist_violation" in names([ev("persist", "package_installer", "p-1", f=2)])
    assert "contract_persist_violation" not in names([ev("persist", "script_host", "p-1", f=2)])


@pytest.mark.parametrize(
    ("role", "asset", "violation"),
    [
        ("web_worker", "app-config-secrets", True),
        ("browser", "browser-passwords", False),
        ("browser", "app-config-secrets", True),
        ("script_host", "browser-passwords", False),
    ],
)
def test_may_read_assets(role, asset, violation):
    n = names([ev("asset_access", role, "p-1", cls="credential_store", f=2, protected_asset=asset)])
    assert ("contract_asset_violation" in n) is violation


@pytest.mark.parametrize(
    ("role", "violation", "effect"),
    [
        ("app_server", True, True),
        ("web_worker", True, True),
        ("elevation_tool", False, False),
        ("script_host", False, True),
    ],
)
def test_may_change_privilege(role, violation, effect):
    n = names([ev("priv_change", role, "p-1", f=2)])
    assert ("contract_privilege_violation" in n) is violation
    assert ("effect_escalate" in n) is effect


# -- launcher contract (D20) --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("signed", "fires"),
    [(False, True), (True, False), ("unknown", False), (None, False)],
)
def test_an_unsigned_externally_labeled_file_launched_by_a_launcher(signed, fires):
    attrs = {} if signed is None else {"signed": signed}
    n = names(
        [
            ev(
                "content_in",
                "browser",
                "p-1",
                cls="executable_file",
                f=1,
                source_class="download",
                t=0,
            ),
            ev("exec", "launcher", "p-2", cls="executable_file", f=1, t=1, **attrs),
        ]
    )
    assert ("contract_unsigned_launch" in n) is fires


def test_an_unsigned_file_without_an_external_label_raises_nothing():
    assert "contract_unsigned_launch" not in names(
        [ev("exec", "launcher", "p-2", f=1, signed=False)]
    )


# -- universal contract (D19) and the origin label (D23) --------------------------------------------


def burst_files(role, n=60, **kw):
    return [
        ev("file_write", role, "p-1", f=100 + i, t=i * 0.05, path_group="x", **kw) for i in range(n)
    ]


UNIVERSAL = {
    "may_tamper": (
        "effect_tamper",
        lambda role: [ev("security_tamper", role, "p-1", cls="security_tool", f=1)],
    ),
    "may_mass_change": ("effect_mass_change", lambda role: burst_files(role)),
    "may_fan_out": (
        "effect_lateral",
        lambda role: [
            ev(
                "net_connect",
                role,
                "p-1",
                f=200 + i,
                t=i * 0.1,
                destination_class="internal_network",
            )
            for i in range(30)
        ],
    ),
    "may_repeat_large_responses": (
        "effect_response_anomaly_repeated",
        lambda role: [
            ev("response_out", role, "p-1", cls="client", f=300, t=i, bytes=20_000_000)
            for i in range(3)
        ],
    ),
}
ALLOWED_ROLE = {
    "may_tamper": "patch_tool",
    "may_mass_change": "backup_job",
    "may_fan_out": "vuln_scanner",
    "may_repeat_large_responses": None,
}


@pytest.mark.parametrize("flag", UNIVERSAL)
def test_a_role_without_the_allowance_raises_contract_and_effect(flag):
    effect, make = UNIVERSAL[flag]
    n = names(make("script_host"))
    assert "contract_universal_violation" in n and effect in n


@pytest.mark.parametrize("flag", UNIVERSAL)
def test_an_allowance_removes_both_signals_without_an_origin_label(flag):
    effect, make = UNIVERSAL[flag]
    role = ALLOWED_ROLE[flag] or "app_server"
    policy = default_policy()
    if ALLOWED_ROLE[flag] is None:  # nobody ships with this allowance, so grant it to a role
        data = {
            **policy.model_dump(by_alias=True),
            "contracts": {
                **policy.model_dump(by_alias=True)["contracts"],
                "app_server": {"role": "app_server", flag: True},
            },
        }
        policy = type(policy).parse({**data, "extra_roles": data["extra_roles"]})
    n = names(make(role), policy)
    assert "contract_universal_violation" not in n and effect not in n


@pytest.mark.parametrize("flag", ["may_tamper", "may_mass_change", "may_fan_out"])
def test_with_an_origin_label_the_effect_still_counts_but_the_contract_signal_stays_gone(flag):
    effect, make = UNIVERSAL[flag]
    role = ALLOWED_ROLE[flag]
    n = names([labeled(role, "p-1", f=900), *make(role)])
    assert effect in n and "contract_universal_violation" not in n


def test_allowing_one_behaviour_allows_no_other():
    n = names(
        [
            *burst_files("backup_job"),
            ev("security_tamper", "backup_job", "p-1", cls="security_tool", f=1, t=5),
        ]
    )
    assert (
        "contract_universal_violation" in n
        and "effect_tamper" in n
        and "effect_mass_change" not in n
    )
