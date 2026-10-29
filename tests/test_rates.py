"""The statistical rate tests inside the pipeline (CLAUDE.md C11.6)."""

import pytest

from evhelp import ev
from refmon.calculus.stats import poisson_tail
from refmon.pipeline.rates import StatRates
from refmon.policy import default_policy
from scenario_run import run_events

STAT = default_policy()


def names(events, policy=STAT):
    p = run_events(events, policy)
    return {s.name for j in p.judgements().values() for s in j.signals}


def writes(n, gap=0.05, role="script_host"):
    return [ev("file_write", role, "p-1", f=100 + i, t=i * gap) for i in range(n)]


def smallest_burst(lam, alpha):
    k = 1
    while poisson_tail(k, lam) >= alpha:
        k += 1
    return k


def test_a_burst_is_mass_change_exactly_when_the_poisson_tail_is_below_alpha():
    k = smallest_burst(STAT.math.baseline_rate_default, STAT.math.poisson_alpha)
    assert 10 < k < 25  # for the default baseline of 3 per window and alpha 1e-6
    assert "effect_mass_change" not in names(writes(k - 1))
    assert "effect_mass_change" in names(writes(k))


def test_the_burst_threshold_follows_the_role_baseline_in_the_policy():
    busy = default_policy(
        math={"weights": STAT.math.weights, "baseline_rate": {"mass_change:script_host": 30}}
    )
    k = smallest_burst(30.0, STAT.math.poisson_alpha)
    assert "effect_mass_change" not in names(writes(k - 1), busy)
    assert "effect_mass_change" in names(writes(k), busy)
    assert "effect_mass_change" in names(writes(k - 1))  # the default baseline would have fired


def test_the_burst_threshold_follows_alpha():
    strict = default_policy(math={"weights": STAT.math.weights, "poisson_alpha": 1e-12})
    k = smallest_burst(3.0, 1e-12)
    assert "effect_mass_change" not in names(writes(k - 1), strict)
    assert "effect_mass_change" in names(writes(k), strict)


def test_distinct_hosts_not_connections_make_fan_out():
    k = smallest_burst(3.0, 1e-6)
    hosts = [
        ev(
            "net_connect",
            "script_host",
            "p-1",
            f=10 + i,
            t=i * 0.1,
            destination_class="internal_network",
        )
        for i in range(k)
    ]
    assert "effect_lateral" in names(hosts)
    repeated = [
        ev(
            "net_connect",
            "script_host",
            "p-1",
            f=10,
            t=i * 0.1,
            destination_class="internal_network",
        )
        for i in range(3 * k)
    ]
    assert "effect_lateral" not in names(repeated)


def test_events_far_apart_do_not_add_up_to_a_burst():
    k = smallest_burst(3.0, 1e-6)
    spread = [ev("file_write", "script_host", "p-1", f=100 + i, t=i * 30.0) for i in range(2 * k)]
    assert "effect_mass_change" not in names(spread)


def test_the_baseline_follows_a_busy_workload_when_no_incident_is_open():
    rates = StatRates(STAT)
    window = STAT.rates.window
    before = rates._rate_for("mass_change", "script_host").value
    for second in range(20):  # twenty windows of ten files each, nothing anomalous
        for i in range(10):
            rates.mass_change("root", "script_host", second * window + i * 0.1, f"f{second}-{i}")
    assert rates._rate_for("mass_change", "script_host").value > before


def test_an_open_incident_freezes_the_baseline_so_an_attacker_cannot_teach_it():
    rates = StatRates(STAT)
    window = STAT.rates.window
    rates.mark_incident("root", True)
    before = rates._rate_for("mass_change", "script_host").value
    for second in range(20):
        for i in range(10):
            rates.mass_change("root", "script_host", second * window + i * 0.1, f"f{second}-{i}")
    assert rates._rate_for("mass_change", "script_host").value == before
    rates.mark_incident("root", False)
    for i in range(10):
        rates.mass_change("root", "script_host", 99 * window + i * 0.1, f"g{i}")
    rates.mass_change("root", "script_host", 100 * window, "h")
    assert rates._rate_for("mass_change", "script_host").value != before


def test_the_pipeline_marks_an_incident_while_a_story_is_held_or_blocked():
    events = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("exec", "web_worker", "p-1", f=2, t=1, exec_class="unknown"),
        ev("net_connect", "web_worker", "p-1", f=3, t=2, destination_class="unknown"),
    ]
    p = run_events(events)
    assert "p-1" in p.rates._incident


# -- exfil: CUSUM ------------------------------------------------------------------------------------------


def sends(volumes, role="web_worker", spacing=61.0):
    return [
        ev("net_connect", role, "p-1", f=7, t=i * spacing, destination_class="db_server", bytes=v)
        for i, v in enumerate(volumes)
    ]


def test_one_huge_window_is_exfil():
    assert "effect_exfil" in names(sends([800_000_000]))


def test_normal_volume_is_not_exfil_and_the_backup_role_has_its_own_baseline():
    assert "effect_exfil" not in names(sends([900_000, 1_100_000, 1_000_000] * 5))
    assert "effect_exfil" not in names(sends([60_000_000_000], role="backup_job"))
    assert "effect_exfil" in names(sends([60_000_000_000]))  # the same volume from a web worker


def test_a_slow_drift_above_the_baseline_is_caught_by_cusum_not_by_a_single_window():
    # 2.1 sigma above the mean each window (sigma 500 kB), so no single window is extreme
    window = 1_000_000 + int(2.1 * 500_000)
    assert "effect_exfil" not in names(sends([window] * 2))
    assert "effect_exfil" in names(sends([window] * 6))


# -- responses: Poisson on repeats ---------------------------------------------------------------------------


def responses(n, client=7):
    return [
        ev("response_out", "web_worker", "p-1", cls="client", f=client, t=i, bytes=20_000_000)
        for i in range(n)
    ]


def test_one_oversized_response_is_an_anomaly_and_a_repeat_needs_a_poisson_level_count():
    one, two, three = names(responses(1)), names(responses(2)), names(responses(3))
    assert "effect_response_anomaly" in one and "effect_response_anomaly_repeated" not in one
    assert "effect_response_anomaly_repeated" not in two  # two in a window is not yet unusual
    assert "effect_response_anomaly_repeated" in three


def test_repeats_are_counted_per_client():
    mixed = [responses(1, client=1)[0], responses(1, client=2)[0], responses(1, client=3)[0]]
    mixed = [
        ev("response_out", "web_worker", "p-1", cls="client", f=c, t=i, bytes=20_000_000)
        for i, c in enumerate([1, 2, 3])
    ]
    assert "effect_response_anomaly_repeated" not in names(mixed)


def test_the_counted_fallback_is_still_available_through_the_policy():
    counted = default_policy(rates={"method": "counted"})
    assert not counted.statistical_rates and counted.uses_calculus
    assert "effect_mass_change" in names(writes(50, 0.05), counted)
    assert "effect_mass_change" not in names(writes(49, 0.05), counted)


@pytest.mark.parametrize("method", ["counted", "statistical"])
def test_both_rate_methods_agree_on_the_clear_cases(method):
    p = default_policy(rates={"method": method})
    assert "effect_mass_change" in names(writes(80), p)
    assert "effect_mass_change" not in names(writes(2), p)
