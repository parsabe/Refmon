"""The evidence calculus as pure functions (CLAUDE.md Phase 4b, C11): unit and property tests."""

import math
import random

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from refmon.calculus.evidence import (
    Evidence,
    block_threshold,
    contributions,
    decide,
    hold_threshold,
    log_odds,
    prior_log_odds,
    reestimate_weights,
)
from refmon.calculus.labels import attenuate, decay, noisy_or
from refmon.calculus.privacy import (
    BloomFilter,
    bloom_false_positive_rate,
    bloom_size,
    laplace_noise,
    noisy_count,
    suppress_small_groups,
)
from refmon.calculus.rarity import (
    Baseline,
    good_turing_unseen,
    is_mature,
    laplace_probability,
    surprisal_bits,
)
from refmon.calculus.stats import Cusum, Ema, burst_is_anomalous, poisson_tail, z_score
from refmon.policy import WEIGHTS
from refmon.schemas import Decision

COSTS = {"missed_attack": 1000.0, "false_block": 20.0, "hold": 5.0}

unit = st.floats(min_value=0.0, max_value=1.0, allow_nan=False)


# -- label strength (C11.1, C11.2) -------------------------------------------------------------


def test_decay_halves_each_half_life_and_persistent_labels_never_decay():
    assert decay(1.0, 1800, 1800) == pytest.approx(0.5)
    assert decay(1.0, 3600, 1800) == pytest.approx(0.25)
    assert decay(0.8, 10**9, None) == 0.8
    assert decay(1.0, 0, 1800) == 1.0


@settings(max_examples=100, deadline=None)
@given(s0=unit, t1=st.floats(0, 1e5), dt=st.floats(0, 1e5), half=st.floats(1, 1e5))
def test_decay_is_monotone_and_bounded(s0, t1, dt, half):
    assert 0.0 <= decay(s0, t1 + dt, half) <= decay(s0, t1, half) <= s0


def test_attenuation_multiplies_and_stays_in_range():
    assert attenuate(0.8, 0.5) == pytest.approx(0.4)
    for bad in (0.0, 1.5, -1.0):
        with pytest.raises(ValueError):
            attenuate(0.8, bad)


@settings(max_examples=100, deadline=None)
@given(strengths=st.lists(unit, max_size=8), extra=unit)
def test_noisy_or_is_in_the_unit_interval_and_never_below_the_largest_input(strengths, extra):
    combined = noisy_or(strengths)
    assert 0.0 <= combined <= 1.0
    assert combined >= max(strengths, default=0.0) - 1e-12
    assert noisy_or([*strengths, extra]) >= combined - 1e-12  # another label never lowers it


# -- contract rarity (C11.3) ---------------------------------------------------------------------


def test_laplace_smoothed_probability_and_surprisal():
    # 4095 events of two kinds plus "unseen": K = 3, so an unseen kind has p = 1 / 4098
    assert laplace_probability(0, 4095, 2) == pytest.approx(1 / 4098)
    assert surprisal_bits(laplace_probability(0, 4095, 2)) == pytest.approx(math.log2(4098))
    assert laplace_probability(4000, 4095, 2) > laplace_probability(95, 4095, 2)


def test_probabilities_over_seen_kinds_and_the_unseen_mass_sum_to_one():
    counts = {"a": 7, "b": 2, "c": 1}
    total = sum(counts.values())
    seen = sum(laplace_probability(n, total, len(counts)) for n in counts.values())
    unseen = laplace_probability(0, total, len(counts))
    assert seen + unseen == pytest.approx(1.0)


def test_a_probability_must_be_valid():
    for bad in (0.0, -0.1, 1.1):
        with pytest.raises(ValueError):
            surprisal_bits(bad)


def test_good_turing_counts_the_kinds_seen_exactly_once():
    assert good_turing_unseen({"a": 5, "b": 1, "c": 1, "d": 3}) == pytest.approx(2 / 10)
    assert good_turing_unseen({}) == 1.0
    assert is_mature({"a": 5000, "b": 3000}, 0.01)
    assert not is_mature({"a": 5, "b": 1}, 0.01)


def test_baseline_maturity_gates_by_role():
    base = Baseline({"web_worker": {"write:cache": 9000, "connect:db": 6000}, "new": {"x": 1}})
    assert base.mature("web_worker", 0.01) and not base.mature("new", 0.01)
    assert not base.mature("unknown_role", 0.01)
    assert base.surprisal("web_worker", "exec:unknown") > 12  # never seen in 15000 events
    assert base.surprisal("web_worker", "write:cache") < 2


@settings(max_examples=60, deadline=None)
@given(
    counts=st.dictionaries(st.text("abc", min_size=1, max_size=3), st.integers(1, 200), min_size=1)
)
def test_surprisal_is_larger_for_rarer_kinds(counts):
    base = Baseline({"r": counts})
    ordered = sorted(counts, key=counts.get)
    assert base.surprisal("r", ordered[0]) >= base.surprisal("r", ordered[-1])
    assert base.surprisal("r", "never-seen") >= base.surprisal("r", ordered[0])


# -- evidence combination (C11.4) --------------------------------------------------------------------


def test_the_worked_check_s01_clickfix():
    ev = [
        Evidence("origin", "origin_external", 1.0),
        Evidence("contract", "contract_external_exec", 1.0),
        Evidence("effect", "effect_fetch", 1.0),
        Evidence("effect", "effect_hide", 1.0),
    ]
    contribs = contributions(ev, WEIGHTS)
    assert sum(c.nats for c in contribs if c.counted) == pytest.approx(4.3)  # 0.8 + 1.0 + 2.5
    assert log_odds(0.001, contribs) == pytest.approx(-2.61, abs=0.005)
    assert [c.signal for c in contribs if not c.counted] == ["effect_hide"]


def test_the_worked_thresholds():
    assert prior_log_odds(0.001) == pytest.approx(-6.9068, abs=1e-3)
    assert block_threshold(COSTS) == pytest.approx(-3.912, abs=1e-3)
    assert hold_threshold(COSTS, 0.7) == pytest.approx(-4.942, abs=1e-3)


@pytest.mark.parametrize(
    ("signals", "expected"),
    [
        ([("origin", "origin_external"), ("contract", "contract_external_exec"),
          ("effect", "effect_fetch")], Decision.BLOCK),  # S01
        ([("origin", "origin_external"), ("contract", "contract_external_exec")], Decision.ALLOW),  # S11
        ([("effect", "effect_fetch")], Decision.HOLD),  # S05
        ([("origin", "origin_external"), ("contract", "contract_web_worker_exec"),
          ("effect", "effect_fetch")], Decision.BLOCK),  # S13
    ],
)  # fmt: skip
def test_worked_checks_decide(signals, expected):
    contribs = contributions([Evidence(q, n, 1.0) for q, n in signals], WEIGHTS)
    L = log_odds(0.001, contribs)
    outcome = decide(
        L, block_threshold(COSTS), hold_threshold(COSTS, 0.7),
        has_contract_signal=any(q == "contract" for q, _ in signals),
    )  # fmt: skip
    assert outcome.decision is expected


def test_the_contract_gate_caps_a_block_at_hold_and_says_so():
    contribs = contributions(
        [Evidence("origin", "origin_external", 1.0), Evidence("effect", "effect_fetch", 1.0)],
        WEIGHTS,
    )
    L = log_odds(0.001, contribs)
    assert block_threshold(COSTS) <= L
    out = decide(L, block_threshold(COSTS), hold_threshold(COSTS, 0.7), has_contract_signal=False)
    assert (out.decision, out.crossed, out.gated) == (Decision.HOLD, "block", True)


def test_an_override_bypasses_the_thresholds():
    out = decide(-100.0, -3.9, -4.9, has_contract_signal=False, override=Decision.BLOCK)
    assert (out.decision, out.crossed, out.gated) == (Decision.BLOCK, None, False)
    assert (
        decide(100.0, -3.9, -4.9, has_contract_signal=True, override=Decision.ALLOW).decision
        is Decision.ALLOW
    )


signal_lists = st.lists(
    st.tuples(
        st.sampled_from(["origin", "contract", "effect"]),
        st.sampled_from(sorted(WEIGHTS)),
        unit,
    ),
    max_size=10,
)


@settings(max_examples=100, deadline=None)
@given(signals=signal_lists)
def test_contributions_sum_exactly_to_the_log_odds(signals):
    evidence = [Evidence(q, n, s) for q, n, s in signals]
    contribs = contributions(evidence, WEIGHTS)
    counted = [c for c in contribs if c.counted]
    assert len({c.question for c in counted}) == len(counted)  # at most one per question
    assert log_odds(0.001, contribs) == prior_log_odds(0.001) + sum(c.nats for c in counted)
    for c in contribs:
        assert c.nats == pytest.approx(c.weight * c.strength)


@settings(max_examples=100, deadline=None)
@given(signals=signal_lists, extra=st.tuples(st.sampled_from(["origin", "contract", "effect"]),
                                              st.sampled_from(sorted(WEIGHTS)), unit))  # fmt: skip
def test_adding_a_signal_never_lowers_the_log_odds(signals, extra):
    before = log_odds(0.001, contributions([Evidence(q, n, s) for q, n, s in signals], WEIGHTS))
    after = log_odds(
        0.001, contributions([Evidence(q, n, s) for q, n, s in [*signals, extra]], WEIGHTS)
    )
    assert after >= before - 1e-12


@settings(max_examples=100, deadline=None)
@given(
    missed=st.floats(100, 1e5), block=st.floats(1, 90), hold=st.floats(0.1, 9),
    h=st.floats(0.1, 1.0), factor=st.floats(1.01, 10),
)  # fmt: skip
def test_thresholds_move_in_the_right_direction_when_costs_change(missed, block, hold, h, factor):
    base = {"missed_attack": missed, "false_block": block, "hold": hold}
    # a dearer false block raises the block threshold; a dearer missed attack lowers both
    assert block_threshold({**base, "false_block": block * factor}) > block_threshold(base)
    assert block_threshold({**base, "missed_attack": missed * factor}) < block_threshold(base)
    assert hold_threshold({**base, "missed_attack": missed * factor}, h) < hold_threshold(base, h)
    assert hold_threshold({**base, "hold": hold * factor}, h) > hold_threshold(base, h)
    assert hold_threshold(base, min(1.0, h * factor)) <= hold_threshold(
        base, h
    )  # better catch rate


def test_weights_can_be_reestimated_from_labeled_counts_with_laplace_smoothing():
    attacks = [{"effect_fetch", "contract_x"}] * 9 + [{"contract_x"}]
    benign = [{"effect_fetch"}] * 1 + [set()] * 99
    w = reestimate_weights(attacks, benign)
    assert w["effect_fetch"] == pytest.approx(math.log((10 / 12) / (2 / 102)))
    assert w["contract_x"] > w["effect_fetch"] * 0  # attack-only signals get large positive weights
    assert math.isfinite(w["contract_x"])  # smoothing keeps a zero count finite
    assert reestimate_weights([], []) == {}


# -- rate anomalies (C11.6) ------------------------------------------------------------------------------


def test_poisson_tail_matches_the_textbook_values():
    assert poisson_tail(0, 3.0) == 1.0
    assert poisson_tail(1, 3.0) == pytest.approx(1 - math.exp(-3.0))
    assert poisson_tail(3, 2.0) == pytest.approx(1 - math.exp(-2) * (1 + 2 + 2))
    assert poisson_tail(30, 3.0) < 1e-17
    assert poisson_tail(5, 0.0) == 0.0


@settings(max_examples=80, deadline=None)
@given(lam=st.floats(0.1, 50), k=st.integers(0, 120))
def test_poisson_tail_is_a_probability_and_falls_with_k(lam, k):
    assert 0.0 <= poisson_tail(k, lam) <= 1.0
    assert poisson_tail(k + 1, lam) <= poisson_tail(k, lam) + 1e-12  # float noise near 1


def test_a_burst_is_anomalous_only_beyond_the_alpha_quantile():
    assert not burst_is_anomalous(8, 3.0, 1e-6)
    assert burst_is_anomalous(30, 3.0, 1e-6)
    assert burst_is_anomalous(8, 3.0, 0.05) and not burst_is_anomalous(2, 3.0, 0.05)


def test_cusum_catches_a_slow_drift_that_no_single_value_shows():
    c = Cusum(k=0.5, h=5.0)
    alerts = [c.update(z_score(x, 100.0, 10.0)) for x in [112] * 8]  # z = 1.2 each, drift +0.7
    assert alerts == [False] * 7 + [True]
    quiet = Cusum(k=0.5, h=5.0)
    assert not any(quiet.update(z_score(x, 100.0, 10.0)) for x in [104, 96, 103, 99, 101] * 20)


def test_cusum_peek_does_not_change_state_and_resets_at_zero():
    c = Cusum(k=0.5, h=5.0)
    assert c.peek(3.0) == 2.5 and c.s == 0.0
    c.update(-9.0)
    assert c.s == 0.0


def test_the_ema_follows_the_data_but_is_frozen_during_an_incident():
    ema = Ema(value=3.0, beta=0.5)
    assert ema.update(5.0) == 4.0
    ema.frozen = True  # an incident is open: the attacker cannot teach the baseline
    assert [ema.update(1000.0) for _ in range(3)] == [4.0] * 3
    ema.frozen = False
    assert ema.update(4.0) == 4.0


# -- privacy mathematics (C11.8) ------------------------------------------------------------------------------


def test_laplace_noise_has_the_right_scale():
    rng = random.Random(7)
    samples = [laplace_noise(1.0, rng) for _ in range(40_000)]
    mean_abs = sum(abs(s) for s in samples) / len(samples)
    assert mean_abs == pytest.approx(1.0, rel=0.05)  # E|X| = 1 / epsilon
    assert abs(sum(samples) / len(samples)) < 0.05
    rng = random.Random(7)
    small = [laplace_noise(4.0, rng) for _ in range(40_000)]
    assert sum(abs(s) for s in small) / len(small) == pytest.approx(0.25, rel=0.05)
    with pytest.raises(ValueError):
        laplace_noise(0.0, rng)


def test_noisy_counts_are_reproducible_with_a_seeded_generator():
    assert noisy_count(10, 1.0, random.Random(1)) == noisy_count(10, 1.0, random.Random(1))
    assert noisy_count(10, 1.0, random.Random(1)) != noisy_count(10, 1.0, random.Random(2))


def test_groups_below_k_are_suppressed():
    counts = {"lab-a": 12, "lab-b": 4, "lab-c": 5}
    assert suppress_small_groups(counts, 5) == {"lab-a": 12, "lab-c": 5}


def test_bloom_sizing_meets_the_target_and_the_formula_agrees():
    bits, hashes = bloom_size(1000, 0.001)
    assert bloom_false_positive_rate(1000, bits, hashes) <= 0.0011
    bloom = BloomFilter(1000, 0.001)
    assert bloom.expected_false_positive_rate() <= 0.0011


def test_a_bloom_filter_has_no_false_negatives_and_few_false_positives():
    bloom = BloomFilter(1000, 0.001)
    members = [f"member-{i}" for i in range(1000)]
    for m in members:
        bloom.add(m)
    assert all(bloom.might_contain(m) for m in members)
    probes = 100_000
    false_hits = sum(bloom.might_contain(f"stranger-{i}") for i in range(probes))
    assert false_hits / probes < 0.002  # target 0.1 %
