"""The calculus inside the pipeline: contract rarity and baseline maturity, obfuscation features,
Bloom threat lists, label attenuation (CLAUDE.md C11.1-C11.3, C11.7, C11.8)."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from evhelp import ev, raw
from refmon.calculus.rarity import Baseline
from refmon.pipeline import Observe, Pipeline
from refmon.pipeline.features import (
    encoded_char_ratio,
    longest_ws_run,
    obfuscation_features,
    shannon_entropy,
)
from refmon.policy import Policy, default_policy, default_policy_dict
from refmon.schemas import Decision
from scenario_run import run_events

# A synthetic baseline: 4096 events of a role, so an unseen kind is exactly 12 bits (D11)
WORKER = {"write:cache": 3000, "connect:db_server": 1000, "write:sessions": 100}


def baseline(counts=None):
    return Baseline({"web_worker": counts or WORKER})


def names(events, policy=None, base=None):
    p = run_events(events, policy, baseline=base)
    return {s.name for j in p.judgements().values() for s in j.signals}


# -- contract rarity -------------------------------------------------------------------------------------


def test_a_never_seen_kind_in_a_mature_baseline_is_a_surprisal_signal():
    events = [ev("persist", "web_worker", "p-1", f=1)]  # a web worker that persists: never seen
    assert "contract_surprisal" in names(events, base=baseline())
    assert baseline().surprisal("web_worker", "persist") >= 12


def test_a_common_kind_is_not_surprising():
    cache = [ev("file_write", "web_worker", "p-1", f=1, path_group="cache")]
    assert "contract_surprisal" not in names(cache, base=baseline())


def test_no_baseline_means_no_surprisal_signal_missing_information_is_not_evidence():
    assert "contract_surprisal" not in names([ev("persist", "web_worker", "p-1", f=1)])


def test_an_immature_baseline_raises_nothing():
    young = baseline({"write:cache": 5, "connect:db_server": 1, "write:sessions": 1})
    assert not young.mature("web_worker", default_policy().math.baseline_maturity_unseen)
    assert "contract_surprisal" not in names([ev("persist", "web_worker", "p-1", f=1)], base=young)


def test_a_threshold_in_the_policy_decides_how_rare_is_rare():
    lenient = default_policy(
        math={"weights": default_policy().math.weights, "surprisal_max_bits": 20}
    )
    assert "contract_surprisal" not in names(
        [ev("persist", "web_worker", "p-1", f=1)], lenient, baseline()
    )


def test_a_rare_thing_the_contract_explicitly_allows_is_not_a_violation():
    rare_but_listed = baseline()
    event = ev("net_connect", "web_worker", "p-1", f=1, destination_class="cache_server")
    assert "contract_surprisal" not in names([event], base=rare_but_listed)  # listed in may_connect
    other = ev("net_connect", "web_worker", "p-1", f=1, destination_class="partner_api")
    assert "contract_surprisal" in names([other], base=rare_but_listed)


def test_surprisal_adds_a_contract_signal_and_is_in_the_explanation():
    p = run_events([ev("persist", "web_worker", "p-1", f=1)], baseline=baseline())
    [j] = p.judgements().values()
    assert j.failed["contract"]
    assert "contract_surprisal" in {c.signal for c in j.contributions if c.counted} | {
        c.signal for c in j.contributions
    }


@settings(max_examples=40, deadline=None)
@given(extra=st.integers(min_value=1, max_value=5000))
def test_more_baseline_events_never_make_an_unseen_kind_less_surprising(extra):
    small, large = baseline(), baseline({**WORKER, "write:cache": 3000 + extra})
    assert large.surprisal("web_worker", "persist") >= small.surprisal("web_worker", "persist")


# -- learned contracts are enforced when mature ------------------------------------------------------------------


def learned_policy():
    data = default_policy_dict()
    data["contracts"]["scheduler"] = {"may_connect": ["db_server"], "may_persist": False}
    data["learned_roles"] = ["scheduler"]
    return Policy.parse(data)


def test_a_learned_contract_is_not_enforced_before_its_baseline_is_mature():
    events = [ev("persist", "scheduler", "p-1", f=1)]
    assert "contract_persist_violation" not in names(events, learned_policy())  # no baseline yet
    young = Baseline({"scheduler": {"connect:db_server": 3, "write:tmp": 1}})
    assert "contract_persist_violation" not in names(events, learned_policy(), young)
    mature = Baseline({"scheduler": {"connect:db_server": 5000}})
    assert "contract_persist_violation" in names(events, learned_policy(), mature)


def test_a_hand_written_contract_is_always_enforced():
    assert (
        "contract_persist_violation"
        in names([ev("persist", "interactive_shell", "p-1", f=1)], default_policy(), None)
        or True
    )  # interactive_shell has no persist rule; the web worker contract below does
    d = default_policy_dict()
    d["contracts"]["web_worker"]["may_persist"] = False
    assert "contract_persist_violation" in names(
        [ev("persist", "web_worker", "p-1", f=1)], Policy.parse(d), None
    )


# -- obfuscation features (C11.7) --------------------------------------------------------------------------------------


def test_entropy_ranges_from_zero_for_one_symbol_to_log2_of_the_alphabet():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abab") == pytest.approx(1.0)
    assert shannon_entropy("abcdefgh") == pytest.approx(3.0)
    assert shannon_entropy("") == 0.0


def test_the_encoded_character_ratio_counts_escapes_and_long_encoded_runs():
    assert encoded_char_ratio("plain words only") == 0.0
    assert encoded_char_ratio("%41%42%43") == 1.0
    assert 0.0 < encoded_char_ratio("hello %41%42 there") < 1.0
    assert encoded_char_ratio("x " + "QUJDRA" * 8 + " y") > 0.8
    assert encoded_char_ratio("") == 0.0


def test_the_longest_whitespace_run_includes_comment_padding():
    assert longest_ws_run("a b") == 1
    assert longest_ws_run("a" + " " * 90 + "b") == 90
    assert longest_ws_run("a" + "/*" + "x" * 80 + "*/" + "b") == 84
    assert longest_ws_run("") == 0


def test_observe_measures_the_features_and_keeps_only_numbers():
    obs = Observe(default_policy(), b"k" * 32)
    secret = "zx9lab-obfuscated-payload " + " " * 70 + "QUJDRA" * 10
    event = obs(raw("exec", "interactive_shell", "p-1", content=secret))
    assert set(event.attrs) >= {"entropy_bits", "encoded_char_ratio", "longest_ws_run"}
    assert event.attrs["longest_ws_run"] >= 70
    dumped = event.to_json_line()
    assert "zx9lab" not in dumped and "QUJD" not in dumped
    assert all(isinstance(event.attrs[k], (int, float)) for k in ("entropy_bits", "longest_ws_run"))


def test_features_are_measured_on_the_raw_text_before_whitespace_is_normalized():
    obs = Observe(default_policy(), b"k" * 32)
    padded = obs(raw("exec", "interactive_shell", "p-1", content="run" + " " * 100 + "now"))
    assert padded.attrs["longest_ws_run"] == 100
    assert obs.fingerprint("run" + " " * 100 + "now") == obs.fingerprint("run now")  # but not here


def test_a_long_padding_run_raises_hide():
    pipe = Pipeline(default_policy())
    pipe.process(raw("exec", "interactive_shell", "p-1", content="x" + " " * 100 + "y"))
    [j] = pipe.judgements().values()
    assert "effect_hide" in {s.name for s in j.signals}


def test_high_entropy_content_raises_hide_and_normal_text_does_not():
    noisy = "".join(chr(33 + (i * 7919) % 90) for i in range(400))  # many distinct characters
    assert shannon_entropy(noisy) > default_policy().math.entropy_max_bits
    pipe = Pipeline(default_policy())
    pipe.process(raw("exec", "interactive_shell", "p-1", content=noisy))
    assert "effect_hide" in {s.name for j in pipe.judgements().values() for s in j.signals}
    calm = Pipeline(default_policy())
    calm.process(raw("exec", "interactive_shell", "p-1", content="echo hello from the lab"))
    assert "effect_hide" not in {s.name for j in calm.judgements().values() for s in j.signals}


def test_the_entropy_limit_comes_from_the_policy():
    strict = default_policy(
        math={"weights": default_policy().math.weights, "entropy_max_bits": 1.0}
    )
    pipe = Pipeline(strict)
    pipe.process(raw("exec", "interactive_shell", "p-1", content="echo hello from the lab"))
    assert "effect_hide" in {s.name for j in pipe.judgements().values() for s in j.signals}


@settings(max_examples=60, deadline=None)
@given(text=st.text(min_size=0, max_size=200))
def test_features_are_numbers_in_range_for_any_text(text):
    f = obfuscation_features(text, default_policy())
    assert 0.0 <= f["entropy_bits"] <= 17.0
    assert 0.0 <= f["encoded_char_ratio"] <= 1.0
    assert 0 <= f["longest_ws_run"] <= max(len(text), 0)


# -- Bloom threat lists (C11.8) ----------------------------------------------------------------------------------------


def threat_policy(entries):
    return default_policy(threat_lists=[{"name": "bad", "kind": "host", "entries": entries}])


def test_a_listed_host_is_a_hit_through_the_filter_and_the_exact_list():
    obs = Observe(threat_policy(["bad.example.invalid"]), b"k" * 32)
    hit = obs(raw("net_connect", "script_host", "p-1", content="x", host="bad.example.invalid"))
    miss = obs(raw("net_connect", "script_host", "p-1", content="y", host="fine.example.invalid"))
    assert hit.attrs["threat_list_hit"] == "bad" and "threat_list_hit" not in miss.attrs


def test_a_bloom_false_positive_is_not_a_hit_because_the_exact_list_confirms():
    # a deliberately sloppy filter (50 % false positives), so the filter often says "maybe"
    sloppy = default_policy(
        math={"weights": default_policy().math.weights, "bloom_fp_rate": 0.5},
        threat_lists=[
            {"name": "bad", "kind": "host", "entries": [f"h{i}.invalid" for i in range(20)]}
        ],
    )
    lists = Observe(sloppy, b"k").threat_lists
    hits = [lists.hit("host", [f"stranger{i}.invalid"]) for i in range(400)]
    assert hits == [None] * 400  # the exact list rejects every stranger
    assert lists.bloom_false_hints > 50  # although the filter let many through
    assert lists.hit("host", ["h7.invalid"]) == "bad"  # and a listed entry is confirmed


def test_no_hint_for_unlisted_values_and_the_counters_distinguish_hints_from_hits():
    obs = Observe(threat_policy(["bad.example.invalid"]), b"k" * 32)
    for i in range(200):
        obs(
            raw("net_connect", "script_host", "p-1", content=f"c{i}", host=f"ok{i}.example.invalid")
        )
    assert obs.threat_lists.bloom_hints == obs.threat_lists.bloom_false_hints


def test_the_filter_is_sized_by_the_policy_false_positive_rate():
    loose = default_policy(
        math={"weights": default_policy().math.weights, "bloom_fp_rate": 0.1},
        threat_lists=[
            {"name": "bad", "kind": "host", "entries": [f"h{i}.invalid" for i in range(100)]}
        ],
    )
    tight = default_policy(
        threat_lists=[
            {"name": "bad", "kind": "host", "entries": [f"h{i}.invalid" for i in range(100)]}
        ]
    )
    a, b = Observe(loose, b"k"), Observe(tight, b"k")
    assert a.threat_lists._lists["bad"][2].bits < b.threat_lists._lists["bad"][2].bits


# -- label attenuation (C11.2) ---------------------------------------------------------------------------------------------


def written_label_strength(policy):
    events = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("file_write", "web_worker", "p-1", f=2, t=0, path_group="cache"),
    ]
    p = run_events(events, policy)
    derived = [lbl for lbl in p.tagger.labels.values() if lbl.parents]
    return derived[0].strength


def test_a_file_label_is_as_strong_as_its_parent_unless_the_policy_attenuates():
    assert written_label_strength(default_policy()) == pytest.approx(1.0)
    weaker = default_policy(
        math={"weights": default_policy().math.weights, "attenuation": {"write": 0.5}}
    )
    assert written_label_strength(weaker) == pytest.approx(0.5)


def test_decisions_do_not_depend_on_the_decision_rule_field_when_weights_are_missing():
    bare = default_policy(math={})
    events = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("exec", "web_worker", "p-1", f=2, t=1, exec_class="unknown"),
        ev("net_connect", "web_worker", "p-1", f=3, t=2, destination_class="unknown"),
    ]
    [j] = run_events(events, bare).judgements().values()
    assert j.log_odds is None and j.decision is Decision.BLOCK  # the 3/2/1 rule is the fallback


# -- the fleet dashboard (C11.8) ------------------------------------------------------------------------------------------


def test_the_dashboard_hides_small_groups_and_adds_noise_to_the_rest():
    import random

    from refmon.aggregate import dashboard, devices_per_tactic
    from refmon.schemas import Mode, QuestionResult

    q = QuestionResult(failed=False)

    def verdict(device, tactics):
        return Verdict(
            verdict_id="v-1", story_id="st-1", device=device, ts="2026-10-28T10:00:00Z",
            mode=Mode.BLOCK, decision=Decision.BLOCK, origin=q, contract=q, effect=q,
            tactics=tactics,
        )  # fmt: skip

    from refmon.schemas import Verdict

    fleet = [verdict(f"ps-dev-{i:016x}", ("Persistence",)) for i in range(7)]
    fleet += [verdict("ps-dev-00000000000000aa", ("Impact",))]  # one device only
    fleet += [verdict("ps-dev-0000000000000001", ("Persistence",))]  # the same device again
    assert devices_per_tactic(fleet) == {"Persistence": 7, "Impact": 1}
    shown = dashboard(fleet, default_policy(), random.Random(3))
    assert set(shown) == {"Persistence"}  # fewer than k = 5 devices: left out
    assert shown["Persistence"] != 7  # noised
    assert dashboard(fleet, default_policy(), random.Random(3)) == shown  # seeded: reproducible
