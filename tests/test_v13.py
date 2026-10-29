"""v1.3: the calculus is monotone in label strength (F8, A55).

Until v1.2 a Contract or Effect signal counted at the strength of the label behind it while that
label was at or above the origin threshold, and at 1.0 below it. A label that faded from 1.0 to 0.69
made the same behaviour weaker evidence, and a label that faded under 0.5 made it full strength
again: a weaker label could give stronger evidence. From v1.3 a behavioural signal counts at full
strength and only Origin carries the label's strength.
"""

import itertools
import os

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from evhelp import ev
from refmon import variants as v
from refmon.pipeline import Pipeline
from refmon.policy import default_policy
from refmon.replay import ReplaySource
from refmon.schemas import Decision
from scenario_run import GOLDEN_DIR, run_events

POLICY = default_policy()


def golden(scenario):
    return list(
        ReplaySource(GOLDEN_DIR / f"{scenario}.events.jsonl", extra_roles=POLICY.extra_roles)
    )


def counted(pipe):
    j = pipe.best()
    return {c.signal: c.strength for c in j.contributions if c.counted}


# -- the finding, and its repair ----------------------------------------------------------------------


def test_the_variant_that_was_worse_in_v1_1_is_a_block_again():
    """S02 with 299 s between its events: block in v1.0, a hold in v1.1 and v1.2 (F8)."""
    events = v.timing(golden("S02"), "minutes", POLICY.thresholds.story_quiet_window, gap=298.9)
    assert run_events(events).best().decision is Decision.BLOCK


def test_a_behavioural_signal_counts_at_full_strength_whatever_the_age_of_the_label():
    stream = [
        ev("request_in", "script_host", "p-1", f=1, source_class="inbound_request", t=0),
        ev("net_connect", "script_host", "p-1", f=3, t=1500, destination_class="unknown"),
    ]
    strengths = counted(run_events(stream))  # the label is at 0.56 when the process connects
    assert strengths["effect_fetch"] == 1.0
    assert 0.5 < strengths["origin_external"] < 0.6  # only Origin carries the label's strength


def test_origin_alone_decays_with_the_label():
    def origin(gap):
        stream = [
            ev("request_in", "script_host", "p-1", f=1, source_class="inbound_request", t=0),
            ev("net_connect", "script_host", "p-1", f=2, t=gap, destination_class="unknown"),
        ]
        return counted(run_events(stream)).get("origin_external", 0.0)

    assert origin(10) > origin(600) > origin(1700) > 0.0
    assert origin(4000) == 0.0  # below the threshold the label is not evidence of origin at all


def test_the_worked_check_of_the_specification_now_holds_to_the_digit():
    """C11, S01: 0.8 + 1.0 + max(2.5, 2.0) = 4.3 from a prior of -6.91 is -2.61 (v1.2: -2.62)."""
    pipe = run_events(golden("S01"))
    assert pipe.best().log_odds == pytest.approx(-2.61, abs=0.006)


# -- the property: a weaker label never produces stronger evidence --------------------------------------

KINDS = st.sampled_from(
    [
        "request_in", "content_in", "exec", "net_connect", "file_write", "persist",
        "asset_access", "priv_change", "security_tamper", "response_out",
    ]
)  # fmt: skip
ROLES = st.sampled_from(["web_worker", "script_host", "other", "interactive_shell", "launcher"])
STEP = st.tuples(
    KINDS,
    st.integers(min_value=1, max_value=4),  # process
    st.integers(min_value=0, max_value=4),  # parent (0: none)
    st.integers(min_value=1, max_value=6),  # object
    st.booleans(),  # a flag the kind uses
    st.integers(min_value=0, max_value=1800),  # seconds since the previous event
    ROLES,
)


def build(steps):
    out, t, roles = [], 0.0, {}
    for kind, proc, parent, obj, flag, gap, role in steps:
        t += gap
        role = roles.setdefault(proc, role)  # a process keeps its role
        attrs = {}
        if kind in ("request_in", "content_in"):
            attrs["source_class"] = "inbound_request" if kind == "request_in" else "web"
        if kind == "exec":
            attrs["exec_class"] = "unknown"
            attrs["hidden_window"] = flag
        if kind == "net_connect":
            attrs["destination_class"] = "unknown" if flag else "internal_network"
        if kind == "file_write":
            attrs["new_file"] = flag
            if flag and obj % 2:
                attrs["web_root"] = (
                    "main_site"  # a persistent label is derived from a labeled writer
                )
        if kind == "response_out":
            attrs["bytes"] = 9_000_000 if flag else 100
        cls = {"security_tamper": "security_tool", "asset_access": "credential_store"}.get(
            kind, "x"
        )
        out.append(
            ev(
                kind, role, f"p-{proc}", cls=cls, f=obj, t=t,
                parent=f"p-{parent}" if parent and parent != proc else None, **attrs,
            )
        )  # fmt: skip
    return out


def judged(events, half_life):
    """Every story's log-odds under a label half-life. The alive floor is lowered to nothing so that
    a faster decay changes the strength of labels and not which stories they link."""
    policy = default_policy(thresholds={"decay_half_life": half_life, "label_alive_floor": 0.0})
    pipe = Pipeline(policy)
    for e in events:
        pipe.process(e)
    return {sid: j.log_odds for sid, j in pipe.judgements().items()}


@settings(max_examples=int(os.environ.get("REFMON_PROPERTY_EXAMPLES", "150")), deadline=None)
@given(steps=st.lists(STEP, min_size=1, max_size=14))
def test_a_label_that_fades_faster_never_makes_a_story_stronger(steps):
    events = build(steps)
    slow, medium, fast = judged(events, 3600.0), judged(events, 600.0), judged(events, 60.0)
    assert slow.keys() == medium.keys() == fast.keys()
    for sid in slow:
        assert medium[sid] <= slow[sid] + 1e-9, (sid, medium[sid], slow[sid])
        assert fast[sid] <= medium[sid] + 1e-9, (sid, fast[sid], medium[sid])


# -- the F3 expectations, pinned to fixed variants (they no longer depend on the seed) -----------------


def fixed(scenario, level, gap):
    events = v.timing(golden(scenario), level, POLICY.thresholds.story_quiet_window, gap=gap)
    return run_events(events).best().decision


@pytest.mark.xfail(
    strict=True, reason="F3: the S19 stand-in changes 55 files, the hour test needs 60"
)
def test_slow_ransomware_at_90_seconds_is_not_allowed():
    assert fixed("S19", "minutes", 90.0) is not Decision.ALLOW


def test_a_slow_leak_beyond_the_story_window_is_no_longer_allowed():
    """S27 with 11 minutes between its oversized responses was allowed until v1.2: each response
    counted at the strength of a label that had faded to 0.5. A response is evidence at full
    strength now (F8), and together with Origin it reaches a hold."""
    assert fixed("S27", "beyond_window", 660.0) is not Decision.ALLOW


def test_the_slow_variants_are_pinned_to_numbers_not_to_a_seed():
    a = v.timing(golden("S19"), "minutes", 600.0, gap=90.0)
    assert min((y.ts - x.ts).total_seconds() for x, y in itertools.pairwise(a)) >= 90.0


# -- benign variants and their labels (docs/variant-seeds.md, "Benign variants") ------------------------

from refmon.golden import ScenarioKind, load_golden_cases  # noqa: E402

CASES = load_golden_cases(GOLDEN_DIR)
BENIGN = [c for c in CASES if c.expected.kind is ScenarioKind.BENIGN]


@pytest.fixture(scope="module")
def generated():
    return v.generate(CASES, POLICY, seed=31)


def named(generated, scenario, name):
    return next(x for x in generated if x.scenario == scenario and x.name == name)


def test_every_benign_golden_file_gets_a_baseline_and_variants(generated):
    benign = [x for x in generated if x.kind == "benign"]
    assert {x.scenario for x in benign} == {c.scenario for c in BENIGN} and len(BENIGN) == 19
    assert len(benign) > 150
    assert {x.kind for x in generated} == {"malicious", "benign"}
    assert all(x.adds == () for x in generated if x.kind == "malicious")


def test_an_unlabelled_benign_variant_expects_the_decision_of_its_file(generated):
    for x in generated:
        if x.kind != "benign":
            continue
        if x.adds:
            assert x.expected is None, (x.scenario, x.name)
        else:
            base = named(generated, x.scenario, "baseline").expected
            assert x.expected is base, (x.scenario, x.name)
    assert named(generated, "S49", "baseline").expected is Decision.HOLD  # a hold by design
    assert named(generated, "S09", "baseline").expected is Decision.ALLOW


def test_the_levels_that_change_how_a_story_arrives_are_never_labelled(generated):
    for x in generated:
        if x.kind == "benign" and set(x.dims) <= {"delivery", "lineage", "timing"}:
            assert x.adds == (), (x.scenario, x.name)
        if x.kind == "benign" and x.dims == {"obfuscation": "stripped"}:
            assert x.adds == ()


def test_the_labels_follow_the_rules_of_the_table(generated):
    assert named(generated, "S36", "entry=web_worker").adds == (
        "contract",
    )  # a worker may not exec
    assert named(generated, "S11", "entry=terminal").adds == ("contract",)  # external content
    assert named(generated, "S10", "entry=terminal").adds == ()  # internal source: nothing external
    assert named(generated, "S11", "obfuscation=high_entropy").adds == ("effect",)
    assert named(generated, "S11", "obfuscation=padded").adds == ("effect",)
    assert named(generated, "S11", "obfuscation=stripped").adds == ()
    # a web worker's contract lists db and cache servers: any other class is a Contract violation
    assert named(generated, "S26a", "destination=unknown").adds == ("contract",)
    # a role with no list of destinations: an unknown host is an Effect (fetch), a trusted class is not
    assert named(generated, "S09", "destination=unknown").adds in {("effect",), ("contract",)}


def test_a_combination_takes_the_union_of_the_labels_of_its_levels(generated):
    for x in generated:
        if x.kind != "benign" or not x.name.startswith("combo-"):
            continue
        singles = set()
        for dim, level in x.dims.items():
            single = next(
                (y for y in generated if y.scenario == x.scenario and y.name == f"{dim}={level}"),
                None,
            )
            if single is not None:
                singles |= set(single.adds)
        # the combination may add labels the single level did not (its input changed), never lose one
        assert singles <= set(x.adds) or "entry" in x.dims or "delivery" in x.dims, (
            x.scenario,
            x.name,
        )


def test_the_labels_are_decided_without_replaying_anything():
    """The generator must not import or run a pipeline to label a variant."""
    import inspect

    src = inspect.getsource(v.step_labels) + inspect.getsource(v._variant)
    assert "Pipeline" not in src and ".process(" not in src
