"""v1.5: lineage-aware trust (A60), incidents that end (A61), bounded state (A62).

Each rule is stated without a scenario, as the weight methodology of CLAUDE.md C11 requires; the
evaluation on seed 833754500 is in docs/v1.5-evaluation.md.
"""

from __future__ import annotations

import math
from datetime import timedelta

import pytest

from evhelp import T0, ev
from refmon.pipeline import Pipeline
from refmon.pipeline.rates import StatRates
from refmon.policy import default_policy
from refmon.schemas import Decision, Mode

POLICY = default_policy()
HALF = POLICY.thresholds.decay_half_life


def signals(events, **kw):
    p = Pipeline(POLICY, **kw)
    for e in events:
        p.process(e)
    return p, {s.name for j in p.judgements().values() for s in j.signals}


def _lineage(connect_at: float, dest: str = "package_index"):
    """A downloaded file handled by a role with no contract: no Contract signal, so the label
    decays normally (a Contract signal would freeze it, A49)."""
    return [
        ev("content_in", "script_host", "p-1", f=1, source_class="download", t=0),
        ev("exec", "script_host", "p-1", f=2, t=1, exec_class="x"),
        ev("exec", "script_host", "p-2", parent="p-1", f=3, t=2, exec_class="x"),
        ev("net_connect", "script_host", "p-2", f=4, t=connect_at, destination_class=dest),
    ]


# -- A60 -------------------------------------------------------------------------------------------


def test_a_faded_but_live_external_lineage_is_not_excused_by_a_trusted_class():
    """Under the origin threshold (no Origin fail) the process still came from outside."""
    p, _ = signals(_lineage(connect_at=1.4 * HALF))
    sid = next(s for s, r in p.linker.records.items() if r.events[-1].type.value == "net_connect")
    j = p.judgements()[sid]
    assert not j.failed["origin"] and not j.failed["contract"]
    assert [s.name for s in j.signals] == ["effect_fetch"]


def test_a_process_with_no_external_lineage_keeps_the_trust_of_the_class():
    events = [ev("net_connect", "script_host", "p-9", f=4, t=0, destination_class="package_index")]
    _, names = signals(events)
    assert "effect_fetch" not in names


def test_once_the_lineage_is_dead_the_class_is_trusted_again():
    """Below the alive floor a label is gone for every rule, this one included."""
    floor = POLICY.thresholds.label_alive_floor
    dead_after = HALF * math.log2(1 / floor) + 60
    _, names = signals(_lineage(connect_at=dead_after))
    assert "effect_fetch" not in names


def test_an_untrusted_destination_is_a_fetch_whatever_the_lineage():
    _, names = signals(_lineage(connect_at=10, dest="unknown"))
    assert "effect_fetch" in names


# -- A61 -------------------------------------------------------------------------------------------


def test_an_incident_ends_when_its_tree_is_silent_for_the_long_window():
    rates = StatRates(POLICY)
    rates.mark_incident("root-a", True, 0.0)
    assert rates._incident
    rates.mark_incident("root-b", False, POLICY.rates.long_window - 1)
    assert "root-a" in rates._incident  # not yet
    rates.mark_incident("root-b", False, POLICY.rates.long_window + 1)
    assert not rates._incident
    assert not rates._rate_for("mass_change", "script_host").frozen


def test_an_active_incident_stays_open_and_keeps_baselines_frozen():
    rates = StatRates(POLICY)
    for t in range(0, 3 * int(POLICY.rates.long_window), 600):
        rates.mark_incident("root-a", True, float(t))
    assert "root-a" in rates._incident
    assert rates._rate_for("mass_change", "script_host").frozen


def test_a_contained_story_no_longer_freezes_baselines_for_good():
    events = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("exec", "web_worker", "p-1", f=2, t=1, exec_class="unknown"),
        ev("net_connect", "web_worker", "p-1", f=3, t=2, destination_class="unknown"),
        # much later, unrelated benign work by another tree
        ev("exec", "script_host", "p-50", f=9, t=2 * POLICY.rates.long_window, exec_class="x"),
    ]
    p, _ = signals(events)
    assert p.judgements()["st-1"].decision is Decision.BLOCK
    assert not p.rates._incident


# -- A62 -------------------------------------------------------------------------------------------


def _busy(n_stories: int, gap: float):
    out = []
    for i in range(n_stories):
        t = i * gap
        out.append(ev("exec", "script_host", f"p-{i}", f=10_000 + i, t=t, exec_class="x"))
    return out


def test_retain_must_cover_the_windows():
    with pytest.raises(ValueError):
        Pipeline(POLICY, retain=60)


def test_a_long_running_pipeline_stays_bounded():
    gap = POLICY.thresholds.story_quiet_window + 1
    retain = POLICY.rates.long_window
    p, _ = signals(_busy(2000, gap), retain=retain)
    kept = len(p.linker.records)
    assert kept <= retain / gap + 2  # the retained ones, plus the stories of one quiet window
    assert len(p.tagger.procs) <= kept + 2
    unbounded, _ = signals(_busy(2000, gap))
    assert len(unbounded.linker.records) == 2000


def test_forgetting_never_changes_a_decision_of_a_story_still_kept():
    events = _busy(600, POLICY.thresholds.story_quiet_window + 1)
    last_t = (len(events) + 5) * (POLICY.thresholds.story_quiet_window + 1)
    events += [
        ev("request_in", "web_worker", "p-a", f=1, source_class="inbound_request", t=last_t),
        ev("exec", "web_worker", "p-a", f=2, t=last_t + 1, exec_class="unknown"),
        ev("net_connect", "web_worker", "p-a", f=3, t=last_t + 2, destination_class="unknown"),
    ]
    bounded, _ = signals(events, retain=POLICY.rates.long_window)
    full, _ = signals(events)
    jb, jf = bounded.best(), full.best()
    assert (jb.decision, jb.log_odds) == (jf.decision, jf.log_odds) == (jb.decision, jb.log_odds)
    assert jb.decision is Decision.BLOCK


def test_a_story_with_a_pending_hold_is_never_forgotten():
    events = [ev("net_connect", "script_host", "p-h", f=3, t=0, destination_class="unknown")]
    blocking = POLICY.model_copy(update={"mode": Mode.BLOCK})
    p = Pipeline(blocking, gate=True, retain=POLICY.rates.long_window)
    for e in events:
        p.process(e)
    assert p.gate.open_hold_stories()
    p.forget(T0 + timedelta(seconds=10 * POLICY.rates.long_window))
    assert p.gate.open_hold_stories() <= set(p.linker.records)


# -- v1.6, A63: a labeled block with no labeled process acts on its producers -------------------


def test_a_timed_out_hold_contains_the_producer_when_only_a_channel_role_saw_the_label():
    """The label sits on content only the launcher touched (a channel role never carries one), so
    no labeled process ever appears. The hold times out into a block, which must act on the process
    that read the credentials, and never on the launcher."""
    gap = 600
    stream = [
        ev("content_in", "launcher", "p-1", parent="p-0", f=1, source_class="package", t=0),
        ev("exec", "launcher", "p-1", parent="p-0", f=2, t=gap, hidden_window=True),
        ev("asset_access", "script_host", "p-2", parent="p-1", cls="credential_store", f=3,
           t=2 * gap),
        ev("persist", "launcher", "p-1", parent="p-0", f=4, t=3 * gap, persist_kind="startup"),
    ]  # fmt: skip
    blocking = POLICY.model_copy(update={"mode": Mode.BLOCK})
    p = Pipeline(blocking, gate=True)
    actions = [o for e in stream for o in p.process(e) if hasattr(o, "target")]
    touched = {(a.type.value, a.target.ref) for a in actions}
    assert ("kill_process_tree", "p-2") in touched
    assert not any(ref == "p-1" for _, ref in touched)
