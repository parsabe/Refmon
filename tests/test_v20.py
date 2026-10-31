"""v2.0: trust is lineage (A65), a channel role relays and the program it starts acts (A66).

Each rule is stated without a scenario (CLAUDE.md C11, weight methodology); the evaluation on seed
171139148 is in docs/v2.0-evaluation.md.
"""

from __future__ import annotations

import math

from evhelp import ev
from refmon.pipeline import Pipeline
from refmon.policy import default_policy
from refmon.schemas import Action, Decision, Mode, Override

POLICY = default_policy()
HALF = POLICY.thresholds.decay_half_life
QUIET = POLICY.thresholds.story_quiet_window
BLOCKING = POLICY.model_copy(update={"mode": Mode.BLOCK})


def run(events, policy=POLICY, **kw):
    p = Pipeline(policy, **kw)
    out = []
    for e in events:
        out += p.process(e)
    return p, out


def last_story(p):
    return p.judgements()[max(p.linker.records, key=lambda s: int(s.split("-")[1]))]


def _install(gap: float, *, child: bool = False, extra=()):
    """Trusted content ingested by an installer, a startup entry written `gap` seconds later."""
    actor = ("script_host", "p-2", "p-1") if child else ("package_installer", "p-1", "p-0")
    role, pid, parent = actor
    return [
        ev("content_in", "package_installer", "p-1", parent="p-0", f=1, t=0,
           source_class="download", trusted_source="university-software-portal"),
        *extra,
        ev("persist", role, pid, parent=parent, f=2, t=gap, persist_kind="startup_entry"),
    ]  # fmt: skip


# -- A65 -------------------------------------------------------------------------------------------


def test_a_later_step_of_a_trusted_install_beyond_the_quiet_window_keeps_the_trust():
    p, _ = run(_install(gap=QUIET + 300))
    assert len(p.linker.records) == 2  # the window split the install into two stories
    j = last_story(p)
    assert j.override is Override.TRUSTED_ROOT and j.decision is Decision.ALLOW


def test_the_trust_mark_is_inherited_by_children():
    p, _ = run(_install(gap=QUIET + 300, child=True))
    assert last_story(p).decision is Decision.ALLOW


def test_the_trust_mark_dies_where_a_label_would():
    floor = POLICY.thresholds.label_alive_floor
    dead_after = HALF * math.log2(1 / floor) + 60
    p, _ = run(_install(gap=dead_after))
    j = last_story(p)
    assert j.override is None and j.decision is not Decision.ALLOW


def test_any_live_external_label_in_the_lineage_cancels_the_trust():
    """Even a faded one, under the origin threshold: the lineage is no longer only trusted."""
    extra = [ev("content_in", "package_installer", "p-1", parent="p-0", f=9, t=1,
                source_class="download")]  # fmt: skip
    p, _ = run(_install(gap=1.4 * HALF, extra=extra))
    j = last_story(p)
    assert not j.failed["origin"]  # the label has faded under the origin threshold
    assert j.override is None and j.decision is not Decision.ALLOW


def test_a_channel_role_never_carries_the_trust_mark():
    events = [
        ev("content_in", "browser", "p-1", parent="p-0", f=1, t=0,
           source_class="download", trusted_source="university-software-portal"),
        ev("persist", "browser", "p-1", parent="p-0", f=2, t=QUIET + 300,
           persist_kind="startup_entry"),
    ]  # fmt: skip
    p, _ = run(events)
    assert last_story(p).override is None


def test_the_trust_mark_never_passes_to_a_file_or_persistence_item():
    """A startup item written under trust and run later starts a story without trust."""
    events = [
        *_install(gap=10),
        ev("exec", "launcher", "p-5", parent="p-4", f=2, t=QUIET + 400, exec_class="unknown"),
        ev("net_connect", "script_host", "p-6", parent="p-5", f=3, t=QUIET + 401,
           destination_class="unknown"),
    ]  # fmt: skip
    p, _ = run(events)
    assert last_story(p).override is None


def test_blocking_overrides_still_beat_the_trust_mark():
    events = [
        *_install(gap=QUIET + 300),
        ev("asset_access", "package_installer", "p-1", parent="p-0", f=7, t=QUIET + 301,
           cls="credential", canary_hit=True),
    ]  # fmt: skip
    p, _ = run(events)
    assert last_story(p).decision is Decision.BLOCK


def test_a_long_running_pipeline_does_not_forget_a_live_trust_mark():
    retain = POLICY.rates.long_window
    events = _install(gap=retain - 60)
    p, _ = run(events, retain=retain)
    assert last_story(p).decision is Decision.ALLOW


# -- A66 -------------------------------------------------------------------------------------------


def _relay(dest: str = "package_index"):
    """External content reaches a launcher, which runs an obfuscated command; the program it starts
    connects to a destination its role does not list. The program has no label of its own (the
    launcher never carries one), so only the launcher produced a signal."""
    return [
        ev("content_in", "launcher", "p-1", parent="p-0", f=1, t=0, source_class="agent_input"),
        ev("exec", "launcher", "p-1", parent="p-0", f=2, t=1, exec_class="unknown",
           encoded_payload=True, launched_via="run_dialog"),
        ev("net_connect", "script_host", "p-2", parent="p-1", f=3, t=2, destination_class=dest),
    ]  # fmt: skip


def test_a_hold_whose_only_producer_is_a_relay_pauses_the_program_it_started():
    p, out = run(_relay(), BLOCKING, gate=True)
    acts = [(a.type.value, a.target.ref) for a in out if isinstance(a, Action)]
    assert p.best().decision is Decision.HOLD
    assert ("hold", "p-2") in acts
    assert not any(ref == "p-1" for _, ref in acts)  # the relay itself is never touched


def test_a_relay_that_started_nothing_hands_nothing_over():
    events = [
        ev("exec", "script_host", "p-2", parent="p-1", f=2, t=0, exec_class="x"),
        ev("net_connect", "launcher", "p-1", parent="p-0", f=3, t=1, destination_class="unknown"),
    ]
    _, out = run(events, BLOCKING, gate=True)
    assert not [a for a in out if isinstance(a, Action) and a.target.ref == "p-2"]


def test_the_relay_rule_still_spares_the_users_shell():
    events = [
        ev("content_in", "launcher", "p-1", parent="p-0", f=1, t=0, source_class="web"),
        ev("exec", "launcher", "p-1", parent="p-0", f=1, t=1, exec_class="unknown",
           encoded_payload=True),
        ev("exec", "interactive_shell", "p-2", parent="p-1", f=4, t=2, exec_class="unknown"),
    ]  # fmt: skip
    _, out = run(events, BLOCKING, gate=True)
    assert not [a for a in out if isinstance(a, Action) and a.target.ref in ("p-1",)]
