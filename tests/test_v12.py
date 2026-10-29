"""v1.2: what a fallback does (A51, A52), decided before the first run on its variant seed.

A hold on a story with no labeled process pauses the processes that produced the signals (v1.1,
A47). v1.2 keeps a channel role (browser, mail, launcher) out of that fallback, lets a block do the
same when the story has no external origin label either, and so lets `stop` on a fallback hold act
on the processes that were paused.
"""

from datetime import timedelta

import pytest

from evhelp import ev
from refmon.gate import RecordingNotifier
from refmon.pipeline import Pipeline
from refmon.policy import default_policy
from refmon.schemas import Action, Decision


def gate_run(events, policy=None):
    pipe = Pipeline(policy or default_policy(mode="block"), gate=True, notifier=RecordingNotifier())
    actions: list[Action] = []
    for e in events:
        actions += [o for o in pipe.process(e) if isinstance(o, Action)]
    return pipe, actions


def kinds(actions, process=None):
    return sorted(
        (a.type.value, a.target.ref) for a in actions if process is None or a.target.ref == process
    )


def typed_command():
    """A command typed by hand: no label, a hidden window and a connection out (a hold)."""
    return [
        ev(
            "user_input",
            "interactive_shell",
            "p-1",
            cls="command_text",
            f=1,
            t=0,
            input_method="typed",
        ),
        ev("exec", "interactive_shell", "p-1", cls="command_text", f=1, t=2, hidden_window=True),
        ev(
            "net_connect", "script_host", "p-2", parent="p-1", f=3, t=3, destination_class="unknown"
        ),
    ]


def tamper_without_label():
    """A service process stops a security tool: a Contract signal and an Effect, no label at all."""
    return [
        ev("security_tamper", "script_host", "p-1", cls="security_tool", f=1, t=0),
        ev("net_connect", "script_host", "p-1", f=2, t=1, destination_class="unknown"),
    ]


# -- A52: a block with no labeled process and no origin label acts on the producers ----------------


def test_a_block_on_a_story_with_no_label_at_all_acts_on_the_processes_that_produced_it():
    pipe, actions = gate_run(tamper_without_label())
    assert pipe.best().decision is Decision.BLOCK
    assert ("kill_process_tree", "p-1") in kinds(actions)
    assert ("cut_network", "p-1") in kinds(actions)  # it connected out


def test_the_override_of_an_unlabeled_process_is_contained_too():
    """A canary read by a process that carries no label: the override blocks, and the process that
    raised it is the only thing there is to stop."""
    stream = [ev("asset_access", "script_host", "p-1", cls="credential", f=5, t=1, canary_hit=True)]
    pipe, actions = gate_run(stream)
    assert pipe.best().override is not None
    assert kinds(actions) == [("kill_process_tree", "p-1")]


def test_a_labeled_story_whose_labeled_child_has_not_appeared_yet_is_left_to_the_labeled_rule():
    """The shell ran pasted external text; until a labeled child exists a block touches nothing
    (the shell is the user's), and when the child appears only the child is killed."""
    stream = [
        ev("content_in", "browser", "p-0", cls="clipboard_text", f=1, source_class="web", t=0),
        ev("exec", "interactive_shell", "p-1", cls="command_text", f=1, t=2, hidden_window=True),
        ev(
            "net_connect", "script_host", "p-2", parent="p-1", f=3, t=3, destination_class="unknown"
        ),
    ]
    pipe, actions = gate_run(stream[:2])
    assert pipe.best().decision is Decision.BLOCK and actions == []
    _, actions = gate_run(stream)
    assert [r for t, r in kinds(actions) if t == "kill_process_tree"] == ["p-2"]


def test_a_story_that_has_a_labeled_process_is_handled_as_before():
    stream = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("net_connect", "web_worker", "p-1", f=2, t=1, destination_class="unknown"),
        ev(
            "net_connect", "script_host", "p-5", f=2, t=2, destination_class="unknown"
        ),  # same story
    ]
    pipe, actions = gate_run(stream)
    assert len(pipe.linker.records) == 1
    assert {a.target.ref for a in actions if a.target.kind.value == "process"} == {"p-1"}


# -- A51: a channel role is never touched by the fallback ------------------------------------------


@pytest.mark.parametrize("role", ["launcher", "browser", "mail"])
def test_a_channel_role_that_produced_a_signal_is_not_paused(role):
    """A hold, but the only process behind it is the channel itself: nothing is paused."""
    stream = [ev("exec", role, "p-9", cls="command_text", f=3, t=1, hidden_window=True)]
    pipe, actions = gate_run(stream)
    assert pipe.best().decision is Decision.HOLD
    assert actions == []


def test_a_channel_role_that_produced_a_signal_is_not_killed_by_a_block_either():
    stream = [
        ev("exec", "launcher", "p-9", cls="command_text", f=3, t=1, hidden_window=True),
        ev("security_tamper", "script_host", "p-1", cls="security_tool", f=1, t=2),
        ev("net_connect", "launcher", "p-9", f=3, t=3, destination_class="unknown"),
    ]
    pipe, actions = gate_run(stream)
    assert pipe.best().decision is Decision.BLOCK
    assert "p-9" not in {a.target.ref for a in actions}
    assert ("kill_process_tree", "p-1") in kinds(actions)


def test_the_other_producers_of_the_story_are_still_paused_when_a_channel_role_is_one_of_them():
    stream = [
        ev("exec", "launcher", "p-0", cls="command_text", f=1, t=0, hidden_window=True),
        *typed_command(),
    ]
    _, actions = gate_run(stream)
    assert "p-0" not in {a.target.ref for a in actions}
    assert ("hold", "p-1") in kinds(actions)


# -- stop and timeout on a fallback hold -------------------------------------------------------------


def test_stop_on_a_fallback_hold_kills_the_processes_that_were_paused():
    pipe, actions = gate_run(typed_command())
    assert kinds(actions) == [("hold", "p-1")]
    [case] = pipe.gate.holds.values()
    res = pipe.gate.answer_user(case.hold_id, "stop", case.started)
    assert ("kill_process_tree", "p-1") in kinds(res.actions)
    assert ("cut_network", "p-2") in kinds(res.actions)


def test_no_answer_is_a_stop_and_acts_the_same_way():
    pipe, _ = gate_run(typed_command())
    [case] = pipe.gate.holds.values()
    acts = pipe.gate.tick(case.deadline + timedelta(seconds=1))
    assert ("kill_process_tree", "p-1") in kinds(acts)


def test_continue_still_releases_what_was_paused():
    pipe, actions = gate_run(typed_command())
    [case] = pipe.gate.holds.values()
    assert pipe.gate.answer_user(case.hold_id, "continue", case.started).undo == [
        a.action_id for a in actions
    ]


def test_a_second_answer_to_a_resolved_hold_is_refused():
    pipe, _ = gate_run(typed_command())
    [case] = pipe.gate.holds.values()
    pipe.gate.answer_user(case.hold_id, "stop", case.started)
    with pytest.raises(ValueError):
        pipe.gate.answer_user(case.hold_id, "stop", case.started)


def test_a_server_block_without_a_label_quarantines_what_the_producer_wrote():
    stream = [
        ev("security_tamper", "script_host", "p-1", cls="security_tool", f=1, t=0),
        ev("file_write", "script_host", "p-1", f=7, t=1, new_file=True),
    ]
    _, actions = gate_run(stream, default_policy(mode="block", devices={"dev-1": "server"}))
    assert ("kill_process_tree", "p-1") in kinds(actions)
    assert any(a.type.value == "quarantine_file" for a in actions)


# -- the seed now draws the numbers of every variant (docs/variant-seeds.md) -------------------------


def _variants(seed):
    from refmon import variants as v
    from refmon.golden import load_golden_cases
    from scenario_run import GOLDEN_DIR

    return v.generate(load_golden_cases(GOLDEN_DIR), default_policy(), seed)


def test_the_seed_decides_the_numbers_of_the_one_factor_variants_too():
    a, b = _variants(11), _variants(12)
    pick = lambda vs: {  # noqa: E731
        (x.scenario, x.name): (x.params, [e.ts for e in x.events])
        for x in vs
        if x.name in ("timing=minutes", "timing=beyond_window", "obfuscation=high_entropy")
    }
    pa, pb = pick(a), pick(b)
    assert pa.keys() == pb.keys() and pa
    assert sum(pa[k][0] != pb[k][0] for k in pa) > len(pa) // 2  # the draws differ
    # the variants without a number are the same events for every seed
    same = lambda vs: {  # noqa: E731
        (x.scenario, x.name): [e.to_json_line() for e in x.events]
        for x in vs
        if x.name in ("baseline", "delivery=typed", "entry=terminal", "lineage=2")
    }
    assert same(a) == same(b)


def test_the_drawn_numbers_are_reproducible_and_in_their_ranges():
    policy = default_policy()
    first, second = _variants(21), _variants(21)
    assert [(x.name, x.params) for x in first] == [(x.name, x.params) for x in second]
    for x in first:
        p = x.params
        if x.dims.get("timing") == "minutes":
            assert 60.0 <= p["gap"] <= 900.0
        if x.dims.get("timing") == "beyond_window":
            assert policy.thresholds.story_quiet_window + 30 <= p["gap"]
        if x.dims.get("obfuscation") == "high_entropy":
            assert p["entropy_bits"] > policy.math.entropy_max_bits
        if x.dims.get("obfuscation") == "padded":
            assert p["longest_ws_run"] > policy.math.ws_run_max
        if not {"timing", "obfuscation"} & x.dims.keys():
            assert p == {}
