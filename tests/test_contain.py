"""Contain (CLAUDE.md Phase 3): labeled-only actions with undo records, and the property that it
never touches an unlabeled object."""

from hypothesis import given, settings
from hypothesis import strategies as st

from evhelp import ev
from refmon.contain import Contain
from refmon.pipeline import Pipeline
from refmon.policy import default_policy
from refmon.schemas import UNDO_OPS, Action, ActionType, Effect
from scenario_run import run_events


def plan(events, kind="block", effects=()):
    p = run_events(events)
    [rec] = p.linker.records.values()
    return Contain(p.tagger).plan(rec, kind, effects), p


def types(steps):
    return [(s.type.value, s.target.ref) for s in steps]


def labeled_story():
    return [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("exec", "web_worker", "p-1", f=2, t=1),
        ev(
            "net_connect", "script_host", "p-2", parent="p-1", f=3, t=2, destination_class="unknown"
        ),
        ev("file_write", "script_host", "p-2", parent="p-1", f=4, t=3, new_file=True),
        ev("file_write", "script_host", "p-2", parent="p-1", f=5, t=4),
        ev("persist", "script_host", "p-2", parent="p-1", f=6, t=5),
    ]


def test_a_block_plans_kill_cut_quarantine_restore_and_revert():
    steps, _p = plan(labeled_story())
    assert types(steps) == [
        ("kill_process_tree", "p-1"),
        ("cut_network", "p-2"),
        ("quarantine_file", labeled_story()[3].object.fingerprint),
        ("restore_file", labeled_story()[4].object.fingerprint),
        ("revert_persistence", labeled_story()[5].object.fingerprint),
    ]


def test_only_the_root_of_a_labeled_tree_is_killed():
    steps, _ = plan(labeled_story())
    assert [s.target.ref for s in steps if s.type is ActionType.KILL_PROCESS_TREE] == ["p-1"]


def test_an_unlabeled_process_in_the_story_is_left_alone():
    events = [
        *labeled_story(),
        ev("net_connect", "other", "p-9", f=9, t=6, destination_class="unknown"),
        ev("file_write", "other", "p-9", f=10, t=7, new_file=True),
    ]
    p = run_events(events)
    steps = [s for rec in p.linker.records.values() for s in Contain(p.tagger).plan(rec, "block")]
    assert all(s.target.ref != "p-9" for s in steps)
    assert all(s.target.ref != events[-1].object.fingerprint for s in steps)


def test_an_endpoint_hold_only_pauses_the_roots():
    steps, _ = plan(labeled_story(), "hold_endpoint")
    assert types(steps) == [("hold", "p-1")]


def test_a_server_hold_pauses_and_quarantines_the_new_files_only():
    steps, _ = plan(labeled_story(), "hold_server")
    assert types(steps) == [
        ("hold", "p-1"),
        ("quarantine_file", labeled_story()[3].object.fingerprint),
    ]


def test_lateral_movement_adds_the_host_isolation():
    steps, _p = plan(labeled_story(), "block", (Effect.LATERAL,))
    assert types(steps)[-1] == ("isolate_host", "dev-1")


def test_a_story_without_a_label_has_nothing_to_contain():
    steps, _ = plan([ev("net_connect", "other", "p-1", f=1, destination_class="unknown")])
    assert steps == []


def test_a_label_that_has_decayed_no_longer_makes_a_process_part_of_containment():
    events = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("file_write", "web_worker", "p-1", f=2, t=1, path_group="cache"),  # in role
        ev(
            "file_write", "web_worker", "p-1", f=3, t=6 * 3600, path_group="cache"
        ),  # six half-lives
    ]
    p = run_events(events)
    recs = list(p.linker.records.values())
    assert all(Contain(p.tagger).labeled_processes(r) == [] for r in recs[-1:])


def test_a_label_behind_a_contract_violation_does_not_decay_so_the_process_stays_contained():
    """v1.1 (A49): the same stream, but the worker runs a program it may not: its label has
    Contract evidence, keeps its strength, and the process is still part of containment later."""
    events = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("exec", "web_worker", "p-1", f=2, t=1, exec_class="unknown"),
        ev("file_write", "web_worker", "p-1", f=3, t=6 * 3600, new_file=True),
    ]
    p = run_events(events)
    recs = list(p.linker.records.values())
    assert Contain(p.tagger).labeled_processes(recs[-1]) == ["p-1"]


def test_nothing_is_deleted_there_is_no_delete_action():
    assert not [a for a in ActionType if "delete" in a.value or "remove" in a.value]
    assert UNDO_OPS[ActionType.QUARANTINE_FILE] is not None  # quarantine can always be released


# -- property: Contain never touches an unlabeled object ---------------------------------------------------


EVENT = st.tuples(
    st.sampled_from(["request_in", "exec", "net_connect", "file_write", "persist", "request_end"]),
    st.integers(min_value=1, max_value=4),  # process
    st.integers(min_value=0, max_value=4),  # parent (0: none)
    st.integers(min_value=1, max_value=6),  # object
    st.booleans(),  # new file
)


@settings(max_examples=80, deadline=None)
@given(stream=st.lists(EVENT, min_size=1, max_size=18))
def test_contain_never_touches_an_unlabeled_object(stream):
    events = []
    for i, (kind, proc, parent, obj, new) in enumerate(stream):
        attrs = {}
        if kind == "request_in":
            attrs["source_class"] = "inbound_request"
        if kind == "net_connect":
            attrs["destination_class"] = "unknown"
        if kind == "file_write" and new:
            attrs["new_file"] = True
        events.append(
            ev(
                kind,
                ["web_worker", "script_host", "launcher"][proc % 3],
                f"p-{proc}",
                f=obj,
                parent=f"p-{parent}" if parent and parent != proc else None,
                t=i,
                **attrs,
            )
        )
    pipe = Pipeline(default_policy(mode="block"), gate=True)
    actions: list[Action] = []
    for e in events:
        actions += [o for o in pipe.process(e) if isinstance(o, Action)]
    labeled = {pid for pid, proc in pipe.tagger.procs.items() if proc.ever}
    # v1.1 and v1.2 (A47, A51, A52): a story with no labeled process falls back to the processes
    # that produced its signals or raised its override, never a channel role; nothing else without a
    # label is touched.
    by_event = {e.event_id: e.actor.id for e in events}
    producers = {
        by_event[s.event_id]
        for rec in pipe.linker.records.values()
        for s in rec.signals
        if s.event_id in by_event
    } | {p for rec in pipe.linker.records.values() for p in rec.flag_processes}
    channel = set(pipe.policy.non_carrier_roles)
    role_of = {e.actor.id: e.actor.role for e in events}
    written_by = {
        e.object.fingerprint
        for e in events
        if (e.actor.id in labeled or e.actor.id in producers)
        and e.type.value in ("file_write", "persist")
    }
    for a in actions:
        if a.target.kind.value == "process":
            if a.target.ref not in labeled:
                assert a.target.ref in producers and role_of[a.target.ref] not in channel, a
        elif a.target.kind.value in ("file", "persistence_item"):
            assert a.target.ref in written_by
    keys = [(a.type, a.target.ref) for a in actions]
    assert len(keys) == len(set(keys))
