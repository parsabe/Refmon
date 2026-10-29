from evhelp import ev
from scenario_run import run_events


def stories(events):
    return run_events(events).linker.records


def test_events_sharing_an_object_fingerprint_join_one_story():
    recs = stories([
        ev("content_in", "browser", "p-1", f=1, source_class="web", t=0),
        ev("user_input", "interactive_shell", "p-2", f=1, t=1),
    ])  # fmt: skip
    assert len(recs) == 1


def test_a_child_joins_the_story_of_the_parent_that_has_appeared():
    recs = stories(
        [
            ev("exec", "interactive_shell", "p-1", t=0),
            ev("exec", "script_host", "p-2", parent="p-1", t=1),
        ]
    )
    assert len(recs) == 1


def test_unrelated_processes_with_an_unseen_common_parent_stay_apart():
    recs = stories(
        [
            ev("request_in", "web_worker", "p-1", f=1, parent="p-77", t=0),
            ev("request_in", "web_worker", "p-2", f=2, parent="p-77", t=1),
        ]
    )
    assert len(recs) == 2


def test_the_browser_process_does_not_merge_unrelated_downloads():
    recs = stories(
        [
            ev("content_in", "browser", "p-1", f=1, source_class="web", t=0),
            ev("content_in", "browser", "p-1", f=2, source_class="web", t=1),
        ]
    )
    assert len(recs) == 2


def test_a_quiet_window_closes_the_story_and_a_later_event_starts_a_new_one():
    recs = stories([ev("exec", "other", "p-1", t=0), ev("exec", "other", "p-1", t=700)])
    assert len(recs) == 2
    assert len(stories([ev("exec", "other", "p-1", t=0), ev("exec", "other", "p-1", t=500)])) == 1


def test_a_later_event_that_bridges_two_open_stories_merges_them():
    recs = stories([
        ev("content_in", "browser", "p-1", f=1, source_class="web", t=0),
        ev("exec", "other", "p-2", f=2, t=1),
        ev("exec", "other", "p-2", f=1, t=2),
    ])  # fmt: skip
    assert len(recs) == 1
    [rec] = recs.values()
    assert len(rec.events) == 3 and rec.story.event_ids == [e.event_id for e in rec.events]


def test_the_story_records_its_labels_and_processes():
    [rec] = stories(
        [
            ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
            ev("exec", "script_host", "p-2", parent="p-1", t=1),
        ]
    ).values()
    assert rec.story.process_ids == ["p-1", "p-2"] and rec.story.label_ids
