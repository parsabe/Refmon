"""One test per propagation rule of CLAUDE.md C3 (rules 1 to 7)."""

import pytest

from evhelp import ev, fp
from refmon.pipeline.tag import Tagger
from refmon.policy import default_policy
from scenario_run import run_events


@pytest.fixture
def tagger():
    return Tagger(default_policy())


def test_rule1_external_content_creates_a_label_of_strength_one(tagger):
    tg = tagger.process(
        ev("content_in", "browser", "p-1", cls="clipboard_text", f=1, source_class="web")
    )
    [lid] = tg.new_labels
    assert tagger.labels[lid].strength == 1.0
    assert tagger.labels[lid].persistent is False
    assert tagger.fp_labels[fp(1)] == {lid}


@pytest.mark.parametrize("source", ["internal"])
def test_rule1_internal_content_creates_no_label(tagger, source):
    assert (
        tagger.process(ev("content_in", "browser", "p-1", f=1, source_class=source)).new_labels
        == ()
    )


@pytest.mark.parametrize("etype", ["content_in", "request_in"])
def test_rule1_request_in_and_content_in_both_label(tagger, etype):
    assert (
        len(
            tagger.process(
                ev(etype, "web_worker", "p-1", f=1, source_class="inbound_request")
            ).new_labels
        )
        == 1
    )


def test_rule6_a_trusted_source_creates_no_label(tagger):
    tg = tagger.process(
        ev(
            "content_in",
            "package_installer",
            "p-1",
            f=1,
            source_class="download",
            trusted_source="official-python-index",
        )
    )
    assert tg.new_labels == () and tg.trusted is True and tg.actor_labels == ()


def test_rule2_a_worker_carries_its_request_label_until_the_request_ends(tagger):
    tg = tagger.process(
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0)
    )
    assert tg.actor_labels
    assert tagger.process(
        ev("file_write", "web_worker", "p-1", f=2, path_group="cache", t=1)
    ).actor_labels
    after = tagger.process(ev("request_end", "web_worker", "p-1", f=1, t=2))
    assert after.actor_labels == ()
    assert (
        tagger.process(
            ev("file_write", "web_worker", "p-1", f=3, path_group="cache", t=3)
        ).actor_labels
        == ()
    )


@pytest.mark.parametrize("role", ["browser", "mail", "launcher"])
def test_rule2_the_channel_itself_does_not_carry_the_label(tagger, role):
    tg = tagger.process(ev("content_in", role, "p-1", f=1, source_class="web"))
    assert tg.new_labels and tg.actor_labels == ()


def test_rule2_an_office_app_that_opens_labeled_content_carries_it(tagger):
    tagger.process(ev("content_in", "mail", "p-1", f=1, source_class="mail", t=0))
    tg = tagger.process(ev("content_in", "office", "p-2", f=1, source_class="mail", t=5))
    assert tg.actor_labels and tg.new_labels == ()  # the same label, not a second one


def test_rule3_an_exec_that_matches_labeled_content_labels_the_process_it_spawns(tagger):
    tagger.process(ev("content_in", "browser", "p-1", f=1, source_class="web", t=0))
    spawner = tagger.process(ev("exec", "interactive_shell", "p-2", f=1, t=1))
    assert spawner.actor_labels == ()  # the spawner itself stays unlabeled
    child = tagger.process(ev("net_connect", "script_host", "p-3", parent="p-2", t=2))
    assert child.actor_labels


def test_rule3_an_exec_of_other_content_labels_nothing(tagger):
    tagger.process(ev("content_in", "browser", "p-1", f=1, source_class="web", t=0))
    tagger.process(ev("exec", "interactive_shell", "p-2", f=99, t=1))
    assert (
        tagger.process(ev("net_connect", "script_host", "p-3", parent="p-2", t=2)).actor_labels
        == ()
    )


def test_rule3_the_label_goes_to_the_next_child_only(tagger):
    tagger.process(ev("content_in", "browser", "p-1", f=1, source_class="web", t=0))
    tagger.process(ev("exec", "interactive_shell", "p-2", f=1, t=1))
    assert tagger.process(ev("exec", "script_host", "p-3", parent="p-2", t=2)).actor_labels
    assert tagger.process(ev("exec", "script_host", "p-4", parent="p-2", t=3)).actor_labels == ()


def test_rule4_children_and_grandchildren_inherit_every_label_of_the_parent(tagger):
    tagger.process(ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0))
    tagger.process(
        ev("content_in", "web_worker", "p-1", f=2, source_class="outbound_response", t=1)
    )
    parent = tagger.procs["p-1"].labels
    assert len(parent) == 2
    tagger.process(ev("exec", "script_host", "p-2", parent="p-1", t=2))
    tagger.process(ev("exec", "script_host", "p-3", parent="p-2", t=3))
    assert tagger.procs["p-2"].labels == parent == tagger.procs["p-3"].labels


def test_rule5_a_file_written_by_a_labeled_process_inherits_the_label(tagger):
    tagger.process(ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0))
    tg = tagger.process(ev("file_write", "web_worker", "p-1", f=2, path_group="cache", t=1))
    [lid] = tg.new_labels
    assert tagger.labels[lid].parents and not tagger.labels[lid].persistent
    assert tagger.fp_labels[fp(2)] == {lid}


def test_rule5_a_file_written_by_an_unlabeled_process_gets_no_label(tagger):
    assert (
        tagger.process(ev("file_write", "web_worker", "p-1", f=2, path_group="cache")).new_labels
        == ()
    )


def test_rule5_persistence_items_and_web_root_files_are_persistent(tagger):
    tagger.process(ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0))
    persist = tagger.process(ev("persist", "web_worker", "p-1", f=2, t=1))
    shell = tagger.process(
        ev(
            "file_write",
            "web_worker",
            "p-1",
            f=3,
            web_root="main_site",
            executable=True,
            new_file=True,
            t=2,
        )
    )
    plain = tagger.process(ev("file_write", "web_worker", "p-1", f=4, path_group="cache", t=3))
    assert tagger.labels[persist.new_labels[0]].persistent
    assert tagger.labels[shell.new_labels[0]].persistent
    assert not tagger.labels[plain.new_labels[0]].persistent


def test_rule6_strength_halves_every_half_life_unless_persistent(tagger):
    tagger.process(ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0))
    tagger.process(ev("persist", "web_worker", "p-1", f=2, t=0))
    [plain] = tagger.fp_labels[fp(1)]
    [persistent] = tagger.fp_labels[fp(2)]
    half_life = default_policy().thresholds.decay_half_life
    ts = ev("exec", "other", "p-9", t=half_life).ts
    assert tagger.strength(plain, ts) == pytest.approx(0.5)
    assert tagger.strength(persistent, ts) == 1.0
    far = ev("exec", "other", "p-9", t=86_400).ts
    assert tagger.strength(plain, far) < 1e-6 and tagger.strength(persistent, far) == 1.0


def test_rule6_a_decayed_label_is_no_longer_carried(tagger):
    tagger.process(ev("content_in", "office", "p-1", f=1, source_class="mail", t=0))
    assert tagger.process(ev("exec", "office", "p-1", f=5, t=60)).actor_labels
    assert tagger.process(ev("exec", "office", "p-1", f=5, t=86_400)).actor_labels == ()


def test_rule7_a_persistent_label_carries_the_contract_evidence_of_its_story():
    events = [
        ev("content_in", "browser", "p-1", cls="clipboard_text", f=1, source_class="web", t=0),
        ev("user_input", "interactive_shell", "p-2", f=1, parent="p-0", t=1, input_method="paste"),
        ev("exec", "interactive_shell", "p-2", f=1, parent="p-0", t=2),
        ev("persist", "script_host", "p-3", f=2, parent="p-2", t=3, persist_kind="startup_entry"),
    ]
    p = run_events(events)
    [pl] = [lbl for lbl in p.tagger.labels.values() if lbl.persistent]
    assert pl.contract_evidence == ("contract_external_exec",)


def test_rule7_the_evidence_applies_to_the_story_in_which_the_item_runs_later():
    events = [
        ev("content_in", "browser", "p-1", cls="clipboard_text", f=1, source_class="web", t=0),
        ev("exec", "interactive_shell", "p-2", f=1, parent="p-0", t=2),
        ev("persist", "script_host", "p-3", f=2, parent="p-2", t=3, persist_kind="startup_entry"),
        ev("exec", "scheduler", "p-9", f=2, parent="p-8", t=90_000),
        ev(
            "net_connect",
            "script_host",
            "p-10",
            parent="p-9",
            t=90_001,
            destination_class="unknown",
        ),
    ]
    p = run_events(events)
    later = max(p.judgements().values(), key=lambda j: j.ts)
    assert later.failed == {"origin": True, "contract": True, "effect": True}
    assert any(s.carried and s.name == "contract_external_exec" for s in later.signals)
