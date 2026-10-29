"""v1.1: the four structural changes made after Phase 7, each motivated by a design finding (F1 to
F4) and decided before the first run on the new variant seed (docs/variant-seeds.md). The streams
here are hand-built; none is a generated variant.

F4  external content run as a command is a Contract signal for every role unless its contract allows it
F1  a hold on a story with no labeled process pauses the processes that produced the signals
F2  a trusted destination class excuses a labeled process only where the role's contract lists it
F3  a label behind a Contract violation does not decay; the rate tests have an hour-scale window
"""

from datetime import timedelta

import pytest

from evhelp import T0, ev
from refmon.calculus.stats import poisson_tail
from refmon.gate import RecordingNotifier
from refmon.pipeline import Pipeline
from refmon.policy import default_policy, default_policy_dict
from refmon.schemas import Action, ActionType, Decision
from scenario_run import run_events


def names(pipe):
    return {s.name for j in pipe.judgements().values() for s in j.signals}


def policy_with(contracts=None, **overrides):
    data = default_policy_dict()
    data["contracts"] = {**data["contracts"], **(contracts or {})}
    for key, value in overrides.items():
        data[key] = {**data[key], **value}
    return type(default_policy()).parse(data)


def gate_run(events, policy=None):
    pipe = Pipeline(policy or default_policy(mode="block"), gate=True, notifier=RecordingNotifier())
    actions: list[Action] = []
    for e in events:
        actions += [o for o in pipe.process(e) if isinstance(o, Action)]
    return pipe, actions


# -- F4: the universal external-content contract ------------------------------------------------------


def pasted(role, **kw):
    """Content from the web, copied and run as a command by a process of `role`."""
    return [
        ev("content_in", "browser", "p-100", cls="clipboard_text", f=1, source_class="web", t=0),
        ev("exec", role, "p-7", cls="command_text", f=1, t=2, **kw),
    ]


@pytest.mark.parametrize(
    "role", ["launcher", "script_host", "scheduler", "other", "web_worker", "office"]
)
def test_pasted_external_command_is_a_contract_signal_for_any_role(role):
    assert "contract_external_exec" in names(run_events(pasted(role)))


def test_a_contract_that_allows_it_explicitly_raises_no_signal():
    policy = policy_with({"script_host": {"external_content_exec": "allow"}})
    assert "contract_external_exec" not in names(run_events(pasted("script_host"), policy))
    assert "contract_external_exec" in names(run_events(pasted("script_host")))  # not by default


def test_the_default_needs_the_executed_text_itself_to_carry_the_label():
    """A labeled process that runs something else is not external content run as a command: the
    wider rule (any exec by a labeled process) stays with the roles that say `deny`."""
    stream = [
        ev("request_in", "node_app_server", "p-1", f=1, source_class="inbound_request", t=0),
        ev("exec", "node_app_server", "p-1", cls="command_text", f=2, t=1, exec_class="build_tool"),
    ]
    assert "contract_external_exec" not in names(run_events(stream))
    shell = [
        ev("request_in", "interactive_shell", "p-1", f=1, source_class="inbound_request", t=0),
        ev("exec", "interactive_shell", "p-1", cls="command_text", f=2, t=1),
    ]
    assert "contract_external_exec" in names(run_events(shell))  # explicit deny: as before


def test_starting_an_external_file_stays_with_the_launcher_contract():
    stream = [
        ev(
            "content_in",
            "browser",
            "p-100",
            cls="executable_file",
            f=1,
            source_class="download",
            t=0,
        ),
        ev("exec", "launcher", "p-7", cls="executable_file", f=1, t=2, signed=True),
    ]
    assert "contract_external_exec" not in names(run_events(stream))


def test_a_pasted_command_through_a_launcher_now_reaches_block_with_a_contract_signal():
    stream = [
        *pasted("launcher"),
        ev(
            "net_connect", "script_host", "p-8", parent="p-7", f=3, t=3, destination_class="unknown"
        ),
    ]
    best = run_events(stream).best()
    assert best.decision is Decision.BLOCK and not best.gated


# -- F2: role-scoped trust of a destination class -----------------------------------------------------


def connect(role, labeled=True, dest="package_index"):
    stream = [ev("net_connect", role, "p-1", f=2, t=1, destination_class=dest)]
    if labeled:
        stream.insert(0, ev("request_in", role, "p-1", f=1, source_class="inbound_request", t=0))
    return stream


def test_a_labeled_process_connecting_to_a_class_its_contract_does_not_list_is_a_fetch():
    assert "effect_fetch" in names(run_events(connect("web_worker")))
    assert "effect_fetch" in names(run_events(connect("script_host")))  # no contract at all


def test_a_class_the_contract_lists_excuses_the_connection_labeled_or_not():
    assert "effect_fetch" not in names(run_events(connect("package_installer")))
    assert "effect_fetch" not in names(run_events(connect("web_worker", dest="db_server")))


def test_an_unlabeled_process_keeps_the_trust_of_the_class():
    assert "effect_fetch" not in names(run_events(connect("script_host", labeled=False)))
    assert "effect_fetch" in names(
        run_events(connect("script_host", labeled=False, dest="unknown"))
    )


# -- F3: evidence-carrying labels do not decay ---------------------------------------------------------


def violation_then_late_write(gap):
    return [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("exec", "web_worker", "p-1", f=2, t=1, exec_class="unknown"),  # may_exec is empty
        ev("file_write", "web_worker", "p-1", f=3, t=gap, path_group="cache"),
    ]


def test_a_label_behind_a_contract_violation_keeps_its_strength():
    pipe = run_events(violation_then_late_write(6 * 3600))
    [label] = [x for x in pipe.tagger.labels.values() if x.contract_evidence]
    assert "contract_web_worker_exec" in label.contract_evidence
    soon = T0 + timedelta(seconds=2)
    assert pipe.tagger.strength(label.label_id, T0 + timedelta(hours=24)) == pytest.approx(
        pipe.tagger.strength(label.label_id, soon)
    )
    assert pipe.tagger.strength(label.label_id, soon) > 0.99  # frozen where it stood, not restored


def test_a_label_without_evidence_still_decays():
    stream = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("file_write", "web_worker", "p-1", f=3, t=1, path_group="cache"),
    ]
    pipe = run_events(stream)
    assert not any(x.contract_evidence for x in pipe.tagger.labels.values())
    assert pipe.tagger.strength("L-1", T0 + timedelta(hours=6)) < 0.02


def test_a_label_that_has_already_faded_is_not_restored_by_a_late_violation():
    stream = [
        ev("request_in", "script_host", "p-1", f=1, source_class="inbound_request", t=0),
        ev("net_connect", "script_host", "p-1", f=2, t=4000, destination_class="unknown"),
    ]
    pipe = run_events(stream)  # the label is at 0.22 when the fetch happens: below the threshold
    assert not any(x.contract_evidence for x in pipe.tagger.labels.values())


def test_carried_evidence_applies_to_a_later_story_that_shows_the_same_label():
    """Without the freeze the label would have decayed before the second story."""
    pipe = run_events(violation_then_late_write(3600))  # an hour on: beyond the quiet window
    first, last = sorted(pipe.linker.records.values(), key=lambda r: r.last_ts)
    assert first.story.story_id != last.story.story_id
    j = pipe.judge(last)
    assert any(s.carried and s.name == "contract_web_worker_exec" for s in j.signals)
    assert j.failed["origin"] and j.failed["contract"]


# -- F3: the hour-scale window ----------------------------------------------------------------------------


def smallest_burst(lam, alpha):
    k = 1
    while poisson_tail(k, lam) >= alpha:
        k += 1
    return k


def test_a_slow_burst_that_never_fills_a_minute_adds_up_over_the_hour():
    policy = default_policy()
    short, long_ = policy.math.baseline_rate_default, policy.math.baseline_rate_long_default
    alpha = policy.math.poisson_alpha
    need = smallest_burst(long_, alpha)
    assert smallest_burst(short, alpha) < need  # a minute needs fewer: it is the faster test
    step = 3000.0 / need  # all of them within 50 minutes, a few seconds apart at most
    assert step > 60 / smallest_burst(short, alpha)  # never enough for one 60 s window
    writes = lambda n: [  # noqa: E731
        ev("file_write", "script_host", "p-1", f=100 + i, t=i * step, path_group="cache")
        for i in range(n)
    ]
    assert "effect_mass_change" not in names(run_events(writes(need - 1)))
    assert "effect_mass_change" in names(run_events(writes(need)))


def test_the_long_window_and_its_baseline_come_from_the_policy():
    policy = default_policy()
    assert policy.rates.long_window == 3600.0
    quiet = policy_with(rates={"long_window": "1m"}, math={"baseline_rate_long_default": 30.0})
    assert quiet.rates.long_window == 60.0


def test_repeated_oversized_responses_add_up_over_the_hour():
    policy = default_policy()
    need = smallest_burst(
        policy.math.baseline_rate_long["response_anomaly"], policy.math.poisson_alpha
    )

    def responses(n):
        return [
            ev("response_out", "web_worker", "p-1", f=7, t=i * 600.0, bytes=6_000_000)
            for i in range(n)
        ]

    assert "effect_response_anomaly_repeated" not in names(run_events(responses(need - 1)))
    assert "effect_response_anomaly_repeated" in names(run_events(responses(need)))


# -- F1: a hold with no labeled process pauses the processes that produced the signals ----------------


def typed_command():
    """S05 in miniature: nothing external behind it, so only the Effect question can fail."""
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


def test_a_hold_with_no_labeled_process_pauses_the_root_of_the_signal_producers():
    pipe, actions = gate_run(typed_command())
    assert pipe.best().decision is Decision.HOLD
    assert [(a.type, a.target.ref) for a in actions] == [(ActionType.HOLD, "p-1")]
    [case] = pipe.gate.holds.values()
    assert case.platform == "endpoint" and case.action_ids


def test_the_hold_is_not_extended_to_a_process_that_produced_nothing():
    stream = [*typed_command(), ev("exec", "other", "p-9", cls="command_text", f=9, t=4)]
    _, actions = gate_run(stream)
    assert {a.target.ref for a in actions} <= {"p-1", "p-2"}


def test_a_story_that_has_a_labeled_process_never_touches_an_unlabeled_one():
    """An unlabeled process in the same story that also produced a signal is left alone."""
    stream = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("net_connect", "web_worker", "p-1", f=2, t=1, destination_class="unknown"),
        # the same object, so the same story, but no label on this process
        ev("net_connect", "script_host", "p-5", f=2, t=2, destination_class="unknown"),
    ]
    pipe, actions = gate_run(stream)
    assert len(pipe.linker.records) == 1
    touched = {a.target.ref for a in actions if a.target.kind.value == "process"}
    assert touched == {"p-1"}


def test_continue_releases_the_processes_the_fallback_paused():
    pipe, actions = gate_run(typed_command())
    [case] = pipe.gate.holds.values()
    res = pipe.gate.answer_user(case.hold_id, "continue", case.started)
    assert res.undo == [a.action_id for a in actions]


# -- the evaluation scripts measure what the library measures ----------------------------------------


def test_the_comparison_scripts_classify_variants_like_the_library(tmp_path):
    import json
    import sys

    from refmon import variants as v
    from refmon.golden import load_golden_cases
    from scenario_run import GOLDEN_DIR, ROOT

    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import compare_versions as cv
        import dump_matrix as dm
        import generate_variants as gv
    finally:
        sys.path.pop(0)
    policy = default_policy()
    variants = tmp_path / "variants.jsonl"
    dump = tmp_path / "dump.jsonl"
    gv.main(["--golden", str(GOLDEN_DIR), "--seed", "7", "--out", str(variants)])
    dm.main(["--variants", str(variants), "--out", str(dump)])
    rows = {
        (r["scenario"], r["variant"]): r for r in map(json.loads, dump.read_text().splitlines())
    }
    sample = v.generate(load_golden_cases(GOLDEN_DIR), policy, seed=7)[::17]
    assert len(sample) > 30
    for variant in sample:
        result = v.run(variant, policy)
        row = rows[(variant.scenario, variant.name)]
        assert row["decision"] == result.decision.value
        assert row["actions"] == result.actions
        assert row["params"] == variant.params
        assert cv.outcome(row).replace(" ", "_") == result.outcome
    report = cv.report({"a": cv.load(str(dump)), "b": cv.load(str(dump))})
    assert "identical event streams" in report and "changed, a to b: 0" in report
