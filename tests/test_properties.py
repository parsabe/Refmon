"""Property tests (CLAUDE.md Phase 1): labels are never lost along process chains, no raw content in
any output, and an event a contract allows never counts as a Contract fail."""

from hypothesis import given, settings
from hypothesis import strategies as st

from evhelp import ev, raw
from refmon.pipeline import Pipeline
from refmon.policy import default_policy
from scenario_run import run_events

# A marker keeps a random word from colliding with a field name such as "contract".
words = st.text(
    alphabet=st.characters(min_codepoint=97, max_codepoint=122), min_size=8, max_size=24
).map(lambda w: f"zx9{w}")


@settings(max_examples=60, deadline=None)
@given(
    depth=st.integers(min_value=1, max_value=12),
    spawn_roles=st.lists(
        st.sampled_from(["script_host", "other", "interactive_shell"]), min_size=12, max_size=12
    ),
)
def test_labels_are_never_lost_along_a_process_chain(depth, spawn_roles):
    events = [ev("request_in", "web_worker", "p-0", f=1, source_class="inbound_request", t=0)]
    for i in range(1, depth + 1):
        events.append(ev("exec", spawn_roles[i - 1], f"p-{i}", parent=f"p-{i - 1}", t=i))
    p = run_events(events)
    root = p.tagger.procs["p-0"].labels
    assert root
    for i in range(1, depth + 1):
        assert root <= p.tagger.procs[f"p-{i}"].labels


@settings(max_examples=60, deadline=None)
@given(secret=words, host=words, path=words, program=words)
def test_no_raw_content_in_any_output(secret, host, path, program):
    p = Pipeline(default_policy())
    outputs = []
    for e in [
        raw(
            "content_in",
            "browser",
            "p-1",
            content=secret,
            source_class="web",
            domain=f"{host}.example",
        ),
        raw("exec", "interactive_shell", "p-2", content=secret, program=program, t=1),
        raw(
            "net_connect",
            "script_host",
            "p-3",
            parent="p-2",
            content=secret,
            host=f"{host}.example",
            ip="203.0.113.5",
            t=2,
        ),
        raw(
            "request_in",
            "web_worker",
            "p-4",
            content=secret,
            url_path=f"/{path}",
            source_class="inbound_request",
            t=3,
        ),
    ]:
        outputs.extend(p.process(e))
    rendered = " ".join(o.model_dump_json() for o in outputs) + " ".join(
        e.to_json_line() for e in p.observe.buffer
    )
    rendered += " ".join(rec.story.model_dump_json() for rec in p.linker.records.values())
    rendered += " ".join(lbl.model_dump_json() for lbl in p.tagger.labels.values())
    for needle in (secret, host, path, program):
        assert needle not in rendered


@settings(max_examples=60, deadline=None)
@given(
    group=st.sampled_from(["cache", "sessions", "uploads_non_executable"]),
    dest=st.sampled_from(["db_server", "cache_server"]),
)
def test_an_event_a_contract_allows_never_counts_as_a_contract_fail(group, dest):
    events = [
        ev("request_in", "web_worker", "p-1", f=1, source_class="inbound_request", t=0),
        ev("file_write", "web_worker", "p-1", f=2, t=1, path_group=group),
        ev("net_connect", "web_worker", "p-1", f=3, t=2, destination_class=dest),
    ]
    p = run_events(events)
    [j] = p.judgements().values()
    assert not j.failed["contract"]
