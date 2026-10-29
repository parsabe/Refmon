import json

import pytest

from refmon.replay import RawReplaySource, ReplayError, ReplaySource
from refmon.schemas import Event

FP = "hmac:" + "ab" * 16


def event(n: int, ts: str = "2026-10-28T10:00:00Z", role: str = "web_worker") -> dict:
    return {
        "event_id": f"e-{n}",
        "ts": ts,
        "device": "dev-1",
        "type": "request_in",
        "actor": {"id": "p-1", "role": role, "interactive": False, "user": "svc"},
        "object": {"class": "request_body", "fingerprint": FP},
        "attrs": {"source_class": "inbound_request"},
    }


def write(tmp_path, *lines: str):
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(lines) + "\n")
    return path


def test_reads_events_in_order(tmp_path):
    path = write(
        tmp_path,
        json.dumps(event(1)),
        json.dumps(event(2, "2026-10-28T10:00:01Z")),
    )
    events = list(ReplaySource(path))
    assert [e.event_id for e in events] == ["e-1", "e-2"]
    assert all(isinstance(e, Event) for e in events)


def test_blank_lines_are_skipped_and_source_can_be_read_twice(tmp_path):
    path = write(tmp_path, json.dumps(event(1)), "", "   ", json.dumps(event(2)))
    source = ReplaySource(path)
    assert len(list(source)) == len(list(source)) == 2


def test_emit_pushes_every_event_to_the_sink(tmp_path):
    path = write(tmp_path, json.dumps(event(1)), json.dumps(event(2)))
    seen: list[Event] = []
    ReplaySource(path).emit(seen.append)
    assert [e.event_id for e in seen] == ["e-1", "e-2"]


def test_error_names_file_and_line(tmp_path):
    path = write(tmp_path, json.dumps(event(1)), json.dumps(event(2) | {"type": "teleport"}))
    with pytest.raises(ReplayError) as info:
        list(ReplaySource(path))
    assert info.value.line_no == 2
    assert info.value.path == path
    assert f"{path}:2:" in str(info.value)


def test_malformed_json_is_a_replay_error(tmp_path):
    path = write(tmp_path, "{not json")
    with pytest.raises(ReplayError) as info:
        list(ReplaySource(path))
    assert info.value.line_no == 1


def test_duplicate_event_id_is_rejected(tmp_path):
    path = write(tmp_path, json.dumps(event(1)), json.dumps(event(1, "2026-10-28T10:00:01Z")))
    with pytest.raises(ReplayError, match="duplicate event_id e-1"):
        list(ReplaySource(path))


def test_timestamps_must_not_go_backwards(tmp_path):
    path = write(
        tmp_path,
        json.dumps(event(1, "2026-10-28T10:00:05Z")),
        json.dumps(event(2, "2026-10-28T10:00:04Z")),
    )
    with pytest.raises(ReplayError, match="backwards"):
        list(ReplaySource(path))


def test_equal_timestamps_are_fine(tmp_path):
    path = write(tmp_path, json.dumps(event(1)), json.dumps(event(2)))
    assert len(list(ReplaySource(path))) == 2


def test_extra_roles_are_passed_through(tmp_path):
    path = write(tmp_path, json.dumps(event(1, role="build_agent")))
    with pytest.raises(ReplayError):
        list(ReplaySource(path))
    assert len(list(ReplaySource(path, extra_roles=["build_agent"]))) == 1


def test_raw_replay_reads_lab_fixtures_that_the_observed_form_rejects(tmp_path):
    line = json.dumps(
        {
            "event_id": "e-1",
            "ts": "2026-10-28T10:00:00Z",
            "device": "dev-1",
            "type": "content_in",
            "actor": {"id": "p-1", "role": "browser", "interactive": True, "user": "u"},
            "object": {"class": "clipboard_text", "content": "echo harmless stand-in"},
            "attrs": {"source_class": "web", "domain": "lure.example.net"},
        }
    )
    path = write(tmp_path, line)
    [raw] = list(RawReplaySource(path))
    assert raw.object.content == "echo harmless stand-in"
    with pytest.raises(ReplayError):
        list(ReplaySource(path))


def test_raw_replay_has_the_same_ordering_rules(tmp_path):
    path = write(
        tmp_path,
        json.dumps(event(1, "2026-10-28T10:00:05Z")),
        json.dumps(event(2, "2026-10-28T10:00:04Z")),
    )
    with pytest.raises(ReplayError, match="backwards"):
        list(RawReplaySource(path))
