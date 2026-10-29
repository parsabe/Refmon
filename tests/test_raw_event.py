"""RawEvent is the pre-Observe form: it may carry content, the stored form (Event) never may."""

import json

import pytest
from pydantic import ValidationError

from refmon.schemas import Event, RawEvent

FP = "hmac:" + "9c1e5a7d40b2f813" * 4


def raw(**overrides) -> dict:
    data = {
        "event_id": "e-1",
        "ts": "2026-10-28T10:02:15.120Z",
        "device": "dev-7f3a",
        "type": "content_in",
        "actor": {"id": "p-100", "role": "browser", "interactive": True, "user": "alice"},
        "object": {"class": "clipboard_text", "content": "echo harmless stand-in"},
        "attrs": {"source_class": "web", "domain": "lure.example.net"},
    }
    data.update(overrides)
    return data


def test_raw_event_may_carry_content_and_a_domain():
    event = RawEvent.model_validate(raw())
    assert event.object.content == "echo harmless stand-in"
    assert event.attrs["domain"] == "lure.example.net"


def test_the_stored_form_rejects_both():
    with pytest.raises(ValidationError):
        Event.model_validate(raw())  # content is not a field of ObjectRef
    with pytest.raises(ValidationError):
        Event.model_validate(
            raw(object={"class": "clipboard_text", "fingerprint": FP})
        )  # domain is not an allowed Event key


def test_content_and_fingerprint_are_mutually_exclusive():
    with pytest.raises(ValidationError):
        RawEvent.model_validate(raw(object={"class": "x", "content": "abc", "fingerprint": FP}))


def test_every_observed_event_line_is_also_a_valid_raw_event():
    observed = raw(object={"class": "clipboard_text", "fingerprint": FP}, attrs={})
    line = json.dumps(observed)
    assert RawEvent.model_validate_json(line).object.fingerprint == FP
    assert Event.model_validate_json(line).object.fingerprint == FP


def test_raw_event_still_checks_structure():
    with pytest.raises(ValidationError):
        RawEvent.model_validate(raw(attrs={"source_class": "carrier_pigeon"}))
    with pytest.raises(ValidationError):
        RawEvent.model_validate(raw(ts="2026-10-28T10:02:15"))  # naive
    with pytest.raises(ValidationError):
        RawEvent.model_validate(raw(attrs={"note": "x" * 257}))
    with pytest.raises(ValidationError):
        RawEvent.model_validate(raw(extra=1))


def test_raw_event_round_trips_through_a_json_line():
    event = RawEvent.model_validate(raw())
    assert RawEvent.from_json_line(event.to_json_line()) == event
    assert json.loads(event.to_json_line())["object"]["class"] == "clipboard_text"


def test_raw_event_checks_signed_the_same_way():
    for value in (True, False, "unknown"):
        assert RawEvent.model_validate(raw(attrs={"signed": value})).attrs["signed"] == value
    with pytest.raises(ValidationError, match="signed"):
        RawEvent.model_validate(raw(attrs={"signed": "maybe"}))
