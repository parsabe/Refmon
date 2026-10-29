from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from refmon.schemas import Story

T0 = datetime(2026, 10, 28, 10, 2, 15, tzinfo=UTC)


def story(**overrides) -> dict:
    data = {"story_id": "st-1", "device": "dev-7f3a", "opened_at": T0, "last_event_at": T0}
    data.update(overrides)
    return data


def test_story_can_grow_while_open():
    parsed = Story.model_validate(story())
    parsed.event_ids.append("e-1")
    parsed.last_event_at = T0 + timedelta(seconds=3)
    assert parsed.last_event_at > parsed.opened_at


def test_story_rejects_time_going_backwards():
    with pytest.raises(ValidationError):
        Story.model_validate(story(last_event_at=T0 - timedelta(seconds=1)))
    parsed = Story.model_validate(story())
    with pytest.raises(ValidationError):
        parsed.last_event_at = T0 - timedelta(seconds=1)


@pytest.mark.parametrize("name", ["event_ids", "label_ids", "process_ids"])
def test_story_rejects_duplicate_ids(name):
    with pytest.raises(ValidationError):
        Story.model_validate(story(**{name: ["x-1", "x-1"]}))


def test_story_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        Story.model_validate(story(verdict="block"))
