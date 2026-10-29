"""Helpers for writing golden event streams: stand-in fingerprints, actors, a numbered stream.

Everything is a harmless stand-in: fingerprints are HMACs of placeholder labels such as
"s01.clipboard", never of a real command, request or payload.
"""

import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from pathlib import Path

from refmon.policy import default_policy
from refmon.schemas import Event

GOLDEN_DIR = Path(__file__).parent / "golden"
LAB_KEY = b"refmon-lab-only-test-key"
START = datetime(2026, 10, 28, 10, 2, 15, 120000, tzinfo=UTC)

ENDPOINT = "dev-7f3a"
SERVER = "dev-b21c"
EXTRA_ROLES = tuple(default_policy().extra_roles)


def fp(label: str) -> str:
    digest = hmac.new(LAB_KEY, f"standin:{label}".encode(), hashlib.sha256).hexdigest()
    return f"hmac:{digest}"


def actor(pid, role, user, parent=None, interactive=False):
    return {"id": pid, "parent": parent, "role": role, "interactive": interactive, "user": user}


class Stream:
    """Numbers events e-000001.. and spaces them in time."""

    def __init__(self, device: str):
        self.device = device
        self.events: list[Event] = []
        self._clock = START

    def add(self, ms_later: int, type_: str, who: dict, obj_class: str, label: str | None, **attrs):
        self._clock += timedelta(milliseconds=ms_later)
        obj = {"class": obj_class}
        if label is not None:
            obj["fingerprint"] = fp(label)
        event = Event.model_validate(
            {
                "event_id": f"e-{len(self.events) + 1:06d}",
                "ts": self._clock,
                "device": self.device,
                "type": type_,
                "actor": {k: v for k, v in who.items() if v is not None},
                "object": obj,
                "attrs": attrs,
            },
            context={"extra_roles": EXTRA_ROLES},
        )
        self.events.append(event)
        return event.event_id
