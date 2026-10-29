"""Tiny event factories for unit tests."""

from datetime import UTC, datetime, timedelta

from refmon.policy import default_policy
from refmon.schemas import Event, RawEvent

T0 = datetime(2026, 10, 28, 10, 0, 0, tzinfo=UTC)
ROLES = tuple(default_policy().extra_roles)


def fp(n: int) -> str:
    return "hmac:" + f"{n:064x}"


def _actor(role, pid, parent, user="u"):
    a = {"id": pid, "role": role, "interactive": False, "user": user}
    if parent:
        a["parent"] = parent
    return a


class Counter:
    def __init__(self) -> None:
        self.n = 0

    def next(self) -> str:
        self.n += 1
        return f"e-{self.n:06d}"


_ids = Counter()


def ev(type_, role, pid, *, cls="x", f=None, parent=None, t=0.0, **attrs) -> Event:
    obj = {"class": cls}
    if f is not None:
        obj["fingerprint"] = fp(f)
    return Event.model_validate(
        {"event_id": _ids.next(), "ts": T0 + timedelta(seconds=t), "device": "dev-1", "type": type_,
         "actor": _actor(role, pid, parent), "object": obj, "attrs": attrs},
        context={"extra_roles": ROLES},
    )  # fmt: skip


def raw(
    type_, role, pid, *, cls="x", content=None, f=None, parent=None, t=0.0, **attrs
) -> RawEvent:
    obj = {"class": cls}
    if content is not None:
        obj["content"] = content
    if f is not None:
        obj["fingerprint"] = fp(f)
    return RawEvent.model_validate(
        {"event_id": _ids.next(), "ts": T0 + timedelta(seconds=t), "device": "dev-1", "type": type_,
         "actor": _actor(role, pid, parent), "object": obj, "attrs": attrs},
        context={"extra_roles": ROLES},
    )  # fmt: skip
