"""The seams between the platform-independent core and everything platform-specific (C1)."""

from collections.abc import Callable
from typing import Protocol

from .schemas import Action, ActionResult, Event, RawEvent, Verdict

# A sensor emits what the platform saw (RawEvent, content in memory only). Replay files of
# already-observed events are Events. The core's Observe stage accepts both.
type AnyEvent = Event | RawEvent


class Sensor(Protocol):
    """Turns platform signals into normalized events and pushes each one to `sink`."""

    def emit(self, sink: Callable[[AnyEvent], None]) -> None: ...


class Enforcer(Protocol):
    """Carries out an Action on the platform and reports what happened."""

    def act(self, action: Action) -> ActionResult: ...


class Core(Protocol):
    """Observe, Tag, Link, Judge, Gate, Contain, Report, Tune behind one call."""

    def process(self, event: AnyEvent) -> list[Verdict | Action]: ...
