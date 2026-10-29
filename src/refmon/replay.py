"""Replay sources: JSON Lines file -> validated events. Every behaviour is testable through replay.

`ReplaySource` reads the post-Observe `Event` form, the only form that may be recorded.
`RawReplaySource` reads `RawEvent` lab fixtures made of harmless stand-in content, so that Observe
itself can be tested.
"""

from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from pydantic import ValidationError

from .schemas import Event, RawEvent


class ReplayError(ValueError):
    def __init__(self, path: Path, line_no: int, message: str) -> None:
        super().__init__(f"{path}:{line_no}: {message}")
        self.path = path
        self.line_no = line_no


class _Replay[M: (Event, RawEvent)]:
    """A Sensor that reads events from a JSON Lines file.

    Besides schema validity, a replay file must have unique event ids and non-decreasing
    timestamps, so a stream always reaches the core in the order it happened.
    """

    model: type[M]

    def __init__(self, path: Path | str, *, extra_roles: Iterable[str] = ()) -> None:
        self.path = Path(path)
        self._context = {"extra_roles": tuple(extra_roles)}

    def __iter__(self) -> Iterator[M]:
        seen: set[str] = set()
        previous = None
        with self.path.open(encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    event = self.model.model_validate_json(line, context=self._context)
                except ValidationError as error:
                    raise ReplayError(self.path, line_no, _first_error(error)) from error
                if event.event_id in seen:
                    raise ReplayError(self.path, line_no, f"duplicate event_id {event.event_id}")
                if previous is not None and event.ts < previous:
                    raise ReplayError(self.path, line_no, "timestamp goes backwards")
                seen.add(event.event_id)
                previous = event.ts
                yield event

    def emit(self, sink: Callable[[M], None]) -> None:
        for event in self:
            sink(event)


class ReplaySource(_Replay[Event]):
    model = Event


class RawReplaySource(_Replay[RawEvent]):
    model = RawEvent


def _first_error(error: ValidationError) -> str:
    first = error.errors(include_url=False, include_input=False)[0]
    location = ".".join(str(part) for part in first["loc"])
    return f"{location}: {first['msg']}" if location else first["msg"]
