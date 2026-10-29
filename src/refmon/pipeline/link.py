"""Link: group related events into stories (CLAUDE.md Part A "story").

Events join the same story when they share a key (an acting process, a spawning parent that has
appeared before, an object fingerprint, or a label) and the story saw an event within the quiet
window. A persistent label keeps its labeled item recognisable beyond the window, but a later run
of that item starts a new story: it carries the old story's Contract evidence (D21), not its events.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..policy import Policy
from ..schemas import Event, Story
from .signals import Signal
from .tag import Tagged, Tagger


@dataclass
class StoryRecord:
    story: Story
    events: list[Event] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    label_ids: set[str] = field(default_factory=set)
    flags: set[str] = field(default_factory=set)  # override flags raised by events
    flag_processes: set[str] = field(default_factory=set)  # processes whose events raised a flag
    trusted: bool = False
    keys: set[str] = field(default_factory=set)
    emitted: tuple | None = None
    verdict_id: str | None = None  # the latest verdict emitted for this story

    @property
    def last_ts(self):
        return self.story.last_event_at


class Linker:
    def __init__(self, policy: Policy, tagger: Tagger) -> None:
        self.policy = policy
        self.tagger = tagger
        self.records: dict[str, StoryRecord] = {}
        self._by_key: dict[str, str] = {}
        self._counter = 0

    def keys_for(self, tg: Tagged, parent_known: bool) -> set[str]:
        ev = tg.event
        keys = set()
        if ev.actor.role not in self.policy.non_process_keyed_roles:
            keys.add(f"p:{ev.actor.id}")
        if ev.actor.parent and parent_known:
            keys.add(f"p:{ev.actor.parent}")
        if ev.object.fingerprint and ev.object.class_ != "network_endpoint":
            keys.add(f"f:{ev.object.fingerprint}")
        for lid in (*tg.actor_labels, *tg.object_labels, *tg.new_labels):
            keys.add(f"l:{lid}")
        return keys

    def assign(self, tg: Tagged, parent_known: bool, signals, flags) -> StoryRecord:
        ev = tg.event
        window = self.policy.thresholds.story_quiet_window
        keys = self.keys_for(tg, parent_known)
        open_ids = []
        for k in keys:
            sid = self._by_key.get(k)
            if sid is None:
                continue
            rec = self.records[sid]
            if (ev.ts - rec.last_ts).total_seconds() <= window and sid not in open_ids:
                open_ids.append(sid)
        if open_ids:
            rec = self.records[open_ids[0]]
            for other in open_ids[1:]:
                self._merge(rec, self.records.pop(other))
        else:
            self._counter += 1
            rec = StoryRecord(
                Story(
                    story_id=f"st-{self._counter}",
                    device=ev.device,
                    opened_at=ev.ts,
                    last_event_at=ev.ts,
                )
            )
            self.records[rec.story.story_id] = rec
        rec.events.append(ev)
        rec.signals.extend(signals)
        rec.flags |= flags
        if flags:
            rec.flag_processes.add(ev.actor.id)
        rec.trusted |= tg.trusted
        rec.label_ids |= {*tg.actor_labels, *tg.object_labels, *tg.new_labels}
        rec.keys |= keys
        story = rec.story
        story.last_event_at = max(story.last_event_at, ev.ts)
        story.event_ids.append(ev.event_id)
        story.label_ids = sorted(rec.label_ids)
        if ev.actor.id not in story.process_ids:
            story.process_ids.append(ev.actor.id)
        for k in keys:
            self._by_key[k] = story.story_id
        return rec

    def _merge(self, into: StoryRecord, other: StoryRecord) -> None:
        into.events.extend(other.events)
        into.events.sort(key=lambda e: e.ts)
        into.signals.extend(other.signals)
        into.label_ids |= other.label_ids
        into.flags |= other.flags
        into.flag_processes |= other.flag_processes
        into.trusted |= other.trusted
        into.keys |= other.keys
        s, o = into.story, other.story
        s.opened_at = min(s.opened_at, o.opened_at)
        s.event_ids = [e.event_id for e in into.events]
        s.process_ids = list(dict.fromkeys([*s.process_ids, *o.process_ids]))
        for k in other.keys:
            self._by_key[k] = s.story_id
