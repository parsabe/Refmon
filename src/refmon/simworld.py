"""A small model of the world a Contain action acts on, for the SimulatedEnforcer (Phase 3).

It holds processes (running, paused, killed), per-process network cuts, files (where they are and
which version), persistence items and the host isolation flag. Files and persistence items are known
only by the fingerprint of their path, as everywhere in the core. `from_events` builds the world a
replay file implies: every actor exists, a written file exists (and had a known-good version unless
the event says it was new), every persistence item is active.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field

from .schemas import Action, ActionType, Event, EventType


@dataclass
class FileState:
    location: str = "origin"  # origin | quarantine
    version: str = "modified"  # new (created by the attacker) | modified | known_good
    has_baseline: bool = True  # a known-good copy exists to restore from


@dataclass
class SimWorld:
    parents: dict[str, str | None] = field(default_factory=dict)
    process: dict[str, str] = field(default_factory=dict)  # running | paused | killed
    network_cut: set[str] = field(default_factory=set)
    files: dict[str, FileState] = field(default_factory=dict)
    persistence: dict[str, str] = field(default_factory=dict)  # active | reverted
    isolated: bool = False

    @classmethod
    def from_events(cls, events: list[Event]) -> SimWorld:
        world = cls()
        for ev in events:
            pid = ev.actor.id
            world.parents.setdefault(pid, ev.actor.parent)
            world.process.setdefault(pid, "running")
            fp = ev.object.fingerprint
            if ev.type is EventType.FILE_WRITE and fp is not None:
                new = ev.attrs.get("new_file") is True
                world.files.setdefault(
                    fp, FileState(version="new" if new else "modified", has_baseline=not new)
                )
            elif ev.type is EventType.PERSIST and fp is not None:
                world.persistence.setdefault(fp, "active")
        return world

    def snapshot(self) -> SimWorld:
        return copy.deepcopy(self)

    def tree(self, pid: str) -> list[str]:
        out, grew = [pid], True
        while grew:
            grew = False
            for child, parent in self.parents.items():
                if parent in out and child not in out:
                    out.append(child)
                    grew = True
        return out

    # -- applying and reversing an action ---------------------------------------------------------

    def apply(self, action: Action) -> tuple[str, object | None]:
        """Apply `action`. Returns (detail, prior) where prior is what `revert` needs."""
        ref, kind = action.target.ref, action.type
        if kind in (ActionType.HOLD, ActionType.BLOCK, ActionType.KILL_PROCESS_TREE):
            if ref not in self.process:
                return "no_such_target", None
            if kind is ActionType.KILL_PROCESS_TREE:
                tree = self.tree(ref)
                prior = {p: self.process[p] for p in tree if p in self.process}
                for pid in tree:
                    self.process[pid] = "killed"
                return "applied", prior
            prior = self.process[ref]
            if prior == "killed":
                return "already_killed", None
            self.process[ref] = "paused" if kind is ActionType.HOLD else "killed"
            return "applied", prior
        if kind is ActionType.CUT_NETWORK:
            if ref not in self.process:
                return "no_such_target", None
            self.network_cut.add(ref)
            return "applied", None
        if kind in (ActionType.QUARANTINE_FILE, ActionType.RESTORE_FILE):
            state = self.files.get(ref)
            if state is None:
                return "no_such_target", None
            prior = copy.copy(state)
            if kind is ActionType.QUARANTINE_FILE:
                if state.location == "quarantine":
                    return "already_quarantined", None
                state.location = "quarantine"  # moved, never deleted
            else:
                if not state.has_baseline:
                    return "no_known_good", None
                state.version = "known_good"
            return "applied", prior
        if kind is ActionType.REVERT_PERSISTENCE:
            if ref not in self.persistence:
                return "no_such_target", None
            prior = self.persistence[ref]
            self.persistence[ref] = "reverted"
            return "applied", prior
        if kind is ActionType.ISOLATE_HOST:
            prior = self.isolated
            self.isolated = True
            return "applied", prior
        return "unsupported", None  # pragma: no cover

    def revert(self, action: Action, prior: object | None) -> None:
        ref, kind = action.target.ref, action.type
        if kind is ActionType.HOLD:
            self.process[ref] = str(prior)
        elif kind is ActionType.CUT_NETWORK:
            self.network_cut.discard(ref)
        elif kind in (ActionType.QUARANTINE_FILE, ActionType.RESTORE_FILE):
            self.files[ref] = prior  # type: ignore[assignment]
        elif kind is ActionType.REVERT_PERSISTENCE:
            self.persistence[ref] = str(prior)
        elif kind is ActionType.ISOLATE_HOST:
            self.isolated = bool(prior)
