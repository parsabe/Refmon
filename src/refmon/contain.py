"""Contain: what to do to the objects of a story (CLAUDE.md Phase 3).

Every step acts on a *labeled* object only: a process that carries a live external label, or a
file or persistence item written by one. Nothing is ever deleted (files are moved to quarantine)
and every action has an undo record (a killed process stays killed). `plan` only decides; the Gate
turns the steps into Actions and the Enforcer carries them out.

block:           kill the process tree of each labeled root, cut the network of each labeled
                 process that connected out, quarantine the new files, revert the persistence
                 items they wrote, restore changed files from the known-good baseline, and
                 isolate the host when the story shows lateral movement.
hold, endpoint:  pause the labeled roots.
hold, server:    pause the labeled roots and quarantine the new files they wrote.

v1.1 (A47), v1.2 (A51, A52): when no process of the story is labeled, a hold pauses the processes
that produced the story's signals or raised its override instead, and so does a block when the
story also has no external origin label (nothing else could say what to act on): the roots of their
trees and their new files, network, persistence and changed files. This is the only case in which
a process without a label is touched, and it never reaches the channel roles (browser, mail,
launcher): a file manager or run dialog that only started the command is not part of the attack. A
story with a labeled process is handled as before.

v1.6 (A63): a block falls back to the producers whenever no process of the story is labeled, also
when the story has an external origin label; in that case it still spares the user's interactive
shell, which ran the external text but is the user's session (its labeled children are killed when
they appear, as before). Until v1.5 such a block acted on no producer at all, waiting for a labeled
child that never appears when the label sits on content only a channel role touched (channel roles
never carry labels): a hold that timed out into a block then acted on nothing (F11).

v2.0 (A66): a channel role relays, it does not act. When a producer of the story's signals is a
channel role that ran an exec in the story, the fallback reaches the programs that producer started
inside the story (its children among the story's processes, with their trees) instead of reaching
nobody; a channel role that acted itself (connected, wrote) without starting anything leaves its
other children alone. Until v1.7 a
hold whose only producer was a channel role (a run dialog that ran an obfuscated command whose
program then did the rest) paused nothing. The channel role itself is still never touched, and the
user's interactive shell is still spared where A63 spares it.
"""

from __future__ import annotations

from dataclasses import dataclass

from .pipeline.link import StoryRecord
from .pipeline.tag import Tagger
from .schemas import ActionType, Effect, EventType, Target, TargetKind


@dataclass(frozen=True)
class Step:
    type: ActionType
    target: Target

    @property
    def key(self) -> tuple[str, str]:
        return self.type.value, self.target.ref


def _process(pid: str) -> Target:
    return Target(kind=TargetKind.PROCESS, ref=pid)


def _file(fp: str) -> Target:
    return Target(kind=TargetKind.FILE, ref=fp)


class Contain:
    def __init__(self, tagger: Tagger) -> None:
        self.tagger = tagger

    def labeled_processes(self, rec: StoryRecord) -> list[str]:
        ts = rec.last_ts
        return [
            pid
            for pid in rec.story.process_ids
            if pid in self.tagger.procs and self.tagger.alive(self.tagger.procs[pid].ever, ts)
        ]

    def has_origin_label(self, rec: StoryRecord) -> bool:
        thr = self.tagger.policy.thresholds.origin_strength
        return any(self.tagger.strength(i, rec.last_ts) >= thr for i in rec.label_ids)

    def fallback(
        self, rec: StoryRecord, producers: tuple[str, ...], spare_session: bool = False
    ) -> list[str]:
        """The producers that may be touched when nothing is labeled: not a channel role, and
        with `spare_session` not the user's interactive shell (A63)."""
        procs = self.tagger.procs
        known = [p for p in rec.story.process_ids if p in procs]
        relays = set(self.tagger.policy.non_carrier_roles)
        spared = relays | ({"interactive_shell"} if spare_session else set())
        started = {e.actor.id for e in rec.events if e.type is EventType.EXEC}
        out: list[str] = []
        for p in producers:
            if p not in procs or p not in known:
                continue
            if procs[p].role in relays:
                if p in started:  # v2.0 (A66): the programs the relay started act, not the relay
                    out += [
                        c for c in known if procs[c].parent == p and procs[c].role not in spared
                    ]
            elif procs[p].role not in spared:
                out.append(p)
        return list(dict.fromkeys(out))

    def roots(self, rec: StoryRecord, within: list[str] | None = None) -> list[str]:
        members = self.labeled_processes(rec) if within is None else within
        inside = set(members)
        return [p for p in members if self.tagger.procs[p].parent not in inside]

    def plan(
        self,
        rec: StoryRecord,
        kind: str,
        effects: tuple[Effect, ...] = (),
        producers: tuple[str, ...] = (),
    ) -> list[Step]:
        """kind: "block", "hold_endpoint" or "hold_server".

        `producers` are the processes that produced the story's signals or raised its override
        (`signal_processes`); when no process of the story is labeled the plan falls back to them.
        """
        members = self.labeled_processes(rec)
        if not members:  # v1.6 (A63): a labeled block falls back too, sparing the user's shell
            spare = kind == "block" and self.has_origin_label(rec)
            members = self.fallback(rec, producers, spare_session=spare)
        roots = self.roots(rec, members)
        labeled = set(members)
        steps: list[Step] = []
        if kind == "block":
            steps += [Step(ActionType.KILL_PROCESS_TREE, _process(p)) for p in roots]
            connected = {e.actor.id for e in rec.events if e.type is EventType.NET_CONNECT}
            steps += [Step(ActionType.CUT_NETWORK, _process(p)) for p in members if p in connected]
        else:
            steps += [Step(ActionType.HOLD, _process(p)) for p in roots]
        for ev in rec.events:
            fp = ev.object.fingerprint
            if ev.actor.id not in labeled or fp is None:
                continue
            if ev.type is EventType.FILE_WRITE:
                new = ev.attrs.get("new_file") is True
                if new and kind != "hold_endpoint":
                    steps.append(Step(ActionType.QUARANTINE_FILE, _file(fp)))
                elif not new and kind == "block":
                    steps.append(Step(ActionType.RESTORE_FILE, _file(fp)))
            elif ev.type is EventType.PERSIST and kind == "block":
                steps.append(
                    Step(
                        ActionType.REVERT_PERSISTENCE,
                        Target(kind=TargetKind.PERSISTENCE_ITEM, ref=fp),
                    )
                )
        if kind == "block" and Effect.LATERAL in effects:
            steps.append(
                Step(ActionType.ISOLATE_HOST, Target(kind=TargetKind.HOST, ref=rec.story.device))
            )
        return list(dict.fromkeys(steps))


def signal_processes(rec: StoryRecord, signals) -> tuple[str, ...]:
    """The processes whose events produced the given signals or raised an override flag, in the
    order the story saw them."""
    actor = {e.event_id: e.actor.id for e in rec.events}
    produced = {actor[s.event_id] for s in signals if s.event_id in actor} | rec.flag_processes
    return tuple(p for p in rec.story.process_ids if p in produced)
