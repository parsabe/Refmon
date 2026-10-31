"""Gate: turns a judged story into actions, with the mode downgrade and the two hold flows
(CLAUDE.md Phase 3).

Mode downgrade: `observe` never acts (the verdict is logged and nothing else happens), `warn` never
blocks (the user or admin is told and nothing is paused, killed, moved or cut), `block` acts.

Endpoint hold: pause the labeled processes, ask the user in plain language, no answer in time means
stop (deny), and "continue" is not offered when all three questions failed. Stopping contains the
story like a block. When no process is labeled, a hold pauses and a block acts on the processes that
produced the story's signals instead, never a channel role (v1.1 A47, v1.2 A51 and A52).

Server hold: pause the labeled workers and quarantine the new files they wrote, notify the admin,
and when no admin answers the story simply stays quarantined (`server_hold_timeout:
keep_quarantined`): nothing is released and nothing is killed until a person decides.

A story that has been blocked stays blocked; later events add containment for newly labeled
objects, and no action is issued twice.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol

from .contain import Contain, Step, signal_processes
from .pipeline.judge import Judgement
from .pipeline.link import StoryRecord
from .pipeline.tag import Tagger
from .policy import Policy
from .schemas import Action, AdminNotice, Decision, Mode, UserPrompt


class Notifier(Protocol):
    def ask_user(self, prompt: UserPrompt) -> None: ...
    def notify_admin(self, notice: AdminNotice) -> None: ...


class RecordingNotifier:
    """Keeps what was said, for tests and for the local log."""

    def __init__(self) -> None:
        self.prompts: list[UserPrompt] = []
        self.notices: list[AdminNotice] = []

    def ask_user(self, prompt: UserPrompt) -> None:
        self.prompts.append(prompt)

    def notify_admin(self, notice: AdminNotice) -> None:
        self.notices.append(notice)


class HoldState(StrEnum):
    PENDING = "pending"
    RELEASED = "released"
    CONTAINED = "contained"
    KEPT_QUARANTINED = "kept_quarantined"


@dataclass
class HoldCase:
    hold_id: str
    story_id: str
    platform: str
    started: datetime
    deadline: datetime
    can_continue: bool
    action_ids: list[str] = field(default_factory=list)
    state: HoldState = HoldState.PENDING


@dataclass
class Resolution:
    """Actions to carry out and earlier actions to undo, after an answer or a timeout."""

    actions: list[Action] = field(default_factory=list)
    undo: list[str] = field(default_factory=list)


@dataclass
class _Story:
    blocked: bool = False
    hold: HoldCase | None = None
    warned: int = 0
    issued: set[tuple[str, str]] = field(default_factory=set)


_RANK = {Decision.ALLOW: 0, Decision.HOLD: 1, Decision.BLOCK: 2}

_WHY = {
    "origin": "it started from something that came in from outside",
    "contract": "it did something its job does not include",
    "effect": "it tried a risky action",
}


class Gate:
    def __init__(self, policy: Policy, tagger: Tagger, notifier: Notifier | None = None) -> None:
        self.policy = policy
        self.contain = Contain(tagger)
        self.notifier: Notifier = notifier or RecordingNotifier()
        self.holds: dict[str, HoldCase] = {}
        self._stories: dict[str, _Story] = {}
        self._records: dict[str, StoryRecord] = {}
        self._last: dict[str, Judgement] = {}
        self._device: dict[str, str] = {}
        self._issued: set[tuple[str, str]] = set()
        self._actions = 0
        self._holds = 0

    # -- called by the pipeline on every event -------------------------------------------------

    def handle(
        self, rec: StoryRecord, j: Judgement, now: datetime, verdict_id: str | None
    ) -> list[Action]:
        state = self._stories.setdefault(rec.story.story_id, _Story())
        if j.mode is Mode.OBSERVE or j.decision is Decision.ALLOW:
            return self._continue_block(rec, j, now, verdict_id, state)
        if j.mode is Mode.WARN:
            self._warn(rec, j, now, state)
            return []
        if j.decision is Decision.BLOCK or state.blocked:
            return self._block(rec, j, now, verdict_id, state)
        if state.hold is None:
            return self._start_hold(rec, j, now, verdict_id, state)
        if state.hold.state is HoldState.PENDING:
            return self._extend_hold(rec, j, now, verdict_id, state)
        return []

    def tick(self, now: datetime) -> list[Action]:
        """Resolve holds whose time is up. Endpoint: stop. Server: stay quarantined."""
        out: list[Action] = []
        for case in list(self.holds.values()):
            if case.state is not HoldState.PENDING or now < case.deadline:
                continue
            if case.platform == "endpoint":
                out += self._deny(case, now).actions
            else:
                case.state = HoldState.KEPT_QUARANTINED
                self.notifier.notify_admin(
                    AdminNotice(
                        kind="still_quarantined", hold_id=case.hold_id, story_id=case.story_id,
                        device=self._device.get(case.story_id, "unknown"), ts=now,
                        text="No answer yet. It stays paused and quarantined until you decide.",
                        action_ids=tuple(case.action_ids),
                    )
                )  # fmt: skip
        return out

    def open_hold_stories(self) -> set[str]:
        return {c.story_id for c in self.holds.values() if c.state is HoldState.PENDING}

    def forget(self, story_ids: set[str]) -> None:
        """v1.5 (A62): drop the state of stories the pipeline no longer keeps (never a story
        with a pending hold). The action keys stay, so no object is ever acted on twice."""
        for sid in story_ids:
            self._stories.pop(sid, None)
            self._records.pop(sid, None)
            self._last.pop(sid, None)
            self._device.pop(sid, None)
        for hid in [h for h, c in self.holds.items() if c.story_id in story_ids]:
            if self.holds[hid].state is not HoldState.PENDING:
                del self.holds[hid]

    # -- answers from people -------------------------------------------------------------------

    def answer_user(self, hold_id: str, answer: str, now: datetime) -> Resolution:
        case = self._pending(hold_id, "endpoint")
        if answer not in ("stop", "continue"):
            raise ValueError("the user answers stop or continue")
        if now >= case.deadline:
            return self._deny(case, now)
        if answer == "continue":
            if not case.can_continue:
                raise ValueError("continue is not offered when all three questions failed")
            case.state = HoldState.RELEASED
            return Resolution(undo=list(case.action_ids))
        return self._deny(case, now)

    def answer_admin(self, hold_id: str, answer: str, now: datetime) -> Resolution:
        case = self.holds.get(hold_id)
        if case is None or case.platform != "server" or case.state not in (
            HoldState.PENDING, HoldState.KEPT_QUARANTINED
        ):  # fmt: skip
            raise ValueError(f"no open server hold {hold_id!r}")
        if answer == "release":
            case.state = HoldState.RELEASED
            return Resolution(undo=list(case.action_ids))
        if answer == "confirm":
            return self._deny(case, now)
        raise ValueError("the admin answers release or confirm")

    # -- internals -----------------------------------------------------------------------------

    def _pending(self, hold_id: str, platform: str) -> HoldCase:
        case = self.holds.get(hold_id)
        if case is None or case.platform != platform or case.state is not HoldState.PENDING:
            raise ValueError(f"no pending {platform} hold {hold_id!r}")
        return case

    def _deny(self, case: HoldCase, now: datetime) -> Resolution:
        case.state = HoldState.CONTAINED
        rec = self._records[case.story_id]
        j = self._last[case.story_id]
        state = self._stories[case.story_id]
        return Resolution(actions=self._block(rec, j, now, rec.verdict_id, state, force=True))

    def _wrap(self, step: Step, rec: StoryRecord, now: datetime, verdict_id: str | None) -> Action:
        self._actions += 1
        return Action(
            action_id=f"a-{self._actions}", ts=now, type=step.type, target=step.target,
            story_id=rec.story.story_id, verdict_id=verdict_id,
        )  # fmt: skip

    def _issue(self, steps, rec, now, verdict_id, state) -> list[Action]:
        out = []
        for step in steps:
            if step.key in self._issued:  # one action per object, also across merged stories
                continue
            self._issued.add(step.key)
            state.issued.add(step.key)
            out.append(self._wrap(step, rec, now, verdict_id))
        return out

    def _continue_block(self, rec, j, now, verdict_id, state) -> list[Action]:
        self._remember(rec, j)
        return self._block(rec, j, now, verdict_id, state) if state.blocked else []

    def _remember(self, rec: StoryRecord, j: Judgement) -> None:
        self._records[rec.story.story_id] = rec
        self._last[rec.story.story_id] = j
        self._device[rec.story.story_id] = rec.story.device

    def _block(self, rec, j, now, verdict_id, state, *, force: bool = False) -> list[Action]:
        self._remember(rec, j)
        state.blocked = True
        if state.hold is not None and state.hold.state is HoldState.PENDING and not force:
            state.hold.state = HoldState.CONTAINED
        steps = self.contain.plan(rec, "block", j.effects, signal_processes(rec, j.signals))
        actions = self._issue(steps, rec, now, verdict_id, state)
        if actions:
            self.notifier.notify_admin(
                AdminNotice(
                    kind="blocked", story_id=rec.story.story_id, device=rec.story.device, ts=now,
                    text="Refmon stopped a story that looked like an attack and undid what it had "
                    "changed. Nothing was deleted; quarantined files can be released.",
                    action_ids=tuple(a.action_id for a in actions),
                )
            )  # fmt: skip
        return actions

    def _warn(self, rec, j, now, state) -> None:
        self._remember(rec, j)
        rank = _RANK[j.decision]
        if rank <= state.warned:
            return
        state.warned = rank
        self.notifier.notify_admin(
            AdminNotice(
                kind="warning", story_id=rec.story.story_id, device=rec.story.device, ts=now,
                text=f"Warn mode: this story would be {j.decision.value}. {_reasons(j)} "
                "Nothing was paused, stopped or moved.",
            )
        )  # fmt: skip

    def _extend_hold(self, rec, j, now, verdict_id, state) -> list[Action]:
        """A pending hold also covers what the story labels or writes while it waits."""
        self._remember(rec, j)
        case = state.hold
        producers = signal_processes(rec, j.signals)
        steps = self.contain.plan(rec, f"hold_{case.platform}", j.effects, producers)
        actions = self._issue(steps, rec, now, verdict_id, state)
        case.action_ids += [a.action_id for a in actions]
        if case.can_continue and j.fail_count == len(j.failed):
            case.can_continue = False  # all three questions failed in the meantime
            if case.platform == "endpoint":
                self._ask(case, rec.story.device, j, "stop only")
        return actions

    def _ask(self, case: HoldCase, device: str, j: Judgement, _why: str = "") -> None:
        self.notifier.ask_user(
            UserPrompt(
                hold_id=case.hold_id, story_id=case.story_id, device=device,
                text=f"Refmon paused a program because it looks unsafe. {_reasons(j)} "
                "Do you want it to stop? If you do not answer, it will be stopped.",
                options=("stop", "continue") if case.can_continue else ("stop",),
                deadline=case.deadline,
            )
        )  # fmt: skip

    def _start_hold(self, rec, j, now, verdict_id, state) -> list[Action]:
        self._remember(rec, j)
        roles = {e.actor.role for e in rec.events}
        platform = self.policy.platform_for(rec.story.device, roles)
        producers = signal_processes(rec, j.signals)
        steps = self.contain.plan(rec, f"hold_{platform}", j.effects, producers)
        actions = self._issue(steps, rec, now, verdict_id, state)
        self._holds += 1
        endpoint = platform == "endpoint"
        wait = (
            self.policy.decisions.endpoint_hold_timeout
            if endpoint
            else self.policy.decisions.server_hold_wait
        )
        case = HoldCase(
            hold_id=f"h-{self._holds}", story_id=rec.story.story_id, platform=platform,
            started=now, deadline=now + timedelta(seconds=wait),
            can_continue=j.fail_count < len(j.failed), action_ids=[a.action_id for a in actions],
        )  # fmt: skip
        self.holds[case.hold_id] = case
        state.hold = case
        text = _reasons(j)
        if endpoint:
            self._ask(case, rec.story.device, j)
        else:
            self.notifier.notify_admin(
                AdminNotice(
                    kind="hold", hold_id=case.hold_id, story_id=case.story_id,
                    device=rec.story.device, ts=now,
                    text=f"Refmon paused and quarantined part of a server story. {text} "
                    "It stays that way until you release it or confirm the attack.",
                    action_ids=tuple(case.action_ids),
                )
            )  # fmt: skip
        return actions


def _reasons(j: Judgement) -> str:
    why = [_WHY[q] for q, failed in j.failed.items() if failed]
    return ("Why: " + "; ".join(why) + ".") if why else ""
