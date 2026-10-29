import json
from datetime import UTC, datetime

from refmon.core import EmptyCore, RunReport, run_pipeline
from refmon.enforcer import SimulatedEnforcer
from refmon.replay import ReplaySource
from refmon.schemas import Action, ActionType, Event, Target, TargetKind, Verdict

FP = "hmac:" + "ab" * 16


def write_events(tmp_path, count: int):
    lines = []
    for n in range(1, count + 1):
        lines.append(
            json.dumps(
                {
                    "event_id": f"e-{n}",
                    "ts": f"2026-10-28T10:00:0{n}Z",
                    "device": "dev-1",
                    "type": "exec",
                    "actor": {"id": "p-1", "role": "web_worker", "interactive": False, "user": "s"},
                    "object": {"class": "command_text", "fingerprint": FP},
                }
            )
        )
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(lines) + "\n")
    return path


def test_empty_core_produces_nothing(tmp_path):
    enforcer = SimulatedEnforcer()
    report = run_pipeline(ReplaySource(write_events(tmp_path, 3)), EmptyCore(), enforcer)
    assert report == RunReport(events=3)
    assert enforcer.actions == []


def test_actions_from_the_core_reach_the_enforcer(tmp_path):
    class KillOnSecondEvent:
        def process(self, event: Event) -> list[Verdict | Action]:
            if event.event_id != "e-2":
                return []
            return [
                Action(
                    action_id="a-1",
                    ts=datetime(2026, 10, 28, tzinfo=UTC),
                    type=ActionType.KILL_PROCESS_TREE,
                    target=Target(kind=TargetKind.PROCESS, ref=event.actor.id),
                    story_id="st-1",
                )
            ]

    enforcer = SimulatedEnforcer()
    report = run_pipeline(ReplaySource(write_events(tmp_path, 3)), KillOnSecondEvent(), enforcer)
    assert report.events == 3
    assert [a.action_id for a in report.actions] == ["a-1"]
    assert enforcer.actions == report.actions
    assert [r.ok for r in report.results] == [True]
