"""After a replay under the Gate with the simulated world: in how many blocks is a process still
paused, and what is it? Runs against whichever `refmon` is on the path (v1.0 or v1.1).

    PYTHONPATH=<tree>/src python scripts/paused_after_block.py --variants variants.jsonl
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from refmon.enforcer import SimulatedEnforcer
from refmon.pipeline import Pipeline
from refmon.policy import default_policy
from refmon.schemas import Action, Decision, Event
from refmon.simworld import SimWorld


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variants", required=True)
    args = parser.parse_args(argv)
    policy = default_policy()
    extra = tuple(policy.extra_roles)
    totals: Counter[str] = Counter()
    roles: Counter[str] = Counter()
    for line in Path(args.variants).read_text(encoding="utf-8").splitlines():
        events = [Event.from_json_line(e, extra_roles=extra) for e in json.loads(line)["events"]]
        world = SimWorld.from_events(events)
        enforcer = SimulatedEnforcer(world)
        pipe = Pipeline(policy.model_copy(update={"mode": "block"}), gate=True)
        for event in events:
            for out in pipe.process(event):
                if isinstance(out, Action):
                    enforcer.act(out)
        best = pipe.best()
        if best is None or best.decision is not Decision.BLOCK:
            continue
        totals["blocks"] += 1
        paused = sorted(p for p, state in world.process.items() if state == "paused")
        if not paused:
            continue
        totals["blocks with a process left paused"] += 1
        role_of = {e.actor.id: e.actor.role for e in events}
        for pid in paused:
            labeled = bool(pipe.tagger.procs[pid].ever)
            totals[
                "left paused, had carried a label" if labeled else "left paused, never labeled"
            ] += 1
            roles[role_of[pid]] += 1
    for key, value in totals.items():
        print(f"{key}: {value}")
    print("roles of the processes left paused:", dict(sorted(roles.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
