"""Replay a file of generated variants (scripts/generate_variants.py) through whichever `refmon` is
on the path and dump one JSON line per variant. The same file runs against every tagged version, so
all of them are measured by identical code: a plain observe-mode replay for the decision, and a
block-mode replay with the Gate for what the Gate does (action counts).

    PYTHONPATH=<tree>/src python scripts/dump_matrix.py --variants variants.jsonl --out v1.0.jsonl

It uses only what every version has, and it never reads a verdict's decision from the Gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter

import refmon
from refmon.pipeline import Pipeline
from refmon.policy import default_policy
from refmon.schemas import Action, Event

QUESTIONS = ("origin", "contract", "effect")


def event_hash(events) -> str:
    digest = hashlib.sha256()
    for e in events:
        digest.update(e.to_json_line().encode())
    return digest.hexdigest()[:16]


def decide(events, policy):
    pipe = Pipeline(policy)
    for e in events:
        pipe.process(e)
    best = pipe.best()
    if best is None:
        return "allow", "allow", [], None
    failed = [q for q in QUESTIONS if best.failed[q]]
    return best.decision.value, best.rule_decision.value, failed, best.log_odds


def gate_actions(events, policy) -> dict[str, int]:
    pipe = Pipeline(policy.model_copy(update={"mode": "block"}), gate=True)
    counts: Counter[str] = Counter()
    for e in events:
        for out in pipe.process(e):
            if isinstance(out, Action):
                counts[out.type.value] += 1
    return dict(sorted(counts.items()))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variants", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    policy = default_policy()
    roles = tuple(policy.extra_roles)
    with (
        open(args.variants, encoding="utf-8") as src,
        open(args.out, "w", encoding="utf-8") as handle,
    ):
        count = 0
        for line in src:
            v = json.loads(line)
            events = [Event.from_json_line(e, extra_roles=roles) for e in v["events"]]
            decision, rule, failed, log_odds = decide(events, policy)
            count += 1
            row = {
                "scenario": v["scenario"],
                "variant": v["variant"],
                "dims": v["dims"],
                "params": v["params"],
                "kind": v.get("kind", "malicious"),
                "adds": v.get("adds", []),
                "expected": v.get("expected"),
                "events": event_hash(events),
                "decision": decision,
                "rule_decision": rule,
                "failed": failed,
                "log_odds": None if log_odds is None else round(log_odds, 3),
                "actions": gate_actions(events, policy),
            }
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    print(f"{count} variants, refmon from {refmon.__file__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
