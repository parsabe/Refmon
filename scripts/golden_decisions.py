"""The decision of every golden scenario under whichever `refmon` is on the path.

    PYTHONPATH=<tree>/src python scripts/golden_decisions.py --golden <tree>/tests/golden

Prints one JSON object: scenario -> {kind, expected, decision, rule_decision}. The decision is the
highest of the scenario's stories, as everywhere in the repository.
"""

from __future__ import annotations

import argparse
import json

from refmon.golden import load_golden_cases
from refmon.pipeline import Pipeline
from refmon.policy import default_policy
from refmon.replay import ReplaySource


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--golden", required=True)
    args = parser.parse_args(argv)
    policy = default_policy()
    out = {}
    for case in load_golden_cases(args.golden):
        pipe = Pipeline(policy)
        for event in ReplaySource(case.events_path, extra_roles=policy.extra_roles):
            pipe.process(event)
        best = pipe.best()
        out[case.scenario] = {
            "kind": case.expected.kind.value,
            "expected": case.expected.decision.value,
            "decision": best.decision.value if best else "allow",
            "rule_decision": best.rule_decision.value if best else "allow",
        }
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
