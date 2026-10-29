"""Generate the variants of one seed once, to a file that every version then replays.

    python scripts/generate_variants.py --golden tests/golden --seed 892499628 --out variants.jsonl

One line per variant: scenario, name, dimension levels, the numbers the seed drew, and the events as
JSON lines. Replaying the same file in v1.0, v1.1 and v1.2 makes the comparison one of pipelines,
never of generators.
"""

from __future__ import annotations

import argparse
import json

from refmon.golden import load_golden_cases
from refmon.policy import default_policy
from refmon.variants import generate


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--golden", required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    policy = default_policy()
    variants = generate(load_golden_cases(args.golden), policy, args.seed)
    with open(args.out, "w", encoding="utf-8") as handle:
        for v in variants:
            row = {
                "scenario": v.scenario,
                "variant": v.name,
                "dims": v.dims,
                "params": v.params,
                "kind": v.kind,
                "adds": list(v.adds),
                "expected": v.expected.value if v.expected else None,
                "events": [e.to_json_line() for e in v.events],
            }
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    print(f"{len(variants)} variants of seed {args.seed} written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
