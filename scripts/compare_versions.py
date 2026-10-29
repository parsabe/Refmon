"""Compare dumps of `dump_matrix.py`: the same variants replayed in two or more versions.

    python scripts/compare_versions.py v1.0=a.jsonl v1.1=b.jsonl v1.2=c.jsonl --out report.md

Malicious variants are classified in one of four ways (F1):
    block                a block;
    effective hold       a hold during which the Gate paused or quarantined something;
    hold pauses nothing  a hold that paused nothing (the user is asked, nothing is stopped);
    allow.
`uncontained` is allow plus hold-pauses-nothing. Benign variants are reported as allow, hold and
block, in the groups the generator labelled (docs/variant-seeds.md): neutral variants, whose false
block rate is the headline, and variants whose mutation adds a Contract violation or an Effect.
For every group the report gives the numbers side by side and lists every variant whose class
changed from one version to the next.
"""

from __future__ import annotations

import argparse
import itertools
import json
from collections import Counter
from pathlib import Path

PAUSING = ("hold", "quarantine_file")
RANK = {"allow": 0, "hold": 1, "block": 2}


def load(path: str) -> dict[tuple[str, str], dict]:
    rows = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    return {(r["scenario"], r["variant"]): r for r in rows}


def outcome(row: dict) -> str:
    """The class of a variant. A benign variant is allow, hold or block; a malicious one also
    tells an effective hold from a hold that pauses nothing."""
    if row["decision"] == "block":
        return "block"
    if row["decision"] == "hold":
        if row.get("kind", "malicious") == "benign":
            return "hold"
        paused = any(row["actions"].get(t, 0) for t in PAUSING)
        return "effective hold" if paused else "hold pauses nothing"
    return "allow"


def seeded(key: tuple[str, str], row: dict) -> bool:
    """The seed decides a combination and any variant with a number it drew. A baseline, a no-label
    variant and a one-factor variant without a parameter are the same events for every seed."""
    return key[1].startswith("combo-") or bool(row.get("params"))


def malicious_counts(rows: list[dict]) -> dict[str, int]:
    by = Counter(outcome(r) for r in rows)
    return {
        "variants": len(rows),
        "block": by["block"],
        "effective hold": by["effective hold"],
        "uncontained (allow + hold pauses nothing)": by["allow"] + by["hold pauses nothing"],
        "- allow": by["allow"],
        "- hold pauses nothing": by["hold pauses nothing"],
        "blocks that act on nothing": sum(outcome(r) == "block" and not r["actions"] for r in rows),
    }


def benign_counts(rows: list[dict]) -> dict[str, str]:
    by = Counter(r["decision"] for r in rows)
    n = len(rows) or 1
    worse = sum(1 for r in rows if r.get("expected") and RANK[r["decision"]] > RANK[r["expected"]])
    return {
        "variants": str(len(rows)),
        "allow": str(by["allow"]),
        "hold": str(by["hold"]),
        "block": str(by["block"]),
        "block rate (the false block rate for neutral variants)": f"{by['block'] / n:.1%}",
        "worse than the unmodified file": str(worse),
    }


def table(title: str, names: list[str], groups: list[list[dict]], counter) -> list[str]:
    cols = [counter(g) for g in groups]
    lines = [f"**{title}**", "", "| | " + " | ".join(names) + " |"]
    lines.append("|---|" + "---:|" * len(names))
    for key in cols[0]:
        lines.append(f"| {key} | " + " | ".join(str(c[key]) for c in cols) + " |")
    return [*lines, ""]


def label(key: tuple[str, str], row: dict) -> str:
    dims = ", ".join(f"{d}={v}" for d, v in sorted(row["dims"].items())) or "unmodified"
    return f"{key[0]} {key[1]} ({dims})"


def group_of(row: dict) -> str:
    adds = row.get("adds") or []
    if row.get("kind", "malicious") == "malicious":
        return "malicious"
    if not adds:
        return "benign, neutral"
    return "benign, adds a Contract violation" if "contract" in adds else "benign, adds an Effect"


def changes(runs: dict[str, dict], names: list[str], keys: list, title: str) -> list[str]:
    out = []
    for before, after in itertools.pairwise(names):
        old, new = runs[before], runs[after]
        changed = [k for k in keys if outcome(old[k]) != outcome(new[k])]
        out.append(f"**{title}, {before} to {after}: {len(changed)}**")
        out.append("")
        moves = Counter((outcome(old[k]), outcome(new[k])) for k in changed)
        out += [f"- {a} -> {b}: {n}" for (a, b), n in sorted(moves.items())]
        out += ["", f"| variant | {before} | {after} | seed decides |", "|---|---|---|---|"]
        for k in changed:
            out.append(
                f"| {label(k, old[k])} | {outcome(old[k])} | {outcome(new[k])} | "
                f"{'yes' if seeded(k, old[k]) else 'no'} |"
            )
        out.append("")
    return out


def report(runs: dict[str, dict]) -> str:
    names = list(runs)
    first = runs[names[0]]
    for name in names[1:]:
        assert runs[name].keys() == first.keys(), f"{name} has different variants"
        bad = [k for k in first if first[k]["events"] != runs[name][k]["events"]]
        assert not bad, f"{name}: the same variant has different events: {bad[:3]}"
    keys = sorted(first)
    mal = [k for k in keys if group_of(first[k]) == "malicious"]
    out = [f"{len(keys)} variants, identical event streams in every run (hash checked).", ""]
    out += ["## Malicious variants", ""]
    out += table("All", names, [[runs[n][k] for k in mal] for n in names], malicious_counts)
    dep = [k for k in mal if seeded(k, first[k])]
    ind = [k for k in mal if not seeded(k, first[k])]
    out += table(
        f"Variants the seed decides ({len(dep)}): the independent test",
        names, [[runs[n][k] for k in dep] for n in names], malicious_counts,
    )  # fmt: skip
    out += table(
        f"Variants that are the same for every seed ({len(ind)}): a regression check, not fresh "
        "evidence",
        names, [[runs[n][k] for k in ind] for n in names], malicious_counts,
    )  # fmt: skip
    out += ["## Benign variants", ""]
    for group in ("benign, neutral", "benign, adds a Contract violation", "benign, adds an Effect"):
        ks = [k for k in keys if group_of(first[k]) == group]
        if ks:
            rows = [[runs[n][k] for k in ks] for n in names]
            out += table(f"{group.capitalize()} ({len(ks)})", names, rows, benign_counts)
    ben = [k for k in keys if group_of(first[k]) != "malicious"]
    out += table(
        "All benign variants", names, [[runs[n][k] for k in ben] for n in names], benign_counts
    )
    out += ["## Changes", ""]
    out += changes(runs, names, mal, "Malicious variants whose outcome changed")
    out += changes(runs, names, ben, "Benign variants whose outcome changed")
    return "\n".join(out)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("runs", nargs="+", help="name=path of each dump, oldest first")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    runs = {}
    for item in args.runs:
        name, _, path = item.partition("=")
        runs[name] = load(path)
    text = report(runs)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
