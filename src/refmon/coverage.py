"""Coverage map (CLAUDE.md C13): every attack family needs a malicious and a benign scenario.

The map is read from the C13 table in CLAUDE.md itself, so the specification stays the single
source of truth. Adaptive scenarios (S16, S28, S29) belong to Phase 5.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

ADAPTIVE = {"S16", "S28", "S29"}


@dataclass(frozen=True)
class Family:
    name: str
    malicious: tuple[str, ...]
    benign: tuple[str, ...]


def expand(cell: str) -> tuple[str, ...]:
    """'S01-S04, S06, S26b' -> ('S01', 'S02', 'S03', 'S04', 'S06', 'S26b')."""
    cell = re.sub(r"\([^)]*\)", "", cell)
    out: list[str] = []
    for part in cell.split(","):
        part = part.strip()
        m = re.fullmatch(r"S(\d+)\s*[\u2013-]\s*S(\d+)", part)
        if m:
            out += [f"S{n:02d}" for n in range(int(m.group(1)), int(m.group(2)) + 1)]
        elif re.fullmatch(r"S\d+[a-z]?", part):
            out.append(part)
    return tuple(out)


def parse_coverage_map(claude_md: Path | str) -> list[Family]:
    text = Path(claude_md).read_text(encoding="utf-8")
    section = text[text.index("### C13.") :]
    families = []
    for line in section.splitlines():
        if not line.startswith("|") or line.startswith("| ---") or "Attack family" in line:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 6:
            continue
        families.append(Family(cells[0], expand(cells[4]), expand(cells[5])))
    return families


def gaps(families: list[Family], passing: set[str]) -> list[str]:
    """Families lacking a passing malicious or benign scenario (adaptive ones skipped)."""
    out = []
    for f in families:
        mal = [s for s in f.malicious if s not in ADAPTIVE]
        ben = [s for s in f.benign if s not in ADAPTIVE]
        if not mal and not ben:
            continue  # purely adaptive family: Phase 5
        if not any(s in passing for s in mal):
            out.append(f"{f.name}: no passing malicious scenario")
        if not any(s in passing for s in ben):
            out.append(f"{f.name}: no passing benign scenario")
    return out


def adaptive_gaps(families: list[Family], passing: set[str]) -> list[str]:
    """Adaptive scenarios (Phase 5) that are listed in the map but have no passing run."""
    out = []
    for f in families:
        for scenario in (*f.malicious, *f.benign):
            if scenario in ADAPTIVE and scenario not in passing:
                out.append(f"{f.name}: no passing {scenario}")
    return out
