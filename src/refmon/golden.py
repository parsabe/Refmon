"""Golden scenarios: an events file plus the verdict it must reach (C8).

Layout in a golden directory, for each scenario ID:
    S01.events.jsonl    the replay stream
    S01.expected.json   an ExpectedVerdict
"""

import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .schemas import ActionType, Decision, Effect, Identifier, Override, Question


class ScenarioKind(StrEnum):
    MALICIOUS = "malicious"
    BENIGN = "benign"
    ADAPTIVE = "adaptive"


class ExpectedAction(BaseModel):
    """A containment step the scenario must lead to.

    Names its target either as a process id or as the object of an event in the stream (files and
    persistence items are only known by fingerprint).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: ActionType
    process: Identifier | None = None
    object_of_event: Identifier | None = None
    host: Identifier | None = None

    @model_validator(mode="after")
    def _exactly_one_target(self) -> Self:
        if sum(x is not None for x in (self.process, self.object_of_event, self.host)) != 1:
            raise ValueError("give exactly one of process / object_of_event / host")
        return self


class ExpectedVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario: str = Field(pattern=r"^S\d{2}[a-z]?$")
    title: str
    kind: ScenarioKind
    platform: Literal["endpoint", "server"]
    # The final decision, and what the plain fail-count rule gives for the same story. They differ
    # only where the evidence calculus overrules the rule (docs/design-decisions.md, D1).
    decision: Decision
    rule_decision: Decision
    # First phase in which the pipeline reaches `decision` (rate tests and weights arrive in 4b).
    decided_in_phase: Literal["1", "4b", "5"] = "1"
    questions_failed: tuple[Question, ...] = ()
    effects: tuple[Effect, ...] = ()
    override: Override | None = None
    known_gap: bool = False
    actions: tuple[ExpectedAction, ...] = ()
    notes: str = ""

    @property
    def fail_count(self) -> int:
        return len(self.questions_failed)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if len(set(self.questions_failed)) != len(self.questions_failed):
            raise ValueError("questions_failed contains duplicates")
        if self.rule_decision != self.decision and not self.notes:
            raise ValueError("decision differs from rule_decision: explain why in notes")
        return self


@dataclass(frozen=True)
class GoldenCase:
    scenario: str
    events_path: Path
    expected: ExpectedVerdict


def load_golden_cases(directory: Path | str) -> list[GoldenCase]:
    directory = Path(directory)
    events = {p.name.removesuffix(".events.jsonl"): p for p in directory.glob("*.events.jsonl")}
    expected = {p.name.removesuffix(".expected.json"): p for p in directory.glob("*.expected.json")}
    unpaired = sorted(events.keys() ^ expected.keys())
    if unpaired:
        raise ValueError(f"golden files without a partner: {', '.join(unpaired)}")
    cases = []
    for scenario in sorted(events):
        verdict = ExpectedVerdict.model_validate(json.loads(expected[scenario].read_text()))
        if verdict.scenario != scenario:
            raise ValueError(f"{expected[scenario].name} declares scenario {verdict.scenario}")
        cases.append(GoldenCase(scenario, events[scenario], verdict))
    return cases
