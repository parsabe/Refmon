"""Helpers that run a golden scenario through the pipeline."""

from pathlib import Path

from refmon.golden import GoldenCase, load_golden_cases
from refmon.pipeline import Pipeline
from refmon.policy import Policy, default_policy
from refmon.replay import ReplaySource

GOLDEN_DIR = Path(__file__).parent / "golden"
ROOT = Path(__file__).resolve().parent.parent
RANK = {"allow": 0, "hold": 1, "block": 2}


def cases() -> list[GoldenCase]:
    return load_golden_cases(GOLDEN_DIR)


def run_events(events, policy: Policy | None = None, **kw) -> Pipeline:
    p = Pipeline(policy or default_policy(), **kw)
    out = []
    for e in events:
        out.extend(p.process(e))
    p.outputs = out
    return p


def run_case(case: GoldenCase, policy: Policy | None = None, **kw) -> Pipeline:
    policy = policy or default_policy()
    return run_events(ReplaySource(case.events_path, extra_roles=policy.extra_roles), policy, **kw)


def summary(p: Pipeline, field: str = "rule_decision") -> dict:
    """Scenario-level result: every story at the highest decision, combined."""
    js = list(p.judgements().values())
    top = max(RANK[getattr(j, field).value] for j in js)
    best = [j for j in js if RANK[getattr(j, field).value] == top]
    questions = {q for j in best for q, failed in j.failed.items() if failed}
    effects = {e.value for j in best for e in j.effects}
    override = next((j.override.value for j in best if j.override), None)
    return {
        "decision": next(getattr(j, field) for j in best),
        "questions": questions,
        "effects": effects,
        "override": override,
        "fails": max(j.fail_count for j in best),
    }
