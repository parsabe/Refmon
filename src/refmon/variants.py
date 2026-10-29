"""Variant and robustness testing (CLAUDE.md Phase 7).

The generator mutates every malicious golden file along six dimensions (one at a time, and in seeded
combinations) and replays every variant through the pipeline:

    delivery     paste (original), typed, dragged, opened, inbound_request
    entry        run_dialog, terminal, file_manager, script_host, web_worker, scheduled_task
    obfuscation  stripped flags, high entropy, whitespace padding
    timing       immediate (original), minutes apart, beyond the story quiet window
    destination  unknown (original), popular trusted host, internal network
    lineage      depth 1 to 4: unrelated processes between the labeled process and its children

and, for every hold, what a user or an administrator can do about it. It also builds the no-label
variants of S17-S20 (the initial-access label removed), whose expected decision is block (D22).

The output is a robustness matrix (CSV, scenario x variant -> decision) and the list of every
malicious variant that was *allowed*, with the questions that passed. Each allowed variant must be
fixed or documented as a known gap (`tests/variants/known_gaps.yaml`); the structural rules and
weights are frozen, so documenting is what happens. Every run also reports the share of processes of
role `other`: a high share means the role contracts do not cover the workload.

The seed is recorded in docs/variant-seeds.md before generating (CLAUDE.md C11).
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
import sys
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

import yaml

from .gate import RecordingNotifier
from .golden import GoldenCase, ScenarioKind, load_golden_cases
from .pipeline import Pipeline
from .pipeline.observe import EXTERNAL_SOURCES
from .policy import Policy, default_policy
from .replay import ReplaySource
from .schemas import Action, ActionType, Decision, Event, EventType

SEED = 711829743  # active seed; earlier seeds are retired, see docs/variant-seeds.md

DIMENSIONS: dict[str, list[str]] = {
    "delivery": ["typed", "dragged", "opened", "inbound_request"],
    "entry": [
        "run_dialog",
        "terminal",
        "file_manager",
        "script_host",
        "web_worker",
        "scheduled_task",
    ],
    "obfuscation": ["stripped", "high_entropy", "padded"],
    "timing": ["minutes", "beyond_window"],
    "destination": ["unknown", "popular_trusted", "internal_network"],
    "lineage": ["1", "2", "3", "4"],
}
ORDER = ["delivery", "entry", "obfuscation", "destination", "lineage", "timing"]
ENTRY_ROLE = {
    "run_dialog": "launcher",
    "terminal": "interactive_shell",
    "file_manager": "launcher",
    "script_host": "script_host",
    "web_worker": "web_worker",
    "scheduled_task": "scheduler",
}
DESTINATION_CLASS = {
    "unknown": "unknown",
    "popular_trusted": "package_index",  # a popular host that the policy trusts
    "internal_network": "internal_network",
}
OBFUSCATION_KEYS = (
    "hidden_window",
    "encoded_payload",
    "entropy_bits",
    "encoded_char_ratio",
    "longest_ws_run",
)
QUIET_GAP = {"minutes": 90.0, "beyond_window": None}  # None: the policy quiet window plus a minute


@dataclass
class Variant:
    scenario: str
    name: str
    dims: dict[str, str]
    events: list[Event]
    expected: Decision | None = None  # set where a decision is pinned (baseline, no-label variants)
    params: dict[str, float] = field(default_factory=dict)  # the numbers the seed drew (v1.2)
    kind: str = "malicious"  # or "benign" (v1.3): the unmodified file's kind
    # A benign variant is labelled here, from its mutations and the contracts and before any version
    # is replayed, when the mutation itself adds forbidden behaviour: "contract" (a Contract
    # violation) or "effect" (an Effect). Such a variant has no expected decision.
    adds: tuple[str, ...] = ()


def _fp(old: str, salt: str) -> str:
    return "hmac:" + hashlib.sha256(f"{salt}|{old}".encode()).hexdigest()


def _with_attrs(event: Event, **updates) -> Event:
    attrs = {k: v for k, v in event.attrs.items()}
    for key, value in updates.items():
        if value is None:
            attrs.pop(key, None)
        else:
            attrs[key] = value
    return event.model_copy(update={"attrs": attrs})


def _replace_actor(event: Event, **updates) -> Event:
    return event.model_copy(update={"actor": event.actor.model_copy(update=updates)})


# -- the mutations: new events, or None when one does not apply ------------------------------


def delivery(events: list[Event], level: str) -> list[Event] | None:
    inputs = [e for e in events if e.type is EventType.USER_INPUT]
    if level == "inbound_request":
        content = [
            e
            for e in events
            if e.type is EventType.CONTENT_IN and e.attrs.get("source_class") != "inbound_request"
        ]
        if not content:
            return None
        return [
            _with_attrs(e, source_class="inbound_request") if e in content else e for e in events
        ]
    if not inputs:
        return None
    if level == "typed":  # typing makes new text: it no longer matches the labeled content
        old = {e.object.fingerprint for e in inputs}
        out = []
        for e in events:
            fp = e.object.fingerprint
            if fp in old and e.type in (EventType.USER_INPUT, EventType.EXEC):
                e = e.model_copy(
                    update={"object": e.object.model_copy(update={"fingerprint": _fp(fp, "typed")})}
                )
            if e.type is EventType.USER_INPUT:
                e = _with_attrs(e, input_method="typed")
            out.append(e)
        return out
    return [
        _with_attrs(e, input_method=level) if e.type is EventType.USER_INPUT else e for e in events
    ]


def entry(events: list[Event], level: str) -> list[Event] | None:
    first = next((e for e in events if e.type is EventType.EXEC), None)
    if first is None:
        return None
    actor_id, role = first.actor.id, ENTRY_ROLE[level]
    out = []
    for e in events:
        if e.actor.id == actor_id:
            e = _replace_actor(e, role=role)
        if e.event_id == first.event_id:
            e = _with_attrs(e, launched_via=level)
        out.append(e)
    return out


def obfuscation(
    events: list[Event], level: str, values: dict[str, float] | None = None
) -> list[Event] | None:
    if not any(e.type is EventType.EXEC for e in events):
        return None
    strip = dict.fromkeys(OBFUSCATION_KEYS)
    values = values or {}
    extra = {
        "high_entropy": {"entropy_bits": values.get("entropy_bits", 6.5)},
        "padded": {"longest_ws_run": int(values.get("longest_ws_run", 200))},
    }.get(level, {})
    return [_with_attrs(e, **{**strip, **extra}) if e.type is EventType.EXEC else e for e in events]


def destination(events: list[Event], level: str) -> list[Event] | None:
    target = DESTINATION_CLASS[level]
    connects = [e for e in events if e.type is EventType.NET_CONNECT]
    if not connects or all(e.attrs.get("destination_class") == target for e in connects):
        return None
    return [
        _with_attrs(e, destination_class=target) if e.type is EventType.NET_CONNECT else e
        for e in events
    ]


def lineage(events: list[Event], level: str) -> list[Event] | None:
    depth = int(level)
    known = {e.actor.id for e in events}
    first_seen: dict[str, Event] = {}
    for e in events:
        first_seen.setdefault(e.actor.id, e)
    children = {
        pid: e for pid, e in first_seen.items() if e.actor.parent and e.actor.parent in known
    }
    if not children:
        return None
    reparent: dict[str, str] = {}
    inserted: dict[str, list[Event]] = {}
    serial = 0
    for pid, e in children.items():
        chain, parent = [], e.actor.parent
        for _ in range(depth):
            serial += 1
            mid = f"p-mid-{serial:03d}"
            chain.append(
                Event.model_validate(
                    {
                        "event_id": f"lin-{serial:04d}",
                        "ts": e.ts,
                        "device": e.device,
                        "type": "exec",
                        "actor": {
                            "id": mid,
                            "parent": parent,
                            "role": "other",
                            "interactive": False,
                            "user": e.actor.user,
                        },
                        "object": {"class": "command_text", "fingerprint": _fp(mid, "lineage")},
                        "attrs": {"exec_class": "unknown"},
                    },
                    context={"extra_roles": tuple(default_policy().extra_roles)},
                )
            )
            parent = mid
        reparent[pid], inserted[e.event_id] = parent, chain
    out = []
    for e in events:
        out.extend(inserted.get(e.event_id, []))
        if e.actor.id in reparent:
            e = _replace_actor(e, parent=reparent[e.actor.id])
        out.append(e)
    return out


def timing(
    events: list[Event], level: str, quiet_window: float, gap: float | None = None
) -> list[Event] | None:
    if len(events) < 2:
        return None
    if gap is None:
        gap = QUIET_GAP[level] if QUIET_GAP[level] is not None else quiet_window + 60.0
    out, clock, previous = [events[0]], events[0].ts, events[0].ts
    for e in events[1:]:
        step = max((e.ts - previous).total_seconds(), gap)
        previous = e.ts
        clock = clock + timedelta(seconds=step)
        out.append(e.model_copy(update={"ts": clock}))
    return out


# -- labels of benign variants (docs/variant-seeds.md, "Benign variants") -------------------------


def _external_content(events: list[Event]) -> set[str]:
    """Fingerprints of content that came in from outside and is not from a trusted source."""
    return {
        e.object.fingerprint
        for e in events
        if e.type in (EventType.CONTENT_IN, EventType.REQUEST_IN)
        and e.attrs.get("source_class") in EXTERNAL_SOURCES
        and "trusted_source" not in e.attrs
        and e.object.fingerprint
    }


def step_labels(
    dim: str, level: str, before: list[Event], after: list[Event], policy: Policy
) -> set[str]:
    """What one mutation adds to a benign story that the specification forbids: "contract" for a
    Contract violation, "effect" for an Effect. The rules are those of the table in
    docs/variant-seeds.md; nothing here looks at a replay."""
    external = _external_content(before)
    execs = [e for e in before if e.type is EventType.EXEC]
    out: set[str] = set()
    if dim == "entry" and execs:
        runs_external_text = any(
            e.object.class_ == "command_text" and e.object.fingerprint in external for e in execs
        )
        unsigned_file = any(
            e.attrs.get("signed") is False and e.object.fingerprint in external for e in execs
        )
        if level == "web_worker":
            out.add("contract")  # a web worker may not start programs
        elif level == "terminal":
            if external:
                out.add("contract")  # an interactive shell may not run external content
        elif runs_external_text or (level in ("run_dialog", "file_manager") and unsigned_file):
            out.add("contract")  # external command text is forbidden for every role (C4)
    elif dim == "destination":
        for old, new in zip(before, after, strict=True):
            target = new.attrs.get("destination_class")
            if (
                old.type is not EventType.NET_CONNECT
                or old.attrs.get("destination_class") == target
            ):
                continue
            contract = policy.contract_for(new.actor.role)
            if contract is not None and contract.may_connect is not None:
                if target not in contract.may_connect and "any" not in contract.may_connect:
                    out.add("contract")
            else:
                known = policy.destination(target)
                if target == "unknown" or known is None or not known.trusted:
                    out.add("effect")
    elif dim == "obfuscation" and level in ("high_entropy", "padded") and execs:
        out.add("effect")  # a hidden or obfuscated command is the `hide` Effect
    return out


_MUTATIONS: dict[str, Callable] = {
    "delivery": delivery,
    "entry": entry,
    "obfuscation": obfuscation,
    "destination": destination,
    "lineage": lineage,
}


def draw_params(
    seed: int, scenario: str, name: str, dims: dict[str, str], policy: Policy
) -> dict[str, float]:
    """The numbers of one variant, drawn from the seed (v1.2): the gap between events of a `timing`
    level (minutes: one to fifteen; beyond the story window: 30 s to 30 min past it), the entropy
    of a `high_entropy` command and the whitespace run of a `padded` one (both above the policy's
    threshold). The same seed, scenario and variant name give the same numbers."""
    rng = random.Random(f"{seed}:{scenario}:{name}:params")
    out: dict[str, float] = {}
    if dims.get("timing") == "minutes":
        out["gap"] = round(rng.uniform(60.0, 900.0), 1)
    elif dims.get("timing") == "beyond_window":
        out["gap"] = round(policy.thresholds.story_quiet_window + rng.uniform(30.0, 1800.0), 1)
    if dims.get("obfuscation") == "high_entropy":
        out["entropy_bits"] = round(policy.math.entropy_max_bits + rng.uniform(0.1, 2.6), 2)
    if dims.get("obfuscation") == "padded":
        out["longest_ws_run"] = policy.math.ws_run_max + rng.randint(1, 340)
    return out


def apply(
    events: list[Event],
    dims: dict[str, str],
    quiet_window: float,
    params: dict[str, float] | None = None,
    policy: Policy | None = None,
    labels: set[str] | None = None,
) -> list[Event] | None:
    """Apply the mutations in order. With a policy and a set, `labels` collects what the mutations
    add that the specification forbids (benign variants)."""
    params = params or {}
    for dim in ORDER:
        level = dims.get(dim)
        if level is None:
            continue
        before = events
        if dim == "timing":
            events = timing(events, level, quiet_window, params.get("gap"))
        elif dim == "obfuscation":
            events = obfuscation(events, level, params)
        else:
            events = _MUTATIONS[dim](events, level)
        if events is None:
            return None
        if labels is not None and policy is not None:
            labels |= step_labels(dim, level, before, events, policy)
    return events


def no_label(events: list[Event]) -> list[Event]:
    """The story of S17-S20 without its initial-access label: no inbound request, no request end."""
    return [e for e in events if e.type not in (EventType.REQUEST_IN, EventType.REQUEST_END)]


# -- generation ---------------------------------------------------------------------------------


def _variant(sid, name, dims, mutated, params, found, base) -> Variant:
    """A mutated variant. A benign one expects the decision of its unmodified file, unless a
    mutation labelled it as adding forbidden behaviour: then it expects nothing."""
    kind, benign, baseline = base
    adds = tuple(sorted(found))
    expected = baseline if benign and not adds else None
    return Variant(sid, name, dims, mutated, expected, params=params, kind=kind, adds=adds)


def generate(
    cases: Iterable[GoldenCase],
    policy: Policy,
    seed: int = SEED,
    combos: int = 12,
) -> list[Variant]:
    quiet = policy.thresholds.story_quiet_window
    roles = tuple(policy.extra_roles)
    out: list[Variant] = []
    for case in cases:
        kind = case.expected.kind.value
        events = list(ReplaySource(case.events_path, extra_roles=roles))
        sid = case.scenario
        benign = case.expected.kind is ScenarioKind.BENIGN
        baseline = case.expected.decision
        out.append(Variant(sid, "baseline", {}, events, baseline, kind=kind))
        if sid in {"S17", "S18", "S19", "S20"}:
            no = Variant(sid, "no-label", {"label": "removed"}, no_label(events), Decision.BLOCK)
            no.kind = kind
            out.append(no)
        base = (kind, benign, baseline)

        for dim in ORDER:
            for level in DIMENSIONS[dim]:
                name, dims = f"{dim}={level}", {dim: level}
                params = draw_params(seed, sid, name, dims, policy)
                found: set[str] = set()
                mutated = apply(events, dims, quiet, params, policy, found if benign else None)
                if mutated is not None:
                    out.append(_variant(sid, name, dims, mutated, params, found, base))
        rng = random.Random(f"{seed}:{sid}")
        seen: set[tuple] = set()
        for n in range(combos):
            for _ in range(20):
                chosen = rng.sample(ORDER, k=rng.choice([2, 3, 4]))
                dims = {d: rng.choice(DIMENSIONS[d]) for d in sorted(chosen, key=ORDER.index)}
                key = tuple(sorted(dims.items()))
                name = f"combo-{n + 1}"
                params = draw_params(seed, sid, name, dims, policy)
                found = set()
                mutated = apply(events, dims, quiet, params, policy, found if benign else None)
                if key not in seen and mutated is not None:
                    seen.add(key)
                    out.append(_variant(sid, name, dims, mutated, params, found, base))
                    break
    return out


# -- running ------------------------------------------------------------------------------------

RANK = {Decision.ALLOW: 0, Decision.HOLD: 1, Decision.BLOCK: 2}


PAUSING = (ActionType.HOLD, ActionType.QUARANTINE_FILE)


@dataclass
class Result:
    variant: Variant
    decision: Decision
    rule_decision: Decision
    failed: tuple[str, ...]
    passed: tuple[str, ...]
    log_odds: float | None
    other_share: float
    holds: dict[str, str] = field(default_factory=dict)
    # What the Gate does with this variant in block mode: action type -> count (Phase 7 / v1.1).
    actions: dict[str, int] = field(default_factory=dict)

    @property
    def caught(self) -> bool:
        return self.decision is not Decision.ALLOW

    @property
    def pauses(self) -> bool:
        """The Gate paused or quarantined something (the test of an effective hold)."""
        return any(self.actions.get(t.value, 0) for t in PAUSING)

    @property
    def acts(self) -> bool:
        """The Gate did anything to the story's objects."""
        return bool(self.actions)

    @property
    def outcome(self) -> str:
        """block, effective_hold, hold_pauses_nothing or allow (F1: a hold must pause something).
        A benign variant is only allow, hold or block."""
        if self.variant.kind == "benign":
            return self.decision.value
        if self.decision is Decision.BLOCK:
            return "block"
        if self.decision is Decision.HOLD:
            return "effective_hold" if self.pauses else "hold_pauses_nothing"
        return "allow"


def other_share(events: Iterable[Event]) -> float:
    roles = {e.actor.id: e.actor.role for e in events}
    return sum(r == "other" for r in roles.values()) / len(roles) if roles else 0.0


def run(variant: Variant, policy: Policy) -> Result:
    pipe = Pipeline(policy)
    for event in variant.events:
        pipe.process(event)
    best = pipe.best()
    questions = ("origin", "contract", "effect")
    failed = tuple(q for q in questions if best and best.failed[q])
    decision = best.decision if best else Decision.ALLOW
    rule = best.rule_decision if best else Decision.ALLOW
    result = Result(
        variant,
        decision,
        rule,
        failed,
        tuple(q for q in questions if q not in failed),
        best.log_odds if best else None,
        other_share(variant.events),
    )
    result.actions = action_profile(variant, policy)
    if result.decision is Decision.HOLD and variant.kind == "malicious":
        result.holds = hold_outcomes(variant, policy)
    return result


def action_profile(variant: Variant, policy: Policy) -> dict[str, int]:
    """What the Gate does with a variant in block mode, counted by action type. Every action the
    replay issues counts, so a hold that later times out still shows the pause it started with."""
    pipe = Pipeline(policy.model_copy(update={"mode": "block"}), gate=True)
    counts: Counter[str] = Counter()
    for event in variant.events:
        for out in pipe.process(event):
            if isinstance(out, Action):
                counts[out.type.value] += 1
    return dict(sorted(counts.items()))


def hold_outcomes(variant: Variant, policy: Policy) -> dict[str, str]:
    """What a person can do with a hold: each answer, and the outcome for the attack."""
    block = policy.model_copy(update={"mode": "block"})
    outcomes: dict[str, str] = {}
    answers: dict[str, tuple[str, ...]] = {}
    for answer in ("stop", "continue", "timeout", "confirm", "release", "silent"):
        pipe = Pipeline(block, gate=True, notifier=RecordingNotifier())
        actions: list[Action] = []
        for event in variant.events:
            actions += [o for o in pipe.process(event) if isinstance(o, Action)]
        cases = [c for c in pipe.gate.holds.values() if c.state.value == "pending"]
        if not cases:
            continue
        case = cases[-1]
        platform = case.platform
        if (platform, answer) not in {
            ("endpoint", "stop"),
            ("endpoint", "continue"),
            ("endpoint", "timeout"),
            ("server", "confirm"),
            ("server", "release"),
            ("server", "silent"),
        }:
            continue
        now = case.started
        try:
            if answer == "timeout":
                actions += pipe.gate.tick(case.deadline)
            elif answer == "silent":
                pipe.gate.tick(case.deadline + timedelta(hours=1))
            elif answer in ("stop", "continue"):
                res = pipe.gate.answer_user(case.hold_id, answer, now)
                actions += res.actions
                if res.undo:
                    outcomes[answer] = "released: the attack proceeds"
                    continue
            else:
                res = pipe.gate.answer_admin(case.hold_id, answer, now)
                actions += res.actions
                if res.undo:
                    outcomes[answer] = "released: the attack proceeds"
                    continue
        except ValueError as error:  # continue is not offered at three fails
            outcomes[answer] = f"not offered ({error})"
            continue
        killed = any(a.type is ActionType.KILL_PROCESS_TREE for a in actions)
        paused = any(a.type in PAUSING for a in actions)
        if answer == "silent" and paused:
            outcomes[answer] = "stays paused and quarantined"
        elif killed:
            outcomes[answer] = "contained"
        elif paused:  # v1.1 (A47): the processes that produced the signals stay paused
            outcomes[answer] = "stays paused"
        else:
            outcomes[answer] = "nothing labeled to contain"
        answers[platform] = (*answers.get(platform, ()), answer)
    return outcomes


def run_all(variants: list[Variant], policy: Policy) -> list[Result]:
    return [run(v, policy) for v in variants]


# -- output -------------------------------------------------------------------------------------

CSV_COLUMNS = [
    "scenario",
    "variant",
    "dims",
    "decision",
    "rule_decision",
    "failed",
    "passed",
    "log_odds",
    "role_other_share",
    "hold_outcomes",
    "params",
    "pauses",
    "acts",
    "outcome",
    "kind",
    "adds",
    "expected",
]


def write_csv(results: list[Result], path: Path | str) -> None:
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for r in results:
            writer.writerow(
                [
                    r.variant.scenario,
                    r.variant.name,
                    json.dumps(r.variant.dims, sort_keys=True),
                    r.decision.value,
                    r.rule_decision.value,
                    "|".join(r.failed),
                    "|".join(r.passed),
                    "" if r.log_odds is None else f"{r.log_odds:.2f}",
                    f"{r.other_share:.2f}",
                    json.dumps(r.holds, sort_keys=True) if r.holds else "",
                    json.dumps(r.variant.params, sort_keys=True) if r.variant.params else "",
                    int(r.pauses),
                    int(r.acts),
                    r.outcome,
                    r.variant.kind,
                    "|".join(r.variant.adds),
                    r.variant.expected.value if r.variant.expected else "",
                ]
            )


def malicious(results: list[Result]) -> list[Result]:
    return [r for r in results if r.variant.kind == "malicious"]


def benign(results: list[Result]) -> list[Result]:
    return [r for r in results if r.variant.kind == "benign"]


def allowed(results: list[Result]) -> list[Result]:
    return [
        r
        for r in malicious(results)
        if r.decision is Decision.ALLOW and r.variant.name != "baseline"
    ]


def render_allowed(results: list[Result]) -> str:
    lines = ["scenario,variant,questions_failed,questions_passed"]
    for r in allowed(results):
        lines.append(
            f"{r.variant.scenario},{r.variant.name},{'|'.join(r.failed)},{'|'.join(r.passed)}"
        )
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class KnownGap:
    id: str
    reason: str
    match: dict[str, str]  # dimension levels the variant must carry
    scenarios: tuple[str, ...]  # "*" for any
    finding: str = ""

    def covers(self, r: Result) -> bool:
        dims = r.variant.dims
        scenario_ok = "*" in self.scenarios or r.variant.scenario in self.scenarios
        return scenario_ok and all(dims.get(k) == v for k, v in self.match.items())


def load_known_gaps(path: Path | str) -> list[KnownGap]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return [
        KnownGap(
            g["id"],
            g["reason"],
            g.get("match", {}),
            tuple(g.get("scenarios", ["*"])),
            g.get("finding", ""),
        )
        for g in raw.get("gaps", [])
    ]


def undocumented(results: list[Result], gaps: list[KnownGap]) -> list[Result]:
    return [r for r in allowed(results) if not any(g.covers(r) for g in gaps)]


def stale(results: list[Result], gaps: list[KnownGap]) -> list[KnownGap]:
    """Documented gaps that no allowed variant matches (the entry can go, or the gap was fixed)."""
    return [g for g in gaps if not any(g.covers(r) for r in allowed(results))]


def split(results: list[Result]) -> dict[str, int]:
    """Block, effective hold and uncontained (allow plus a hold that pauses nothing), reported as
    three numbers (F1); `blocks_acting_on_nothing` is a block that issued no action at all."""
    results = malicious(results)
    by = Counter(r.outcome for r in results)
    return {
        "block": by["block"],
        "effective_hold": by["effective_hold"],
        "uncontained": by["allow"] + by["hold_pauses_nothing"],
        "allow": by["allow"],
        "hold_pauses_nothing": by["hold_pauses_nothing"],
        "blocks_acting_on_nothing": len(blocks_acting_on_nothing(results)),
    }


def blocks_acting_on_nothing(results: list[Result]) -> list[Result]:
    return [r for r in malicious(results) if r.outcome == "block" and not r.acts]


BENIGN_GROUPS = (
    ("neutral", lambda r: not r.variant.adds),
    ("adds a Contract violation", lambda r: "contract" in r.variant.adds),
    ("adds an Effect only", lambda r: r.variant.adds == ("effect",)),
)
_RANK = {Decision.ALLOW: 0, Decision.HOLD: 1, Decision.BLOCK: 2}


def benign_split(results: list[Result]) -> dict[str, dict[str, float]]:
    """allow, hold and block for the benign variants, in three groups (labelled by the generator):
    the neutral ones, whose false-alarm figures are the headline, and the two labelled kinds.
    `above_expected` counts a neutral variant that is worse than its unmodified file."""
    out: dict[str, dict[str, float]] = {}
    for name, member in BENIGN_GROUPS:
        group = [r for r in benign(results) if member(r)]
        by = Counter(r.decision.value for r in group)
        worse = [
            r for r in group if r.variant.expected and _RANK[r.decision] > _RANK[r.variant.expected]
        ]
        out[name] = {
            "variants": len(group),
            "allow": by["allow"],
            "hold": by["hold"],
            "block": by["block"],
            "false_block_rate": by["block"] / len(group) if group else 0.0,
            "above_expected": len(worse),
        }
    return out


def summarize(results: list[Result]) -> str:
    bs = benign_split(results)
    results = malicious(results)
    n = len(results)
    counts = Counter(r.decision.value for r in results)
    sp = split(results)
    shares = [r.other_share for r in results]
    by_family = Counter(r.variant.scenario for r in allowed(results))
    base = [r.other_share for r in results if r.variant.name == "baseline"]
    answers: Counter[str] = Counter()
    for r in results:
        for answer, outcome in r.holds.items():
            answers[f"{answer}: {outcome.split(':')[0].split(' (')[0]}"] += 1
    benign_lines = [
        f"benign variants, {name}: {g['variants']}: allow {g['allow']}, hold {g['hold']}, "
        f"block {g['block']} ("
        + (
            "false block rate"
            if name == "neutral"
            else "block rate, expected: the mutation adds it"
        )
        + f" {g['false_block_rate']:.1%}, worse than the unmodified file {g['above_expected']})"
        for name, g in bs.items()
    ]
    return "\n".join(
        [
            f"malicious variants {n}: block {counts['block']}, hold {counts['hold']}, "
            f"allow {counts['allow']}",
            f"block {sp['block']}, effective hold {sp['effective_hold']}, uncontained "
            f"{sp['uncontained']} (allow {sp['allow']} + hold that pauses nothing "
            f"{sp['hold_pauses_nothing']}); blocks that act on nothing: "
            f"{sp['blocks_acting_on_nothing']}",
            f"allowed malicious variants (excluding baselines): {len(allowed(results))}",
            "share of role 'other' in the unmodified malicious files: "
            f"mean {sum(base) / len(base):.3f}",
            "what people can do at a hold: "
            + "; ".join(f"{k} x{v}" for k, v in sorted(answers.items())),
            f"share of processes in role 'other': mean {sum(shares) / n:.3f}, "
            f"max {max(shares):.2f}",
            "allowed per scenario: " + ", ".join(f"{k}={v}" for k, v in sorted(by_family.items())),
            *benign_lines,
        ]
    )


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="refmon.variants")
    parser.add_argument("--golden", default="tests/golden")
    parser.add_argument("--known-gaps", default="tests/variants/known_gaps.yaml")
    parser.add_argument("--out", default="build/robustness-matrix.csv")
    parser.add_argument("--allowed-out", default="build/allowed-variants.csv")
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args(argv)

    policy = default_policy()
    cases = load_golden_cases(args.golden)
    results = run_all(generate(cases, policy, args.seed), policy)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    write_csv(results, args.out)
    Path(args.allowed_out).write_text(render_allowed(results), encoding="utf-8")
    print(summarize(results))
    benign_shares = [
        other_share(list(ReplaySource(c.events_path, extra_roles=policy.extra_roles)))
        for c in cases
        if c.expected.kind is ScenarioKind.BENIGN
    ]
    mean_share = sum(benign_shares) / len(benign_shares)
    print(f"benign golden workload, share of role 'other': mean {mean_share:.3f}")
    gaps = load_known_gaps(args.known_gaps) if Path(args.known_gaps).exists() else []
    missing = undocumented(results, gaps)
    for r in missing:
        print(
            f"UNDOCUMENTED allowed variant: {r.variant.scenario} {r.variant.name}", file=sys.stderr
        )
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
