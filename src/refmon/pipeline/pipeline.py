"""The core pipeline: Observe, Tag, Link, Judge (Phase 1). Gate, Contain, Report arrive later."""

from __future__ import annotations

import copy
import logging

from ..policy import Policy
from ..schemas import Action, Decision, Event, Mode, QuestionResult, RawEvent, Verdict
from .judge import Judgement, judge
from .link import Linker, StoryRecord
from .observe import Observe
from .rates import CountedRates, StatRates
from .signals import extract
from .tag import Tagger

_RANK = {Decision.ALLOW: 0, Decision.HOLD: 1, Decision.BLOCK: 2}
log = logging.getLogger("refmon.pipeline")


def _log_engine_fallback(policy: Policy) -> None:
    log.warning(
        "decision engine fallback: no weights are configured, so the plain 3/2/1 rule decides "
        "(A28); the heartbeat reports it as degraded protection"
    )


class Pipeline:
    def __init__(
        self,
        policy: Policy,
        key: bytes = b"refmon-device-key",
        *,
        features=None,
        rates=None,
        gate: bool = False,
        notifier=None,
        baseline=None,
    ) -> None:
        self.policy = policy
        if policy.engine_fallback:
            _log_engine_fallback(policy)
        self.observe = Observe(policy, key, features=features)
        self.tagger = Tagger(policy)
        self.baseline = baseline  # per-role event counts for contract rarity (C11.3)
        if rates is None:
            rates = StatRates(policy) if policy.statistical_rates else CountedRates(policy)
        self.rates = rates
        self.linker = Linker(policy, self.tagger)
        self._verdicts = 0
        self.last: dict[str, Judgement] = {}
        self.gate = None
        if gate:  # Phase 3: act on the verdicts (observe never acts, warn never blocks)
            from ..gate import Gate

            self.gate = Gate(policy, self.tagger, notifier)

    # -- Core protocol --

    def process(self, event: RawEvent | Event) -> list[Verdict | Action]:
        ev = self.observe(event)
        parent_known = ev.actor.parent in self.tagger.procs
        tg = self.tagger.process(ev)
        signals, flags = extract(ev, tg, self.tagger, self.policy, self.rates, self.baseline)
        rec = self.linker.assign(tg, parent_known, signals, flags)
        j = self.judge(rec)
        self.last[rec.story.story_id] = j
        if hasattr(self.rates, "mark_incident"):  # baselines stay frozen while an incident is open
            self.rates.mark_incident(
                self.tagger.root_of(ev.actor.id), j.decision is not Decision.ALLOW
            )
        persistent_new = [i for i in tg.new_labels if self.tagger.labels[i].persistent]
        if persistent_new:  # D21: remember the Contract signals of the story that made the item
            self.tagger.set_evidence(
                persistent_new,
                tuple(sorted({s.name for s in j.signals if s.question == "contract"})),
            )
        own = tuple(
            sorted({s.name for s in j.signals if s.question == "contract" and not s.carried})
        )
        if own:  # v1.1 (A49): the labels behind a Contract violation keep their strength
            thr = self.policy.thresholds.origin_strength
            live = [i for i in rec.label_ids if self.tagger.strength(i, ev.ts) >= thr]
            self.tagger.set_evidence(live, own, ev.ts)
        out = self._emit(rec, j)
        if self.gate is not None:
            out = [*self.gate.tick(ev.ts), *out, *self.gate.handle(rec, j, ev.ts, rec.verdict_id)]
        return out

    def probe(self) -> Pipeline:
        """An isolated copy of this pipeline as it is configured now, for the self-test (Phase 6).

        It has the live policy, rates, baseline and code, so a protection that was switched off or
        broken in the live pipeline is switched off or broken in the copy. Nothing that happens in
        the copy reaches the live state, the enforcer, a notifier or a report.
        """
        from ..gate import RecordingNotifier

        notifier = self.gate.notifier if self.gate is not None else None
        if self.gate is not None:
            self.gate.notifier = RecordingNotifier()  # a real notifier may hold sockets
        try:
            clone = copy.deepcopy(self)
        finally:
            if self.gate is not None:
                self.gate.notifier = notifier
        return clone

    def set_policy(self, policy: Policy) -> None:
        """Switch every stage to a new effective policy (a reloaded one, or with the exposure
        overlay). Threat lists are rebuilt only when they changed."""
        lists_changed = policy.threat_lists != self.policy.threat_lists
        if policy.engine_fallback and not self.policy.engine_fallback:
            _log_engine_fallback(policy)
        self.policy = policy
        for stage in (self.observe, self.tagger, self.linker, self.rates, self.gate):
            if stage is not None:
                stage.policy = policy
        if self.gate is not None:
            self.gate.contain.tagger = self.tagger
        if lists_changed:
            self.observe.threat_lists = type(self.observe.threat_lists)(policy)

    def judge(self, rec: StoryRecord) -> Judgement:
        return judge(rec, self.tagger, self.policy)

    # -- results --

    def judgements(self) -> dict[str, Judgement]:
        return {sid: self.judge(rec) for sid, rec in self.linker.records.items()}

    def record(self, story_id: str) -> StoryRecord:
        return self.linker.records[story_id]

    def best(self) -> Judgement | None:
        """The story with the highest decision, ties broken by most failed questions."""
        js = list(self.judgements().values())
        return max(js, key=lambda j: (_RANK[j.decision], j.fail_count), default=None)

    def best_by_rule(self) -> Judgement | None:
        js = list(self.judgements().values())
        return max(js, key=lambda j: (_RANK[j.rule_decision], j.fail_count), default=None)

    # -- verdicts --

    def _emit(self, rec: StoryRecord, j: Judgement) -> list[Verdict | Action]:
        reasons = tuple(sorted({s.name for s in j.signals}))
        sig = (j.decision, j.rule_decision, j.override, j.effects, reasons)
        if sig == rec.emitted or j.decision is Decision.ALLOW:
            return []
        rec.emitted = sig
        verdict = self.verdict(rec, j)
        rec.verdict_id = verdict.verdict_id
        return [verdict]

    def verdict(self, rec: StoryRecord, j: Judgement) -> Verdict:
        self._verdicts += 1

        def q(name: str) -> QuestionResult:
            sigs = [s for s in j.signals if s.question == name]
            s = (
                j.origin_strength
                if name == "origin"
                else max((x.strength for x in sigs), default=0.0)
            )
            reasons = tuple(dict.fromkeys(x.name for x in sigs)) if name != "origin" else ()
            return QuestionResult(
                failed=j.failed[name], strength=min(1.0, max(0.0, s)), reasons=reasons
            )

        return Verdict(
            verdict_id=f"v-{self._verdicts}", story_id=rec.story.story_id, device=rec.story.device,
            ts=j.ts, mode=j.mode, decision=j.decision, rule_decision=j.rule_decision,
            origin=q("origin"), contract=q("contract"), effect=q("effect"),
            effects=j.effects, override=j.override,
            users=tuple(sorted({e.actor.user for e in rec.events})),
            prior_log_odds=j.prior_log_odds, log_odds=j.log_odds, contributions=j.contributions,
            threshold_crossed=j.threshold_crossed, contract_gate=j.gated,
            virtual_patch=j.protection_reasons,
        )  # fmt: skip


def mode_name(policy: Policy) -> Mode:
    return policy.mode
