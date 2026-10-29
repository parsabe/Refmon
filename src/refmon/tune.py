"""Tune: feedback becomes proposals, and nothing applies without a person (CLAUDE.md Phase 4).

"False alarm" proposes a scoped, expiring exception for the rules that fired and, when the story
broke a contract, a contract extension (the same per-change proposal that learning mode writes).
"Confirmed" proposes block-list entries: fingerprints of the labeled objects of the story. Observe
checks them on the next event (`threat_list_hit`). A suggestion only changes the policy data
returned by `apply_suggestion`, after an approver has named what they accept, and that data still
has to be signed before it loads.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .learning import Approval, ContractLearner, ContractProposal, apply_proposal, approve
from .pipeline.pipeline import Pipeline
from .rules import SIGNAL_RULE_IDS, rule_id
from .schemas import EventType, Verdict

BLOCKLIST_NAME = "confirmed-local"
BLOCKABLE_CLASSES = {
    "network_endpoint",
    "command_text",
    "executable_file",
    "script_file",
    "startup_item",
}


class Feedback(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict_id: str
    kind: Literal["false_alarm", "confirmed"]
    by: str


class ExceptionProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    reason: str
    scope: dict[str, str]
    disables: list[str]
    expires: str


class BlocklistProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    list_name: str = BLOCKLIST_NAME
    kind: str = "fingerprint"
    entries: list[str] = Field(default_factory=list)


class Suggestion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["proposed", "approved"] = "proposed"
    feedback: Feedback
    exception: ExceptionProposal | None = None
    contract_extension: ContractProposal | None = None
    blocklist: BlocklistProposal | None = None
    accepted: list[Literal["exception", "contract_extension", "blocklist"]] = Field(
        default_factory=list
    )
    approvals: list[Approval] = Field(default_factory=list)
    note: str = ""


class Tuner:
    def __init__(self, pipeline: Pipeline, today: Callable[[], date] | None = None) -> None:
        self.pipeline = pipeline
        self._today = today or (lambda: datetime.now(UTC).date())

    def suggest(self, feedback: Feedback, verdict: Verdict) -> Suggestion:
        record = self.pipeline.linker.records.get(verdict.story_id)
        if record is None:
            raise KeyError(f"unknown story {verdict.story_id}")
        if feedback.kind == "confirmed":
            return self._confirmed(feedback, record)
        return self._false_alarm(feedback, record)

    # -- false alarm -------------------------------------------------------------------------

    def _false_alarm(self, feedback: Feedback, record) -> Suggestion:
        judgement = self.pipeline.judge(record)
        fired = {rule_id(s.name) for s in judgement.signals}
        if judgement.failed["origin"]:
            fired.add("R-ORI-EXTERNAL")
        disables = sorted(fired & SIGNAL_RULE_IDS)
        by_event = {e.event_id: e for e in record.events}
        actors = [by_event[s.event_id].actor for s in judgement.signals if s.event_id in by_event]
        actor = actors[0] if actors else record.events[0].actor
        note = ""
        exception = None
        if disables:
            days = self.pipeline.policy.tune.exception_days
            exception = ExceptionProposal(
                id="X-new",
                reason=f"False alarm reported by {feedback.by} for verdict {feedback.verdict_id}",
                scope={"role": actor.role, "user": actor.user},
                disables=disables,
                expires=(self._today() + timedelta(days=days)).isoformat(),
            )
        elif judgement.override is not None:
            note = "The decision came from an override; overrides cannot be excepted."
        extension = None
        if judgement.failed["contract"]:
            learner = ContractLearner(self.pipeline.policy)
            for event in record.events:
                learner.learn(event)
            proposal = learner.proposal()
            roles = {r: rp for r, rp in proposal.roles.items() if rp.changes}
            if roles:
                extension = proposal.model_copy(update={"roles": roles})
        return Suggestion(
            feedback=feedback, exception=exception, contract_extension=extension, note=note
        )

    # -- confirmed ---------------------------------------------------------------------------

    def _confirmed(self, feedback: Feedback, record) -> Suggestion:
        from .contain import Contain

        labeled = set(Contain(self.pipeline.tagger).labeled_processes(record))
        entries = []
        for event in record.events:
            fp = event.object.fingerprint
            blockable = event.object.class_ in BLOCKABLE_CLASSES
            if event.actor.id in labeled and fp and blockable and fp not in entries:
                entries.append(fp)
        if not entries and any(e.type is EventType.EXEC for e in record.events):
            note = "Nothing in the story carries a label, so there is nothing safe to block-list."
        else:
            note = ""
        blocklist = BlocklistProposal(entries=entries) if entries else None
        return Suggestion(feedback=feedback, blocklist=blocklist, note=note)


def approve_suggestion(
    suggestion: Suggestion, approver: str, accept: list[str], *, at: str = ""
) -> Suggestion:
    if not approver.strip():
        raise ValueError("an approval needs the name of the approving person")
    present = {
        "exception": suggestion.exception,
        "contract_extension": suggestion.contract_extension,
        "blocklist": suggestion.blocklist,
    }
    missing = [a for a in accept if present.get(a) is None]
    if not accept or missing:
        raise ValueError(f"nothing to accept for {missing or 'an empty choice'}")
    extension = suggestion.contract_extension
    if "contract_extension" in accept and extension is not None:
        extension = approve(extension, approver, include_relax=True, at=at)
    return suggestion.model_copy(
        update={
            "status": "approved",
            "accepted": list(accept),
            "contract_extension": extension,
            "approvals": [*suggestion.approvals, Approval(by=approver, at=at)],
        }
    )


def apply_suggestion(policy_data: dict[str, Any], suggestion: Suggestion) -> dict[str, Any]:
    """New policy data with what an approver accepted. The result still has to be signed."""
    if suggestion.status != "approved" or not suggestion.approvals:
        raise PermissionError("only a suggestion approved by a person can be applied")
    data = {**policy_data}
    if "exception" in suggestion.accepted and suggestion.exception is not None:
        existing = list(data.get("exceptions", []))
        number = 1 + sum(1 for e in existing if str(e.get("id", "")).startswith("X-"))
        item = suggestion.exception.model_dump()
        item["id"] = f"X-{number:03d}"
        data["exceptions"] = [*existing, item]
    if "contract_extension" in suggestion.accepted and suggestion.contract_extension is not None:
        data = apply_proposal(data, suggestion.contract_extension)
    if "blocklist" in suggestion.accepted and suggestion.blocklist is not None:
        lists = [dict(item) for item in data.get("threat_lists", [])]
        target = next((x for x in lists if x["name"] == suggestion.blocklist.list_name), None)
        if target is None:
            target = {
                "name": suggestion.blocklist.list_name,
                "kind": suggestion.blocklist.kind,
                "entries": [],
            }
            lists.append(target)
        target["entries"] = list(dict.fromkeys([*target["entries"], *suggestion.blocklist.entries]))
        data["threat_lists"] = lists
    return data
