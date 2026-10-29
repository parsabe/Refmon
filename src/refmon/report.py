"""Report: verdicts a non-expert service desk can read (CLAUDE.md Phase 4).

Every report answers three questions in plain words: what happened, what Refmon did about it, and
what the service desk should do next. The text is built from fixed phrases chosen by the verdict's
reasons, effects, override, mode and the actions taken, never from event content (there is none
after Observe). Tactic names come from MITRE ATT&CK Enterprise (`tactics.py`). A report leaves the
device only through `export`, which replaces device and user names by pseudonyms.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from .pipeline.pipeline import Pipeline
from .pseudonym import Pseudonymizer
from .schemas import Action, ActionType, Decision, Mode, Override, Verdict
from .tactics import tactics_for

SOURCE_TEXT = {
    "web": "a web page",
    "mail": "an email",
    "removable": "a USB stick or other removable medium",
    "download": "a downloaded file",
    "inbound_request": "a request from the internet",
    "outbound_response": "an answer the server fetched from another site",
    "package": "a software package",
    "agent_input": "text given to an AI assistant",
}

CONTRACT_TEXT = {
    "contract_external_exec": "ran a command that was copied in from outside",
    "contract_web_worker_exec": "started another program, which a web server worker never does",
    "contract_exec_violation": "started a program that is not on its list",
    "contract_write_executable": "wrote a program file it is not allowed to write",
    "contract_write_other": "wrote files outside its normal area",
    "contract_connect_violation": "connected to a place outside its normal list",
    "contract_persist_violation": "set itself up to start again later",
    "contract_asset_violation": "touched data it has no reason to touch",
    "contract_privilege_violation": "raised its own access level",
    "contract_surprisal": "did something this kind of program almost never does",
    "contract_universal_violation": "did something no program may do without explicit permission",
    "contract_unsigned_launch": "started an unsigned file that came from outside",
}

EFFECT_TEXT = {
    "fetch": "tried to reach or download from an unknown place",
    "hide": "tried to hide what it was doing",
    "persist": "tried to start again after a restart",
    "escalate": "tried to gain more access rights",
    "lateral": "tried to reach many other computers",
    "exfil": "sent out an unusual amount of data",
    "tamper": "tried to switch off security tools or erase logs",
    "credential": "tried to read saved passwords or keys",
    "asset_access": "tried to read protected data",
    "mass_change": "changed a very large number of files very quickly",
    "response_anomaly": "sent unusually large replies",
    "threat_list_hit": "contacted something on a list of known bad places",
}

OVERRIDE_TEXT = {
    Override.CANARY: "It touched a decoy that no real program should touch.",
    Override.PROTECTED_ASSET: "A program that came from outside read protected data.",
    Override.SELF_TAMPER: "Someone tried to stop or change Refmon itself.",
    Override.TRUSTED_ROOT: "It came from a trusted source.",
}

ACTION_TEXT = {
    ActionType.HOLD: "paused the program",
    ActionType.KILL_PROCESS_TREE: "stopped the program and everything it started",
    ActionType.CUT_NETWORK: "cut its network connection",
    ActionType.QUARANTINE_FILE: "moved new files to quarantine (nothing was deleted)",
    ActionType.REVERT_PERSISTENCE: "removed its start-up entries",
    ActionType.RESTORE_FILE: "restored changed files from their last good copy",
    ActionType.ISOLATE_HOST: "isolated the computer from the network",
    ActionType.BLOCK: "blocked the action",
}
_ACTION_ORDER = list(ACTION_TEXT)


def _join(parts: list[str]) -> str:
    if len(parts) <= 1:
        return "".join(parts)
    return ", ".join(parts[:-1]) + " and " + parts[-1]


def what_happened(verdict: Verdict, sources: set[str]) -> str:
    sentences = []
    if verdict.origin.failed and sources:
        where = _join(sorted(SOURCE_TEXT.get(s, "outside content") for s in sources))
        sentences.append(f"A program started from something that came in from {where}.")
    elif verdict.origin.failed:
        sentences.append("A program started from something that came in from outside.")
    acts = [CONTRACT_TEXT[r] for r in verdict.contract.reasons if r in CONTRACT_TEXT]
    if acts:
        sentences.append("It " + _join(list(dict.fromkeys(acts))) + ".")
    effects = [EFFECT_TEXT[e] for e in verdict.effects]
    if effects:
        sentences.append("It also " + _join(effects) + ".")
    if verdict.override is not None:
        sentences.append(OVERRIDE_TEXT[verdict.override])
    for reason in verdict.virtual_patch:
        component, _, advisory = reason.partition(":")
        why = "no fix will ever come" if advisory == "end_of_life" else f"advisory {advisory}"
        sentences.append(
            f"Extra protection was on for this kind of program because the software {component} "
            f"is exposed ({why})."
        )
    return " ".join(sentences) or "Nothing unusual was found."


def action_taken(verdict: Verdict, actions: list[Action], platform: str) -> str:
    if verdict.mode is Mode.OBSERVE:
        return "Refmon only recorded this (observe mode). Nothing was stopped or changed."
    if verdict.mode is Mode.WARN:
        return "Refmon only warned (warn mode). Nothing was stopped or changed."
    if verdict.decision is Decision.ALLOW:
        return "Nothing was stopped or changed."
    done = {a.type for a in actions}
    steps = [ACTION_TEXT[t] for t in _ACTION_ORDER if t in done]
    if not steps:
        if verdict.decision is Decision.HOLD:
            return (
                "The user was asked. Nothing could be paused because no program in the story "
                "came from the outside content."
            )
        return "Nothing needed to be stopped."
    text = "Refmon " + _join(steps) + "."
    if verdict.decision is Decision.HOLD:
        who = "an administrator was told" if platform == "server" else "the user was asked"
        text += f" {who[0].upper()}{who[1:]}."
    return text


def next_step(verdict: Verdict, platform: str) -> str:
    if verdict.mode is not Mode.BLOCK and verdict.decision is not Decision.ALLOW:
        return (
            "No action is needed now. If this looks wrong or dangerous, pass it to the "
            "security team."
        )
    if verdict.decision is Decision.BLOCK:
        return (
            "Tell the user their computer was protected and ask what they were doing just before "
            "(opening a file, pasting a command, using a website). Pass it to the security team. "
            "Do not release anything from quarantine without them."
        )
    if verdict.decision is Decision.HOLD and platform == "server":
        return (
            "An administrator must either release the paused service or confirm the attack. "
            "Until then it stays paused and quarantined."
        )
    if verdict.decision is Decision.HOLD:
        return (
            "Wait for the user's answer; without one the program is stopped. If the user says it "
            "was expected, mark it as a false alarm so the security team can review it."
        )
    return "No action is needed."


@dataclass(frozen=True)
class Report:
    verdict: Verdict  # summary and tactics filled in, names still real
    what_happened: str
    action_taken: str
    next_step: str
    platform: str


def compose(verdict: Verdict, actions: list[Action], sources: set[str], platform: str) -> Report:
    what = what_happened(verdict, sources)
    did = action_taken(verdict, actions, platform)
    nxt = next_step(verdict, platform)
    summary = f"What happened: {what} Action taken: {did} Next step: {nxt}"
    full = verdict.model_copy(update={"summary": summary[:1000], "tactics": tactics_for(verdict)})
    return Report(full, what, did, nxt, platform)


class Reporter:
    """Collects verdicts and actions from a pipeline and keeps the latest report per story."""

    def __init__(self, pipeline: Pipeline, pseudonymizer: Pseudonymizer | None = None) -> None:
        self.pipeline = pipeline
        self.pseudonymizer = pseudonymizer
        self._verdicts: dict[str, Verdict] = {}
        self._actions: dict[str, list[Action]] = defaultdict(list)
        self.reports: dict[str, Report] = {}

    def consume(self, outputs: Iterable[Verdict | Action]) -> list[Report]:
        touched: list[str] = []
        for out in outputs:
            if isinstance(out, Verdict):
                self._verdicts[out.story_id] = out
            else:
                self._actions[out.story_id].append(out)
            if out.story_id not in touched:
                touched.append(out.story_id)
        built = []
        for story_id in touched:
            verdict = self._verdicts.get(story_id)
            if verdict is None:
                continue
            record = self.pipeline.linker.records.get(story_id)
            sources = set()
            platform = "endpoint"
            if record is not None:
                labels = self.pipeline.tagger.labels
                sources = {labels[i].source_class.value for i in record.label_ids if i in labels}
                roles = {e.actor.role for e in record.events}
                platform = self.pipeline.policy.platform_for(record.story.device, roles)
            report = compose(verdict, self._actions[story_id], sources, platform)
            self.reports[story_id] = report
            built.append(report)
        return built

    def export(self, report: Report) -> Verdict:
        """The verdict as it may leave the device: pseudonyms for the device and the users."""
        verdict = report.verdict
        if not self.pipeline.policy.reporting.pseudonymize:
            return verdict
        if self.pseudonymizer is None:
            raise ValueError("the policy asks for pseudonyms but there is no pseudonymizer")
        return verdict.model_copy(
            update={
                "device": self.pseudonymizer.device(verdict.device),
                "users": tuple(self.pseudonymizer.user(u) for u in verdict.users),
            }
        )
