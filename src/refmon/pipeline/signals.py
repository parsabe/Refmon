"""Signal extraction: what one observed event says about the three questions.

A Signal is a named piece of evidence for Origin (labels), Contract or Effect. The names are the
weights of CLAUDE.md C11. The fail-count rule and, from Phase 4b, the evidence calculus both read
the same signals. "Allowed" signals are Effects that a role's contract allows; the Judge keeps them
only in a story with an external origin label (design decision D23).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..behaviour import behaviour_kind
from ..calculus.rarity import Baseline
from ..policy import Policy
from ..schemas import Event, EventType
from .rates import CountedRates, StatRates
from .tag import Tagged, Tagger


@dataclass(frozen=True)
class Signal:
    name: str
    strength: float
    event_id: str
    allowed: bool = False  # an Effect the actor's contract allows (D23)
    carried: bool = False  # evidence carried by a persistent label (D21)
    role: str = ""  # role of the acting process, for per-role rule modes

    @property
    def question(self) -> str:
        return self.name.split("_", 1)[0]


def extract(
    ev: Event,
    tg: Tagged,
    tagger: Tagger,
    policy: Policy,
    rates: CountedRates | StatRates,
    baseline: Baseline | None = None,
) -> tuple[list[Signal], set[str]]:
    """Return the signals of one event and any override flags it raises."""
    ts, role = ev.ts, ev.actor.role
    contract = policy.contract_for(role)
    thr = policy.thresholds.origin_strength
    a_strength = tagger.combined(tg.actor_labels, ts)
    o_strength = tagger.combined(tg.object_labels, ts)
    labeled_actor, labeled_obj = a_strength >= thr, o_strength >= thr
    # v1.3 (A55): a Contract or Effect signal counts at full strength. Before, it counted at the
    # strength of the label behind it while that label was above the origin threshold and at 1.0
    # below it, so a weaker label could give stronger evidence (F8). Only Origin carries the
    # label's strength now, and a weaker label never produces stronger evidence.
    strength = 1.0
    sigs: list[Signal] = []
    flags: set[str] = set()
    attrs = ev.attrs
    root = tagger.root_of(ev.actor.id)
    t = ts.timestamp()

    # A contract that learning mode created is enforced only once its baseline is mature; until
    # then the Contract signals of that role are absent, not raised (missing information).
    maturity = policy.math.baseline_maturity_unseen
    immature = role in policy.learned_roles and not (
        baseline is not None and baseline.mature(role, maturity)
    )

    def add(name: str, s: float = strength, allowed: bool = False) -> None:
        if immature and name.startswith("contract_"):
            return
        sigs.append(Signal(name, s, ev.event_id, allowed, role=role))

    def universal(flag: str, effect: str) -> None:
        if contract is not None and getattr(contract, flag):
            add(effect, allowed=True)  # in role: the Effect counts only in a labeled story (D23)
        else:
            add("contract_universal_violation")
            add(effect)

    if attrs.get("threat_list_hit"):
        add("effect_threat_list_hit")
    if attrs.get("canary_hit"):
        flags.add("canary")

    typ = ev.type
    if typ is EventType.EXEC:
        # v1.1 (A46): running external command text is forbidden for every role unless its
        # contract explicitly allows it. A role whose contract says `deny` keeps the wider rule
        # (any exec by a labeled process counts); a role with no setting gets the default, which
        # needs the executed text itself to carry the label. Starting an external *file* stays
        # with the launcher contract (C4).
        setting = contract.external_content_exec if contract is not None else None
        if setting == "deny":
            external = labeled_obj or labeled_actor
        else:
            external = setting is None and labeled_obj and ev.object.class_ == "command_text"
        if external:
            add("contract_external_exec")
        if contract is not None:
            if (
                contract.may_exec is not None
                and attrs.get("exec_class", "unknown") not in contract.may_exec
            ):
                add(
                    "contract_web_worker_exec"
                    if role in policy.strict_exec_roles
                    else "contract_exec_violation"
                )
            if (
                contract.unsigned_external_exec == "deny"
                and labeled_obj
                and attrs.get("signed") is False
            ):
                add("contract_unsigned_launch")
        if attrs.get("hidden_window") or attrs.get("encoded_payload") or _obfuscated(attrs, policy):
            add("effect_hide")
    elif typ is EventType.NET_CONNECT:
        dest = attrs.get("destination_class", "unknown")
        allowed_classes = contract.may_connect if contract is not None else None
        restricted = role in policy.restricted_network_roles  # virtual patching (Phase 5)
        if restricted and allowed_classes is None:
            allowed_classes = ()  # an exposed role may connect only where its contract says
        in_contract = allowed_classes is not None and (
            "any" in allowed_classes or dest in allowed_classes
        )
        d = policy.destination(dest)
        trusted = bool(d and d.trusted) and not restricted  # trust no longer excuses a connection
        # v1.5 (A60): trust excuses only a process with no live external provenance in its lineage.
        # Until v1.4 the label had to be at the origin threshold, so a process whose label had
        # faded under it (or whose request had ended) could use any trusted class freely (F2).
        proc = tagger.procs.get(ev.actor.id)
        lineage = bool(proc and tagger.alive(proc.ever, ts))
        if allowed_classes is not None and not in_contract:
            add("contract_connect_violation")
        # v1.1 (A48): a trusted class excuses a connection only for a role whose contract lists it
        # (then it is in_contract); for any other role a labeled process connecting there is a
        # fetch. An unlabeled process of an unlisted role keeps the trust of the class.
        if not in_contract and (not trusted or labeled_actor or lineage):
            add("effect_fetch")
        if d is not None and d.internal and rates.lateral(root, role, t, ev.object.fingerprint):
            universal("may_fan_out", "effect_lateral")
        nbytes = attrs.get("bytes")
        if isinstance(nbytes, (int, float)) and rates.exfil(root, role, t, float(nbytes)):
            add("effect_exfil")
    elif typ is EventType.FILE_WRITE:
        if contract is not None and contract.may_write is not None:
            if attrs.get("executable") is True:
                add("contract_write_executable")
            elif attrs.get("path_group") not in contract.may_write:
                add("contract_write_other")
        if (
            attrs.get("executable") is True
            and attrs.get("new_file") is True
            and "web_root" in attrs
        ):
            add("effect_persist")
        if rates.mass_change(root, role, t, ev.object.fingerprint):
            universal("may_mass_change", "effect_mass_change")
    elif typ is EventType.PERSIST:
        if contract is not None and contract.may_persist is False:
            add("contract_persist_violation")
        add("effect_persist")
    elif typ is EventType.ASSET_ACCESS:
        asset = attrs.get("protected_asset")
        cls = ev.object.class_
        readable = contract.may_read_assets if contract is not None else None
        permitted = readable is not None and (asset in readable or cls in readable)
        if readable is not None and not permitted:
            add("contract_asset_violation")
        if not permitted:
            if cls in policy.credential_classes:
                add("effect_credential")
            if asset:
                add("effect_asset_access")
        if asset and labeled_actor:
            flags.add("protected_asset")
    elif typ is EventType.PRIV_CHANGE:
        allowed_priv = contract.may_change_privilege if contract is not None else None
        if allowed_priv is False:
            add("contract_privilege_violation")
        if allowed_priv is not True:
            add("effect_escalate")
    elif typ is EventType.SECURITY_TAMPER:
        if ev.object.class_ == "refmon_component":
            flags.add("self_tamper")
        universal("may_tamper", "effect_tamper")
    elif typ is EventType.RESPONSE_OUT:
        nbytes = attrs.get("bytes")
        if isinstance(nbytes, (int, float)):
            anomalous, repeated = rates.response(
                ev.object.fingerprint or ev.actor.id, role, t, float(nbytes)
            )
            if repeated:
                universal("may_repeat_large_responses", "effect_response_anomaly_repeated")
            elif anomalous:
                add("effect_response_anomaly")
    if (
        baseline is not None
        and baseline.mature(role, maturity)
        and not _explicitly_allowed(ev, contract)
        and baseline.surprisal(role, behaviour_kind(ev)) >= policy.math.surprisal_max_bits
    ):
        add("contract_surprisal")  # rare for this role, and no contract entry covers it
    return sigs, flags


def _explicitly_allowed(ev: Event, contract) -> bool:
    """The role's contract lists this exact thing, so rarity alone must not make it a violation."""
    if contract is None:
        return False
    attrs = ev.attrs
    listed = {
        EventType.EXEC: (contract.may_exec, attrs.get("exec_class", "unknown")),
        EventType.NET_CONNECT: (contract.may_connect, attrs.get("destination_class", "unknown")),
        EventType.FILE_WRITE: (contract.may_write, attrs.get("path_group")),
        EventType.ASSET_ACCESS: (contract.may_read_assets, attrs.get("protected_asset")),
    }.get(ev.type)
    if listed is None or listed[0] is None:
        return False
    return "any" in listed[0] or listed[1] in listed[0]


def _obfuscated(attrs: dict, policy: Policy) -> bool:
    entropy = attrs.get("entropy_bits")
    run = attrs.get("longest_ws_run")
    return (isinstance(entropy, (int, float)) and entropy > policy.math.entropy_max_bits) or (
        isinstance(run, (int, float)) and run > policy.math.ws_run_max
    )
