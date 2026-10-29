"""Continuous self-test (CLAUDE.md Phase 6): is each enabled protection actually working?

On a schedule the scheduler injects harmless synthetic stories, one per protection, into an
isolated copy of the live pipeline (`Pipeline.probe`) and checks the expected outcome. The copy has
the live policy, rates and code, so a protection that was switched off or broken in the live
pipeline fails here. The stories carry the device `selftest-<n>`, are never given to the live
pipeline, and nothing from the copy reaches an enforcer, a notifier or a report: tests are never
incidents.

What *should* work comes from the signed policy (`intent`), not from the live pipeline: a protection
the signed policy switched off is skipped (and the heartbeat lists it); a protection the signed
policy enables that fails in the live pipeline raises the alert "protection X is not working".
A case also declares when it does not apply to a policy (a contract the policy does not have), so a
custom policy is not blamed for something it never asked for.

The synthetic content is made of placeholder labels only; fingerprints are HMACs of those labels.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .alerts import Alert, AlertLog
from .pipeline.pipeline import Pipeline
from .policy import Policy
from .schemas import Action, ActionType, Decision, Event, Mode, Override, Verdict

SELFTEST_PREFIX = "selftest-"
_KEY = b"refmon-selftest-placeholder-key"  # fingerprints of placeholder labels, never of content


def fingerprint(label: str) -> str:
    return "hmac:" + hmac.new(_KEY, label.encode(), hashlib.sha256).hexdigest()


class Story:
    """Builds the events of one synthetic story."""

    def __init__(self, case: str, serial: int, start: datetime, policy: Policy) -> None:
        self.case, self.device, self.policy = case, f"{SELFTEST_PREFIX}{serial}", policy
        self._clock = start
        self.events: list[Event] = []

    def who(self, name: str, role: str, parent: str | None = None) -> dict:
        actor = {
            "id": f"{SELFTEST_PREFIX}{self.case}-{name}"[:64],
            "role": role,
            "interactive": False,
            "user": "selftest",
        }
        if parent:
            actor["parent"] = f"{SELFTEST_PREFIX}{self.case}-{parent}"[:64]
        return actor

    def add(self, type_: str, who: dict, cls: str, label: str | None, **attrs) -> Event:
        self._clock += timedelta(milliseconds=100)
        obj = {"class": cls}
        if label is not None:
            obj["fingerprint"] = fingerprint(f"{self.case}:{label}")
        event = Event.model_validate(
            {
                "event_id": f"selftest-{self.case}-{len(self.events) + 1}"[:64],
                "ts": self._clock,
                "device": self.device,
                "type": type_,
                "actor": who,
                "object": obj,
                "attrs": attrs,
            },
            context={"extra_roles": tuple(self.policy.extra_roles)},
        )
        self.events.append(event)
        return event


@dataclass
class Observed:
    """What the isolated copy did with a synthetic story."""

    signals: set[str]
    failed: dict[str, bool]
    decision: Decision
    rule_decision: Decision
    override: Override | None
    gated: bool
    mode: Mode
    actions: list[Action]
    verdicts: list[Verdict]


@dataclass(frozen=True)
class Case:
    protection: str  # a rule id (R-..., OVR-...) or a structural protection (GATE-..., ...)
    title: str
    build: Callable[[Story], None]
    expect: Callable[[Observed], bool]
    applies: Callable[[Policy], str | None] = lambda policy: None  # None: applies; else the reason


def _contract(policy: Policy, role: str):
    return policy.contract_for(role)


def _needs(cond: bool, reason: str) -> str | None:
    return None if cond else reason


def _burst(policy: Policy) -> int:
    """Enough distinct objects to be a burst under the counted threshold and the Poisson test."""
    return max(policy.rates.mass_change_files, policy.rates.lateral_hosts, 3 * 20)


def _internal_class(policy: Policy) -> str | None:
    return next((d.name for d in policy.destinations if d.internal), None)


def build_catalog() -> list[Case]:
    def sig(name: str) -> Callable[[Observed], bool]:
        return lambda o: name in o.signals

    def c_web(story: Story, kind: str, cls: str, label: str, **attrs):
        story.add(kind, story.who("w", "web_worker"), cls, label, **attrs)

    def other(story: Story, kind: str, cls: str, label: str | None, **attrs):
        story.add(kind, story.who("o", "other"), cls, label, **attrs)

    cases: list[Case] = []
    add = cases.append

    # -- Origin --------------------------------------------------------------------------
    add(
        Case(
            "R-ORI-EXTERNAL",
            "inbound request labels the worker",
            lambda s: c_web(s, "request_in", "request_body", "req", source_class="inbound_request"),
            lambda o: o.failed["origin"],
        )
    )

    # -- Contract ------------------------------------------------------------------------
    def external_exec(s: Story):
        b = s.who("b", "browser")
        s.add("content_in", b, "clipboard_text", "clip", source_class="web")
        s.add("exec", s.who("sh", "interactive_shell"), "command_text", "clip")

    def shell_denies_external(p: Policy) -> str | None:
        c = _contract(p, "interactive_shell")
        return _needs(
            c is not None and c.external_content_exec == "deny", "shell may run external content"
        )

    add(
        Case(
            "R-CON-EXTERNAL-EXEC",
            "shell runs pasted external content",
            external_exec,
            sig("contract_external_exec"),
            shell_denies_external,
        )
    )

    add(
        Case(
            "R-CON-WEB-WORKER-EXEC",
            "web worker starts a program",
            lambda s: c_web(s, "exec", "command_text", "cmd", exec_class="unknown"),
            sig("contract_web_worker_exec"),
            lambda p: _needs(
                "web_worker" in p.strict_exec_roles
                and bool(_contract(p, "web_worker"))
                and _contract(p, "web_worker").may_exec is not None,
                "web_worker has no exec contract",
            ),
        )
    )

    add(
        Case(
            "R-CON-EXEC-VIOLATION",
            "office app starts a program that is not on its list",
            lambda s: s.add(
                "exec", s.who("of", "office"), "command_text", "cmd", exec_class="unknown"
            ),
            sig("contract_exec_violation"),
            lambda p: _needs(
                bool(_contract(p, "office"))
                and _contract(p, "office").may_exec is not None
                and "office" not in p.strict_exec_roles,
                "office has no exec contract",
            ),
        )
    )

    def web_contract(p: Policy, field_: str):
        c = _contract(p, "web_worker")
        return _needs(
            c is not None and getattr(c, field_) is not None, f"web_worker has no {field_}"
        )

    add(
        Case(
            "R-CON-WRITE-EXECUTABLE",
            "web worker writes an executable file",
            lambda s: c_web(
                s,
                "file_write",
                "script_file",
                "f",
                executable=True,
                new_file=True,
                path_group="selftest_web",
            ),
            sig("contract_write_executable"),
            lambda p: web_contract(p, "may_write"),
        )
    )
    add(
        Case(
            "R-CON-WRITE-OTHER",
            "web worker writes outside its places",
            lambda s: c_web(s, "file_write", "data_file", "f", path_group="selftest_elsewhere"),
            sig("contract_write_other"),
            lambda p: web_contract(p, "may_write"),
        )
    )
    add(
        Case(
            "R-CON-CONNECT-VIOLATION",
            "web worker connects to an unknown place",
            lambda s: c_web(
                s, "net_connect", "network_endpoint", "ep", destination_class="unknown"
            ),
            sig("contract_connect_violation"),
            lambda p: web_contract(p, "may_connect"),
        )
    )
    add(
        Case(
            "R-CON-PERSIST-VIOLATION",
            "package installer sets up a start-up entry",
            lambda s: s.add(
                "persist",
                s.who("pi", "package_installer"),
                "startup_item",
                "su",
                persist_kind="startup_entry",
            ),
            sig("contract_persist_violation"),
            lambda p: _needs(
                bool(_contract(p, "package_installer"))
                and _contract(p, "package_installer").may_persist is False,
                "package_installer may persist",
            ),
        )
    )

    def asset_name(p: Policy) -> str | None:
        return p.protected_assets[0].name if p.protected_assets else None

    add(
        Case(
            "R-CON-ASSET-VIOLATION",
            "web worker reads a protected asset",
            lambda s: c_web(
                s,
                "asset_access",
                "credential_store",
                "asset",
                protected_asset=asset_name(s.policy) or "none",
            ),
            sig("contract_asset_violation"),
            lambda p: _needs(
                bool(asset_name(p)) and web_contract(p, "may_read_assets") is None,
                "no protected asset or no asset contract",
            ),
        )
    )
    add(
        Case(
            "R-CON-PRIVILEGE-VIOLATION",
            "app server raises its privileges",
            lambda s: s.add("priv_change", s.who("a", "app_server"), "privilege_level", "root"),
            sig("contract_privilege_violation"),
            lambda p: _needs(
                bool(_contract(p, "app_server"))
                and _contract(p, "app_server").may_change_privilege is False,
                "app_server may change privilege",
            ),
        )
    )
    add(
        Case(
            "R-CON-UNIVERSAL-VIOLATION",
            "a role with no allowance stops a security tool",
            lambda s: other(s, "security_tamper", "security_tool", "av"),
            sig("contract_universal_violation"),
            lambda p: _needs(
                not (_contract(p, "other") and _contract(p, "other").may_tamper),
                "role other may tamper",
            ),
        )
    )

    def unsigned_launch(s: Story):
        s.add(
            "content_in", s.who("b", "browser"), "executable_file", "prog", source_class="download"
        )
        s.add("exec", s.who("l", "launcher"), "executable_file", "prog", signed=False)

    add(
        Case(
            "R-CON-UNSIGNED-LAUNCH",
            "launcher starts an unsigned downloaded program",
            unsigned_launch,
            sig("contract_unsigned_launch"),
            lambda p: _needs(
                bool(_contract(p, "launcher"))
                and _contract(p, "launcher").unsigned_external_exec == "deny",
                "launcher has no unsigned_external_exec deny",
            ),
        )
    )

    # -- Effect --------------------------------------------------------------------------
    add(
        Case(
            "R-EFF-FETCH",
            "a process with no contract connects to an unknown place",
            lambda s: other(
                s, "net_connect", "network_endpoint", "ep", destination_class="unknown"
            ),
            sig("effect_fetch"),
        )
    )
    add(
        Case(
            "R-EFF-HIDE",
            "a hidden window",
            lambda s: other(s, "exec", "command_text", "cmd", hidden_window=True),
            sig("effect_hide"),
        )
    )
    add(
        Case(
            "R-EFF-PERSIST",
            "a start-up entry",
            lambda s: other(s, "persist", "startup_item", "su", persist_kind="startup_entry"),
            sig("effect_persist"),
        )
    )
    add(
        Case(
            "R-EFF-EXFIL",
            "a very large outbound volume",
            lambda s: other(
                s,
                "net_connect",
                "network_endpoint",
                "ep",
                destination_class="unknown",
                bytes=max(s.policy.rates.exfil_bytes, 10**9) * 10,
            ),
            sig("effect_exfil"),
        )
    )
    add(
        Case(
            "R-EFF-ESCALATE",
            "a privilege change",
            lambda s: other(s, "priv_change", "privilege_level", "root"),
            sig("effect_escalate"),
            lambda p: _needs(
                not (_contract(p, "other") and _contract(p, "other").may_change_privilege),
                "role other may change privilege",
            ),
        )
    )
    add(
        Case(
            "R-EFF-TAMPER",
            "a security tool is stopped",
            lambda s: other(s, "security_tamper", "security_tool", "av"),
            sig("effect_tamper"),
        )
    )
    add(
        Case(
            "R-EFF-CREDENTIAL",
            "a credential store is read",
            lambda s: other(s, "asset_access", "credential_store", "cs"),
            sig("effect_credential"),
        )
    )
    add(
        Case(
            "R-EFF-ASSET-ACCESS",
            "a protected asset is read",
            lambda s: other(
                s,
                "asset_access",
                "file_set",
                "asset",
                protected_asset=asset_name(s.policy) or "none",
            ),
            sig("effect_asset_access"),
            lambda p: _needs(bool(asset_name(p)), "no protected asset in the policy"),
        )
    )

    def mass_change(s: Story):
        for i in range(_burst(s.policy)):
            s.add(
                "file_write", s.who("o", "other"), "user_file", f"f{i}", path_group="selftest_files"
            )

    add(
        Case(
            "R-EFF-MASS-CHANGE",
            "many files changed at once",
            mass_change,
            sig("effect_mass_change"),
        )
    )

    def fan_out(s: Story):
        cls = _internal_class(s.policy) or "unknown"
        for i in range(_burst(s.policy)):
            s.add(
                "net_connect",
                s.who("o", "other"),
                "network_endpoint",
                f"h{i}",
                destination_class=cls,
            )

    add(
        Case(
            "R-EFF-LATERAL",
            "many internal hosts at once",
            fan_out,
            sig("effect_lateral"),
            lambda p: _needs(_internal_class(p) is not None, "no internal destination class"),
        )
    )

    def big_replies(s: Story, n: int):
        for _ in range(n):
            s.add(
                "response_out",
                s.who("w", "web_worker"),
                "client",
                "client",
                bytes=s.policy.rates.response_anomaly_bytes * 4,
            )

    add(
        Case(
            "R-EFF-RESPONSE-ANOMALY",
            "an oversized response",
            lambda s: big_replies(s, 1),
            sig("effect_response_anomaly"),
        )
    )
    add(
        Case(
            "R-EFF-RESPONSE-ANOMALY-REPEATED",
            "oversized responses to one client",
            lambda s: big_replies(s, 6),
            sig("effect_response_anomaly_repeated"),
        )
    )
    add(
        Case(
            "R-EFF-THREAT-LIST-HIT",
            "a connection flagged by a threat list",
            lambda s: other(
                s,
                "net_connect",
                "network_endpoint",
                "ep",
                destination_class="unknown",
                threat_list_hit="selftest-list",
            ),
            sig("effect_threat_list_hit"),
        )
    )

    # -- Overrides -----------------------------------------------------------------------
    add(
        Case(
            "OVR-CANARY",
            "a canary is touched",
            lambda s: other(s, "asset_access", "credential_store", "decoy", canary_hit=True),
            lambda o: o.override is Override.CANARY and o.decision is Decision.BLOCK,
        )
    )
    add(
        Case(
            "OVR-SELF-TAMPER",
            "Refmon itself is stopped",
            lambda s: other(s, "security_tamper", "refmon_component", "self"),
            lambda o: o.override is Override.SELF_TAMPER and o.decision is Decision.BLOCK,
        )
    )

    def protected_by_label(s: Story):
        w = s.who("w", "web_worker")
        s.add("request_in", w, "request_body", "req", source_class="inbound_request")
        s.add(
            "asset_access",
            w,
            "credential_store",
            "asset",
            protected_asset=asset_name(s.policy) or "none",
        )

    add(
        Case(
            "OVR-PROTECTED-ASSET",
            "a labeled process reads a protected asset",
            protected_by_label,
            lambda o: o.override is Override.PROTECTED_ASSET and o.decision is Decision.BLOCK,
            lambda p: _needs(bool(asset_name(p)), "no protected asset in the policy"),
        )
    )
    add(
        Case(
            "OVR-TRUSTED-ROOT",
            "content from a trusted source",
            lambda s: s.add(
                "content_in",
                s.who("p", "package_installer"),
                "package_archive",
                "pkg",
                source_class="download",
                trusted_source="selftest-source",
            ),
            lambda o: o.override is Override.TRUSTED_ROOT and o.decision is Decision.ALLOW,
        )
    )

    # -- Decisions and structure ---------------------------------------------------------
    def attack(s: Story):
        w = s.who("w", "web_worker")
        s.add("request_in", w, "request_body", "req", source_class="inbound_request")
        s.add("exec", w, "command_text", "cmd", exec_class="unknown")
        s.add(
            "net_connect",
            s.who("c", "script_host", parent="w"),
            "network_endpoint",
            "ep",
            destination_class="unknown",
        )

    add(
        Case(
            "DECISION-BLOCK",
            "all three questions fail",
            attack,
            lambda o: o.decision is Decision.BLOCK,
            lambda p: _needs(
                p.uses_calculus or p.decisions.fails_3 is Decision.BLOCK,
                "the policy does not block three fails",
            ),
        )
    )

    def origin_and_effect(s: Story):
        a = s.who("a", "app_server")
        s.add("request_in", a, "request_body", "req", source_class="inbound_request")
        s.add("net_connect", a, "network_endpoint", "ep", destination_class="unknown")

    add(
        Case(
            "GATE-CONTRACT",
            "origin and effect without a Contract signal are capped at hold",
            origin_and_effect,
            lambda o: o.decision is Decision.HOLD and (o.gated or not o.failed["contract"]),
            lambda p: _needs(p.uses_calculus, "the contract gate is part of the calculus"),
        )
    )

    def benign(s: Story):
        w = s.who("w", "web_worker")
        s.add("request_in", w, "request_body", "req", source_class="inbound_request")
        s.add("file_write", w, "cache_file", "cache", path_group="cache")

    add(
        Case(
            "BENIGN-ALLOW",
            "a worker writing its cache is allowed",
            benign,
            lambda o: o.decision is Decision.ALLOW,
            lambda p: _needs(
                bool(_contract(p, "web_worker"))
                and "cache" in (_contract(p, "web_worker").may_write or ()),
                "the web worker contract does not list cache",
            ),
        )
    )
    add(
        Case(
            "CONTAIN-KILL",
            "a blocked story is contained",
            attack,
            lambda o: any(a.type is ActionType.KILL_PROCESS_TREE for a in o.actions),
            lambda p: _needs(p.mode is Mode.BLOCK, "the global mode is not block"),
        )
    )
    return cases


@dataclass(frozen=True)
class CaseResult:
    protection: str
    status: str  # passed | failed | skipped
    reason: str = ""


@dataclass
class SelfTestReport:
    ts: datetime
    results: list[CaseResult] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)

    def with_status(self, status: str) -> list[CaseResult]:
        return [r for r in self.results if r.status == status]

    @property
    def passed(self) -> list[str]:
        return [r.protection for r in self.with_status("passed")]

    @property
    def failed(self) -> list[str]:
        return [r.protection for r in self.with_status("failed")]

    @property
    def skipped(self) -> list[str]:
        return [r.protection for r in self.with_status("skipped")]

    @property
    def ok(self) -> bool:
        return not self.failed


class SelfTestScheduler:
    def __init__(
        self,
        pipeline: Pipeline,
        intent: Policy | object,
        alerts: AlertLog | None = None,
        catalog: list[Case] | None = None,
    ) -> None:
        self.pipeline = pipeline
        self._intent = intent
        self.alerts = alerts if alerts is not None else AlertLog()
        self.catalog = catalog if catalog is not None else build_catalog()
        self.last: SelfTestReport | None = None
        self._serial = 0

    @property
    def intent(self) -> Policy:
        """What the signed policy says should be in force."""
        return self._intent if isinstance(self._intent, Policy) else self._intent.policy

    def due(self, now: datetime) -> bool:
        return (
            self.last is None
            or (now - self.last.ts).total_seconds() >= self.intent.self_test.interval
        )

    def tick(self, now: datetime) -> SelfTestReport | None:
        return self.run(now) if self.due(now) else None

    def _baseline_cases(self) -> list[Case]:
        """Rarity needs a baseline: a case exists only for a role whose baseline is mature."""
        baseline = self.pipeline.baseline
        if baseline is None:
            return []
        mature = self.intent.math.baseline_maturity_unseen
        bits = self.intent.math.surprisal_max_bits
        roles = [r for r in baseline.counts if baseline.mature(r, mature) and r not in ("other",)]
        for role in roles:
            if baseline.surprisal(role, "persist") >= bits:
                return [
                    Case(
                        "R-CON-SURPRISAL",
                        f"{role} does something it never does",
                        lambda s, role=role: s.add(
                            "persist",
                            s.who("r", role),
                            "startup_item",
                            "su",
                            persist_kind="startup_entry",
                        ),
                        lambda o: "contract_surprisal" in o.signals,
                        lambda p, role=role: _needs(
                            not (_contract(p, role) and _contract(p, role).may_persist),
                            f"{role} may persist",
                        ),
                    )
                ]
        return []

    def run(self, now: datetime) -> SelfTestReport:
        intent = self.intent
        report = SelfTestReport(ts=now)
        probe = self.pipeline.probe()
        for case in [*self.catalog, *self._baseline_cases()]:
            if not intent.rule_enabled(case.protection):
                report.results.append(
                    CaseResult(case.protection, "skipped", "switched off by the signed policy")
                )
                continue
            reason = case.applies(intent)
            if reason is not None:
                report.results.append(CaseResult(case.protection, "skipped", reason))
                continue
            ok = self._run_case(probe, case, now)
            report.results.append(CaseResult(case.protection, "passed" if ok else "failed"))
            if not ok:
                report.alerts.append(
                    self.alerts.raise_(
                        "selftest_failed",
                        case.protection,
                        f"protection {case.protection} is not working",
                        now,
                    )
                )
        self.last = report
        return report

    def _run_case(self, probe: Pipeline, case: Case, now: datetime) -> bool:
        self._serial += 1
        story = Story(case.protection.lower().replace("_", "-"), self._serial, now, probe.policy)
        case.build(story)
        saved_rates = probe.rates
        probe.rates = copy.deepcopy(
            saved_rates
        )  # bursts must not teach the baselines of other cases
        try:
            outputs = []
            for event in story.events:
                outputs.extend(probe.process(event))
        except Exception:  # a crash is a failure of the protection, not of the scheduler
            return False
        finally:
            probe.rates = saved_rates
        mine = {e.event_id for e in story.events}
        judgements = [
            j
            for sid, j in probe.judgements().items()
            if mine & {e.event_id for e in probe.linker.records[sid].events}
        ]
        if not judgements:
            return False
        best = max(judgements, key=lambda j: (len(j.signals), j.log_odds or 0.0))
        observed = Observed(
            signals={s.name for j in judgements for s in j.signals},
            failed={
                q: any(j.failed[q] for j in judgements) for q in ("origin", "contract", "effect")
            },
            decision=max((j.decision for j in judgements), key=_rank),
            rule_decision=best.rule_decision,
            override=next((j.override for j in judgements if j.override), None),
            gated=any(j.gated for j in judgements),
            mode=max((j.mode for j in judgements), key=_mode_rank),
            actions=[o for o in outputs if isinstance(o, Action)],
            verdicts=[o for o in outputs if isinstance(o, Verdict)],
        )
        return bool(case.expect(observed))


def _rank(d: Decision) -> int:
    return {Decision.ALLOW: 0, Decision.HOLD: 1, Decision.BLOCK: 2}[d]


def _mode_rank(m: Mode) -> int:
    return {Mode.OBSERVE: 0, Mode.WARN: 1, Mode.BLOCK: 2}[m]
