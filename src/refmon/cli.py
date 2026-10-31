"""Command line for the human steps around the policy: keys, signing, learning, approval.

    refmon keygen KEYFILE                      write a new signing key; print the public key
    refmon init-policy OUT                     write the reference policy (unsigned)
    refmon sign POLICY KEYFILE                 sign a policy or rule pack in place
    refmon verify POLICY PUBLIC_KEY            check a signature and the policy
    refmon learn POLICY PUBLIC_KEY OUT EVENTS  count what roles do in replay files, write a proposal
    refmon approve PROPOSAL --by NAME          approve a proposal (--relax: relaxing changes too)
    refmon apply POLICY PROPOSAL OUT KEYFILE   apply an approved proposal and sign the result
    refmon audit [GOLDEN_DIR]                  run the privacy audit
    refmon scan-rootkit [--json]               run read-only multi-engine rootkit scanners
    refmon serve [--port PORT] [--workdir DIR] start live background barrier & web dashboard
    refmon guard [OPTS] -- COMMAND...          intercept and enforce policy on a command

Nothing here runs unattended: a person holds the key and names themselves as approver.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import signing
from .learning import (
    ContractLearner,
    apply_proposal,
    approve,
    read_proposal,
    write_proposal,
)
from .policy import default_policy_dict
from .policy_io import PolicyRejected, load_policy_data, read_document, write_document, write_signed
from .replay import ReplaySource


def _read_key(path: str) -> str:
    return Path(path).read_text(encoding="utf-8").strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="refmon", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen")
    keygen.add_argument("keyfile")
    init = sub.add_parser("init-policy")
    init.add_argument("out")
    sign = sub.add_parser("sign")
    sign.add_argument("document")
    sign.add_argument("keyfile")
    verify = sub.add_parser("verify")
    verify.add_argument("policy")
    verify.add_argument("public_key")
    learn = sub.add_parser("learn")
    learn.add_argument("policy")
    learn.add_argument("public_key")
    learn.add_argument("out")
    learn.add_argument("events", nargs="+")
    appr = sub.add_parser("approve")
    appr.add_argument("proposal")
    appr.add_argument("--by", required=True)
    appr.add_argument("--relax", action="store_true")
    appr.add_argument("--only", nargs="*", default=None)
    audit = sub.add_parser("audit")
    audit.add_argument("golden", nargs="?")
    apply_ = sub.add_parser("apply")
    apply_.add_argument("policy")
    apply_.add_argument("proposal")
    apply_.add_argument("out")
    apply_.add_argument("keyfile")
    rk = sub.add_parser("scan-rootkit")
    rk.add_argument("--json", action="store_true", dest="as_json")
    rk.add_argument("--passes", type=int, default=2)
    rk.add_argument("--interval-ms", type=float, default=50.0)
    rk.add_argument("--with-external", action="store_true")
    srv = sub.add_parser("serve")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8765)
    srv.add_argument("--workdir", default=None)
    grd = sub.add_parser("guard")
    grd.add_argument("--host", default="localhost")
    grd.add_argument("--port", type=int, default=8765)
    grd.add_argument("--workdir", default=None)
    grd.add_argument(
        "--origin",
        default="web",
        choices=("web", "mail", "agent_input", "inbound_request", "download", "none"),
    )
    grd.add_argument("--role", default="interactive_shell")
    grd.add_argument("--no-exec", action="store_true")
    grd.add_argument("--json", action="store_true", dest="as_json")
    grd.add_argument("cmd_parts", nargs=argparse.REMAINDER)

    args = parser.parse_args(argv)
    try:
        return _run(args)
    except (PolicyRejected, PermissionError, ValueError, OSError) as error:
        print(f"refmon: {error}", file=sys.stderr)
        return 1


def _run(args: argparse.Namespace) -> int:
    if args.command == "keygen":
        private, public = signing.generate_keypair()
        path = Path(args.keyfile)
        path.write_text(private + "\n", encoding="utf-8")
        path.chmod(0o600)
        print(public)
    elif args.command == "init-policy":
        write_document(default_policy_dict(), args.out)
    elif args.command == "sign":
        document = read_document(args.document)
        write_signed(document, _read_key(args.keyfile), args.document)
    elif args.command == "verify":
        loaded = load_policy_data(args.policy, [args.public_key.strip()])
        print(f"ok {loaded.digest} packs={len(loaded.packs)}")
    elif args.command == "learn":
        loaded = load_policy_data(args.policy, [args.public_key.strip()])
        learner = ContractLearner(loaded.policy)
        for events in args.events:
            learner.new_stream()
            for event in ReplaySource(events, extra_roles=loaded.policy.extra_roles):
                learner.learn(event)
        write_proposal(learner.proposal(), args.out)
        print(f"proposal written: {args.out}")
    elif args.command == "approve":
        proposal = read_proposal(args.proposal)
        only = set(args.only) if args.only is not None else None
        approved = approve(
            proposal,
            args.by,
            change_ids=only,
            include_relax=args.relax,
            at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
        write_proposal(approved, args.proposal)
        print(f"approved {sum(c.approved for c in approved.changes())} changes")
    elif args.command == "audit":
        from .audit import main as audit_main

        return audit_main([args.golden] if args.golden else [])
    elif args.command == "apply":
        document = read_document(args.policy)
        data = apply_proposal(
            {k: v for k, v in document.items() if k != signing.SIGNATURE_FIELD},
            read_proposal(args.proposal),
        )
        write_signed(data, _read_key(args.keyfile), args.out)
        print(f"signed policy written: {args.out}")
    elif args.command == "scan-rootkit":
        import json

        from .rootkit import ScanConfig, evaluate_rootkit_scan, format_scan_report
        from .schemas import Decision

        cfg = ScanConfig(
            passes=max(1, args.passes),
            pass_interval_s=max(0.0, args.interval_ms / 1000.0),
            run_external=args.with_external,
        )
        report, _ = evaluate_rootkit_scan(cfg)
        if args.as_json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(format_scan_report(report))
        return 0 if report.calculus_decision is Decision.ALLOW else 1
    elif args.command == "serve":
        from .live import serve_forever

        return serve_forever(host=args.host, port=args.port, workdir=args.workdir)
    elif args.command == "guard":
        import json
        import shlex

        from .live import send_guard_request

        parts = list(args.cmd_parts)
        if parts and parts[0] == "--":
            parts = parts[1:]
        command_str = parts[0] if len(parts) == 1 else shlex.join(parts)
        if not command_str.strip():
            raise ValueError("guard requires a command after --")
        res = send_guard_request(
            command_str,
            host=args.host,
            port=args.port,
            origin=args.origin,
            role=args.role,
            execute=not args.no_exec,
            workdir=args.workdir,
        )
        if args.as_json:
            print(json.dumps(res, indent=2))
        else:
            verdict = str(res["decision"]).upper()
            print(
                f"[Refmon Barrier: {verdict}] mode={res['mode']} "
                f"log_odds={res['log_odds']} nats executed={res['executed']}"
            )
            print(f"  Why: {res['explanation']}")
            if res.get("output"):
                print(res["output"])
        return 1 if res.get("blocked_by_barrier") else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
