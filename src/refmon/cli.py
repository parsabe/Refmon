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
          [--notify-webhook URL] [--notify-command CMD] [--notify-on block,hold,alert,...]
    refmon health [--workdir DIR] [--json]     is the daemon alive and healthy? (for cron)
    refmon guard [OPTS] -- COMMAND...          intercept and enforce policy on a command
    refmon lab [--list] [--run N ...]          interactive attack lab: templates judged, then run

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


def _notify_args(parser: argparse.ArgumentParser) -> None:
    from .notify import CATEGORIES

    parser.add_argument(
        "--notify-webhook",
        action="append",
        default=[],
        metavar="URL",
        help="POST notifications as JSON to this URL (Slack/Mattermost incoming webhooks work); "
        "repeatable",
    )
    parser.add_argument(
        "--notify-command",
        action="append",
        default=[],
        metavar="CMD",
        help="run CMD (no shell) per notification, JSON on stdin, e.g. "
        "'mail -s Refmon you@example.org'; repeatable",
    )
    parser.add_argument(
        "--notify-on",
        default=None,
        metavar="LIST",
        help=f"categories for the webhook/command: comma list of {', '.join(CATEGORIES)} or all "
        "(default: block,hold,alert,rootkit,lifecycle; the log file and terminal get everything)",
    )


def _build_hub(args: argparse.Namespace):
    import shlex

    from .notify import CommandChannel, NotificationHub, WebhookChannel, parse_categories

    external = [WebhookChannel(url) for url in args.notify_webhook]
    external += [CommandChannel(shlex.split(cmd)) for cmd in args.notify_command]
    return NotificationHub(external=external, external_categories=parse_categories(args.notify_on))


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
    rk = sub.add_parser(
        "scan-rootkit",
        description="Read-only rootkit and stealth scan of this host.",
        epilog="exit codes: 0 allow (nothing to review), 1 hold (findings to review), 2 block",
    )
    rk.add_argument("--json", action="store_true", dest="as_json")
    rk.add_argument("--passes", type=int, default=2)
    rk.add_argument("--interval-ms", type=float, default=50.0)
    rk.add_argument("--with-external", action="store_true")
    rk.add_argument(
        "--strict-jit",
        action="store_true",
        help="also score anonymous rwx memory of JIT runtimes (node, java, Claude Code, ...)",
    )
    srv = sub.add_parser("serve")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8765)
    srv.add_argument("--workdir", default=None)
    _notify_args(srv)
    srv.add_argument(
        "--rootkit-interval",
        type=float,
        default=3600.0,
        help="seconds between rootkit scans while serving (0: only at start; default 3600)",
    )
    hl = sub.add_parser(
        "health",
        description="Check a running `refmon serve` from outside, through its heartbeat file. "
        "Meant for cron or a systemd timer: it notifies once when the daemon dies or gets a "
        "problem, and once when it recovers.",
        epilog="exit codes: 0 healthy, 1 not running or heartbeat stale, 2 running with a problem",
    )
    hl.add_argument("--workdir", default=None, help="the daemon's work directory")
    hl.add_argument("--json", action="store_true", dest="as_json")
    _notify_args(hl)
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
    from .attacklab import GUIDE

    lab = sub.add_parser(
        "lab",
        help="interactive attack lab: pick an attack, Refmon judges it before it runs",
        description="Interactive attack lab: attack templates go through the Refmon pipeline "
        "before they may run. Without options it opens the menu.",
        epilog=GUIDE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    lab.add_argument(
        "--workdir",
        default=None,
        help="lab folder: policy, keys, sandbox, logs/, runs/ (default <Refmon>/attack-lab)",
    )
    lab.add_argument("--list", action="store_true", help="print all templates and exit")
    lab.add_argument(
        "--run",
        nargs="+",
        default=None,
        metavar="TEMPLATE",
        help="run templates without the menu: numbers, ids, ranges, all/attacks/benign/limits",
    )
    lab.add_argument(
        "--mode",
        choices=("block", "warn", "observe"),
        default=None,
        help="set the signed policy mode first (block enforces; warn/observe only log)",
    )
    lab.add_argument("--no-color", action="store_true", help="plain output")
    lab.add_argument("--table", action="store_true", help="print the table of all attacks and exit")
    lab.add_argument(
        "--test-all",
        action="store_true",
        help="run ALL templates and save every result (jsonl, csv, md, console.log)",
    )
    lab.add_argument("--save", action="store_true", help="with --run: also save the results")
    lab.add_argument(
        "--report-dir",
        default=None,
        help="where saved runs go (default <Refmon>/attack-lab/runs; each run gets run-<time>/)",
    )
    lab.add_argument(
        "--analyze",
        nargs="?",
        const="",
        default=None,
        metavar="RUN_DIR",
        help="print the analysis of a saved run (default: the newest) and exit",
    )
    lab.add_argument(
        "--compare",
        nargs="+",
        default=None,
        metavar="RUN_DIR",
        help="compare saved runs side by side (decision per attack per run) and exit",
    )
    lab.add_argument(
        "--record-own-commands",
        action="store_true",
        help="store the text and output of your own $ commands in saved reports "
        "(default: an hmac fingerprint only)",
    )

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
            strict_jit=args.strict_jit,
        )
        from .keys import new_device_key

        # fresh random key per run: fingerprints correlate within this report and reverse nowhere
        report, _ = evaluate_rootkit_scan(cfg, key=new_device_key())
        if args.as_json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(format_scan_report(report))
        return {Decision.ALLOW: 0, Decision.HOLD: 1, Decision.BLOCK: 2}[report.calculus_decision]
    elif args.command == "serve":
        from .live import serve_forever

        try:
            hub = _build_hub(args)
        except ValueError as exc:
            print(f"refmon serve: {exc}", file=sys.stderr)
            return 2
        return serve_forever(
            host=args.host,
            port=args.port,
            workdir=args.workdir,
            hub=hub,
            rootkit_interval_s=args.rootkit_interval,
        )
    elif args.command == "health":
        import json

        from .health import check_health, notify_on_change
        from .live import default_live_workdir

        try:
            hub = _build_hub(args)
        except ValueError as exc:
            print(f"refmon health: {exc}", file=sys.stderr)
            return 2
        workdir = Path(args.workdir) if args.workdir else default_live_workdir()
        now = datetime.now(UTC)
        code, info = check_health(workdir, now)
        if hub.external:
            notify_on_change(workdir, code, info, hub, now)
        if args.as_json:
            print(json.dumps(info, indent=2))
        else:
            print(f"Refmon daemon: {info['status'].upper()} - {info['reason']}")
            for key in ("pid", "mode", "heartbeat_age_s", "policy_digest"):
                if info.get(key) is not None:
                    print(f"  {key:16} {info[key]}")
            st = info.get("self_test") or {}
            if st:
                failed = ", ".join(st.get("failed") or []) or "none"
                print(f"  {'self_test':16} passed={st.get('passed')} failed={failed}")
            for prob in info.get("problems", []):
                print(f"  - [{prob.get('severity')}] {prob.get('title')}: {prob.get('subject')}")
        return code
    elif args.command == "lab":
        from .attacklab import main as lab_main

        return lab_main(args)
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
