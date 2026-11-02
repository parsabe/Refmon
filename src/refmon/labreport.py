# ruff: noqa: E501
"""Tables and saved reports for the CLI attack lab (`refmon lab`).

A saved run is a directory `run-<UTC timestamp>/` with
    results.jsonl   one JSON object per attack: every field the lab knows (for pandas / jq)
    results.csv     the same, flat, one row per attack (for a spreadsheet)
    report.md       summary, score per category, the full results table and every explanation
    templates.md    the table of all attack templates that were available

Template commands are the repository's own harmless stand-ins and are stored as written. Your own
`$` commands are real content, so (CLAUDE.md Part A: no raw content outside lab fixtures) they are
stored only as an HMAC fingerprint with no output, unless you pass `--record-own-commands`.
"""

from __future__ import annotations

import csv
import json
import re
import shutil
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

SHORT_GROUP = {
    "Endpoint & social engineering": "social-eng",
    "Remote access, injection & privilege": "remote/priv",
    "Credentials, exfiltration & persistence": "data/persist",
    "Tampering & destruction": "tamper/destroy",
    "Server attacks (web worker / inbound request)": "server",
    "File attacks (really performed in the sandbox, the watcher must catch them)": "file",
    "Known limits (Refmon is expected to MISS these: honest testing)": "known-limit",
    "Benign controls (must be ALLOWED and run)": "benign",
}
EXPECT_TEXT = {"stop": "block/hold", "allow": "allow", "miss": "miss (limit)", "own": "-"}
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


@dataclass
class Record:
    """One row of a saved run: what was sent, what Refmon decided, and what happened."""

    seq: int
    ts: str
    template_number: int | None
    template_id: str
    title: str
    category: str
    command: str
    origin: str
    role: str
    expected: str
    never_run: bool
    mode: str
    decision: str
    rule_decision: str
    log_odds: float
    origin_failed: bool
    contract_failed: bool
    effect_failed: bool
    fails: int
    override: str | None
    signals: list[str]
    explanation: str
    result: str
    outcome: str
    executed: bool
    stopped_by_refmon: bool
    check: str
    judge_ms: float
    total_ms: float
    story_id: str
    output: str
    watcher: list[str] = field(default_factory=list)


def short_result(r: Any) -> str:
    o = r.outcome
    if o.startswith("QUARANTINED"):
        return "QUARANTINED"
    if o.startswith("DETECTED"):
        return "DETECTED-AFTER"
    if o.startswith("HELD, then RELEASED"):
        return "HELD->RELEASED"
    if o.startswith("HELD"):
        return "HELD->STOPPED"
    if o.startswith("STOPPED"):
        return "STOPPED"
    if "lab safety" in o:
        return "NOT RUN (safety)"
    if o.startswith(("LOGGED ONLY", "NOT STOPPED")):
        return "LET THROUGH"
    return "RAN" if r.ran else o.split(":")[0]


def check_text(r: Any, mode: str) -> str:
    ok = r.verdict_ok
    if ok is None:
        return "-"
    if r.expect == "miss":
        return "known-limit (missed)" if r.decision == "allow" else "known-limit (caught)"
    if r.expect == "allow":
        return "PASS" if ok else "FAIL (false alarm)"
    if not ok:
        return "FAIL (missed)"
    if r.ran and mode != "block":
        return "DETECTED, not stopped"
    return "PASS (after the fact)" if r.ran else "PASS"


def to_record(r: Any, seq: int, mode: str, fingerprint, record_own: bool) -> Record:
    own = r.expect == "own"
    command = r.command if (not own or record_own) else fingerprint(r.command)
    return Record(
        seq=seq,
        ts=r.ts,
        template_number=r.number,
        template_id=r.template_id or ("own" if own else ""),
        title=r.label,
        category=SHORT_GROUP.get(r.group, "own" if own else r.group),
        command=command,
        origin=r.origin,
        role=r.role,
        expected=EXPECT_TEXT.get(r.expect, r.expect),
        never_run=r.never_run,
        mode=r.mode or mode,
        decision=r.decision,
        rule_decision=r.rule_decision,
        log_odds=round(float(r.log_odds), 2),
        origin_failed=bool(r.failed.get("origin")),
        contract_failed=bool(r.failed.get("contract")),
        effect_failed=bool(r.failed.get("effect")),
        fails=sum(bool(v) for v in r.failed.values()),
        override=r.override,
        signals=list(r.signals),
        explanation=r.explanation,
        result=short_result(r),
        outcome=r.outcome,
        executed=r.ran,
        stopped_by_refmon=r.stopped,
        check=check_text(r, r.mode or mode),
        judge_ms=round(r.judge_ms, 2),
        total_ms=round(r.total_ms, 2),
        story_id=r.story_id,
        output="" if (own and not record_own) else r.output,
        watcher=list(r.watcher),
    )


# -- plain-text tables --------------------------------------------------------------------------


def text_table(headers: Sequence[str], rows: Iterable[Sequence[Any]], max_last: int = 0) -> str:
    rows = [[("" if c is None else str(c)) for c in row] for row in rows]
    if max_last:
        rows = [[*row[:-1], _clip(row[-1], max_last)] for row in rows]
    widths = [len(h) for h in headers]
    for row in rows:
        widths = [max(w, len(c)) for w, c in zip(widths, row, strict=True)]
    line = "+".join("-" * (w + 2) for w in widths)
    out = [" " + " | ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True)), "-" + line]
    out += [" " + " | ".join(c.ljust(w) for c, w in zip(row, widths, strict=True)) for row in rows]
    return "\n".join(line.rstrip() for line in out)


def _clip(text: str, width: int) -> str:
    return text if len(text) <= width else text[: max(1, width - 3)] + "..."


def templates_rows(numbered: Sequence[tuple[int, Any]]) -> list[list[Any]]:
    return [
        [
            n,
            t.id,
            SHORT_GROUP.get(t.group, t.group),
            f"{t.origin} -> {t.role}",
            EXPECT_TEXT[t.expect],
            "no (judged only)"
            if t.never_run
            else ("sandbox" if t.kind == "command" else "file op"),
            t.command,
        ]
        for n, t in numbered
    ]


TEMPLATE_HEADERS = ("#", "id", "category", "origin -> role", "expected", "lab executes", "command")
RESULT_HEADERS = ("#", "id", "category", "expected", "Refmon", "L nats", "O C E", "override",
                  "result", "check")  # fmt: skip


def templates_table(numbered: Sequence[tuple[int, Any]]) -> str:
    width = shutil.get_terminal_size((160, 40)).columns
    rows = templates_rows(numbered)
    fixed = text_table(TEMPLATE_HEADERS[:-1], [r[:-1] for r in rows])
    room = max(30, width - len(fixed.splitlines()[0]) - 4)
    return text_table(TEMPLATE_HEADERS, rows, max_last=room)


def results_rows(records: Sequence[Record]) -> list[list[Any]]:
    def oce(r: Record) -> str:
        return " ".join("X" if f else "." for f in (r.origin_failed, r.contract_failed,
                                                    r.effect_failed))  # fmt: skip

    return [
        [
            r.template_number or "-",
            r.template_id,
            r.category,
            r.expected,
            r.decision.upper(),
            f"{r.log_odds:.2f}",
            oce(r),
            r.override or "",
            r.result,
            r.check,
        ]
        for r in records
    ]


def results_table(records: Sequence[Record]) -> str:
    return text_table(RESULT_HEADERS, results_rows(records))


# -- markdown -----------------------------------------------------------------------------------


def _md_cell(text: Any) -> str:
    return str("" if text is None else text).replace("|", "\\|").replace("\n", " ")


def md_table(headers: Sequence[str], rows: Iterable[Sequence[Any]], code_last: bool = False) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        cells = [_md_cell(c) for c in row]
        if code_last and cells[-1]:
            cells[-1] = f"`{cells[-1]}`"
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out)


def templates_markdown(numbered: Sequence[tuple[int, Any]]) -> str:
    return md_table(TEMPLATE_HEADERS, templates_rows(numbered), code_last=True)


def summary(records: Sequence[Record]) -> dict[str, Any]:
    attacks = [r for r in records if r.expected == EXPECT_TEXT["stop"]]
    benign = [r for r in records if r.expected == EXPECT_TEXT["allow"]]
    limits = [r for r in records if r.expected == EXPECT_TEXT["miss"]]
    own = [r for r in records if r.expected == "-"]
    by_cat: dict[str, dict[str, int]] = {}
    for r in attacks + benign + limits:
        c = by_cat.setdefault(r.category, {"total": 0, "pass": 0, "stopped": 0})
        c["total"] += 1
        c["pass"] += r.check.startswith(("PASS", "known-limit", "DETECTED"))
        c["stopped"] += r.stopped_by_refmon
    return {
        "attacks": len(attacks),
        "attacks_detected": sum(r.decision in ("block", "hold") for r in attacks),
        "attacks_stopped": sum(r.stopped_by_refmon for r in attacks),
        "benign": len(benign),
        "benign_allowed": sum(r.decision == "allow" for r in benign),
        "known_limits": len(limits),
        "known_limits_missed": sum(r.decision == "allow" for r in limits),
        "own_commands": len(own),
        "decisions": {d: sum(r.decision == d for r in records) for d in ("block", "hold", "allow")},
        "failures": [r.template_id for r in records if r.check.startswith("FAIL")],
        "mean_judge_ms": round(sum(r.judge_ms for r in records) / max(1, len(records)), 2),
        "by_category": by_cat,
    }


def markdown_report(records: Sequence[Record], meta: dict[str, Any], templates_md: str) -> str:
    s = summary(records)
    lines = [
        f"# Refmon attack lab run {meta['run_id']}",
        "",
        "| | |",
        "|---|---|",
        *(f"| {k} | {_md_cell(v)} |" for k, v in meta.items()),
        "",
        "## Summary",
        "",
        f"- Attacks detected (block or hold): **{s['attacks_detected']}/{s['attacks']}**",
        f"- Attacks stopped by Refmon (never ran / quarantined): **{s['attacks_stopped']}/{s['attacks']}**",
        f"- Benign commands allowed: **{s['benign_allowed']}/{s['benign']}**",
        f"- Known limits missed (documented): {s['known_limits_missed']}/{s['known_limits']}",
        f"- Own commands: {s['own_commands']}",
        f"- Decisions: block {s['decisions']['block']}, hold {s['decisions']['hold']}, "
        f"allow {s['decisions']['allow']}",
        f"- Mean pipeline time per command: {s['mean_judge_ms']} ms",
        f"- Failed checks: {', '.join(s['failures']) or 'none'}",
        "",
        "## Analysis",
        "",
        "```text",
        *analyze(records, _thresholds(meta)),
        "```",
        "",
        "### Per category",
        "",
        md_table(
            ("category", "templates", "checks passed", "stopped by Refmon"),
            [(c, v["total"], v["pass"], v["stopped"]) for c, v in s["by_category"].items()],
        ),
        "",
        "## Results",
        "",
        "`O C E` = Origin, Contract, Effect; `X` = the question failed. Three fails block, two "
        "hold. An override always blocks. `L` is the evidence in nats (block at L >= -3.91, hold "
        "at L >= -4.94).",
        "",
        md_table(RESULT_HEADERS, results_rows(records)),
        "",
        "## Details",
        "",
    ]
    for r in records:
        lines += [
            f"### {r.seq}. {r.title} (`{r.template_id}`)",
            "",
            f"- Command: `{_md_cell(r.command)}`",
            f"- Origin -> role: {r.origin} -> {r.role}; mode: {r.mode}",
            f"- Refmon: **{r.decision.upper()}** (rule: {r.rule_decision}), L = {r.log_odds} nats, "
            f"fails = {r.fails}, override = {r.override or 'none'}",
            f"- Signals: {', '.join(r.signals) or 'none'}",
            f"- Why: {r.explanation}",
            f"- Result: {r.outcome}",
            f"- Check: {r.check}; pipeline {r.judge_ms} ms, total {r.total_ms} ms",
        ]
        if r.output:
            lines += ["- Output:", "", "```text", r.output, "```"]
        lines += [f"- {w}" for w in r.watcher]
        lines.append("")
    lines += ["## Templates available in this run", "", templates_md, ""]
    return "\n".join(lines)


def write_report(
    records: Sequence[Record], meta: dict[str, Any], out_dir: Path, templates_md: str
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "jsonl": out_dir / "results.jsonl",
        "csv": out_dir / "results.csv",
        "markdown": out_dir / "report.md",
        "templates": out_dir / "templates.md",
        "summary": out_dir / "summary.json",
    }
    with paths["jsonl"].open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps({"run_id": meta["run_id"], **asdict(r)}) + "\n")
    with paths["csv"].open("w", encoding="utf-8", newline="") as fh:
        names = ["run_id", *Record.__dataclass_fields__]
        writer = csv.DictWriter(fh, fieldnames=names)
        writer.writeheader()
        for r in records:
            row = {"run_id": meta["run_id"], **asdict(r)}
            row["signals"] = ";".join(r.signals)
            row["watcher"] = ";".join(r.watcher)
            writer.writerow(row)
    paths["markdown"].write_text(markdown_report(records, meta, templates_md), encoding="utf-8")
    paths["analysis"] = out_dir / "analysis.txt"
    paths["analysis"].write_text(
        "\n".join(analyze(records, _thresholds(meta))) + "\n", encoding="utf-8"
    )
    paths["templates"].write_text(
        "# Refmon attack lab templates\n\n" + templates_md + "\n", encoding="utf-8"
    )
    paths["summary"].write_text(
        json.dumps({**meta, **summary(records)}, indent=2) + "\n", encoding="utf-8"
    )
    return paths


def _thresholds(meta: dict[str, Any]) -> dict[str, float]:
    return {k: float(meta[k]) for k in ("prior", "tau_block", "tau_hold") if k in meta}


def analyze_run(run_dir: str | Path) -> list[str]:
    meta, rows = load_run(run_dir)
    records = [Record(**{k: v for k, v in r.items() if k != "run_id"}) for r in rows]
    head = (
        f"Analysis of {meta['run_id']} (mode {meta.get('policy_mode_at_save', '?')}, "
        f"{len(records)} commands)"
    )
    return [head, "", *analyze(records, _thresholds(meta))]


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


# -- comparing saved runs -----------------------------------------------------------------------


def load_run(run_dir: str | Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    run = Path(run_dir)
    if run.is_file():
        run = run.parent
    rows = [
        json.loads(line)
        for line in (run / "results.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    meta = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    return meta, rows


def compare_runs(run_dirs: Sequence[str | Path]) -> str:
    """Side by side: one row per template, one column per saved run (decision / result)."""
    runs = [load_run(d) for d in run_dirs]
    names = [f"{m['run_id']} ({m.get('policy_mode_at_save', '?')})" for m, _ in runs]
    order: list[str] = []
    cells: dict[str, list[str]] = {}
    for i, (_, rows) in enumerate(runs):
        for r in rows:
            key = r["template_id"] if r["template_id"] != "own" else f"own#{r['seq']}"
            if key not in cells:
                order.append(key)
                cells[key] = [""] * len(runs)
            mark = " !" if r["check"].startswith("FAIL") else ""
            cells[key][i] = f"{r['decision'].upper()} {r['log_odds']:.2f} {r['result']}{mark}"
    changed = {k for k in order if len({c.split(" ")[0] for c in cells[k] if c}) > 1}
    rows = [[k, *cells[k], "yes" if k in changed else ""] for k in order]
    score = [
        "score",
        *(
            f"det {m['attacks_detected']}/{m['attacks']} stop {m['attacks_stopped']}/"
            f"{m['attacks']} benign {m['benign_allowed']}/{m['benign']}"
            for m, _ in runs
        ),
        f"{len(changed)} changed",
    ]
    table = text_table(["template", *names, "decision changed"], [*rows, score])
    return table + "\n  (! = FAIL in that run: an attack allowed or a benign command blocked)"


# -- analysis -------------------------------------------------------------------------------------

# the default policy's values (CLAUDE.md C11.5); a saved run records the ones it used
DEFAULT_THRESHOLDS = {"prior": -6.91, "tau_block": -3.91, "tau_hold": -4.94}


def analyze(records: Sequence[Record], thresholds: dict[str, float] | None = None) -> list[str]:
    """What the run means, as readable lines (plain text that is also valid Markdown)."""
    th = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    tb, thold, prior = th["tau_block"], th["tau_hold"], th["prior"]
    s = summary(records)
    attacks = [r for r in records if r.expected == EXPECT_TEXT["stop"]]
    benign = [r for r in records if r.expected == EXPECT_TEXT["allow"]]
    limits = [r for r in records if r.expected == EXPECT_TEXT["miss"]]
    out: list[str] = []
    add = out.append

    # 1. headline
    add("1. Headline")
    if attacks:
        det, stop, n = s["attacks_detected"], s["attacks_stopped"], s["attacks"]
        add(f"   - Detection: {det}/{n} attacks raised BLOCK or HOLD ({100 * det / n:.0f} %).")
        add(f"   - Prevention: {stop}/{n} never ran or were quarantined ({100 * stop / n:.0f} %).")
        after = [r.template_id for r in attacks if r.result == "DETECTED-AFTER"]
        through = [r.template_id for r in attacks if r.result == "LET THROUGH"]
        if after:
            add(
                f"     Detected only after the fact (the action itself is the attack): {', '.join(after)}."
            )
        if through:
            add(f"     Let through because the policy mode only logs: {len(through)} attacks "
                f"(mode {records[0].mode}). Switch to block mode to stop them.")  # fmt: skip
    if benign:
        fa = [r.template_id for r in benign if r.decision != "allow"]
        add(f"   - False alarms: {len(fa)}/{len(benign)} benign commands were held or blocked"
            + (f" ({', '.join(fa)})." if fa else "."))  # fmt: skip
    missed = [r.template_id for r in attacks if r.decision == "allow"]
    if missed:
        add(f"   - MISSED attacks: {', '.join(missed)}.")

    # 2. how the attacks were caught
    if attacks:
        add("")
        add("2. Which of the three questions caught the attacks")
        o = sum(r.origin_failed for r in attacks)
        c = sum(r.contract_failed for r in attacks)
        e = sum(r.effect_failed for r in attacks)
        n = len(attacks)
        add(f"   - Origin failed in {o}/{n}, Contract in {c}/{n}, Effect in {e}/{n}.")
        all3 = sum(r.fails == 3 for r in attacks)
        add(f"   - {all3}/{n} failed all three questions (the clean 3-fail block).")
        no_origin = [
            r.template_id for r in attacks if not r.origin_failed and r.decision != "allow"
        ]
        if no_origin:
            add(f"   - Caught WITHOUT an outside origin: {', '.join(no_origin)}. These rely on the "
                "role contract, the effect or an override, so they would be caught even if the "
                "attacker got in through a channel Refmon does not see.")  # fmt: skip
        ov: dict[str, list[str]] = {}
        for r in attacks:
            if r.override:
                ov.setdefault(r.override, []).append(r.template_id)
        if ov:
            parts = [f"{k} x{len(v)} ({', '.join(v)})" for k, v in ov.items()]
            add(f"   - Absolute overrides (block whatever the score): {'; '.join(parts)}.")

    # 3. evidence margins
    scored = [r for r in attacks if r.decision != "allow" and not r.override]
    if scored or benign:
        add("")
        add(
            f"3. Evidence margins (L in nats; start {prior:.2f}, HOLD at {thold:.2f}, BLOCK at {tb:.2f})"
        )
    if scored:
        weakest = sorted(scored, key=lambda r: r.log_odds)[:3]
        add("   - Attacks closest to the block threshold (least spare evidence):")
        for r in weakest:
            add(f"       {r.template_id:<16} L={r.log_odds:6.2f}  margin {r.log_odds - tb:+.2f} nats "
                f"[{', '.join(r.signals) or 'no signals'}]")  # fmt: skip
        mean = sum(r.log_odds - tb for r in scored) / len(scored)
        add(f"   - Mean margin above BLOCK over {len(scored)} score-based blocks: {mean:+.2f} nats. "
            "A margin under ~1 nat means losing one signal (e.g. a better-hidden command) "
            "could turn the block into a hold.")  # fmt: skip
    if benign:
        closest = max(benign, key=lambda r: r.log_odds)
        add(f"   - Benign command closest to a false alarm: {closest.template_id} "
            f"L={closest.log_odds:.2f}, {thold - closest.log_odds:.2f} nats under HOLD "
            f"[{', '.join(closest.signals) or 'no signals'}].")  # fmt: skip
        if thold - closest.log_odds < 0.5:
            add("     That is a thin margin: one more weak signal on a harmless pasted command "
                "would make Refmon ask the user.")  # fmt: skip

    # 4. what Refmon cannot tell apart
    pairs = []
    for a in [*attacks, *limits]:
        for b in benign:
            if (a.log_odds, a.origin_failed, a.contract_failed, a.effect_failed) == (
                b.log_odds,
                b.origin_failed,
                b.contract_failed,
                b.effect_failed,
            ) and a.decision == b.decision == "allow":
                pairs.append((a.template_id, b.template_id, a.log_odds))
    if pairs or limits:
        add("")
        add("4. Blind spots")
        for a, b, lo in pairs:
            add(
                f"   - '{a}' (malicious) and '{b}' (harmless) get the same verdict and the same "
                f"evidence (L={lo:.2f}): from the command text alone Refmon cannot tell them apart."
            )
        for r in limits:
            add(f"   - Known limit '{r.template_id}': {r.decision.upper()}. A command that only "
                "names a script shows nothing in its text; seeing what the script does needs a "
                "kernel sensor (docs/phase-8-plan.md).")  # fmt: skip

    # 5. signals
    counts: dict[str, int] = {}
    for r in attacks:
        for sig in r.signals:
            counts[sig] = counts.get(sig, 0) + 1
    if counts:
        add("")
        add("5. Signals that fired across the attacks (how often)")
        for sig, k in sorted(counts.items(), key=lambda x: (-x[1], x[0])):
            add(f"   - {sig:<34} {k}")

    # 6. rule vs calculus, timing
    differ = [r.template_id for r in records if r.rule_decision and r.rule_decision != r.decision]
    add("")
    add("6. Consistency and speed")
    add("   - 3/2/1 fail rule and evidence calculus agree on every command."
        if not differ else
        f"   - The evidence calculus overruled the 3/2/1 fail rule on: {', '.join(differ)}.")  # fmt: skip
    cmd = [r for r in records if r.category != "file"]
    if cmd:
        add(
            f"   - Pipeline decision time per command: mean {sum(r.judge_ms for r in cmd) / len(cmd):.1f} ms, "
            f"max {max(r.judge_ms for r in cmd):.1f} ms (decided before the command starts)."
        )
    return out
