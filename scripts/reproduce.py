"""Regenerate every result table of the repository from scratch.

    python scripts/reproduce.py            # what `make reproduce` runs

It (1) generates the variants of the active seed once, (2) extracts the tags v1.0 to v1.3 from git
and replays that one file in each, (3) compares the four, (4) checks the result against the
committed per-variant data in docs/evaluation/, (5) runs the golden catalog in each version, builds
the coverage map, runs the privacy audit, the publishability check and the test suite, and
(6) writes the generated blocks of docs/results.md and the full comparison to docs/evaluation/.

Nothing is fetched from the network. The tags must exist (`git fetch --tags` in a clone).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import compare_versions as cv  # noqa: E402

from refmon import variants  # noqa: E402
from refmon.coverage import ADAPTIVE, parse_coverage_map  # noqa: E402
from refmon.evalstats import mcnemar_exact, wilson_interval  # noqa: E402

TAGS = ["v1.0", "v1.1", "v1.2", "v1.3"]
PY = sys.executable
RESULTS = ROOT / "docs" / "results.md"


def sh(cmd: list[str], env_extra: dict | None = None, cwd: Path = ROOT, check=True) -> str:
    env = {**os.environ, **(env_extra or {})}
    done = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    if check and done.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(cmd)}\n{done.stdout}\n{done.stderr}")
    return done.stdout + (done.stderr if not check else "")


def extract(tag: str, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(
        ["git", "-C", str(ROOT), "archive", tag], check=True, capture_output=True
    ).stdout
    subprocess.run(["tar", "-x", "-C", str(dest)], input=archive, check=True)


def replay_all(tmp: Path, seed: int) -> tuple[dict[str, Path], str]:
    out = tmp / "out"
    out.mkdir()
    variants_file = out / "variants.jsonl"
    generate = [PY, "scripts/generate_variants.py", "--golden", "tests/golden"]
    sh([*generate, "--seed", str(seed), "--out", str(variants_file)])
    digest = hashlib.sha256(variants_file.read_bytes()).hexdigest()
    procs, dumps = {}, {}
    for tag in TAGS:
        tree = tmp / "trees" / tag
        extract(tag, tree)
        dumps[tag] = out / f"{tag}.jsonl"
        command = [PY, "scripts/dump_matrix.py", "--variants", str(variants_file)]
        procs[tag] = subprocess.Popen(
            [*command, "--out", str(dumps[tag])],
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": str(tree / "src")},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    for tag, proc in procs.items():
        text = proc.communicate()[0]
        if proc.returncode != 0:
            raise SystemExit(f"replay in {tag} failed:\n{text}")
    return dumps, digest


def golden_table(tmp: Path) -> tuple[str, dict[str, dict]]:
    per = {}
    for tag in TAGS:
        tree = tmp / "trees" / tag
        command = [PY, "scripts/golden_decisions.py", "--golden", str(tree / "tests" / "golden")]
        text = sh(command, {"PYTHONPATH": str(tree / "src")})
        per[tag] = json.loads(text)
    ids = sorted(per[TAGS[0]])
    lines = [
        "| scenario | kind | expected | " + " | ".join(TAGS) + " |",
        "|---|---|---|" + "---|" * 4,
    ]
    for sid in ids:
        exp = per["v1.3"][sid]["expected"]
        cells = []
        for tag in TAGS:
            got = per[tag][sid]["decision"]
            cells.append(got if got == exp else f"**{got}**")
        lines.append(f"| {sid} | {per['v1.3'][sid]['kind']} | {exp} | " + " | ".join(cells) + " |")
    total = len(ids)
    summary = ["", "| | " + " | ".join(TAGS) + " |", "|---|" + "---:|" * 4]
    ok = [sum(per[t][s]["decision"] == per["v1.3"][s]["expected"] for s in ids) for t in TAGS]
    summary.append(
        f"| scenarios reaching the expected `decision` (of {total}) | "
        + " | ".join(map(str, ok))
        + " |"
    )
    same = [sum(per[t][s]["decision"] == per["v1.0"][s]["decision"] for s in ids) for t in TAGS]
    summary.append("| same `decision` as v1.0 | " + " | ".join(map(str, same)) + " |")
    return "\n".join(lines + summary), per


def coverage_table(per: dict[str, dict]) -> str:
    pytest = [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_phase5_exposure.py"]
    ran = sh(pytest, check=False)
    adaptive_ok = "passed" in ran and "failed" not in ran
    cur = per["v1.3"]

    def mark(sid: str) -> str:
        if sid in ADAPTIVE:
            return f"{sid}{'✓' if adaptive_ok else '✗'}"
        row = cur.get(sid)
        return f"{sid}{'✓' if row and row['decision'] == row['expected'] else '✗'}"

    lines = ["| attack family | malicious | benign |", "|---|---|---|"]
    for fam in parse_coverage_map(ROOT / "CLAUDE.md"):
        mal = ", ".join(mark(s) for s in fam.malicious) or "-"
        ben = ", ".join(mark(s) for s in fam.benign) or "-"
        lines.append(f"| {fam.name} | {mal} | {ben} |")
    lines += [
        "",
        "✓ the scenario reaches its expected `decision` in v1.3 (S16, S28 and S29 are "
        "policy-over-time tests in tests/test_phase5_exposure.py).",
    ]
    return "\n".join(lines)


def stats_table(runs: dict[str, dict]) -> str:
    keys = sorted(runs[TAGS[0]])
    first = runs[TAGS[0]]
    mal = [k for k in keys if first[k].get("kind", "malicious") == "malicious"]
    neutral = [k for k in keys if first[k].get("kind") == "benign" and not first[k].get("adds")]

    def caught(tag, k):
        return runs[tag][k]["decision"] != "allow"

    def blocked(tag, k):
        return runs[tag][k]["decision"] == "block"

    def contained(tag, k):
        return cv.outcome(runs[tag][k]) in ("block", "effective hold")

    def cell(k, n):
        lo, hi = wilson_interval(k, n)
        return f"{k}/{n} = {k / n:.1%} [{lo:.1%}, {hi:.1%}]"

    rows = [
        ("malicious variants caught (block or hold)", mal, caught),
        ("malicious variants blocked", mal, blocked),
        ("malicious variants contained (block or effective hold)", mal, contained),
        ("neutral benign variants blocked (false block rate)", neutral, blocked),
    ]
    lines = ["| rate (Wilson 95 % interval) | " + " | ".join(TAGS) + " |", "|---|" + "---:|" * 4]
    for name, keyset, fn in rows:
        cells = [cell(sum(fn(t, k) for k in keyset), len(keyset)) for t in TAGS]
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "McNemar's exact test on the same malicious variants (only first / only second = variants "
        "that only the first / only the second version gets right):",
        "",
        "| comparison | metric | only first | only second | p |",
        "|---|---|---:|---:|---:|",
    ]
    for a, b in (("v1.0", "v1.3"), ("v1.0", "v1.1"), ("v1.2", "v1.3")):
        for name, fn in (("caught", caught), ("contained", contained), ("blocked", blocked)):
            x = sum(fn(a, k) and not fn(b, k) for k in mal)
            y = sum(fn(b, k) and not fn(a, k) for k in mal)
            lines.append(f"| {a} vs {b} | {name} | {x} | {y} | {mcnemar_exact(x, y):.2g} |")
    return "\n".join(lines)


def versions_table() -> str:
    lines = ["| tag | commit | |", "|---|---|---|"]
    notes = {
        "v1.0": "the frozen state after Phase 7",
        "v1.1": "F1 to F4: external command, hold fallback, role-scoped trust, hour window",
        "v1.2": "F5 to F7: channel roles out of the fallback, no-label blocks act, seeded numbers",
        "v1.3": "F8 and F9: monotone calculus, benign variants",
    }
    for tag in TAGS:
        commit = sh(["git", "-C", str(ROOT), "rev-list", "-n1", tag]).strip()[:7]
        lines.append(f"| {tag} | {commit} | {notes[tag]} |")
    return "\n".join(lines)


def replace_block(text: str, name: str, body: str) -> str:
    pattern = re.compile(
        rf"(<!-- BEGIN GENERATED: {name} -->)\n.*?(<!-- END GENERATED: {name} -->)", re.S
    )
    if not pattern.search(text):
        raise SystemExit(f"docs/results.md has no generated block named {name!r}")
    return pattern.sub(lambda m: f"{m.group(1)}\n{body.strip(chr(10))}\n{m.group(2)}", text)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-tests", action="store_true", help="do not run the test suite")
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="also rewrite docs/evaluation/ (a new seed); the default checks against it",
    )
    args = parser.parse_args(argv)
    seed = variants.SEED
    with tempfile.TemporaryDirectory(prefix="refmon-reproduce-") as name:
        tmp = Path(name)
        print(f"seed {seed}: generating and replaying the variants in {', '.join(TAGS)} ...")
        dumps, digest = replay_all(tmp, seed)
        runs = {tag: cv.load(str(path)) for tag, path in dumps.items()}
        report = cv.report(runs)
        tables = report.split("## Changes")[0]
        evaluation = ROOT / "docs" / "evaluation"
        evaluation.mkdir(exist_ok=True)
        verdict = []
        for tag, path in dumps.items():
            committed = evaluation / f"{tag}-seed-{seed}.jsonl"
            if args.refresh or not committed.exists():
                committed.write_text(path.read_text(), encoding="utf-8")
                verdict.append(f"{tag}: written")
            else:
                same = cv.load(str(committed)) == runs[tag]
                verdict.append(
                    f"{tag}: {'identical to' if same else 'DIFFERENT from'} docs/evaluation"
                )
                if not same:
                    print("\n".join(verdict))
                    raise SystemExit("the regenerated results differ from the committed ones")
        (evaluation / f"comparison-seed-{seed}.md").write_text(report, encoding="utf-8")
        print("variants:", digest[:16], "|", "; ".join(verdict))
        golden, per = golden_table(tmp)
        coverage = coverage_table(per)
        audit = sh([PY, "-m", "refmon.audit", "tests/golden"], check=False).strip()
        if args.skip_tests:
            tests = "(skipped)"
        else:
            out = sh([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider"], check=False)
            last = out.strip().splitlines()[-1] if out.strip() else "no output"
            tests = re.sub(r" in \d+(?:\.\d+)?s.*$", "", last)  # the duration changes every run
        stats = stats_table(runs)
        text = RESULTS.read_text(encoding="utf-8")
        blocks = {
            "versions": versions_table(),
            "matrix": f"Seed {seed}; sha256 of the generated variants file `{digest}`.\n\n{tables}",
            "stats": stats,
            "golden": golden,
            "coverage": coverage,
            "audit": f"```\n{audit}\n```",
            "tests": f"`{tests}`",
            # the publishability check scans this very file, so its block is written last and the
            # scan sees a placeholder, never its own earlier output
            "publishable": "(checking)",
        }
        for key, body in blocks.items():
            text = replace_block(text, key, body)
        RESULTS.write_text(text, encoding="utf-8")
        publishable = sh([PY, "scripts/check_publishable.py"], check=False).strip()
        text = replace_block(text, "publishable", f"```\n{publishable}\n```")
        RESULTS.write_text(text, encoding="utf-8")
    print("docs/results.md and docs/evaluation/ regenerated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
