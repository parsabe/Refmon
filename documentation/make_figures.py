"""Build the charts of the Refmon paper from the committed evaluation data.

    make -C documentation figures      (needs the `paper` extra: pip install -e ".[paper]")

Inputs, all in the repository: the per-variant results of every pre-registered seed
(docs/evaluation/<version>-seed-<seed>.jsonl), the attack-lab reference run
(docs/evaluation/lab-reference-run.json), the golden catalog titles and the signal weights of the
default policy. Outputs: vector PDFs in documentation/figures/, one per figure, and PNG copies of
four of them in docs/img/ for the GitHub README. Nothing is measured
here; every number is counted from those files, with the outcome classes of
scripts/compare_versions.py and the ablation of src/refmon/labreport.py, so a chart cannot disagree
with a table.

Visual system: light print surface; decisions on one blue ordinal ramp (allow light, hold mid, block
dark), errors (an uncontained attack, a false block) in the reserved critical red and always named
in a label; the three questions in categorical slots 1 to 3 (blue, orange, aqua) of the validated
reference palette; recessive grid, no top or right spine, TeX Gyre Heros.
"""

from __future__ import annotations

import itertools
import json
import statistics
import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import matplotlib

matplotlib.use("pdf")
import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DATA = ROOT / "docs" / "evaluation"
OUT = HERE / "figures"
README_IMG = ROOT / "docs" / "img"  # PNG copies for the GitHub README, which shows no PDF
README_FIGURES = {"fig_rounds", "fig_outcomes", "fig_scenarios", "fig_lab_evidence"}
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "scripts")]

import compare_versions as cv  # noqa: E402

from refmon.evalstats import wilson_interval  # noqa: E402
from refmon.labreport import _worst_single_removal  # noqa: E402
from refmon.policy import default_policy  # noqa: E402

# -- visual system -------------------------------------------------------------------------------

TEXT, TEXT2, MUTED = "#0b0b0b", "#52514e", "#8b8a85"
GRID, SURFACE, TRACK = "#e4e3df", "#ffffff", "#f0efec"
ALLOW, HOLD, BLOCK = "#86b6ef", "#2a78d6", "#104281"  # ordinal blue: 250, 450, 650
ERROR = "#d03b3b"  # status critical: an uncontained attack or a false block
BEFORE = "#a3a29c"  # the version before a change (neutral)
Q_COLORS = {"origin": "#2a78d6", "contract": "#eb6834", "effect": "#1baf7a"}  # slots 1-3
COL, FULL = 3.41, 7.06  # inches: one column and the full text width of the paper
WEIGHTS = 0.56 * FULL  # the appendix is one column wide


def _setup() -> None:
    tex = Path.home() / ".TinyTeX" / "texmf-dist" / "fonts" / "opentype" / "public" / "tex-gyre"
    family = "DejaVu Sans"
    if (tex / "texgyreheros-regular.otf").is_file():
        for name in ("regular", "bold", "italic"):
            font_manager.fontManager.addfont(str(tex / f"texgyreheros-{name}.otf"))
        family = "TeX Gyre Heros"
    plt.rcParams.update(
        {
            "font.family": family,
            "font.size": 7,
            "axes.titlesize": 7.5,
            "axes.titleweight": "bold",
            "axes.titlelocation": "left",
            "axes.titlepad": 6,
            "axes.labelsize": 7,
            "axes.labelcolor": TEXT2,
            "axes.edgecolor": MUTED,
            "axes.linewidth": 0.6,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.facecolor": SURFACE,
            "figure.facecolor": SURFACE,
            "xtick.color": TEXT2,
            "ytick.color": TEXT2,
            "xtick.labelsize": 6.5,
            "ytick.labelsize": 6.5,
            "xtick.major.width": 0.6,
            "ytick.major.width": 0,
            "xtick.major.size": 2.5,
            "ytick.major.size": 0,
            "legend.fontsize": 6.5,
            "legend.frameon": False,
            "text.color": TEXT,
            "pdf.fonttype": 42,
            "savefig.bbox": "tight",
            "savefig.pad_inches": 0.02,
        }
    )


def _xgrid(ax) -> None:
    ax.grid(axis="x", color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)


def _fit(fig, width: float) -> None:
    """Resize the figure until its drawn extent (labels included) is `width` inches wide, so LaTeX
    places it at 1:1 and the type stays at its set size instead of being scaled down. Labels do not
    shrink with the figure, but the drawn width still grows with it, so bisection finds the size."""
    h = fig.get_size_inches()[1]
    lo, hi = 0.3 * width, 2.0 * width
    for _ in range(40):
        mid = (lo + hi) / 2
        fig.set_size_inches(mid, h)
        drawn = fig.get_tightbbox().width
        if abs(drawn - width) < 0.003:
            return
        lo, hi = (mid, hi) if drawn < width else (lo, mid)


def _save(fig, name: str, width: float) -> Path:
    OUT.mkdir(exist_ok=True)
    _fit(fig, width - 2 * plt.rcParams["savefig.pad_inches"])
    path = OUT / f"{name}.pdf"
    fig.savefig(path, metadata={"CreationDate": None})  # reproducible: same data, same file
    if name in README_FIGURES:
        README_IMG.mkdir(parents=True, exist_ok=True)
        fig.savefig(README_IMG / f"{name}.png", dpi=170, metadata={"Software": None})
    plt.close(fig)
    return path


def _dot(face: str, edge: str, label: str) -> Line2D:
    """A legend entry for a dot mark."""
    return Line2D([], [], marker="o", ls="none", mfc=face, mec=edge, ms=4.5, label=label)


def _pct(k: int, n: int) -> tuple[float, float, float]:
    lo, hi = wilson_interval(k, n)
    return 100 * k / n, 100 * lo, 100 * hi


# -- data ----------------------------------------------------------------------------------------

ROUNDS = [  # (seed, versions in order); each seed was recorded before the change it measures
    ("654514256", ["v1.0", "v1.1", "v1.2", "v1.3"]),
    ("833754500", ["v1.4", "v1.5"]),
    ("545728926", ["v1.5", "v1.6"]),
    ("616687759", ["v1.6", "v1.7"]),
    ("171139148", ["v1.7", "v2.0"]),
]
ACTIVE = ("171139148", "v2.0")

SHORT = {
    "S01": "ClickFix, run dialog",
    "S02": "ClickFix, terminal",
    "S03": "FileFix, address bar",
    "S04": "Command from a PDF",
    "S05": "Typed from a video (gap)",
    "S06": "Delayed persistence",
    "S07": "Payload on file-share host",
    "S08": "Canary credential read",
    "S12": "Prompt-injected AI agent",
    "S13": "Web worker spawns shell",
    "S14": "Web shell dropped",
    "S15": "Web worker calls out",
    "S17": "Privilege escalation",
    "S18": "Lateral fan-out",
    "S19": "Ransomware burst",
    "S20": "Security tool stopped",
    "S21": "Poisoned package",
    "S22": "Abused DB connection (gap)",
    "S25": "Node2Shell child process",
    "S26b": "Fetch, then outbound call",
    "S26c": "Fetch, then executable write",
    "S27": "Oversized responses",
    "S31": "Macro starts script host",
    "S32": "USB program persists",
    "S33": "Fake installer",
    "S34": "Infostealer",
    "S35": "Drive-by hidden script",
}


def rows(version: str, seed: str) -> list[dict]:
    path = DATA / f"{version}-seed-{seed}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def malicious(rs: list[dict]) -> list[dict]:
    return [r for r in rs if r["kind"] == "malicious"]


def neutral_benign(rs: list[dict]) -> list[dict]:
    return [r for r in rs if r["kind"] == "benign" and not r.get("adds")]


def contained(r: dict) -> bool:
    return cv.outcome(r) in ("block", "effective hold")


def lab() -> tuple[dict, list[dict]]:
    doc = json.loads((DATA / "lab-reference-run.json").read_text())
    return doc["meta"], doc["results"]


# -- figure 1: the pre-registered rounds ---------------------------------------------------------


def fig_rounds() -> Path:
    steps = []
    for seed, versions in ROUNDS:
        data = {v: rows(v, seed) for v in versions}
        for a, b in itertools.pairwise(versions):
            steps.append((seed, a, b, data[a], data[b]))
    steps.reverse()  # newest on top
    fig, (ax1, ax2) = plt.subplots(
        1, 2, figsize=(FULL, 2.35), sharey=True, gridspec_kw={"wspace": 0.08}
    )
    ys = range(len(steps))
    for y, (_, _a, _b, ra, rb) in zip(ys, steps, strict=True):
        for ax, pick, test in (
            (ax1, malicious, contained),
            (ax2, neutral_benign, lambda r: r["decision"] == "block"),
        ):
            pa, pb = pick(ra), pick(rb)
            va = _pct(sum(map(test, pa)), len(pa))
            vb = _pct(sum(map(test, pb)), len(pb))
            for v, dy, color, face in ((va, 0.16, BEFORE, SURFACE), (vb, -0.16, BLOCK, BLOCK)):
                ax.plot([v[1], v[2]], [y + dy, y + dy], color=color, linewidth=0.8, zorder=2)
                ax.plot(v[0], y + dy, "o", ms=4.2, mfc=face, mec=color, mew=1.0, zorder=3)
            ax.annotate(
                f"{vb[0]:.1f}%", (max(va[2], vb[2]), y), xytext=(4, 0), textcoords="offset points",
                va="center", fontsize=6, color=TEXT,
            )  # fmt: skip
    labels = [f"{a} → {b}\nseed {seed}" for seed, a, b, _, _ in steps]
    ax1.set_yticks(list(ys), labels, fontsize=6.2)
    ax1.set_xlim(84, 101.5)
    ax1.set_xlabel("malicious variants contained (block or effective hold), %")
    ax1.set_title("(a) Containment of attacks")
    ax2.set_xlim(-0.4, 8.6)
    ax2.set_xlabel("neutral benign variants blocked (false blocks), %")
    ax2.set_title("(b) False blocks on harmless work")
    for ax in (ax1, ax2):
        _xgrid(ax)
        ax.spines["left"].set_visible(False)
    handles = [
        _dot(SURFACE, BEFORE, "version before the change"),
        _dot(BLOCK, BLOCK, "version after the change"),
        Line2D([], [], color=TEXT2, lw=0.8, label="Wilson 95% interval"),
    ]  # fmt: skip
    fig.legend(handles=handles, loc="upper center", ncol=3, bbox_to_anchor=(0.5, -0.06))
    return _save(fig, "fig_rounds", FULL)


# -- figure 2: golden catalog and the v2.0 outcome split -----------------------------------------


def _donut(ax, parts: list[tuple[str, int, str]], center: str, sub: str, title: str) -> None:
    total = sum(n for _, n, _ in parts)
    shown = [(lab, n, c) for lab, n, c in parts if n > 0]
    ax.pie(
        [n for _, n, _ in shown], colors=[c for _, _, c in shown], startangle=90,
        counterclock=False,
        wedgeprops={"width": 0.34, "edgecolor": SURFACE, "linewidth": 1.2},
    )  # fmt: skip
    ax.text(0, 0.08, center, ha="center", va="center", fontsize=11, fontweight="bold", color=TEXT)
    ax.text(0, -0.2, sub, ha="center", va="center", fontsize=6, color=TEXT2)
    ax.set_title(title, loc="center", pad=2)
    ax.set_aspect("equal")
    ax.legend(
        [Patch(color=c) for _, _, c in parts],
        [f"{lab}  {n} ({100 * n / total:.1f}%)" for lab, n, _ in parts],
        loc="upper center", bbox_to_anchor=(0.5, 0.02), ncol=1, handlelength=1.0,
        handleheight=0.9, labelspacing=0.35,
    )  # fmt: skip


def fig_outcomes() -> Path:
    seed, version = ACTIVE
    rs = rows(version, seed)
    base = [r for r in rs if r["variant"] == "baseline"]
    order = ["allow", "hold", "block"]
    fig = plt.figure(figsize=(FULL, 2.45))
    grid = fig.add_gridspec(1, 3, width_ratios=[1.0, 1.0, 1.0], wspace=0.35)
    ax = fig.add_subplot(grid[0])
    counts = Counter((r["expected"], r["decision"]) for r in base)
    for i, exp in enumerate(order):
        for j, got in enumerate(order):
            n = counts.get((exp, got), 0)
            face = BLOCK if (n and i == j) else (ERROR if n else TRACK)
            ax.add_patch(plt.Rectangle((j, 2 - i), 0.94, 0.94, color=face, lw=0))
            ax.text(j + 0.47, 2 - i + 0.47, str(n), ha="center", va="center", fontsize=8,
                    color=SURFACE if n else MUTED,
                    fontweight="bold" if n else "normal")  # fmt: skip
    ax.set_xlim(-0.06, 3)
    ax.set_ylim(-0.06, 3)
    ax.set_xticks([0.47, 1.47, 2.47], [o.upper() for o in order])
    ax.set_yticks([2.47, 1.47, 0.47], [o.upper() for o in order])
    ax.tick_params(axis="x", length=0)
    ax.set_xlabel(f"decision of {version}")
    ax.set_ylabel("expected decision")
    for side in ("left", "bottom"):
        ax.spines[side].set_visible(False)
    ax.set_aspect("equal")
    ok = sum(n for (e, g), n in counts.items() if e == g)
    ax.set_title(f"(a) Golden catalog: {ok}/{len(base)} as expected", loc="center", pad=4)
    mal = malicious(rs)
    out = Counter(cv.outcome(r) for r in mal)
    unc = out["allow"] + out["hold pauses nothing"]
    n_ok = out["block"] + out["effective hold"]
    _donut(
        fig.add_subplot(grid[1]),
        [("Block", out["block"], BLOCK), ("Effective hold", out["effective hold"], HOLD),
         ("Uncontained", unc, ERROR)],
        f"{100 * n_ok / len(mal):.1f}%", f"of {len(mal)} contained",
        f"(b) Malicious variants, {version}",
    )  # fmt: skip
    neu = neutral_benign(rs)
    nb = Counter(r["decision"] for r in neu)
    _donut(
        fig.add_subplot(grid[2]),
        [("Allow", nb["allow"], ALLOW), ("Hold", nb["hold"], HOLD),
         ("Block (false block)", nb["block"], ERROR)],
        f"{nb['block']}", f"false blocks of {len(neu)}",
        f"(c) Neutral benign variants, {version}",
    )  # fmt: skip
    return _save(fig, "fig_outcomes", FULL)


# -- figure 3: per-scenario outcome of the mutations ---------------------------------------------


def fig_scenarios() -> Path:
    seed, version = ACTIVE
    mal = malicious(rows(version, seed))
    per: dict[str, Counter] = {}
    for r in mal:
        per.setdefault(r["scenario"], Counter())[cv.outcome(r)] += 1

    def share(sid: str) -> tuple[float, float]:
        c = per[sid]
        n = sum(c.values())
        return ((c["block"] + c["effective hold"]) / n, c["block"] / n)

    order = sorted(per, key=lambda s: (share(s), s))  # weakest at the bottom
    fig, ax = plt.subplots(figsize=(COL, 4.6))
    for y, sid in enumerate(order):
        c = per[sid]
        n = sum(c.values())
        left = 0.0
        unc = c["allow"] + c["hold pauses nothing"]
        for value, color in ((c["block"], BLOCK), (c["effective hold"], HOLD), (unc, ERROR)):
            w = 100 * value / n
            if w:
                ax.barh(y, w, left=left, height=0.68, color=color, edgecolor=SURFACE, linewidth=0.6)
            left += w
        if unc:
            ax.text(101.5, y, f"{unc}/{n} missed", va="center", fontsize=5.8, color=ERROR)
    ax.set_yticks(range(len(order)), [f"{s}  {SHORT.get(s, s)}" for s in order], fontsize=6.2)
    ax.set_xlim(0, 100)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_xlabel(f"share of mutated variants, % ({version}, seed {seed})")
    ax.spines["left"].set_visible(False)
    ax.set_title("Outcome per malicious scenario", loc="left", pad=16)
    ax.legend(
        [Patch(color=BLOCK), Patch(color=HOLD), Patch(color=ERROR)],
        ["Block", "Effective hold", "Uncontained"],
        loc="lower right", bbox_to_anchor=(1.02, 0.995), ncol=3, handlelength=1.0,
        borderaxespad=0.2,
    )  # fmt: skip
    ax.set_ylim(-0.6, len(order) - 0.4)
    return _save(fig, "fig_scenarios", COL)


# -- figure 4: robustness per mutation dimension -------------------------------------------------


def _dimension(r: dict) -> str:
    v = r["variant"]
    if v == "baseline":
        return "unmodified"
    if v == "no-label":
        return "origin label removed"
    if v.startswith("combo"):
        return "combination (2-4 factors)"
    return v.split("=", 1)[0]


def fig_dimensions() -> Path:
    seed, version = ACTIVE
    mal = malicious(rows(version, seed))
    groups: dict[str, list[dict]] = {}
    for r in mal:
        groups.setdefault(_dimension(r), []).append(r)
    stats = {}
    for dim, rs in groups.items():
        n = len(rs)
        stats[dim] = (
            n, _pct(sum(map(contained, rs)), n), _pct(sum(r["decision"] == "block" for r in rs), n)
        )  # fmt: skip
    order = sorted(stats, key=lambda d: (stats[d][1][0], stats[d][2][0]))
    fig, ax = plt.subplots(figsize=(COL, 2.55))
    for y, dim in enumerate(order):
        n, cont, blk = stats[dim]
        ax.plot(
            [blk[0], cont[0]], [y, y], color=GRID, linewidth=2.2, solid_capstyle="round", zorder=1
        )
        ax.plot([cont[1], cont[2]], [y, y], color=BLOCK, linewidth=0.8, zorder=2)
        ax.plot(blk[0], y, "o", ms=4.2, mfc=SURFACE, mec=HOLD, mew=1.0, zorder=3)
        ax.plot(cont[0], y, "o", ms=4.4, mfc=BLOCK, mec=BLOCK, zorder=3)
        ax.annotate(f"{cont[0]:.0f}%", (cont[0], y), xytext=(6, 0), textcoords="offset points",
                    va="center", fontsize=6)  # fmt: skip
    ax.set_yticks(range(len(order)), [f"{d}  (n={stats[d][0]})" for d in order], fontsize=6.2)
    ax.set_xlim(40, 106)
    ax.set_xticks([40, 50, 60, 70, 80, 90, 100])
    ax.set_xlabel(f"malicious variants, % ({version}, seed {seed})")
    _xgrid(ax)
    ax.spines["left"].set_visible(False)
    ax.set_title("Robustness by mutation dimension", loc="left")
    ax.legend(
        handles=[
            _dot(BLOCK, BLOCK, "contained (95% CI)"),
            _dot(SURFACE, HOLD, "blocked outright"),
        ],
        loc="upper center", bbox_to_anchor=(0.4, -0.2), ncol=2,
    )  # fmt: skip
    return _save(fig, "fig_dimensions", COL)


# -- figure 5: attack lab evidence ---------------------------------------------------------------


def _lab_kind(r: dict) -> str:
    if r["category"] == "benign":
        return "benign"
    if r["category"] == "known-limit":
        return "limit"
    return "attack"


def fig_lab_evidence() -> Path:
    meta, res = lab()
    prior, tb, th = meta["prior"], meta["tau_block"], meta["tau_hold"]
    groups = [
        ("attack", "Attacks (28)"),
        ("limit", "Known limit (1)"),
        ("benign", "Benign controls (6)"),
    ]
    # top to bottom: a heading row, then the group sorted by evidence (strongest first)
    lines: list[tuple[str, dict | None]] = []
    for kind, name in groups:
        lines.append((name, None))
        part = sorted((r for r in res if _lab_kind(r) == kind), key=lambda r: -r["log_odds"])
        lines.extend((r["template_id"].replace("_", " "), r) for r in part)
    lines.reverse()  # y grows upward
    fig, ax = plt.subplots(figsize=(COL, 5.5))
    lo_x, hi_x = prior - 0.25, max(r["log_odds"] for r in res) + 1.15
    ax.axvspan(lo_x, th, color=TRACK, lw=0, zorder=0)
    ax.axvspan(th, tb, color="#e7f0fb", lw=0, zorder=0)
    ax.axvspan(tb, hi_x, color="#dbe7f7", lw=0, zorder=0)
    ax.axvline(th, color=HOLD, lw=0.7, zorder=1)
    ax.axvline(tb, color=BLOCK, lw=0.7, zorder=1)
    colors = {"allow": ALLOW, "hold": HOLD, "block": BLOCK}
    ticks, names = [], []
    for y, (name, r) in enumerate(lines):
        if r is None:
            ax.text(lo_x + 0.08, y, name, va="center", ha="left", fontsize=6.4, fontweight="bold",
                    color=TEXT)  # fmt: skip
            continue
        ticks.append(y)
        names.append(name)
        dec = r["decision"]
        missed = _lab_kind(r) != "benign" and dec == "allow"
        false_alarm = _lab_kind(r) == "benign" and dec != "allow"
        color = ERROR if (missed or false_alarm) else colors[dec]
        ax.plot([prior, r["log_odds"]], [y, y], color=color, lw=1.0, zorder=2)
        marker = "D" if r["override"] else "o"
        ax.plot(r["log_odds"], y, marker, ms=3.7 if marker == "D" else 4.1, color=color, zorder=3)
        note = r["override"].replace("_", " ") if r["override"] else ("missed" if missed else "")
        if note:
            ax.annotate(note, (r["log_odds"], y), xytext=(5, 0), textcoords="offset points",
                        va="center", fontsize=5.4, color=ERROR if missed else TEXT2)  # fmt: skip
    ax.set_yticks(ticks, names, fontsize=5.9)
    ax.set_xlim(lo_x, hi_x)
    ax.set_ylim(-0.8, len(lines) - 0.3)
    top = len(lines) - 0.3
    ax.text(
        th - 0.06, top, f"HOLD \u2265 {th:.2f}", ha="right", va="bottom", fontsize=5.8, color=HOLD
    )
    ax.text(tb + 0.06, top, f"BLOCK \u2265 {tb:.2f}", ha="left", va="bottom", fontsize=5.8,
            color=BLOCK)  # fmt: skip
    ax.set_xlabel(f"posterior log-odds L (nats); each stem starts at the prior {prior:.2f}")
    ax.spines["left"].set_visible(False)
    ax.set_title("Attack lab: evidence per command", loc="left", pad=22)
    ax.legend(
        handles=[
            Line2D([], [], marker="o", color=BLOCK, lw=1, ms=4, label="Block"),
            Line2D([], [], marker="o", color=HOLD, lw=1, ms=4, label="Hold"),
            Line2D([], [], marker="o", color=ALLOW, lw=1, ms=4, label="Allow"),
            Line2D([], [], marker="o", color=ERROR, lw=1, ms=4, label="Missed"),
            Line2D([], [], marker="D", color=TEXT2, lw=0, ms=3.6, label="override"),
        ],
        loc="lower left", bbox_to_anchor=(-0.02, 1.012), ncol=5, handlelength=1.3,
        columnspacing=0.8, borderaxespad=0.1,
    )  # fmt: skip
    return _save(fig, "fig_lab_evidence", COL)


# -- figure 6: which questions and signals caught the lab attacks --------------------------------


def fig_lab_signals() -> Path:
    _, res = lab()
    attacks = [r for r in res if _lab_kind(r) == "attack"]
    n = len(attacks)
    fig, (ax1, ax2) = plt.subplots(
        2, 1, figsize=(COL, 3.9), gridspec_kw={"height_ratios": [1.0, 2.6], "hspace": 0.55}
    )
    qs = [("Origin", "origin"), ("Contract", "contract"), ("Effect", "effect")]
    vals = [sum(r[f"{q}_failed"] for r in attacks) for _, q in qs]
    extra = [("all three", sum(r["fails"] == 3 for r in attacks)),
             ("no outside origin", sum(not r["origin_failed"] for r in attacks))]  # fmt: skip
    names = [name for name, _ in qs] + [name for name, _ in extra]
    values = vals + [v for _, v in extra]
    colors = [Q_COLORS[q] for _, q in qs] + [MUTED, MUTED]
    ys = list(range(len(names)))[::-1]
    ax1.barh(ys, values, height=0.62, color=colors)
    for y, v in zip(ys, values, strict=True):
        ax1.text(v + 0.4, y, f"{v}/{n}", va="center", fontsize=6)
    ax1.set_yticks(ys, names, fontsize=6.3)
    ax1.set_xlim(0, n + 3.5)
    ax1.set_xlabel(f"lab attacks (of {n}) in which the question failed")
    _xgrid(ax1)
    ax1.spines["left"].set_visible(False)
    ax1.set_title("(a) Which of the three questions caught the attacks")
    freq = Counter(s for r in attacks for s in r["signals"])
    top = freq.most_common(14)[::-1]
    ys2 = range(len(top))
    ax2.barh(list(ys2), [c for _, c in top], height=0.62,
             color=[Q_COLORS[s.split("_", 1)[0]] for s, _ in top])  # fmt: skip
    for y, (_, c) in zip(ys2, top, strict=True):
        ax2.text(c + 0.25, y, str(c), va="center", fontsize=6)
    ax2.set_yticks(list(ys2), [s.split("_", 1)[1].replace("_", " ") for s, _ in top], fontsize=6.2)
    ax2.set_xlabel(f"lab attacks (of {n}) raising the signal")
    ax2.set_xlim(0, max(c for _, c in top) + 2)
    _xgrid(ax2)
    ax2.spines["left"].set_visible(False)
    ax2.set_title("(b) Signals raised, by question")
    ax2.legend(
        [Patch(color=Q_COLORS["contract"]), Patch(color=Q_COLORS["effect"])],
        ["Contract signal", "Effect signal"], loc="lower right", handlelength=1.0,
    )  # fmt: skip
    return _save(fig, "fig_lab_signals", COL)


# -- figure 7: ablation and latency --------------------------------------------------------------


def fig_lab_ablation_latency() -> Path:
    meta, res = lab()
    weights = meta["weights"]
    tb, th = meta["tau_block"], meta["tau_hold"]
    blocks = [r for r in res if _lab_kind(r) == "attack" and r["decision"] == "block"
              and not r["override"]]  # fmt: skip
    worst = Counter()
    for r in blocks:
        out = _worst_single_removal(SimpleNamespace(signals=r["signals"], log_odds=r["log_odds"]),
                                    weights, tb, th)  # fmt: skip
        worst[out[0] if out else "BLOCK"] += 1
    fig, (ax1, ax2) = plt.subplots(
        2, 1, figsize=(COL, 2.75), gridspec_kw={"height_ratios": [0.62, 1.6], "hspace": 0.95}
    )
    left = 0
    total = len(blocks)
    for key, color, name in (("ALLOW", ERROR, "silently allowed"), ("HOLD", HOLD, "held"),
                             ("BLOCK", BLOCK, "still blocked")):  # fmt: skip
        v = worst[key]
        ax1.barh(0, v, left=left, height=0.62, color=color, edgecolor=SURFACE, linewidth=1.0)
        text = f"{v} {name}" if v >= 3 else str(v)
        ax1.text(left + v / 2, 0, text, ha="center", va="center", fontsize=6.3,
                 color=SURFACE, fontweight="bold")  # fmt: skip
        left += v
    ax1.set_xlim(0, total)
    ax1.set_yticks([])
    ax1.set_xticks([0, 5, 10, 15, 20, total])
    ax1.spines["left"].set_visible(False)
    ax1.set_xlabel(f"score-based lab blocks (of {total}), worst case with one signal removed")
    ax1.set_title("(a) Single-signal ablation (contract gate applied)")
    ms = sorted(r["judge_ms"] for r in res)
    med = statistics.median(ms)
    edges = [1.0 * (10 ** (i / 6)) for i in range(0, 15)]
    ax2.hist(ms, bins=edges, color=HOLD, edgecolor=SURFACE, linewidth=0.6)
    ax2.set_xscale("log")
    ax2.axvline(med, color=BLOCK, lw=0.9)
    ax2.text(med * 1.08, ax2.get_ylim()[1] * 0.92, f"median {med:.1f} ms", fontsize=6, color=BLOCK,
             va="top")  # fmt: skip
    ax2.set_xlabel("decision time per command, ms (log scale; before the command starts)")
    ax2.set_ylabel("commands")
    ax2.grid(axis="y", color=GRID, linewidth=0.5)
    ax2.set_axisbelow(True)
    ax2.set_title(f"(b) Decision latency, {len(ms)} lab commands")
    ax2.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:g}"))
    return _save(fig, "fig_lab_ablation_latency", COL)


# -- figure 8: the signal weights ----------------------------------------------------------------


def fig_weights() -> Path:
    weights = dict(default_policy().math.weights)
    order = []
    for q in ("origin", "contract", "effect"):
        part = sorted((s for s in weights if s.startswith(q + "_")), key=lambda s: weights[s])
        order.extend(part)
    order = order[::-1]
    fig, ax = plt.subplots(figsize=(COL, 3.9))
    ys = range(len(order))[::-1]
    for y, s in zip(ys, order, strict=True):
        ax.barh(y, weights[s], height=0.64, color=Q_COLORS[s.split("_", 1)[0]])
    names = [s.split("_", 1)[1].replace("_", " ") for s in order]
    ax.set_yticks(
        list(ys), ["external origin" if n == "external" else n for n in names], fontsize=6.1
    )
    ax.set_xlabel("weight w (nats) = ln P(signal | attack) / P(signal | benign)")
    ax.set_xlim(0, 5)
    _xgrid(ax)
    ax.spines["left"].set_visible(False)
    ax.set_title("Signal weights of the signed policy (frozen since v1.0)", loc="left")
    ax.legend(
        [Patch(color=Q_COLORS[q]) for q in ("origin", "contract", "effect")],
        ["Origin", "Contract", "Effect"], loc="lower right", handlelength=1.0,
    )  # fmt: skip
    return _save(fig, "fig_weights", WEIGHTS)


FIGURES = [
    fig_rounds,
    fig_outcomes,
    fig_scenarios,
    fig_dimensions,
    fig_lab_evidence,
    fig_lab_signals,
    fig_lab_ablation_latency,
    fig_weights,
]


def main() -> int:
    _setup()
    for build in FIGURES:
        print(build().relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
