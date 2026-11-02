# Refmon Technical Paper (Two-Column LaTeX Manuscript)

This directory contains the self-contained two-column LaTeX paper documenting **Refmon (Provenance
Gate v2, specification `v2.0`, package `refmon 2.0.0`)**: vector TikZ pipeline and flow diagrams,
architecture figures, formal algorithms, evaluation tables and eight data-driven charts, the
interactive attack lab, the daemon's self-monitoring and notifications, the deployment status, AI
disclosure, bibliography, and complete mathematical proofs; and the companion diagram book.
`main.pdf` is the built paper.

## Files

- `main.tex`: the manuscript (`\documentclass[10pt,twocolumn,letterpaper]{article}`, 26 pages):
  1. **Introduction**
  2. **Background and Related Work**
  3. **Methodology and Mathematical Formulation**: the six-stage pipeline, provenance decay and
     noisy-OR, the three-question Bayesian calculus and contract gate, surprisal and maturity,
     burst and drift tests, the rootkit sensor, Gate, Contain and reporting
  4. **Experiments, Algorithms, and Implementation Tests**: reference implementation and
     packaging, Algorithms 1 to 3, the golden catalog and seeded mutation matrices (`v1.0` to
     `v2.0`) with reproducibility, where the remaining misses are (per scenario and per mutation
     dimension), the live cluster barrier and rootkit tests, the daemon's self-monitoring and
     notifications, the **interactive attack lab** (35 templates, results per family, evidence
     margins, signals and single-signal ablation, latency), and the privacy audit and test-suite
     summary
  5. **Discussion**: what the attack lab shows, limitations, and the deployment status
  6. **Future Work**, 7. **Conclusion**, 8. **AI Disclosure**, **References**
  - **Appendices**: A supplementary data (pipeline figure, frozen weights and their chart, barrier
    listing, command-intent probes, the 16-scenario live suite); B the attack-lab templates with the
    reference-run decision of each; C to J the proofs (decay and noisy-OR, Bayes-optimal
    thresholds and contract gate, posterior monotonicity in `v1.3`, Laplace surprisal and
    Good-Turing, rate and CUSUM properties, differential privacy and Bloom filtering, bounds of the
    trust mark in `v2.0`, multi-pass rootkit churn suppression)
- `references.bib`: companion BibTeX database for venues that use external BibTeX styles (the
  manuscript embeds its bibliography).
- `figures/refmon_pipeline.jpg`, `figures/refmon_cluster_deployment.jpg`: raster figures.
- `figures/fig_*.pdf` and `make_figures.py`: the eight charts (see [Charts](#charts)).
- `diagrams.tex` and `diagrams/`: the companion diagram book (see [Diagram book](#diagram-book)).
- `Makefile`: `make pdf`, `make figures`, `make diagrams`, `make overleaf-zip`, `make clean`.
- `refmon-paper-overleaf.zip`: the manuscript packaged for Overleaf.

The attack-lab numbers in Section 4 and Appendix B come from the reference run at git `c53167a`,
committed in trimmed form (no command text or paths) as `docs/evaluation/lab-reference-run.json`;
its decisions, log-odds and overrides are identical to the first reference run at `771bf8b`.
`docs/attack-lab.md` holds the same tables and the run's full analysis.

## Charts

`make figures` (needs `pip install -e ".[paper]"` in the repository root, which adds matplotlib)
runs `make_figures.py`. It reads only committed data, so anyone can rebuild the charts:

| File | Figure | Data |
|---|---|---|
| `fig_rounds.pdf` | containment and false blocks of every pre-registered round, Wilson intervals | `docs/evaluation/<version>-seed-<seed>.jsonl` |
| `fig_outcomes.pdf` | golden confusion matrix; v2.0 outcome donuts (malicious, neutral benign) | `v2.0-seed-171139148.jsonl` |
| `fig_scenarios.pdf` | outcome per malicious scenario under mutation | the same |
| `fig_dimensions.pdf` | contained and blocked share per mutation dimension | the same |
| `fig_lab_evidence.pdf` | attack lab: log-odds of every command against the thresholds | `docs/evaluation/lab-reference-run.json` |
| `fig_lab_signals.pdf` | which questions and signals caught the lab attacks | the same |
| `fig_lab_ablation_latency.pdf` | single-signal ablation; decision latency | the same, with `labreport._worst_single_removal` |
| `fig_weights.pdf` | the signal weights of the signed policy (appendix) | `refmon.policy.default_policy()` |

The outcome classes come from `scripts/compare_versions.py`, so a chart cannot disagree with a
table. Every chart is fitted to its final width (one column 3.41 in, full width 7.06 in, the
appendix chart 0.56 of the width), so LaTeX places it at 1:1 and its type stays at 6.5 to 7.5 pt.
The output is deterministic: unchanged data gives byte-identical files. Four charts are also
written as PNG to `docs/img/` for the repository README. Visual system: decisions on one blue
ramp (allow light, hold mid, block dark), errors (a missed attack, a false block) in red and always
labelled, the three questions in blue, orange and aqua, TeX Gyre Heros (DejaVu Sans if TinyTeX's
font is missing).

## Diagram book

`diagrams.tex` (`make diagrams`, 22 pages) draws the system level by level; each figure is a
stand-alone `tikzpicture` in `diagrams/<name>.tex` with the shared styles of `diagrams/styles.tex`,
so `main.tex` can `\input` any of them.

| Level | Diagrams |
|---|---|
| 0 system context | `L0-system-context` |
| 1 one event through the core | `L1-core-pipeline` |
| 2 inside each stage | `L2a-observe`, `L2b-tag-rules`, `L2b2-label-strength`, `L2c-provenance-S06`, `L2d-link`, `L2e-signals`, `L2f-judge`, `L2g-calculus-waterfall`, `L2h-rates`, `L2i-gate`, `L2j-contain` |
| 3 governance and privacy | `L3a-policy-lifecycle`, `L3b-learning-tune`, `L3c-exposure`, `L3d-selftest-heartbeat`, `L3e-privacy-reporting` |
| 4 evaluation | `L4a-reproduce` (replays `v1.7` and `v2.0`, refuses a tag without its code), `L4b-phases-versions` (build phases and the version history `v1.0` to `v2.0` with containment and false blocks), `L4c-test-layers` |
| 5 live user-space deployment | `L5a-live-guard`, `L5b-sandbox-watcher`, `L5c-rootkit`, `L5d-health-notify` (health thread, notification channels, the outside `refmon health` check) |

## Updating the paper after new results

1. Commit the new per-variant data or lab reference run in `docs/evaluation/` (`make reproduce`
   writes and checks the per-variant files of the active seed).
2. `make figures`, then compare the numbers quoted in `main.tex` (Section 4, the abstract and the
   conclusion) with the charts and with `docs/results.md`.
3. `make pdf` (twice is built in), check `main.log` for `!` errors and undefined references.
4. `make diagrams` if a diagram changed; `make overleaf-zip` to refresh the archive.

`diagrams.pdf` and the LaTeX auxiliary files are build outputs and are not committed; `main.pdf`,
the chart PDFs and `refmon-paper-overleaf.zip` are.

## How to compile

### Option A: local TeX Live / MacTeX / MiKTeX

```bash
make pdf
# or directly:
pdflatex main.tex && pdflatex main.tex
```

### Option B: Overleaf

Run `make overleaf-zip` (or upload `main.tex`, `references.bib` and the `figures/` folder into a new
Overleaf project) and click **Recompile**. The archive holds the built chart PDFs, so Overleaf needs
neither Python nor the repository data; `make_figures.py` is included only for reference.
