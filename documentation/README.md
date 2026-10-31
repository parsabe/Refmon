# Refmon Technical Paper (Two-Column LaTeX Manuscript)

This directory contains the self-contained two-column LaTeX paper documenting **Refmon (Provenance Gate v2, `v1.3`)**, including vector TikZ pipeline/shape diagrams, high-resolution architectural figures, formal algorithms, evaluation tables, AI disclosure, bibliography, and complete mathematical proofs.

## Files

- `main.tex` — Complete two-column manuscript (`\documentclass[10pt,twocolumn,letterpaper]{article}`):
  - **Abstract**
  - **1. Introduction**
  - **2. Background and Related Work**
  - **3. Methodology and Mathematical Formulation** (with TikZ pipeline, decision-threshold geometry, hold state-machine shapes, and raster figures)
  - **4. Experiments, Algorithms, and Implementation Tests** (Algorithms 1–3, Python barrier listing, 46 golden scenarios, 879 seeded variants, 16-scenario live barrier suite, 6-engine rootkit tests, privacy audit)
  - **5. Discussion**
  - **6. Future Work**
  - **7. Conclusion**
  - **8. AI Disclosure**
  - **References** (embedded `\thebibliography` for zero-friction compilation + companion `references.bib`)
  - **Appendices A–G** (formal proofs of decay/Noisy-OR, Bayes minimal-risk thresholds, `v1.3` monotonicity theorem resolving Finding F8, Laplace surprisal & Good-Turing unseen mass, Poisson/CUSUM drift & incident-frozen baselines, $\varepsilon$-differential privacy & zero-FP confirmed Bloom filters, and multi-pass rootkit race suppression)
- `references.bib` — Companion BibTeX database for venues using external BibTeX styles.
- `figures/refmon_pipeline.jpg` — Six-stage privacy-preserving pipeline architecture figure.
- `figures/refmon_cluster_deployment.jpg` — Multi-tier cluster barrier and 6-engine cross-view rootkit verification figure.
- `diagrams.tex` — Companion "diagram book": 24 TikZ pipeline shapes, diagrams and flowcharts, level by level (Level 0 system context → Level 1 `Pipeline.process` → Level 2 every stage: Observe, Tag, label strength, S06 provenance graph, Link, signal map, Judge, calculus waterfall, rate tests, Gate, Contain → Level 3 policy lifecycle, learning/tune, Exposure, self-test/heartbeat, privacy → Level 4 reproduction, phases/versions, test layers → Level 5 live guard, sandbox watcher, rootkit scanner).
- `diagrams/` — One stand-alone `tikzpicture` per figure plus `styles.tex` (shared `rm …` styles and colours). To reuse one in `main.tex`: add `\usepackage{adjustbox}` and `\input{diagrams/styles}` to the preamble, then `\adjustbox{max width=\textwidth}{\input{diagrams/L1-core-pipeline}}` inside a `figure*`.
- `Makefile` — Targets for `make pdf`, `make diagrams`, `make overleaf-zip`, and `make clean`.

## How to Compile

### Option A: Local TeX Live / MacTeX / MikTeX
```bash
make pdf
# or directly:
pdflatex main.tex && pdflatex main.tex
```

### Option B: Overleaf
Run `make overleaf-zip` (or upload `main.tex`, `references.bib`, and the `figures/` folder directly into a new Overleaf project) and click **Recompile**.

