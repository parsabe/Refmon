# Refmon Technical Paper (Two-Column LaTeX Manuscript)

This directory contains the self-contained two-column LaTeX paper documenting **Refmon (Provenance
Gate v2, specification `v2.0`, package `refmon 2.0.0`)**: vector TikZ pipeline and flow diagrams,
architecture figures, formal algorithms, evaluation tables, the interactive attack lab, the
deployment status, AI disclosure, bibliography, and complete mathematical proofs.

## Files

- `main.tex`: the manuscript (`\documentclass[10pt,twocolumn,letterpaper]{article}`, 22 pages):
  1. **Introduction**
  2. **Background and Related Work**
  3. **Methodology and Mathematical Formulation**: the six-stage pipeline, provenance decay and
     noisy-OR, the three-question Bayesian calculus and contract gate, surprisal and maturity,
     burst and drift tests, the rootkit sensor, Gate, Contain and reporting
  4. **Experiments, Algorithms, and Implementation Tests**: reference implementation and
     packaging, Algorithms 1 to 3, the golden catalog and seeded mutation matrices (`v1.0` to
     `v2.0`), the live cluster barrier and rootkit tests, the **interactive attack lab** (35
     templates, results per family, evidence margins and single-signal ablation), and the privacy
     audit and test-suite summary
  5. **Discussion**: what the attack lab shows, limitations, and the deployment status
  6. **Future Work**, 7. **Conclusion**, 8. **AI Disclosure**, **References**
  - **Appendices**: A supplementary data (pipeline figure, frozen weights, barrier listing,
    command-intent probes, the 16-scenario live suite); B the attack-lab templates with the
    reference-run decision of each; C to J the proofs (decay and noisy-OR, Bayes-optimal
    thresholds and contract gate, posterior monotonicity in `v1.3`, Laplace surprisal and
    Good-Turing, rate and CUSUM properties, differential privacy and Bloom filtering, bounds of the
    trust mark in `v2.0`, multi-pass rootkit churn suppression)
- `references.bib`: companion BibTeX database for venues that use external BibTeX styles (the
  manuscript embeds its bibliography).
- `figures/refmon_pipeline.jpg`, `figures/refmon_cluster_deployment.jpg`: raster figures.
- `diagrams.tex` and `diagrams/`: the companion "diagram book", one stand-alone `tikzpicture` per
  figure, level by level, with shared styles in `diagrams/styles.tex`.
- `Makefile`: `make pdf`, `make diagrams`, `make overleaf-zip`, `make clean`.
- `refmon-paper-overleaf.zip`: the manuscript packaged for Overleaf.

The attack-lab numbers in Section 4 and Appendix B come from the saved reference run
`attack-lab/runs/run-20261102T125942Z` (git `771bf8b`); `docs/attack-lab.md` in the repository
holds the same tables and the run's full analysis.

## How to compile

### Option A: local TeX Live / MacTeX / MiKTeX

```bash
make pdf
# or directly:
pdflatex main.tex && pdflatex main.tex
```

### Option B: Overleaf

Run `make overleaf-zip` (or upload `main.tex`, `references.bib` and the `figures/` folder into a new
Overleaf project) and click **Recompile**.
