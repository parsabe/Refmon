# Build the two-column Refmon LaTeX paper, its charts, the level-by-level diagram book, or an Overleaf zip archive.
# The charts (figures/fig_*.pdf) are committed; `make figures` rebuilds them from docs/evaluation/
# (needs the paper extra: pip install -e ".[paper]" in the repository root).

LATEX ?= pdflatex
PY    ?= ../.venv/bin/python
MAIN  ?= main

.PHONY: pdf figures diagrams overleaf-zip clean

pdf:
	$(LATEX) -interaction=nonstopmode -halt-on-error $(MAIN).tex
	$(LATEX) -interaction=nonstopmode -halt-on-error $(MAIN).tex

figures:
	$(PY) make_figures.py

diagrams:
	$(LATEX) -interaction=nonstopmode -halt-on-error diagrams.tex
	$(LATEX) -interaction=nonstopmode -halt-on-error diagrams.tex

overleaf-zip:
	zip -r refmon-paper-overleaf.zip $(MAIN).tex diagrams.tex references.bib Makefile make_figures.py figures/ diagrams/

clean:
	rm -f $(MAIN).aux $(MAIN).log $(MAIN).out $(MAIN).toc $(MAIN).bbl $(MAIN).blg $(MAIN).pdf refmon-paper-overleaf.zip \
	      diagrams.aux diagrams.log diagrams.out diagrams.toc diagrams.lof diagrams.pdf

