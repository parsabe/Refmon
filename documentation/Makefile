# Build the two-column Refmon LaTeX paper, the level-by-level diagram book, or an Overleaf zip archive.

LATEX ?= pdflatex
MAIN  ?= main

.PHONY: pdf diagrams overleaf-zip clean

pdf:
	$(LATEX) -interaction=nonstopmode -halt-on-error $(MAIN).tex
	$(LATEX) -interaction=nonstopmode -halt-on-error $(MAIN).tex

diagrams:
	$(LATEX) -interaction=nonstopmode -halt-on-error diagrams.tex
	$(LATEX) -interaction=nonstopmode -halt-on-error diagrams.tex

overleaf-zip:
	zip -r refmon-paper-overleaf.zip $(MAIN).tex diagrams.tex references.bib Makefile figures/ diagrams/

clean:
	rm -f $(MAIN).aux $(MAIN).log $(MAIN).out $(MAIN).toc $(MAIN).bbl $(MAIN).blg $(MAIN).pdf refmon-paper-overleaf.zip \
	      diagrams.aux diagrams.log diagrams.out diagrams.toc diagrams.lof diagrams.pdf

