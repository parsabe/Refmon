# Refmon: install, test, and regenerate every result of the repository.
#   make install      create .venv and install the package with its test tools
#   make test         the test suite
#   make reproduce    regenerate every result table from scratch (docs/results.md, docs/evaluation/)
#   make all          lint, tests, privacy audit, robustness matrix and the publishability check
PY ?= .venv/bin/python

.PHONY: install test lint audit matrix publishable reproduce all clean

install:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

audit:
	$(PY) -m refmon.audit tests/golden

matrix:
	$(PY) -m refmon.variants --golden tests/golden --out build/robustness-matrix.csv

publishable:
	$(PY) scripts/check_publishable.py

reproduce:
	$(PY) scripts/reproduce.py

all: lint test audit matrix publishable

clean:
	rm -rf build .pytest_cache .ruff_cache .hypothesis
