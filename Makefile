# Refmon: install, test, and regenerate every result of the repository.
#   make install      create .venv and install the package with its test tools
#   make test         the test suite
#   make reproduce    regenerate every result table from scratch (docs/results.md, docs/evaluation/)
#   make all          lint, tests, privacy audit, robustness matrix and the publishability check
PY ?= .venv/bin/python
# Refmon needs Python 3.12+ (on the cluster, plain python3 is 3.6); override: make install PYTHON=...
PYTHON ?= python3.12

.PHONY: install test lint audit matrix publishable reproduce serve gui health scan-rootkit lab deb rpm packages all clean

install:  # a venv made by uv has no pip: then uv installs
	test -x .venv/bin/python || $(PYTHON) -m venv .venv
	if .venv/bin/python -m pip --version >/dev/null 2>&1; then \
		.venv/bin/python -m pip install -e ".[dev]"; \
	else uv pip install --python .venv/bin/python -e ".[dev]"; fi

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

serve:
	$(PY) -m refmon.cli serve

gui:  # launch Reference Monitor GUI in default desktop browser
	$(PY) -m refmon.cli gui

health:  # is the daemon alive? exit 0 healthy, 1 not running or stale, 2 running with a problem
	$(PY) -m refmon.cli health

scan-rootkit:  # exit 0 allow, 1 hold (findings to review), 2 block
	$(PY) -m refmon.cli scan-rootkit

lab:
	$(PY) -m refmon.cli lab

deb:  # build standalone .deb installer package in dist/
	$(PY) packaging/build_packages.py --deb

rpm:  # build standalone .rpm installer package in dist/
	$(PY) packaging/build_packages.py --rpm

packages:  # build both .deb and .rpm installer packages in dist/
	$(PY) packaging/build_packages.py --all

all: lint test audit matrix publishable

clean:
	rm -rf build .pytest_cache .ruff_cache .hypothesis
