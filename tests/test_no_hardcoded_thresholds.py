"""Phase 2: "Remove every hard-coded threshold". Numeric literals in the stage code are limited to
structural constants; every threshold, weight, half-life and rate comes from the policy model
(`refmon.policy`), the single place with defaults."""

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "refmon"
# Stage code: where a threshold hidden in a function body would change a decision.
# Left out: features.py (what a feature is: digits kept, the shape of an escape; the limits that
# decide `hide` are in the policy) and privacy.py (bit packing and hashing of the Bloom filter).
DATA_STRUCTURE_MODULES = {"features.py", "privacy.py"}
STAGES = [
    *[p for p in sorted((SRC / "pipeline").glob("*.py")) if p.name not in DATA_STRUCTURE_MODULES],
    *[p for p in sorted((SRC / "calculus").glob("*.py")) if p.name not in DATA_STRUCTURE_MODULES],
    SRC / "learning.py",
    SRC / "gate.py",
    SRC / "contain.py",
]
ALLOWED = {0, 1, 2, 3, -1}  # counters and indices; 3 is the number of questions (the 3/2/1 rule)


def literals(path: Path):
    tree = ast.parse(path.read_text())
    skip = set()
    for node in ast.walk(tree):  # docstrings and annotations are not logic
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            skip.add(id(node.value))
    for node in ast.walk(tree):
        is_number = isinstance(node, ast.Constant) and type(node.value) in (int, float)
        if is_number and id(node) not in skip:
            yield node.lineno, node.value


def test_stage_code_has_no_numeric_literals_beyond_structural_constants():
    offenders = [
        f"{path.relative_to(SRC)}:{line}: {value}"
        for path in STAGES
        for line, value in literals(path)
        if value not in ALLOWED
    ]
    assert offenders == []
