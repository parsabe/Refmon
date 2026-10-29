"""Obfuscation features computed in Observe before raw content is dropped (CLAUDE.md C11.7).

Only numbers leave this module: the Shannon entropy of the characters in bits, the share of
characters that sit in escape sequences or long encoded runs, and the longest run of whitespace
(a `/* ... */` comment counts as whitespace, since padding hides things the same way). `hide` fires
when the entropy or the run length exceeds the policy limit (signals.py).
"""

from __future__ import annotations

import math
import re
from collections import Counter

from ..policy import Policy

_ESCAPES = re.compile(r"%[0-9A-Fa-f]{2}|\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|&#\d+;")
_ENCODED_RUN = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_SPACE_RUN = re.compile(r"\s+")


def shannon_entropy(text: str) -> float:
    """H = -sum p_c log2 p_c over the characters of `text`."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def encoded_char_ratio(text: str) -> float:
    if not text:
        return 0.0
    covered = sum(len(m.group()) for m in _ESCAPES.finditer(text))
    covered += sum(len(m.group()) for m in _ENCODED_RUN.finditer(_ESCAPES.sub("", text)))
    return min(1.0, covered / len(text))


def longest_ws_run(text: str) -> int:
    blanked = _COMMENT.sub(lambda m: " " * len(m.group()), text)
    return max((len(m.group()) for m in _SPACE_RUN.finditer(blanked)), default=0)


def obfuscation_features(content: str, policy: Policy) -> dict[str, float | int]:
    """The three numbers, measured on the content exactly as the sensor handed it over."""
    return {
        "entropy_bits": round(shannon_entropy(content), 4),
        "encoded_char_ratio": round(encoded_char_ratio(content), 4),
        "longest_ws_run": longest_ws_run(content),
    }
