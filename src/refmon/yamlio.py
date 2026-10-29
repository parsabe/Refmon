"""YAML reading and writing for policy files and rule packs: safe loading, no duplicate keys."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate mapping keys (a second value must not hide the first)."""


def _construct_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False):
    seen: set = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in seen:
            raise ValueError(f"duplicate key {key!r}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def read_document(path: Path | str) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        document = yaml.load(handle, Loader=_UniqueKeyLoader)
    if not isinstance(document, dict):
        raise ValueError("a policy file is a YAML mapping")
    return document


def write_document(document: dict[str, Any], path: Path | str) -> None:
    Path(path).write_text(yaml.safe_dump(document, sort_keys=False, width=100), encoding="utf-8")
