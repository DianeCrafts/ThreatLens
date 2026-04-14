from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any


def iter_replay_records(path: Path) -> Iterator[dict[str, Any]]:
    """
    Yield dict records from a JSON replay file.

    Accepts a top-level JSON array or an object with a ``records`` / ``packets`` array.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Replay file not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid replay JSON: {path}") from exc

    items: list[Any]
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        items = []
        for key in ("records", "packets", "observations"):
            block = raw.get(key)
            if isinstance(block, list):
                items = block
                break
    else:
        items = []

    for item in items:
        if isinstance(item, dict):
            yield item
