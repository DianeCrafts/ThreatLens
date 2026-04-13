from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel


class JsonWriter:
    """Writes JSON files with stable, human-readable formatting."""

    def __init__(self, indent: int = 2) -> None:
        self._indent = indent

    def write_model_sequence(self, path: Path, models: Sequence[BaseModel]) -> None:
        payload: list[dict[str, Any]] = [
            item.model_dump(mode="json") for item in models
        ]
        self.write_json(path, payload)

    def write_json(self, path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(payload, indent=self._indent, ensure_ascii=False)
        path.write_text(text + "\n", encoding="utf-8")
