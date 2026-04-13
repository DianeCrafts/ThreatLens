from __future__ import annotations

from pathlib import Path


class FileCollector:
    """Reads raw lines from a UTF-8 text file."""

    def __init__(self, file_path: Path) -> None:
        self._file_path = file_path

    def iter_lines(self) -> list[str]:
        if not self._file_path.is_file():
            raise FileNotFoundError(f"Log file not found: {self._file_path}")
        text = self._file_path.read_text(encoding="utf-8", errors="replace")
        return text.splitlines()
