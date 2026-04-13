from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class PathsConfig(BaseModel):
    log_file: Path
    events_output: Path
    alerts_output: Path
    summary_output: Path


class BruteForceConfig(BaseModel):
    failed_attempt_threshold: int = Field(..., ge=1)
    time_window_seconds: int = Field(..., ge=1)


class DetectionConfig(BaseModel):
    brute_force: BruteForceConfig


class AppSettings(BaseModel):
    paths: PathsConfig
    detection: DetectionConfig

    @classmethod
    def from_yaml(cls, config_path: Path) -> AppSettings:
        raw: dict[str, Any] = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        project_root = config_path.parent.parent
        paths_raw = dict(raw.get("paths", {}))
        for key in ("log_file", "events_output", "alerts_output", "summary_output"):
            if key in paths_raw and paths_raw[key] is not None:
                paths_raw[key] = (project_root / Path(str(paths_raw[key]))).resolve()
        merged = {"paths": paths_raw, "detection": raw.get("detection", {})}
        return cls.model_validate(merged)
