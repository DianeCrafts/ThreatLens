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
    web_log_file: Path
    web_events_output: Path
    web_alerts_output: Path
    network_packets_replay: Path
    network_events_output: Path
    network_alerts_output: Path


class BruteForceConfig(BaseModel):
    failed_attempt_threshold: int = Field(..., ge=1)
    time_window_seconds: int = Field(..., ge=1)


class SuspiciousWebConfig(BaseModel):
    """More than this many requests from one IP inside the window triggers an alert."""

    request_threshold: int = Field(..., ge=1)
    time_window_seconds: int = Field(..., ge=1)


class TrafficSpikeConfig(BaseModel):
    """Global request volume above threshold inside the window triggers an alert."""

    window_seconds: int = Field(..., ge=1)
    min_requests_in_window: int = Field(..., ge=1)


class WebDetectionConfig(BaseModel):
    suspicious_ip: SuspiciousWebConfig
    traffic_spike: TrafficSpikeConfig


class PortScanRuleConfig(BaseModel):
    """More than this many distinct destination ports from one source in the window."""

    min_unique_destination_ports: int = Field(..., ge=1)
    time_window_seconds: int = Field(..., ge=1)


class RepeatedConnectionsRuleConfig(BaseModel):
    """More than this many observations from one source in the window."""

    min_connection_attempts: int = Field(..., ge=1)
    time_window_seconds: int = Field(..., ge=1)


class NetworkDetectionConfig(BaseModel):
    port_scan: PortScanRuleConfig
    repeated_connections: RepeatedConnectionsRuleConfig


class DetectionConfig(BaseModel):
    brute_force: BruteForceConfig
    web: WebDetectionConfig
    network: NetworkDetectionConfig


class AppSettings(BaseModel):
    paths: PathsConfig
    detection: DetectionConfig

    @classmethod
    def from_yaml(cls, config_path: Path) -> AppSettings:
        raw: dict[str, Any] = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        project_root = config_path.parent.parent
        paths_raw = dict(raw.get("paths", {}))
        path_keys = (
            "log_file",
            "events_output",
            "alerts_output",
            "summary_output",
            "web_log_file",
            "web_events_output",
            "web_alerts_output",
            "network_packets_replay",
            "network_events_output",
            "network_alerts_output",
        )
        for key in path_keys:
            if key in paths_raw and paths_raw[key] is not None:
                paths_raw[key] = (project_root / Path(str(paths_raw[key]))).resolve()
        merged = {"paths": paths_raw, "detection": raw.get("detection", {})}
        return cls.model_validate(merged)
