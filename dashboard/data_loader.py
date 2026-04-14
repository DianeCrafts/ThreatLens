from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_output_paths(root: Path | None = None) -> dict[str, Path]:
    base = root or repository_root()
    return {
        "auth_events": base / "outputs" / "events.json",
        "auth_alerts": base / "outputs" / "alerts.json",
        "web_events": base / "outputs" / "web_events.json",
        "web_alerts": base / "outputs" / "web_alerts.json",
    }


def safe_load_json_list(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            return []
        data = json.loads(text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    return [row for row in data if isinstance(row, dict)]


@dataclass(frozen=True)
class DashboardSnapshot:
    auth_events: pd.DataFrame
    web_events: pd.DataFrame
    auth_alerts: pd.DataFrame
    web_alerts: pd.DataFrame


def _records_to_dataframe(
    records: list[dict[str, Any]], default_columns: list[str]
) -> pd.DataFrame:
    if not records:
        return pd.DataFrame(columns=default_columns)
    frame = pd.DataFrame.from_records(records)
    for column in default_columns:
        if column not in frame.columns:
            frame[column] = pd.NA
    return frame


def load_dashboard_snapshot(paths: dict[str, Path] | None = None) -> DashboardSnapshot:
    resolved = paths or default_output_paths()
    auth_event_records = safe_load_json_list(resolved["auth_events"])
    web_event_records = safe_load_json_list(resolved["web_events"])
    auth_alert_records = safe_load_json_list(resolved["auth_alerts"])
    web_alert_records = safe_load_json_list(resolved["web_alerts"])

    auth_events = _records_to_dataframe(
        auth_event_records,
        [
            "timestamp",
            "source_ip",
            "event_type",
            "username",
            "service",
            "status",
            "raw_message",
        ],
    )
    web_events = _records_to_dataframe(
        web_event_records,
        [
            "timestamp",
            "source_ip",
            "event_type",
            "http_method",
            "path",
            "http_status",
            "event_source",
            "user_agent",
            "raw_message",
        ],
    )
    auth_alerts = _records_to_dataframe(
        auth_alert_records,
        [
            "alert_id",
            "timestamp",
            "alert_type",
            "severity",
            "source_ip",
            "message",
            "evidence_count",
            "time_window_seconds",
        ],
    )
    web_alerts = _records_to_dataframe(
        web_alert_records,
        [
            "alert_id",
            "timestamp",
            "alert_type",
            "severity",
            "source_ip",
            "message",
            "evidence_count",
            "time_window_seconds",
        ],
    )

    if not auth_events.empty:
        auth_events = auth_events.copy()
        auth_events["event_source"] = "auth"
    else:
        auth_events = pd.DataFrame(
            columns=[
                "timestamp",
                "source_ip",
                "event_type",
                "username",
                "service",
                "status",
                "raw_message",
                "event_source",
            ]
        )

    if not web_events.empty:
        web_events = web_events.copy()
        if "event_source" not in web_events.columns or web_events["event_source"].isna().all():
            web_events["event_source"] = "web"
    else:
        web_events = pd.DataFrame(
            columns=[
                "timestamp",
                "source_ip",
                "event_type",
                "http_method",
                "path",
                "http_status",
                "event_source",
                "user_agent",
                "raw_message",
            ]
        )

    for frame in (auth_events, web_events, auth_alerts, web_alerts):
        if "timestamp" in frame.columns and not frame.empty:
            frame["timestamp"] = pd.to_datetime(
                frame["timestamp"], utc=True, errors="coerce"
            )

    return DashboardSnapshot(
        auth_events=auth_events,
        web_events=web_events,
        auth_alerts=auth_alerts,
        web_alerts=web_alerts,
    )
