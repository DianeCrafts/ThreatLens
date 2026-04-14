from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from pandas.api.types import is_datetime64_any_dtype

from dashboard.data_loader import (
    DashboardSnapshot,
    default_output_paths,
    load_dashboard_snapshot,
    safe_load_json_list,
)


def test_safe_load_json_list_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    assert safe_load_json_list(missing) == []


def test_safe_load_json_list_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    path.write_text("", encoding="utf-8")
    assert safe_load_json_list(path) == []


def test_safe_load_json_list_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    assert safe_load_json_list(path) == []


def test_safe_load_json_list_non_list_payload(tmp_path: Path) -> None:
    path = tmp_path / "obj.json"
    path.write_text(json.dumps({"a": 1}), encoding="utf-8")
    assert safe_load_json_list(path) == []


def test_load_dashboard_snapshot_with_valid_files(tmp_path: Path) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    auth_events = outputs / "events.json"
    web_events = outputs / "web_events.json"
    auth_alerts = outputs / "alerts.json"
    web_alerts = outputs / "web_alerts.json"

    auth_events.write_text(
        json.dumps(
            [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "source_ip": "10.0.0.1",
                    "event_type": "login_failed",
                    "username": "root",
                    "service": "sshd",
                    "status": "FAIL",
                    "raw_message": "x",
                }
            ]
        ),
        encoding="utf-8",
    )
    web_events.write_text(
        json.dumps(
            [
                {
                    "timestamp": "2024-06-01T00:00:00Z",
                    "source_ip": "10.0.0.2",
                    "event_type": "web_request",
                    "http_method": "GET",
                    "path": "/",
                    "http_status": 200,
                    "event_source": "web",
                    "user_agent": "",
                    "raw_message": "y",
                }
            ]
        ),
        encoding="utf-8",
    )
    auth_alerts.write_text("[]", encoding="utf-8")
    web_alerts.write_text("[]", encoding="utf-8")

    paths = {
        "auth_events": auth_events,
        "web_events": web_events,
        "auth_alerts": auth_alerts,
        "web_alerts": web_alerts,
    }
    snapshot = load_dashboard_snapshot(paths)
    assert isinstance(snapshot, DashboardSnapshot)
    assert len(snapshot.auth_events) == 1
    assert snapshot.auth_events.iloc[0]["event_source"] == "auth"
    assert len(snapshot.web_events) == 1
    assert is_datetime64_any_dtype(snapshot.auth_events["timestamp"])


def test_default_output_paths_contains_expected_keys(tmp_path: Path) -> None:
    paths = default_output_paths(tmp_path)
    assert paths["auth_events"] == tmp_path / "outputs" / "events.json"
    assert paths["web_events"] == tmp_path / "outputs" / "web_events.json"
