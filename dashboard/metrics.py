from __future__ import annotations

import pandas as pd

from .data_loader import DashboardSnapshot


def total_event_rows(snapshot: DashboardSnapshot) -> int:
    return int(len(snapshot.auth_events) + len(snapshot.web_events))


def total_alert_rows(snapshot: DashboardSnapshot) -> int:
    return int(len(snapshot.auth_alerts) + len(snapshot.web_alerts))


def failed_login_count(snapshot: DashboardSnapshot) -> int:
    if snapshot.auth_events.empty or "event_type" not in snapshot.auth_events.columns:
        return 0
    mask = snapshot.auth_events["event_type"].astype(str) == "login_failed"
    return int(mask.sum())


def brute_force_alert_count(snapshot: DashboardSnapshot) -> int:
    if snapshot.auth_alerts.empty or "alert_type" not in snapshot.auth_alerts.columns:
        return 0
    mask = snapshot.auth_alerts["alert_type"].astype(str) == "brute_force"
    return int(mask.sum())


def suspicious_web_activity_alert_count(snapshot: DashboardSnapshot) -> int:
    if snapshot.web_alerts.empty or "alert_type" not in snapshot.web_alerts.columns:
        return 0
    mask = snapshot.web_alerts["alert_type"].astype(str) == "suspicious_web_activity"
    return int(mask.sum())


def unique_source_ip_count(snapshot: DashboardSnapshot) -> int:
    ips: set[str] = set()
    for frame in (snapshot.auth_events, snapshot.web_events):
        if not frame.empty and "source_ip" in frame.columns:
            ips.update(frame["source_ip"].dropna().astype(str).tolist())
    return len(ips)


def top_suspicious_ips(snapshot: DashboardSnapshot, limit: int = 10) -> pd.DataFrame:
    if snapshot.web_alerts.empty:
        return pd.DataFrame(columns=["source_ip", "alerts"])
    suspicious = snapshot.web_alerts[
        snapshot.web_alerts["alert_type"].astype(str) == "suspicious_web_activity"
    ]
    if suspicious.empty or "source_ip" not in suspicious.columns:
        return pd.DataFrame(columns=["source_ip", "alerts"])
    filtered = suspicious[suspicious["source_ip"].astype(str) != "__global__"]
    if filtered.empty:
        return pd.DataFrame(columns=["source_ip", "alerts"])
    grouped = (
        filtered.groupby("source_ip", dropna=False)
        .size()
        .reset_index(name="alerts")
        .sort_values("alerts", ascending=False)
        .head(limit)
    )
    return grouped.reset_index(drop=True)


def merged_alerts(snapshot: DashboardSnapshot) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    if not snapshot.auth_alerts.empty:
        auth = snapshot.auth_alerts.copy()
        auth["dataset"] = "auth"
        frames.append(auth)
    if not snapshot.web_alerts.empty:
        web = snapshot.web_alerts.copy()
        web["dataset"] = "web"
        frames.append(web)
    if not frames:
        return pd.DataFrame(
            columns=[
                "alert_id",
                "timestamp",
                "alert_type",
                "severity",
                "source_ip",
                "message",
                "evidence_count",
                "time_window_seconds",
                "dataset",
            ]
        )
    merged = pd.concat(frames, ignore_index=True)
    if "timestamp" in merged.columns:
        merged = merged.sort_values("timestamp", ascending=False, na_position="last")
    return merged.reset_index(drop=True)


def merged_events(snapshot: DashboardSnapshot) -> pd.DataFrame:
    rows: list[pd.DataFrame] = []
    if not snapshot.auth_events.empty:
        auth = snapshot.auth_events.copy()
        auth["summary"] = (
            auth["event_type"].astype(str)
            + " | "
            + auth["service"].astype(str)
            + " | "
            + auth["status"].astype(str)
        )
        rows.append(
            auth[
                [
                    "timestamp",
                    "source_ip",
                    "event_source",
                    "event_type",
                    "summary",
                    "raw_message",
                ]
            ]
        )
    if not snapshot.web_events.empty:
        web = snapshot.web_events.copy()
        web["summary"] = (
            web["http_method"].astype(str)
            + " "
            + web["path"].astype(str)
            + " "
            + web["http_status"].astype(str)
        )
        rows.append(
            web[
                [
                    "timestamp",
                    "source_ip",
                    "event_source",
                    "event_type",
                    "summary",
                    "raw_message",
                ]
            ]
        )
    if not rows:
        return pd.DataFrame(
            columns=[
                "timestamp",
                "source_ip",
                "event_source",
                "event_type",
                "summary",
                "raw_message",
            ]
        )
    merged = pd.concat(rows, ignore_index=True)
    if "timestamp" in merged.columns:
        merged = merged.sort_values("timestamp", ascending=False, na_position="last")
    return merged.reset_index(drop=True)
