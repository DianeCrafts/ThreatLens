from __future__ import annotations

import pandas as pd


def recent_alerts_table(alerts: pd.DataFrame, limit: int = 50) -> pd.DataFrame:
    if alerts.empty:
        return alerts
    columns = [
        column
        for column in (
            "timestamp",
            "alert_type",
            "severity",
            "source_ip",
            "message",
            "evidence_count",
            "dataset",
        )
        if column in alerts.columns
    ]
    subset = alerts[columns].head(limit)
    return subset.reset_index(drop=True)


def recent_events_table(events: pd.DataFrame, limit: int = 50) -> pd.DataFrame:
    if events.empty:
        return events
    columns = [
        column
        for column in (
            "timestamp",
            "event_source",
            "source_ip",
            "event_type",
            "summary",
        )
        if column in events.columns
    ]
    subset = events[columns].head(limit)
    return subset.reset_index(drop=True)
