from __future__ import annotations

from typing import Any

import pandas as pd
import plotly.express as px


def alert_severity_figure(alerts: pd.DataFrame) -> Any:
    if alerts.empty or "severity" not in alerts.columns:
        empty = pd.DataFrame({"severity": [], "count": []})
        return px.bar(
            empty,
            x="severity",
            y="count",
            title="Alert severity distribution",
        )
    counts = (
        alerts["severity"]
        .fillna("UNKNOWN")
        .astype(str)
        .value_counts()
        .reset_index()
    )
    counts.columns = ["severity", "count"]
    return px.bar(
        counts,
        x="severity",
        y="count",
        title="Alert severity distribution",
        color="severity",
    )


def alerts_over_time_figure(alerts: pd.DataFrame) -> Any:
    if alerts.empty or "timestamp" not in alerts.columns:
        empty = pd.DataFrame({"bucket": [], "alerts": []})
        return px.line(
            empty,
            x="bucket",
            y="alerts",
            title="Alerts over time",
            markers=True,
        )
    working = alerts.dropna(subset=["timestamp"]).copy()
    if working.empty:
        empty = pd.DataFrame({"bucket": [], "alerts": []})
        return px.line(
            empty,
            x="bucket",
            y="alerts",
            title="Alerts over time",
            markers=True,
        )
    working["bucket"] = working["timestamp"].dt.floor("h")
    grouped = (
        working.groupby("bucket", dropna=False)
        .size()
        .reset_index(name="alerts")
        .sort_values("bucket")
    )
    return px.line(
        grouped,
        x="bucket",
        y="alerts",
        title="Alerts over time (hourly buckets)",
        markers=True,
    )
