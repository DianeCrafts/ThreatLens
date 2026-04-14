from __future__ import annotations

from dataclasses import dataclass

import pandas as pd
import streamlit as st


@dataclass(frozen=True)
class FilterState:
    source_ips: tuple[str, ...]
    alert_types: tuple[str, ...]
    severities: tuple[str, ...]
    event_sources: tuple[str, ...]


def _options(series: pd.Series) -> list[str]:
    values = sorted({str(value) for value in series.dropna().unique().tolist()})
    return values


def render_sidebar_filters(
    alerts: pd.DataFrame, events: pd.DataFrame
) -> FilterState:
    st.sidebar.header("Filters")
    ip_options: list[str] = []
    if not alerts.empty and "source_ip" in alerts.columns:
        ip_options.extend(_options(alerts["source_ip"]))
    if not events.empty and "source_ip" in events.columns:
        ip_options.extend(_options(events["source_ip"]))
    ip_choices = sorted(set(ip_options))

    alert_type_choices = (
        _options(alerts["alert_type"]) if not alerts.empty and "alert_type" in alerts.columns else []
    )
    severity_choices = (
        _options(alerts["severity"]) if not alerts.empty and "severity" in alerts.columns else []
    )
    event_source_choices = (
        _options(events["event_source"])
        if not events.empty and "event_source" in events.columns
        else []
    )

    selected_ips = st.sidebar.multiselect(
        "Source IP",
        options=ip_choices,
        default=[],
    )
    selected_alert_types = st.sidebar.multiselect(
        "Alert type",
        options=alert_type_choices,
        default=[],
    )
    selected_severities = st.sidebar.multiselect(
        "Severity",
        options=severity_choices,
        default=[],
    )
    selected_event_sources = st.sidebar.multiselect(
        "Event source",
        options=event_source_choices,
        default=[],
    )

    return FilterState(
        source_ips=tuple(selected_ips),
        alert_types=tuple(selected_alert_types),
        severities=tuple(selected_severities),
        event_sources=tuple(selected_event_sources),
    )


def apply_alert_filters(alerts: pd.DataFrame, state: FilterState) -> pd.DataFrame:
    if alerts.empty:
        return alerts
    filtered = alerts
    if state.source_ips:
        filtered = filtered[filtered["source_ip"].astype(str).isin(state.source_ips)]
    if state.alert_types:
        filtered = filtered[filtered["alert_type"].astype(str).isin(state.alert_types)]
    if state.severities:
        filtered = filtered[filtered["severity"].astype(str).isin(state.severities)]
    if state.event_sources:
        if "dataset" in filtered.columns:
            filtered = filtered[
                filtered["dataset"].astype(str).isin(state.event_sources)
            ]
    return filtered.reset_index(drop=True)


def apply_event_filters(events: pd.DataFrame, state: FilterState) -> pd.DataFrame:
    if events.empty:
        return events
    filtered = events
    if state.source_ips:
        filtered = filtered[filtered["source_ip"].astype(str).isin(state.source_ips)]
    if state.event_sources:
        filtered = filtered[
            filtered["event_source"].astype(str).isin(state.event_sources)
        ]
    return filtered.reset_index(drop=True)
