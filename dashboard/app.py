from __future__ import annotations

import sys
from pathlib import Path

# Streamlit does not add the repo root to sys.path; package imports need it.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st

from dashboard import charts, filters, metrics, tables
from dashboard.data_loader import load_dashboard_snapshot, repository_root

st.set_page_config(page_title="ThreatLens Dashboard", layout="wide")
st.title("ThreatLens Security Dashboard")
st.caption(f"Repository root: `{repository_root()}`")

snapshot = load_dashboard_snapshot()
all_alerts = metrics.merged_alerts(snapshot)
all_events = metrics.merged_events(snapshot)

filter_state = filters.render_sidebar_filters(all_alerts, all_events)
filtered_alerts = filters.apply_alert_filters(all_alerts, filter_state)
filtered_events = filters.apply_event_filters(all_events, filter_state)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total events", metrics.total_event_rows(snapshot))
col2.metric("Total alerts", metrics.total_alert_rows(snapshot))
col3.metric("Failed logins", metrics.failed_login_count(snapshot))
col4.metric("Unique source IPs", metrics.unique_source_ip_count(snapshot))

col5, col6, col7 = st.columns(3)
col5.metric("Brute-force alerts", metrics.brute_force_alert_count(snapshot))
col6.metric(
    "Suspicious web alerts",
    metrics.suspicious_web_activity_alert_count(snapshot),
)

st.subheader("Top suspicious web IPs")
top_ips = metrics.top_suspicious_ips(snapshot)
if top_ips.empty:
    st.info("No suspicious web activity alerts available yet.")
else:
    st.dataframe(top_ips, use_container_width=True, hide_index=True)

st.subheader("Recent alerts")
st.dataframe(
    tables.recent_alerts_table(filtered_alerts),
    use_container_width=True,
    hide_index=True,
)

st.subheader("Recent events")
st.dataframe(
    tables.recent_events_table(filtered_events),
    use_container_width=True,
    hide_index=True,
)

chart_col1, chart_col2 = st.columns(2)
with chart_col1:
    st.plotly_chart(
        charts.alert_severity_figure(filtered_alerts),
        use_container_width=True,
    )
with chart_col2:
    st.plotly_chart(
        charts.alerts_over_time_figure(filtered_alerts),
        use_container_width=True,
    )
