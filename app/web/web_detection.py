from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime, timedelta
from uuid import uuid4

from app.config import SuspiciousWebConfig, TrafficSpikeConfig, WebDetectionConfig
from app.models.alert import Alert
from app.models.web_event import WebEvent

_GLOBAL_SOURCE_IP = "__global__"


class SuspiciousWebActivityDetector:
    """
    Flags source IPs that issue more than N HTTP requests within a sliding window.
    """

    def __init__(self, config: SuspiciousWebConfig) -> None:
        self._config = config

    def detect(self, events: Sequence[WebEvent]) -> list[Alert]:
        by_ip: dict[str, list[WebEvent]] = defaultdict(list)
        for event in events:
            by_ip[event.source_ip].append(event)
        for ip_key in by_ip:
            by_ip[ip_key].sort(key=lambda e: e.timestamp)

        alerts: list[Alert] = []
        window = timedelta(seconds=self._config.time_window_seconds)
        threshold = self._config.request_threshold

        for source_ip, ip_events in by_ip.items():
            times: list[datetime] = [event.timestamp for event in ip_events]
            start_index = 0
            for end_index in range(len(times)):
                while times[end_index] - times[start_index] > window:
                    start_index += 1
                count = end_index - start_index + 1
                if count > threshold:
                    last_event = ip_events[end_index]
                    alerts.append(
                        Alert(
                            alert_id=str(uuid4()),
                            timestamp=last_event.timestamp,
                            alert_type="suspicious_web_activity",
                            severity="HIGH",
                            source_ip=source_ip,
                            message=(
                                f"Suspicious web activity: {count} requests from "
                                f"{source_ip} within {self._config.time_window_seconds}s "
                                f"(threshold {threshold})."
                            ),
                            evidence_count=count,
                            time_window_seconds=self._config.time_window_seconds,
                        )
                    )
        alerts.sort(key=lambda alert: alert.timestamp)
        return alerts


class TrafficSpikeDetector:
    """
    Flags intervals where total HTTP request volume exceeds a configured threshold.
    """

    def __init__(self, config: TrafficSpikeConfig) -> None:
        self._config = config

    def detect(self, events: Sequence[WebEvent]) -> list[Alert]:
        if not events:
            return []
        ordered = sorted(events, key=lambda event: event.timestamp)
        times: list[datetime] = [event.timestamp for event in ordered]
        window = timedelta(seconds=self._config.window_seconds)
        min_requests = self._config.min_requests_in_window

        alerts: list[Alert] = []
        start_index = 0
        for end_index in range(len(times)):
            while times[end_index] - times[start_index] > window:
                start_index += 1
            count = end_index - start_index + 1
            if count > min_requests:
                alerts.append(
                    Alert(
                        alert_id=str(uuid4()),
                        timestamp=times[end_index],
                        alert_type="traffic_spike",
                        severity="CRITICAL",
                        source_ip=_GLOBAL_SOURCE_IP,
                        message=(
                            f"Traffic spike: {count} total requests within "
                            f"{self._config.window_seconds}s "
                            f"(threshold {min_requests})."
                        ),
                        evidence_count=count,
                        time_window_seconds=self._config.window_seconds,
                    )
                )
        alerts.sort(key=lambda alert: alert.timestamp)
        return alerts


class WebDetectionEngine:
    """Runs website detection rules."""

    def __init__(self, config: WebDetectionConfig) -> None:
        self._suspicious = SuspiciousWebActivityDetector(config.suspicious_ip)
        self._spike = TrafficSpikeDetector(config.traffic_spike)

    def run(self, events: Sequence[WebEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        alerts.extend(self._suspicious.detect(events))
        alerts.extend(self._spike.detect(events))
        alerts.sort(key=lambda alert: alert.timestamp)
        return alerts
