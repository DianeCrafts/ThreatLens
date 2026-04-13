from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime, timedelta
from uuid import uuid4

from app.config import BruteForceConfig
from app.models.alert import Alert
from app.models.event import Event


class BruteForceDetector:
    """
    Detects brute-force patterns: more than N failed logins from one source IP
    inside a sliding time window.
    """

    def __init__(self, config: BruteForceConfig) -> None:
        self._config = config

    def detect(self, events: Sequence[Event]) -> list[Alert]:
        failed: list[Event] = [
            event for event in events if event.event_type == "login_failed"
        ]
        by_ip: dict[str, list[Event]] = defaultdict(list)
        for event in failed:
            by_ip[event.source_ip].append(event)
        for ip_key in by_ip:
            by_ip[ip_key].sort(key=lambda e: e.timestamp)

        alerts: list[Alert] = []
        window = timedelta(seconds=self._config.time_window_seconds)
        threshold = self._config.failed_attempt_threshold

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
                            alert_type="brute_force",
                            severity="HIGH",
                            source_ip=source_ip,
                            message=(
                                f"Brute-force pattern: {count} failed login attempts "
                                f"from {source_ip} within {self._config.time_window_seconds}s "
                                f"(threshold {threshold})."
                            ),
                            evidence_count=count,
                            time_window_seconds=self._config.time_window_seconds,
                        )
                    )
        alerts.sort(key=lambda alert: alert.timestamp)
        return alerts
