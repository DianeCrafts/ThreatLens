from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import timedelta
from uuid import uuid4

from app.config import RepeatedConnectionsRuleConfig
from app.models.alert import Alert
from app.network.network_models import NetworkObservation


class RepeatedConnectionsDetector:
    """
    Detects a burst of connection metadata from the same source IP inside a short window.
    """

    def __init__(self, config: RepeatedConnectionsRuleConfig) -> None:
        self._config = config

    def detect(self, observations: Sequence[NetworkObservation]) -> list[Alert]:
        by_source: dict[str, list[NetworkObservation]] = defaultdict(list)
        for obs in observations:
            by_source[obs.source_ip].append(obs)
        for key in by_source:
            by_source[key].sort(key=lambda o: o.timestamp)

        window = timedelta(seconds=self._config.time_window_seconds)
        threshold = self._config.min_connection_attempts
        alerts: list[Alert] = []

        for source_ip, seq in by_source.items():
            times = [o.timestamp for o in seq]
            start = 0
            for end in range(len(seq)):
                while times[end] - times[start] > window:
                    start += 1
                count = end - start + 1
                if count > threshold:
                    last = seq[end]
                    alerts.append(
                        Alert(
                            alert_id=str(uuid4()),
                            timestamp=last.timestamp,
                            alert_type="repeated_connections",
                            severity="MEDIUM",
                            source_ip=source_ip,
                            message=(
                                f"Repeated connection attempts: {count} observations from "
                                f"{source_ip} within {self._config.time_window_seconds}s "
                                f"(threshold {threshold})."
                            ),
                            evidence_count=count,
                            time_window_seconds=self._config.time_window_seconds,
                        )
                    )

        alerts.sort(key=lambda a: a.timestamp)
        return alerts
