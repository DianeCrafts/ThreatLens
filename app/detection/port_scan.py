from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import timedelta
from uuid import uuid4

from app.config import PortScanRuleConfig
from app.models.alert import Alert
from app.network.network_models import NetworkObservation


class PortScanDetector:
    """
    Detects port-scanning: one source IP uses many distinct destination ports
    inside a sliding time window.
    """

    def __init__(self, config: PortScanRuleConfig) -> None:
        self._config = config

    def detect(self, observations: Sequence[NetworkObservation]) -> list[Alert]:
        by_source: dict[str, list[NetworkObservation]] = defaultdict(list)
        for obs in observations:
            by_source[obs.source_ip].append(obs)
        for key in by_source:
            by_source[key].sort(key=lambda o: o.timestamp)

        window = timedelta(seconds=self._config.time_window_seconds)
        threshold = self._config.min_unique_destination_ports
        alerts: list[Alert] = []

        for source_ip, seq in by_source.items():
            times = [o.timestamp for o in seq]
            start = 0
            for end in range(len(seq)):
                while times[end] - times[start] > window:
                    start += 1
                unique_ports: set[int] = set()
                for idx in range(start, end + 1):
                    if seq[idx].destination_port > 0:
                        unique_ports.add(seq[idx].destination_port)
                if len(unique_ports) > threshold:
                    last = seq[end]
                    alerts.append(
                        Alert(
                            alert_id=str(uuid4()),
                            timestamp=last.timestamp,
                            alert_type="port_scan",
                            severity="HIGH",
                            source_ip=source_ip,
                            message=(
                                f"Possible port scan: {len(unique_ports)} distinct destination "
                                f"ports from {source_ip} within {self._config.time_window_seconds}s "
                                f"(threshold {threshold})."
                            ),
                            evidence_count=len(unique_ports),
                            time_window_seconds=self._config.time_window_seconds,
                        )
                    )

        alerts.sort(key=lambda a: a.timestamp)
        return alerts
