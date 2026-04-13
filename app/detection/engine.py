from __future__ import annotations

from collections.abc import Sequence

from app.config import DetectionConfig
from app.detection.brute_force import BruteForceDetector
from app.models.alert import Alert
from app.models.event import Event


class DetectionEngine:
    """Runs configured detection rules over normalized events."""

    def __init__(self, detection_config: DetectionConfig) -> None:
        self._brute_force = BruteForceDetector(detection_config.brute_force)

    def run(self, events: Sequence[Event]) -> list[Alert]:
        return self._brute_force.detect(events)
