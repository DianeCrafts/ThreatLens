from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.config import RepeatedConnectionsRuleConfig
from app.detection.repeated_connections import RepeatedConnectionsDetector
from app.network.network_models import NetworkObservation


def _obs(ts_off: int, src: str) -> NetworkObservation:
    base = datetime(2024, 7, 1, 11, 0, tzinfo=timezone.utc)
    return NetworkObservation(
        timestamp=base + timedelta(seconds=ts_off),
        source_ip=src,
        destination_ip="192.168.1.1",
        destination_port=443,
        protocol="tcp",
        raw_summary="",
    )


def test_repeated_connections_triggers_over_threshold() -> None:
    cfg = RepeatedConnectionsRuleConfig(min_connection_attempts=3, time_window_seconds=60)
    detector = RepeatedConnectionsDetector(cfg)
    events = [_obs(i, "10.0.0.9") for i in range(5)]
    alerts = detector.detect(events)
    assert len(alerts) >= 1
    assert alerts[0].alert_type == "repeated_connections"
    assert alerts[0].source_ip == "10.0.0.9"


def test_repeated_connections_no_alert_at_boundary() -> None:
    cfg = RepeatedConnectionsRuleConfig(min_connection_attempts=4, time_window_seconds=60)
    detector = RepeatedConnectionsDetector(cfg)
    events = [_obs(i, "10.0.0.10") for i in range(4)]
    assert detector.detect(events) == []


def test_repeated_connections_sliding_window_expires() -> None:
    cfg = RepeatedConnectionsRuleConfig(min_connection_attempts=2, time_window_seconds=10)
    detector = RepeatedConnectionsDetector(cfg)
    events = [
        _obs(0, "10.0.0.11"),
        _obs(1, "10.0.0.11"),
        _obs(60, "10.0.0.11"),
    ]
    assert detector.detect(events) == []
