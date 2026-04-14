from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.config import SuspiciousWebConfig, TrafficSpikeConfig, WebDetectionConfig
from app.models.web_event import WebEvent
from app.web.web_detection import (
    SuspiciousWebActivityDetector,
    TrafficSpikeDetector,
    WebDetectionEngine,
)


def _web(ts_minutes: int, ip: str) -> WebEvent:
    base = datetime(2024, 6, 1, 10, 0, tzinfo=timezone.utc)
    return WebEvent(
        timestamp=base + timedelta(minutes=ts_minutes),
        source_ip=ip,
        event_type="web_request",
        http_method="GET",
        path="/",
        http_status=200,
        event_source="web",
        user_agent="ua",
        raw_message="raw",
    )


def test_suspicious_web_triggers_over_threshold() -> None:
    cfg = SuspiciousWebConfig(request_threshold=2, time_window_seconds=600)
    detector = SuspiciousWebActivityDetector(cfg)
    events = [
        _web(0, "10.0.0.1"),
        _web(1, "10.0.0.1"),
        _web(2, "10.0.0.1"),
    ]
    alerts = detector.detect(events)
    assert len(alerts) == 1
    assert alerts[0].alert_type == "suspicious_web_activity"
    assert alerts[0].source_ip == "10.0.0.1"
    assert alerts[0].evidence_count == 3


def test_suspicious_web_respects_sliding_window() -> None:
    cfg = SuspiciousWebConfig(request_threshold=1, time_window_seconds=120)
    detector = SuspiciousWebActivityDetector(cfg)
    events = [
        _web(0, "10.0.0.2"),
        _web(10, "10.0.0.2"),
    ]
    assert detector.detect(events) == []


def test_traffic_spike_global_threshold() -> None:
    cfg = TrafficSpikeConfig(window_seconds=600, min_requests_in_window=4)
    detector = TrafficSpikeDetector(cfg)
    events = [_web(i, f"10.0.0.{i}") for i in range(5)]
    alerts = detector.detect(events)
    assert len(alerts) == 1
    assert alerts[0].alert_type == "traffic_spike"
    assert alerts[0].source_ip == "__global__"
    assert alerts[0].evidence_count == 5


def test_web_detection_engine_runs_both_rules() -> None:
    cfg = WebDetectionConfig(
        suspicious_ip=SuspiciousWebConfig(request_threshold=1, time_window_seconds=600),
        traffic_spike=TrafficSpikeConfig(window_seconds=600, min_requests_in_window=2),
    )
    engine = WebDetectionEngine(cfg)
    events = [
        _web(0, "10.0.0.1"),
        _web(1, "10.0.0.1"),
        _web(2, "10.0.0.2"),
    ]
    alerts = engine.run(events)
    types = {alert.alert_type for alert in alerts}
    assert "suspicious_web_activity" in types
    assert "traffic_spike" in types
