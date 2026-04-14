from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.config import PortScanRuleConfig
from app.detection.port_scan import PortScanDetector
from app.network.network_models import NetworkObservation


def _obs(ts_off: int, src: str, dport: int) -> NetworkObservation:
    base = datetime(2024, 7, 1, 10, 0, tzinfo=timezone.utc)
    return NetworkObservation(
        timestamp=base + timedelta(seconds=ts_off),
        source_ip=src,
        destination_ip="192.168.1.1",
        destination_port=dport,
        protocol="tcp",
        raw_summary="",
    )


def test_port_scan_triggers_when_unique_ports_exceed_threshold() -> None:
    cfg = PortScanRuleConfig(min_unique_destination_ports=3, time_window_seconds=120)
    detector = PortScanDetector(cfg)
    events = [
        _obs(0, "10.0.0.1", 10),
        _obs(1, "10.0.0.1", 11),
        _obs(2, "10.0.0.1", 12),
        _obs(3, "10.0.0.1", 13),
    ]
    alerts = detector.detect(events)
    assert len(alerts) >= 1
    assert alerts[0].alert_type == "port_scan"
    assert alerts[0].source_ip == "10.0.0.1"


def test_port_scan_no_alert_below_threshold() -> None:
    cfg = PortScanRuleConfig(min_unique_destination_ports=5, time_window_seconds=120)
    detector = PortScanDetector(cfg)
    events = [
        _obs(0, "10.0.0.2", 100),
        _obs(1, "10.0.0.2", 101),
        _obs(2, "10.0.0.2", 102),
    ]
    assert detector.detect(events) == []


def test_port_scan_ignores_port_zero_in_unique_count() -> None:
    cfg = PortScanRuleConfig(min_unique_destination_ports=2, time_window_seconds=120)
    detector = PortScanDetector(cfg)
    events = [
        _obs(0, "10.0.0.3", 0),
        _obs(1, "10.0.0.3", 0),
        _obs(2, "10.0.0.3", 1),
    ]
    assert detector.detect(events) == []
