from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.config import BruteForceConfig
from app.detection.brute_force import BruteForceDetector
from app.models.event import Event


def _dt(minutes: int) -> datetime:
    base = datetime(2024, 1, 15, 8, 0, tzinfo=timezone.utc)
    return base + timedelta(minutes=minutes)


def _fail(ip: str, when: datetime, user: str = "u1") -> Event:
    return Event(
        timestamp=when,
        source_ip=ip,
        event_type="login_failed",
        username=user,
        service="sshd",
        status="FAIL",
        raw_message="x",
    )


def _success(ip: str, when: datetime) -> Event:
    return Event(
        timestamp=when,
        source_ip=ip,
        event_type="login_success",
        username="u1",
        service="sshd",
        status="SUCCESS",
        raw_message="y",
    )


def test_brute_force_triggers_when_more_than_threshold_in_window() -> None:
    cfg = BruteForceConfig(failed_attempt_threshold=3, time_window_seconds=600)
    detector = BruteForceDetector(cfg)
    events = [
        _fail("10.0.0.1", _dt(0)),
        _fail("10.0.0.1", _dt(1)),
        _fail("10.0.0.1", _dt(2)),
        _fail("10.0.0.1", _dt(3)),
    ]
    alerts = detector.detect(events)
    assert len(alerts) == 1
    assert alerts[0].source_ip == "10.0.0.1"
    assert alerts[0].evidence_count == 4
    assert alerts[0].alert_type == "brute_force"
    assert alerts[0].time_window_seconds == 600


def test_brute_force_no_alert_at_threshold_boundary() -> None:
    cfg = BruteForceConfig(failed_attempt_threshold=3, time_window_seconds=600)
    detector = BruteForceDetector(cfg)
    events = [
        _fail("10.0.0.2", _dt(0)),
        _fail("10.0.0.2", _dt(1)),
        _fail("10.0.0.2", _dt(2)),
    ]
    assert detector.detect(events) == []


def test_brute_force_ignores_success_events() -> None:
    cfg = BruteForceConfig(failed_attempt_threshold=1, time_window_seconds=600)
    detector = BruteForceDetector(cfg)
    events = [
        _success("10.0.0.3", _dt(0)),
        _success("10.0.0.3", _dt(1)),
    ]
    assert detector.detect(events) == []


def test_brute_force_sliding_window_expires_old_failures() -> None:
    cfg = BruteForceConfig(failed_attempt_threshold=2, time_window_seconds=120)
    detector = BruteForceDetector(cfg)
    events = [
        _fail("10.0.0.4", _dt(0)),
        _fail("10.0.0.4", _dt(1)),
        _fail("10.0.0.4", _dt(10)),
    ]
    alerts = detector.detect(events)
    assert alerts == []
