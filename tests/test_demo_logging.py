from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.web.web_log_parser import WebLogParser
from demo.request_logger import (
    DemoRequestLogger,
    format_log_line,
    normalize_client_ip,
)


def test_normalize_client_ip_maps_ipv6_loopback() -> None:
    assert normalize_client_ip("::1") == "127.0.0.1"
    assert normalize_client_ip("::ffff:127.0.0.1") == "127.0.0.1"
    assert normalize_client_ip("192.168.1.10") == "192.168.1.10"


def test_format_log_line_matches_web_parser_expectations() -> None:
    ts = datetime(2026, 4, 13, 12, 0, 0, tzinfo=timezone.utc)
    line = format_log_line(
        timestamp=ts,
        source_ip="127.0.0.1",
        method="get",
        path="/api/health",
        status_code=200,
        user_agent="ThreatLens-Test/1.0",
    )
    parser = WebLogParser()
    event = parser.parse_line(line)
    assert event is not None
    assert event.source_ip == "127.0.0.1"
    assert event.http_method == "GET"
    assert event.path == "/api/health"
    assert event.http_status == 200


def test_demo_request_logger_writes_parseable_line(tmp_path: Path) -> None:
    log_path = tmp_path / "live_web.log"
    logger = DemoRequestLogger(log_path)
    written = logger.log_request(
        method="GET",
        path="/about",
        status_code=200,
        remote_addr="127.0.0.1",
        user_agent="UnitTest/1.0",
        timestamp=datetime(2026, 4, 13, 12, 0, 1, tzinfo=timezone.utc),
    )
    text = log_path.read_text(encoding="utf-8").strip()
    assert text == written
    parser = WebLogParser()
    assert parser.parse_line(text) is not None


@pytest.mark.parametrize(
    "ua",
    ["-", "Mozilla/5.0 (Windows NT 10.0)"],
)
def test_user_agent_round_trip(ua: str) -> None:
    line = format_log_line(
        timestamp=datetime(2026, 4, 13, 12, 0, 2, tzinfo=timezone.utc),
        source_ip="127.0.0.1",
        method="GET",
        path="/",
        status_code=404,
        user_agent=ua,
    )
    assert WebLogParser().parse_line(line) is not None
