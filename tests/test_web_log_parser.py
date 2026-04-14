from __future__ import annotations

from datetime import timezone

import pytest

from app.web.web_log_parser import WebLogParser


@pytest.fixture
def parser() -> WebLogParser:
    return WebLogParser()


def test_parse_get_request(parser: WebLogParser) -> None:
    line = (
        "2024-06-01T10:00:00Z | 198.51.100.10 | GET | /products | 200 | Mozilla/5.0"
    )
    event = parser.parse_line(line)
    assert event is not None
    assert event.source_ip == "198.51.100.10"
    assert event.http_method == "GET"
    assert event.path == "/products"
    assert event.http_status == 200
    assert event.event_type == "web_request"
    assert event.event_source == "web"
    assert event.timestamp.tzinfo == timezone.utc


def test_parse_post_with_hyphen_user_agent(parser: WebLogParser) -> None:
    line = "2024-06-01T10:00:02Z | 198.51.100.12 | POST | /api/login | 401 | curl/8.0"
    event = parser.parse_line(line)
    assert event is not None
    assert event.http_method == "POST"
    assert event.http_status == 401


def test_user_agent_pipes_preserved(parser: WebLogParser) -> None:
    line = "2024-06-01T10:00:00Z | 10.0.0.1 | GET | / | 200 | a|b|c"
    event = parser.parse_line(line)
    assert event is not None
    assert event.user_agent == "a|b|c"


def test_skip_comment_and_blank(parser: WebLogParser) -> None:
    assert parser.parse_line("# hi") is None
    assert parser.parse_line("") is None


def test_malformed_too_few_fields(parser: WebLogParser) -> None:
    assert parser.parse_line("2024-06-01T10:00:00Z|GET|broken") is None


def test_malformed_invalid_method(parser: WebLogParser) -> None:
    line = "2024-06-01T10:00:00Z | 10.0.0.1 | FETCH | / | 200 | x"
    assert parser.parse_line(line) is None


def test_malformed_invalid_status(parser: WebLogParser) -> None:
    line = "2024-06-01T10:00:00Z | 10.0.0.1 | GET | / | 999 | x"
    assert parser.parse_line(line) is None


def test_malformed_path_not_absolute(parser: WebLogParser) -> None:
    line = "2024-06-01T10:00:00Z | 10.0.0.1 | GET | nolead | 200 | x"
    assert parser.parse_line(line) is None


def test_root_path(parser: WebLogParser) -> None:
    line = "2024-06-01T10:00:00Z | 10.0.0.1 | GET | / | 200 | -"
    event = parser.parse_line(line)
    assert event is not None
    assert event.path == "/"
    assert event.user_agent == ""
