from __future__ import annotations

from datetime import timezone

import pytest

from app.parsers.auth_parser import AuthLogParser


@pytest.fixture
def parser() -> AuthLogParser:
    return AuthLogParser()


def test_parse_failed_login(parser: AuthLogParser) -> None:
    line = (
        "2024-01-15T08:00:00Z | 203.0.113.10 | sshd | admin | FAIL | Invalid password"
    )
    event = parser.parse_line(line)
    assert event is not None
    assert event.source_ip == "203.0.113.10"
    assert event.service == "sshd"
    assert event.username == "admin"
    assert event.status == "FAIL"
    assert event.event_type == "login_failed"
    assert event.timestamp.tzinfo == timezone.utc
    assert "Invalid password" in event.raw_message


def test_parse_successful_login(parser: AuthLogParser) -> None:
    line = "2024-01-15T10:00:00Z | 192.0.2.20 | rdp | bob | SUCCESS | Logon successful"
    event = parser.parse_line(line)
    assert event is not None
    assert event.event_type == "login_success"
    assert event.status == "SUCCESS"


def test_skip_comment_and_blank(parser: AuthLogParser) -> None:
    assert parser.parse_line("# comment") is None
    assert parser.parse_line("   ") is None
    assert parser.parse_line("") is None


def test_malformed_too_few_fields(parser: AuthLogParser) -> None:
    assert parser.parse_line("2024-01-15T08:00:00Z|only|three") is None


def test_malformed_invalid_status(parser: AuthLogParser) -> None:
    line = "2024-01-15T08:00:00Z | 10.0.0.1 | sshd | user | BOGUS | msg"
    assert parser.parse_line(line) is None


def test_malformed_invalid_ip(parser: AuthLogParser) -> None:
    line = "2024-01-15T08:00:00Z | not-an-ip | sshd | user | FAIL | msg"
    assert parser.parse_line(line) is None


def test_malformed_bad_timestamp(parser: AuthLogParser) -> None:
    line = "not-a-date | 10.0.0.1 | sshd | user | FAIL | msg"
    assert parser.parse_line(line) is None


def test_message_preserves_additional_pipes(parser: AuthLogParser) -> None:
    line = "2024-01-15T08:00:00Z | 10.0.0.1 | sshd | user | FAIL | a|b|c"
    event = parser.parse_line(line)
    assert event is not None
    assert event.raw_message.endswith("a|b|c")
