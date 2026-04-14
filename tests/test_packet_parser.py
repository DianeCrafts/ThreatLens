from __future__ import annotations

from datetime import timezone

import pytest

from app.network.connection_parser import parse_connection_record
from app.network.packet_parser import parse_packet_record


def test_parse_valid_tcp_packet() -> None:
    record = {
        "timestamp": "2024-07-01T10:00:00Z",
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "destination_port": 443,
        "protocol": "tcp",
        "raw_summary": "SYN",
    }
    obs = parse_packet_record(record)
    assert obs is not None
    assert obs.source_ip == "10.0.0.1"
    assert obs.destination_ip == "10.0.0.2"
    assert obs.destination_port == 443
    assert obs.protocol == "tcp"
    assert obs.timestamp.tzinfo == timezone.utc


def test_parse_udp_uppercase_protocol() -> None:
    record = {
        "timestamp": "2024-07-01T10:00:00Z",
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "destination_port": 53,
        "protocol": "UDP",
    }
    obs = parse_packet_record(record)
    assert obs is not None
    assert obs.protocol == "udp"


def test_parse_numeric_port_as_string() -> None:
    record = {
        "timestamp": "2024-07-01T10:00:00Z",
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "destination_port": "80",
        "protocol": "tcp",
    }
    obs = parse_packet_record(record)
    assert obs is not None
    assert obs.destination_port == 80


def test_parse_connection_aliases() -> None:
    record = {
        "ts": "2024-07-01T10:01:00Z",
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.8",
        "dst_port": 22,
        "proto": "tcp",
    }
    obs = parse_connection_record(record)
    assert obs is not None
    assert obs.source_ip == "10.0.0.5"
    assert obs.destination_port == 22


@pytest.mark.parametrize(
    "record",
    [
        {},
        {"timestamp": "2024-07-01T10:00:00Z"},
        {
            "timestamp": "bad",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "destination_port": 1,
            "protocol": "tcp",
        },
        {
            "timestamp": "2024-07-01T10:00:00Z",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "destination_port": 80,
            "protocol": "ftp",
        },
        {
            "timestamp": "2024-07-01T10:00:00Z",
            "source_ip": "not-ip",
            "destination_ip": "10.0.0.2",
            "destination_port": 80,
            "protocol": "tcp",
        },
    ],
)
def test_parse_rejects_malformed(record: dict) -> None:
    assert parse_packet_record(record) is None
