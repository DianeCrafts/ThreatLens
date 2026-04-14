from __future__ import annotations

import ipaddress
from typing import Any

from app.network.network_models import NetworkObservation, ProtocolName
from app.utils.time_utils import parse_iso8601_timestamp


def _is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


def _normalize_protocol(value: str) -> ProtocolName | None:
    lowered = value.strip().lower()
    if lowered in ("tcp", "udp", "icmp"):
        return lowered  # type: ignore[return-value]
    if lowered in ("ip", "unknown", "other", ""):
        return "other"
    return None


def parse_packet_record(record: dict[str, Any]) -> NetworkObservation | None:
    """
    Parse a JSON object shaped for packet-style replay.

    Expected keys: timestamp, source_ip, destination_ip, destination_port, protocol
    Optional: raw_summary
    """
    try:
        ts_raw = record.get("timestamp")
        src = record.get("source_ip")
        dst = record.get("destination_ip")
        port_raw = record.get("destination_port")
        proto_raw = record.get("protocol")
        if not isinstance(ts_raw, str) or not isinstance(src, str) or not isinstance(dst, str):
            return None
        if isinstance(port_raw, int):
            port = port_raw
        elif isinstance(port_raw, str) and port_raw.isdigit():
            port = int(port_raw)
        elif isinstance(port_raw, float) and port_raw.is_integer():
            port = int(port_raw)
        else:
            return None
        if not isinstance(proto_raw, str):
            return None
        if not _is_valid_ipv4(src) or not _is_valid_ipv4(dst):
            return None
        if not 0 <= port <= 65535:
            return None
        protocol = _normalize_protocol(proto_raw)
        if protocol is None:
            return None
        timestamp = parse_iso8601_timestamp(ts_raw)
    except (TypeError, ValueError, KeyError):
        return None

    summary = record.get("raw_summary")
    raw_summary = summary if isinstance(summary, str) else ""
    return NetworkObservation(
        timestamp=timestamp,
        source_ip=src,
        destination_ip=dst,
        destination_port=port,
        protocol=protocol,
        raw_summary=raw_summary[:512],
    )
