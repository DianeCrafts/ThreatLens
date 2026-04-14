from __future__ import annotations

from typing import Any

from app.network.network_models import NetworkObservation
from app.utils.time_utils import parse_iso8601_timestamp


def parse_connection_record(record: dict[str, Any]) -> NetworkObservation | None:
    """
    Parse a JSON object using connection-oriented aliases.

    Accepts: src_ip or source_ip, dst_ip or destination_ip, dst_port or destination_port,
    proto or protocol, ts or timestamp.
    Optional: raw_summary
    """
    try:
        ts_raw = record.get("timestamp") or record.get("ts")
        src = record.get("source_ip") or record.get("src_ip")
        dst = record.get("destination_ip") or record.get("dst_ip")
        port_raw = record.get("destination_port", record.get("dst_port"))
        proto_raw = record.get("protocol") or record.get("proto")
        if not isinstance(ts_raw, str) or not isinstance(src, str) or not isinstance(dst, str):
            return None
        if not isinstance(proto_raw, str):
            return None
        if isinstance(port_raw, str) and port_raw.isdigit():
            port = int(port_raw)
        elif isinstance(port_raw, int):
            port = port_raw
        else:
            return None
        timestamp = parse_iso8601_timestamp(ts_raw)
    except (TypeError, ValueError):
        return None

    normalized = {
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "source_ip": src,
        "destination_ip": dst,
        "destination_port": port,
        "protocol": proto_raw,
    }
    summary = record.get("raw_summary")
    if isinstance(summary, str):
        normalized["raw_summary"] = summary
    from app.network.packet_parser import parse_packet_record as _parse_packet

    return _parse_packet(normalized)
