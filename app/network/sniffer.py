from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from app.network.network_models import NetworkObservation, ProtocolName


def _map_protocol_from_packet(pkt: Any) -> tuple[ProtocolName, int, str]:
    """Return (protocol, destination_port, summary) from a Scapy packet with IP layer."""
    summary_parts: list[str] = []
    dport = 0
    proto: ProtocolName = "other"

    try:
        from scapy.layers.inet import ICMP, IP, TCP, UDP
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is required for live capture. Install with: pip install -r requirements-network.txt"
        ) from exc

    if not pkt.haslayer(IP):
        return proto, dport, ""

    ip_layer = pkt[IP]
    summary_parts.append(f"{ip_layer.src}->{ip_layer.dst}")

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        dport = int(tcp.dport)
        proto = "tcp"
        summary_parts.append(f"TCP dport={dport}")
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        dport = int(udp.dport)
        proto = "udp"
        summary_parts.append(f"UDP dport={dport}")
    elif pkt.haslayer(ICMP):
        proto = "icmp"
        dport = 0
        summary_parts.append("ICMP")

    return proto, dport, " ".join(summary_parts)[:512]


def packet_to_observation(pkt: Any) -> NetworkObservation | None:
    """Build metadata-only observation from a Scapy packet (no payload)."""
    try:
        from scapy.layers.inet import IP
    except ImportError:
        return None

    if not pkt.haslayer(IP):
        return None
    ip_layer = pkt[IP]
    ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc)
    protocol, dport, summary = _map_protocol_from_packet(pkt)
    return NetworkObservation(
        timestamp=ts,
        source_ip=str(ip_layer.src),
        destination_ip=str(ip_layer.dst),
        destination_port=dport,
        protocol=protocol,
        raw_summary=summary,
    )


def live_capture(
    *,
    iface: str | None = None,
    count: int = 0,
    timeout: float | None = None,
    prn: Callable[[NetworkObservation], None] | None = None,
) -> list[NetworkObservation]:
    """
    Capture packets using Scapy and return normalized observations (metadata only).

    On Windows, Npcap must be installed and this process typically requires elevation.

    :param iface: Interface name (``None`` lets Scapy choose a default).
    :param count: Stop after this many packets (0 = unlimited until timeout).
    :param timeout: Stop after this many seconds when ``count`` is 0.
    :param prn: Optional callback invoked for each observation as it arrives.
    """
    try:
        from scapy.all import sniff
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is required for live capture. Install with: pip install -r requirements-network.txt"
        ) from exc

    observations: list[NetworkObservation] = []

    def _handle_packet(pkt: Any) -> None:
        obs = packet_to_observation(pkt)
        if obs is None:
            return
        observations.append(obs)
        if prn is not None:
            prn(obs)

    kwargs: dict[str, Any] = {"prn": _handle_packet, "store": False}
    if iface:
        kwargs["iface"] = iface
    if count > 0:
        kwargs["count"] = count
    if timeout is not None and timeout > 0:
        kwargs["timeout"] = float(timeout)

    sniff(**kwargs)
    return observations
