from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


ProtocolName = Literal["tcp", "udp", "icmp", "other"]


class NetworkObservation(BaseModel):
    """Metadata-only view of a network packet or flow observation."""

    timestamp: datetime
    source_ip: str
    destination_ip: str
    destination_port: int = Field(
        ...,
        ge=0,
        le=65535,
        description="Transport destination port; 0 is used for protocols without ports (e.g. ICMP).",
    )
    protocol: ProtocolName
    raw_summary: str = Field(
        default="",
        max_length=512,
        description="Optional short description for auditing (no payload).",
    )
