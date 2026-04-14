from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class Alert(BaseModel):
    """Structured security alert."""

    alert_id: str
    timestamp: datetime
    alert_type: Literal[
        "brute_force",
        "suspicious_web_activity",
        "traffic_spike",
    ]
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    source_ip: str
    message: str
    evidence_count: int = Field(..., ge=0)
    time_window_seconds: int = Field(..., ge=1)
