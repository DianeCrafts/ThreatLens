from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class Event(BaseModel):
    """Normalized authentication log event."""

    timestamp: datetime
    source_ip: str
    event_type: Literal["login_failed", "login_success"]
    username: str
    service: str
    status: Literal["FAIL", "SUCCESS"]
    raw_message: str = Field(
        ...,
        description="Original log line or reconstructed canonical representation.",
    )
