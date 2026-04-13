from __future__ import annotations

from datetime import datetime, timezone


def parse_iso8601_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp string into an aware UTC datetime."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt
