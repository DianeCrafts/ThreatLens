from __future__ import annotations

import ipaddress
from typing import Final

from app.models.web_event import WebEvent
from app.utils.time_utils import parse_iso8601_timestamp

_HTTP_METHODS: Final[frozenset[str]] = frozenset(
    {
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "CONNECT",
        "TRACE",
    }
)


def _is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


class WebLogParser:
    """
    Parser for ThreatLens pipe-delimited web access logs.

    Expected format:

        ISO8601_timestamp | source_ip | METHOD | /path | status | user_agent

    Additional '|' characters in the user agent are preserved by joining the tail.
    Lines starting with '#' and blank lines are skipped.
    """

    def parse_line(self, line: str) -> WebEvent | None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return None
        parts = [segment.strip() for segment in stripped.split("|")]
        if len(parts) < 6:
            return None
        timestamp_raw = parts[0]
        source_ip = parts[1]
        method = parts[2].upper()
        path = parts[3]
        status_raw = parts[4]
        user_agent = "|".join(parts[5:]).strip()
        if not all((timestamp_raw, source_ip, method, path, status_raw)):
            return None
        if method not in _HTTP_METHODS:
            return None
        if not _is_valid_ipv4(source_ip):
            return None
        if not path.startswith("/") or len(path) > 2048:
            return None
        try:
            http_status = int(status_raw)
        except ValueError:
            return None
        if not 100 <= http_status <= 599:
            return None
        try:
            timestamp = parse_iso8601_timestamp(timestamp_raw)
        except ValueError:
            return None

        return WebEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            event_type="web_request",
            http_method=method,
            path=path,
            http_status=http_status,
            event_source="web",
            user_agent=user_agent if user_agent != "-" else "",
            raw_message=stripped,
        )
