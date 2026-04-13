from __future__ import annotations

import ipaddress
import re
from typing import Final

from app.models.event import Event
from app.utils.time_utils import parse_iso8601_timestamp

_STATUS_FAIL: Final[str] = "FAIL"
_STATUS_SUCCESS: Final[str] = "SUCCESS"


def _is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


class AuthLogParser:
    """
    Parser for ThreatLens pipe-delimited authentication logs.

    Expected format (fields separated by '|'):

        ISO8601_timestamp | source_ip | service | username | STATUS | message

    STATUS must be FAIL or SUCCESS. Lines starting with '#' and blank lines are skipped.
    """

    _username_re: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

    def parse_line(self, line: str) -> Event | None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return None
        parts = [segment.strip() for segment in stripped.split("|")]
        if len(parts) < 6:
            return None
        timestamp_raw, source_ip, service, username, status_raw, raw_message = (
            parts[0],
            parts[1],
            parts[2],
            parts[3],
            parts[4],
            "|".join(parts[5:]).strip(),
        )
        if not all(
            (
                timestamp_raw,
                source_ip,
                service,
                username,
                status_raw,
            )
        ):
            return None
        if status_raw not in (_STATUS_FAIL, _STATUS_SUCCESS):
            return None
        if not _is_valid_ipv4(source_ip):
            return None
        if not service or len(service) > 32:
            return None
        if not self._username_re.match(username):
            return None
        try:
            timestamp = parse_iso8601_timestamp(timestamp_raw)
        except ValueError:
            return None

        event_type = "login_failed" if status_raw == _STATUS_FAIL else "login_success"
        return Event(
            timestamp=timestamp,
            source_ip=source_ip,
            event_type=event_type,
            username=username,
            service=service,
            status=status_raw,
            raw_message=stripped,
        )
