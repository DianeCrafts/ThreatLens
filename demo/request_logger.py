from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

_MAX_UA_LEN: Final[int] = 2048


def normalize_client_ip(remote_addr: str | None) -> str:
    """
    Return an IPv4 string suitable for ThreatLens web log parsing.

    ``::1`` (IPv6 loopback) is mapped to ``127.0.0.1`` because the Phase 2 parser
    accepts IPv4 only.
    """
    if not remote_addr:
        return "127.0.0.1"
    stripped = remote_addr.strip()
    if stripped == "::1" or stripped == "::ffff:127.0.0.1":
        return "127.0.0.1"
    return stripped


def format_log_line(
    *,
    timestamp: datetime,
    source_ip: str,
    method: str,
    path: str,
    status_code: int,
    user_agent: str,
) -> str:
    """
    Build one pipe-delimited line compatible with ``app.web.web_log_parser.WebLogParser``.

    Format::

        ISO8601Z | source_ip | METHOD | /path | status | user_agent
    """
    ts = timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    safe_path = path if path.startswith("/") else f"/{path}"
    safe_method = method.upper()
    ua = user_agent.replace("\r", " ").replace("\n", " ").strip() or "-"
    if len(ua) > _MAX_UA_LEN:
        ua = ua[:_MAX_UA_LEN]
    return f"{ts} | {source_ip} | {safe_method} | {safe_path} | {status_code} | {ua}"


class DemoRequestLogger:
    """Append-only structured logging to a UTF-8 text file."""

    def __init__(self, log_path: Path) -> None:
        self._log_path = log_path
        self._lock = threading.Lock()

    @property
    def log_path(self) -> Path:
        return self._log_path

    def log_request(
        self,
        *,
        method: str,
        path: str,
        status_code: int,
        remote_addr: str | None,
        user_agent: str,
        timestamp: datetime | None = None,
    ) -> str:
        """
        Append one log line. Returns the line written (without trailing newline) for tests.
        """
        ts = timestamp or datetime.now(timezone.utc)
        line = format_log_line(
            timestamp=ts,
            source_ip=normalize_client_ip(remote_addr),
            method=method,
            path=path,
            status_code=status_code,
            user_agent=user_agent,
        )
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with self._log_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        return line
