from __future__ import annotations

from collections.abc import Sequence

from app.models.alert import Alert


class AlertManager:
    """Formats alerts for console output and retains them for persistence."""

    def __init__(self) -> None:
        self._alerts: list[Alert] = []

    @property
    def alerts(self) -> list[Alert]:
        return list(self._alerts)

    def publish(self, alerts: Sequence[Alert]) -> None:
        self._alerts.extend(alerts)
        for alert in alerts:
            self._print_alert(alert)

    @staticmethod
    def _print_alert(alert: Alert) -> None:
        ts = alert.timestamp.isoformat().replace("+00:00", "Z")
        lines = [
            "",
            "=" * 72,
            f"[{alert.severity}] {alert.alert_type.upper()} — {ts}",
            f"  ID:          {alert.alert_id}",
            f"  Source IP:   {alert.source_ip}",
            f"  Evidence:    {alert.evidence_count} events in {alert.time_window_seconds}s window",
            f"  Message:     {alert.message}",
            "=" * 72,
        ]
        print("\n".join(lines))
