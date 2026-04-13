from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.alerts.manager import AlertManager
from app.collectors.file_collector import FileCollector
from app.config import AppSettings
from app.detection.engine import DetectionEngine
from app.models.event import Event
from app.parsers.auth_parser import AuthLogParser
from app.storage.json_writer import JsonWriter


def run(config_path: Path) -> None:
    settings = AppSettings.from_yaml(config_path)
    collector = FileCollector(settings.paths.log_file)
    parser = AuthLogParser()

    events: list[Event] = []
    lines_read = 0
    malformed_lines = 0

    for line in collector.iter_lines():
        lines_read += 1
        parsed = parser.parse_line(line)
        if parsed is not None:
            events.append(parsed)
            continue
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            malformed_lines += 1

    events.sort(key=lambda event: event.timestamp)

    engine = DetectionEngine(settings.detection)
    alerts = engine.run(events)

    alert_manager = AlertManager()
    alert_manager.publish(alerts)

    writer = JsonWriter()
    writer.write_model_sequence(settings.paths.events_output, events)
    writer.write_model_sequence(settings.paths.alerts_output, alert_manager.alerts)

    summary: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "config_path": str(config_path.resolve()),
        "paths": {
            "log_file": str(settings.paths.log_file),
            "events_output": str(settings.paths.events_output),
            "alerts_output": str(settings.paths.alerts_output),
            "summary_output": str(settings.paths.summary_output),
        },
        "counts": {
            "lines_read": lines_read,
            "events_normalized": len(events),
            "malformed_lines": malformed_lines,
            "alerts": len(alert_manager.alerts),
        },
        "detection": {
            "brute_force": settings.detection.brute_force.model_dump(mode="json"),
        },
    }
    writer.write_json(settings.paths.summary_output, summary)
