from __future__ import annotations

from pathlib import Path

from app.collectors.file_collector import FileCollector
from app.config import AppSettings
from app.models.web_event import WebEvent
from app.storage.json_writer import JsonWriter
from app.web.web_detection import WebDetectionEngine
from app.web.web_log_parser import WebLogParser


def run_web_pipeline(config_path: Path) -> None:
    settings = AppSettings.from_yaml(config_path)
    collector = FileCollector(settings.paths.web_log_file)
    parser = WebLogParser()

    events: list[WebEvent] = []
    for line in collector.iter_lines():
        parsed = parser.parse_line(line)
        if parsed is not None:
            events.append(parsed)

    events.sort(key=lambda event: event.timestamp)

    engine = WebDetectionEngine(settings.detection.web)
    alerts = engine.run(events)

    writer = JsonWriter()
    writer.write_model_sequence(settings.paths.web_events_output, events)
    writer.write_model_sequence(settings.paths.web_alerts_output, alerts)


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent.parent
    config_path = project_root / "config" / "settings.yaml"
    run_web_pipeline(config_path)


if __name__ == "__main__":
    main()
