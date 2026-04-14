from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable

from app.collectors.file_collector import FileCollector
from app.config import AppSettings
from app.models.web_event import WebEvent
from app.storage.json_writer import JsonWriter
from app.web.web_detection import WebDetectionEngine
from app.web.web_log_parser import WebLogParser


def _resolve_input_logs(
    configured_log: Path, overrides: Iterable[Path] | None
) -> list[Path]:
    logs: list[Path] = [configured_log.resolve()]
    if overrides:
        for item in overrides:
            resolved = item.resolve()
            if resolved not in logs:
                logs.append(resolved)
    return logs


def run_web_pipeline(
    config_path: Path, log_file_overrides: Iterable[Path] | None = None
) -> None:
    settings = AppSettings.from_yaml(config_path)
    input_logs = _resolve_input_logs(settings.paths.web_log_file, log_file_overrides)
    parser = WebLogParser()

    events: list[WebEvent] = []
    for log_path in input_logs:
        collector = FileCollector(log_path)
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
    print("Web pipeline input files:")
    for path in input_logs:
        print(f"  - {path}")
    print(f"Events written: {settings.paths.web_events_output} ({len(events)})")
    print(f"Alerts written: {settings.paths.web_alerts_output} ({len(alerts)})")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ThreatLens web pipeline runner.")
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Optional settings.yaml path (default: <repo>/config/settings.yaml).",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        action="append",
        default=None,
        help=(
            "Optional extra log file (can be repeated). "
            "Example: --log-file data/live_web.log --log-file data/sample_web.log"
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    project_root = Path(__file__).resolve().parent.parent.parent
    config_path = args.config or (project_root / "config" / "settings.yaml")
    run_web_pipeline(config_path, args.log_file)


if __name__ == "__main__":
    main()
